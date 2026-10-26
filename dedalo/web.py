"""Portal local: cargas, cola persistente y galería sobre el motor CLI existente."""

from __future__ import annotations

from contextlib import closing
import copy
import csv
from datetime import datetime, timezone
import errno
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import mimetypes
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
import uuid
import webbrowser
from xml.etree.ElementTree import ParseError
import zipfile

from . import (auditoria, catalogo, cli, credenciales, cve, db, descubrimiento, exploits, favicones, fingerprint,
               gowitness, inventory, modelo, parser, prioridad, probador, redes, report, targets, vulnerabilidades)

VERSION_AVISO = ("Con la API de Claude, el HTML y las cabeceras de cada captura salen de tu equipo "
                 "hacia la nube de Anthropic. La clave va en la variable de entorno ANTHROPIC_API_KEY.")

STATIC = Path(__file__).parent / "static"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/logo.png": ("logo.png", "image/png"),
}
MAX_BODY = 32 * 1024 * 1024
ACTIVE = {"en_cola", "en_curso", "deteniendo"}
# Datos del cruce de vulnerabilidades, dentro de la carpeta de datos del portal: los feeds de la NVD
# (temporales), y los ficheros públicos de exploits ya descargados (exploits.KEV_FICHERO y EXPLOITDB_FICHERO).
CARPETA_VULNS = "vulnerabilidades"


class Conflict(ValueError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


def _has_capture_options(raw):
    """Una importación ya migrada guarda las opciones de captura del portal (ver auditoria.portal_options)."""
    try:
        return "captura" in json.loads(raw)
    except (TypeError, ValueError):
        return False


def write_scope_files(directory, scope):
    """Alcance que usará el motor de capturas: rangos incluidos y exclusiones."""
    (directory / "rangos.txt").write_text("".join(f"{net}\n" for net in scope.include), encoding="utf-8")
    (directory / "excluir.txt").write_text("".join(f"{net}\n" for net in scope.exclude), encoding="utf-8")


def text_field(value, label, maximum):
    if not isinstance(value, str) or len(value) > maximum:
        raise ValueError(f"{label}: texto inválido o demasiado largo")
    return value


def options_from(raw):
    if not isinstance(raw, dict):
        raise ValueError("Opciones inválidas")
    result = {}
    for key, default, lower, upper in (("hilos", 6, 1, 32), ("timeout", 60, 1, 300), ("delay", 10, 0, 30)):
        value = raw.get(key, default)
        if type(value) is not int or not lower <= value <= upper:
            raise ValueError(f"{key}: indica un número entre {lower} y {upper}")
        result[key] = value
    result["formato"] = raw.get("formato", "jpeg")
    if result["formato"] not in ("jpeg", "png"):
        raise ValueError("Formato de captura inválido")
    result["puertos"] = text_field(raw.get("puertos", ""), "Puertos", 2000)
    from .targets import parse_port_map
    parse_port_map(result["puertos"])
    for key, default in (("por_servicio", False), ("pagina_completa", False), ("reintentar", True), ("barra_url", True)):
        result[key] = raw.get(key, default)
        if type(result[key]) is not bool:
            raise ValueError(f"{key}: valor inválido")
    result["driver"] = raw.get("driver", gowitness.DRIVERS[0])
    if result["driver"] not in gowitness.DRIVERS:
        raise ValueError("Motor del navegador inválido")
    return result


class _AlcanceVivo:
    """status(ip) con el alcance VIGENTE de la ficha; relee solo cuando cambia store.scope_changes.

    `sweep` lo consulta desde varios hilos; un cerrojo serializa la relectura, que solo ocurre
    cuando el alcance cambió (el caso normal usa la copia cacheada).
    """

    def __init__(self, store, audit_id):
        self._store, self._audit_id = store, audit_id
        self._lock, self._contador, self._scope = threading.Lock(), None, None

    def status(self, ip):
        with self._lock:
            if self._store.scope_changes != self._contador:
                with closing(self._store.database()) as con:
                    self._scope = auditoria.scope(con, self._audit_id)
                self._contador = self._store.scope_changes
            return self._scope.status(ip)


class PortalStore:
    def __init__(self, root, binary=None, chrome=None, model=modelo.DEFAULT_MODEL, ollama=modelo.OLLAMA,
                 dns_dominio="example.com", catalogo_ruta=catalogo.RUTA, sin_internet=None):
        self.root = Path(root).resolve()
        # Interruptor global de salidas a internet (NVD, GitHub…): el resto del código lo consulta antes
        # de cualquier conexión a internet. Orden: argumento (--sin-internet), DEDALO_SIN_INTERNET, False.
        self.sin_internet = bool(sin_internet) if sin_internet is not None else \
            os.environ.get("DEDALO_SIN_INTERNET", "").strip().lower() in ("1", "true", "sí", "si")
        self.dns_dominio = dns_dominio
        # Fichero del catálogo de credenciales (compartido por el repo); configurable para apuntar
        # al del equipo. Se vuelca a la base al arrancar y cada vez que se amplía desde el portal.
        self.catalogo_ruta = Path(catalogo_ruta)
        self.root.mkdir(parents=True, exist_ok=True)
        self.binary_option, self.chrome_option = binary, chrome
        self.model_option, self.model_host = model, ollama
        self.lock = threading.RLock()
        self.imports = threading.Lock()
        self.pending = queue.Queue()
        self.closing = False
        self.token = secrets.token_urlsafe(32)
        # Impide que dos portales ejecuten o modifiquen el mismo historial.
        self.file_lock = (self.root / ".portal.lock").open("a+b")
        if self.file_lock.seek(0, 2) == 0:
            self.file_lock.write(b"1")
            self.file_lock.flush()
        self.file_lock.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.file_lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file_lock.close()
            raise ValueError("Ya hay un portal usando esta carpeta de datos")
        try:
            # Crea o actualiza la base al arrancar para detectar pronto cualquier problema.
            self.database().close()
        except Exception:
            self.file_lock.close()
            raise
        # El historial está en la base (docs/MODELO_DATOS.md); self.jobs es solo su
        # copia en memoria para responder rápido a las consultas del navegador.
        self.jobs = {}
        # Sube con cada cambio de alcance: un plan calculado sin el bloqueo (detail) no se
        # guarda si el alcance cambió mientras tanto.
        self.scope_changes = 0
        # Hosts ya preguntados del análisis en curso de cada ejecución; solo en memoria:
        # al reabrir el portal, un análisis a medias queda interrumpido.
        self.analysis_progress = {}
        # Servicios ya probados de la prueba de credenciales en curso; solo en memoria, como el análisis.
        self.credential_progress = {}
        # Direcciones ya consultadas del descubrimiento en curso; solo en memoria, como el análisis.
        self.discovery_progress = {}
        # Servicios ya mirados de la detección de versión en curso; solo en memoria, como el análisis.
        self.version_progress = {}
        # Servicios ya cruzados del cruce de vulnerabilidades en curso; solo en memoria, como el análisis.
        self.vuln_progress = {}
        # Una sola actualización de la base NVD a la vez (la del arranque y la de un cruce no se pisan).
        self.nvd_lock = threading.Lock()
        # Carpetas antiguas que no se pudieron pasar a la base en este arranque; el
        # portal las muestra (/api/bootstrap) porque no aparecen en el historial.
        self.migration_failures = []
        try:
            self._finish_deletes()
            self._migrate_folders()
            self._load()
        except Exception:
            self.file_lock.close()
            raise
        self.worker = threading.Thread(target=self._worker, name="dedalo-capturas", daemon=True)
        self.worker.start()

    def database(self):
        # Una conexión por operación: los hilos del servidor no comparten conexiones.
        return db.connect(self.root)

    def _finish_deletes(self):
        """Carpetas que delete() apartó y no terminó: vuelven si su ejecución sigue en la base; si no, se borran."""
        with closing(self.database()) as con:
            for path in self.root.glob(".*"):
                job_id = path.name[1:]
                if not re.fullmatch(r"[a-f0-9]{32}", job_id) or path.is_symlink() or path.is_junction():
                    continue
                try:
                    if auditoria.has_execution(con, job_id):
                        path.rename(self.root / job_id)
                    else:
                        shutil.rmtree(path)
                except OSError as exc:
                    print(f"Aviso: no se pudo terminar de borrar ni devolver a su sitio la carpeta {path}: {exc}",
                          file=sys.stderr)

    def _migrate_folders(self):
        """Lleva a la base las ejecuciones que solo tenían trabajo.json (pasos 5 y 6 del plan).

        Cada carpeta se migra una sola vez y no se modifica (salvo el fichero de
        parada de una ejecución que estaba activa). Si una no se puede migrar, se
        avisa en la terminal y en el portal (migration_failures), su carpeta queda
        como estaba y el siguiente arranque lo vuelve a intentar.
        """
        # Las carpetas conservan su trabajo.json después de migrarse: una sola consulta dice cuáles faltan.
        with closing(self.database()) as con:
            migrated = {row["id"] for row in con.execute("SELECT id, opciones FROM ejecucion WHERE tipo = 'importacion'")
                        if _has_capture_options(row["opciones"])}
        pending = [path for path in sorted(self.root.glob("*/trabajo.json"))
                   if re.fullmatch(r"[a-f0-9]{32}", path.parent.name) and path.parent.name not in migrated]
        if pending:
            count = "1 ejecución anterior" if len(pending) == 1 else f"{len(pending)} ejecuciones anteriores"
            print(f"Pasando {count} a la base de datos; la primera vez puede tardar unos minutos.", flush=True)
        for path in pending:
            job_id = path.parent.name
            meta = None
            try:
                with closing(self.database()) as con:
                    meta = json.loads(path.read_text(encoding="utf-8"))
                    found = meta.get("id") if isinstance(meta, dict) else None
                    if found != job_id:
                        shown = "ninguno" if found is None else str(found)[:40]
                        raise ValueError(f"El id que trae trabajo.json ({shown}) no coincide con el de su carpeta; "
                                         "no se migra por si es una copia o se editó a mano.")
                    # Las opciones de versiones anteriores no traen todos los campos de hoy.
                    meta["opciones"] = options_from(meta.get("opciones", {}))
                    self._imported(con, job_id, meta)  # importa sus Nmap si era anterior a la base
                    if meta["estado"] != "preparada" and auditoria.capture_of(con, job_id) is None:
                        self._migrate_capture(con, job_id, meta)
                    # Con "captura" en sus opciones, la ejecución queda migrada.
                    auditoria.set_options(con, job_id, {"archivos": meta["archivos"], "captura": meta["opciones"]})
            except Exception as exc:
                print(f"Aviso: no se pudo pasar a la base la ejecución {job_id}: {exc}. Su carpeta se conserva.",
                      file=sys.stderr)
                name = meta.get("nombre") if isinstance(meta, dict) else ""
                self.migration_failures.append({"id": job_id, "nombre": name if isinstance(name, str) else "",
                                                "error": str(exc) or type(exc).__name__})

    def _migrate_capture(self, con, job_id, meta):
        """Una captura hecha antes de que la base las guardase, con sus resultados."""
        state, error = meta["estado"], meta.get("error", "")
        if state in ACTIVE:
            state, error = "interrumpida", "El portal se cerró antes de completar el trabajo."
            self._request_stop(job_id)
        manifest = self._manifest(meta)
        result = self.directory(job_id) / "resultado"
        logs = self._result_logs(job_id, manifest) if manifest else []
        try:
            _, missing = auditoria.import_capture_history(con, job_id, meta["opciones"], meta.get("grupos", []), state,
                                                          error, meta["fecha"], meta.get("fin"), manifest, result,
                                                          self.root, logs)
        except sqlite3.Error:
            raise  # un fallo de la base no es un dato del manifiesto: la carpeta se reintenta al arrancar
        except Exception as exc:
            # Objetivos que no casan con el inventario, un manifiesto con campos que
            # faltan, una imagen ilegible...: al menos se conserva el estado, y las
            # capturas se siguen viendo desde su carpeta.
            print(f"Aviso: la captura de {job_id} se registra sin sus resultados: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
            auditoria.import_capture_history(con, job_id, meta["opciones"], [], state, error,
                                             meta["fecha"], meta.get("fin"), None, result, self.root)
        else:
            self._report_missing_images(job_id, missing)

    def _load(self):
        """Carga el historial desde la base y cierra lo que quedó a medias."""
        with closing(self.database()) as con:
            auditoria.close_interrupted_analyses(con)
            try:
                catalogo.cargar(con, self.catalogo_ruta)  # vuelca el catálogo al abrir, si su fichero cambió
            except (OSError, ValueError) as exc:
                # Un catálogo roto no tumba el portal: solo deja sin probar credenciales.
                print(f"Aviso: no se pudo cargar el catálogo de credenciales: {exc}. El resto del portal "
                      "funciona; probar credenciales no estará disponible hasta arreglarlo.", file=sys.stderr)
            for row in auditoria.portal_jobs(con):
                if not (self.root / row["id"]).is_dir():
                    continue  # importación sin carpeta del portal
                meta = self._load_run(con, row)
                if meta is not None:
                    self.jobs[meta["id"]] = meta

    def _load_run(self, con, row):
        """Una ejecución del historial, sin su plan: se calcula al abrirla (_ensure_plan).

        Si no se puede cargar, sale igualmente: con su error y sin objetivos.
        """
        meta = {"id": row["id"], "nombre": row["nombre"], "fecha": row["creada"], "archivos": [], "opciones": {},
                "estado": row["estado"] or "preparada", "error": row["error"] or "", "fin": row["terminada"],
                "grupos": None, "total": 0, "subredes": 0, "fuera_alcance": None}
        failure = None
        try:
            options = json.loads(row["opciones"])
            if "captura" not in options:
                return None  # importación que no se pudo migrar: se avisa en migration_failures
            # Lo que no traigan ejecuciones preparadas por versiones anteriores toma el valor de una nueva.
            meta.update(archivos=options.get("archivos", []), opciones=options_from(options["captura"]))
        except Exception as exc:
            failure = exc
        try:
            if meta["estado"] in ACTIVE:
                self._close_interrupted(meta)  # también si sus opciones no se leen: no puede seguir activa
        except Exception as exc:
            failure = failure or exc
        if failure is not None:
            self._unloadable(meta, failure)
        return meta

    @staticmethod
    def _unloadable(meta, failure):
        print(f"Error del portal: no se pudo cargar la ejecución {meta['id']}: {type(failure).__name__}: {failure}",
              file=sys.stderr)
        # Los errores propios (ValueError con su explicación) se muestran tal cual; el resto, en genérico.
        known = type(failure) is ValueError and str(failure)
        meta.update(grupos=[], total=0, subredes=0, fuera_alcance=None,
                    error="No se pudo cargar esta ejecución: " +
                          (str(failure) if known else "sus datos guardados están incompletos o dañados."))
        if meta["estado"] == "preparada":
            meta["estado"] = "error"  # sin lanzar no hay resultados que mostrar: así se ve el motivo

    def _ensure_plan(self, meta):
        """Calcula el plan si la ejecución aún no lo tiene; meta puede ser una copia (detail lo hace sin el bloqueo)."""
        if meta["grupos"] is None:
            try:
                with closing(self.database()) as con:
                    self._load_plan(con, meta)
            except (OSError, sqlite3.OperationalError):
                raise  # disco o base ocupados un momento: se reintenta al volver a pedirla
            except Exception as exc:
                self._unloadable(meta, exc)

    def _request_stop(self, job_id):
        """Pide al motor de una captura que quizá siga viva que pare al acabar la subred actual."""
        # Si el portal murió sin cerrarse, su motor puede seguir conectando (en Windows el
        # proceso hijo sobrevive). Con el fichero de parada acaba la subred actual y no sigue.
        try:
            (self.directory(job_id) / "parar").touch()
        except OSError as exc:
            print(f"Error del portal: no se pudo pedir al motor de {job_id} que pare: {exc}", file=sys.stderr)

    def _close_interrupted(self, meta):
        """El portal se cerró con esta captura activa: se toma el estado del motor si terminó."""
        self._request_stop(meta["id"])
        manifest = self._manifest(meta)
        if manifest and manifest.get("estado") in ("completa", "parcial", "interrumpida"):
            state, error = manifest["estado"], ""
        else:
            state, error = "interrumpida", "El portal se cerró antes de completar el trabajo."
        self._capture_state(meta["id"], state, error, record=True)
        meta.update(estado=state, error=error)

    def _load_plan(self, con, meta):
        """Objetivos de una ejecución: lo planificado si ya se lanzó, o lo que permite el alcance vigente."""
        capture_id = auditoria.capture_of(con, meta["id"])
        if capture_id is None:
            self._plan_unlaunched(con, meta)
            return
        # Lo lanzado no cambia: las URL quedaron en la base y la agrupación en su rangos.txt.
        hosts = auditoria.observed_hosts(con, meta["id"])
        planned = auditoria.planned_urls(con, capture_id)
        ranges_file = self.directory(meta["id"]) / "rangos.txt"
        ranges = targets.read_networks_file(ranges_file) if ranges_file.is_file() else []
        options = meta["opciones"]
        groups = cli.group_hosts(hosts, ranges, options.get("puertos", ""), options.get("por_servicio", False))
        groups = [{**g, "objetivos": [t for t in g["objetivos"] if t["url"] in planned]} for g in groups]
        groups = [g for g in groups if g["objetivos"]]
        meta.update(grupos=groups, total=sum(len(g["objetivos"]) for g in groups), subredes=len(groups),
                    fuera_alcance=None)

    def _result_logs(self, job_id, manifest):
        result = self.directory(job_id) / "resultado"
        return [self.directory(job_id) / "proceso.log"] + [
            report.inside(result, g["carpeta"]) / name for g in manifest["grupos"]
            for name in gowitness.LOGS]

    def _capture_state(self, job_id, state, error="", record=False, strict=False):
        """Guarda en la base el estado de la captura de un trabajo y, si se pide, sus resultados.

        Con strict, un fallo se propaga (acciones del usuario). Si no, se avisa y no para
        la cola: al reabrir el portal, la captura activa se cierra desde el manifiesto.
        Registrar los resultados no impide guardar el estado: sin él, la captura seguiría
        activa en la base y se volvería a cerrar en cada arranque.
        """
        try:
            with closing(self.database()) as con:
                capture_id = auditoria.capture_of(con, job_id)
                if capture_id is None:
                    return
                if record:
                    try:
                        manifest = self._manifest({"id": job_id})
                        if manifest:
                            missing = auditoria.record_captures(con, capture_id, manifest,
                                                                self.directory(job_id) / "resultado", self.root,
                                                                self._result_logs(job_id, manifest))
                            self._report_missing_images(job_id, missing)
                    except Exception as exc:
                        print(f"Error del portal: no se pudieron registrar en la base los resultados de {job_id}: {exc}",
                              file=sys.stderr)
                auditoria.set_state(con, capture_id, state, error)
        except Exception as exc:
            if strict:
                raise
            print(f"Error del portal: no se pudo registrar en la base la captura de {job_id}: {exc}", file=sys.stderr)

    @staticmethod
    def _report_missing_images(job_id, missing):
        """Avisa de las imágenes que el motor citó y ya no estaban en disco al registrar los resultados."""
        if missing:
            shown = ", ".join(missing[:5]) + (", …" if len(missing) > 5 else "")
            print(f"Aviso: la captura de {job_id} se registró sin las imágenes que no están en disco "
                  f"({len(missing)}): {shown}", file=sys.stderr)

    def directory(self, job_id):
        if not re.fullmatch(r"[a-f0-9]{32}", job_id):
            raise FileNotFoundError("Trabajo no encontrado")
        return report.inside(self.root, job_id)

    def _meta(self, job_id):
        if job_id not in self.jobs:
            raise FileNotFoundError("Trabajo no encontrado")
        return self.jobs[job_id]

    def engine(self):
        try:
            binary = gowitness.find_gowitness(self.binary_option)
            chrome = gowitness.find_chrome(self.chrome_option)
            return {"ready": True, "browser": Path(chrome).name if chrome else "Descarga automática",
                    "error": ""}
        except (OSError, ValueError) as exc:
            return {"ready": False, "browser": "", "error": str(exc)}

    def create(self, payload):
        if not isinstance(payload, dict):
            raise ValueError("Carga inválida")
        name = text_field(payload.get("nombre", ""), "Nombre", 120).strip() or "Nueva captura"
        files = payload.get("archivos")
        if not isinstance(files, list) or not 1 <= len(files) <= 20:
            raise ValueError("Selecciona entre 1 y 20 archivos nmap")
        options = options_from(payload.get("opciones", {}))
        audit_id = payload.get("auditoria")
        hosts, uploads = [], []
        for item in files:
            if not isinstance(item, dict):
                raise ValueError("Archivo inválido")
            filename = text_field(item.get("nombre", ""), "Nombre de archivo", 255)
            content = text_field(item.get("contenido", ""), filename, 10 * 1024 * 1024)
            try:
                hosts.append(parser.parse_text(content))
            except (ValueError, ParseError) as exc:
                raise ValueError(f"{filename}: {exc}") from exc
            uploads.append((filename, content))
        merged = parser.merge(hosts)
        inventory.build(merged, [])  # valida los límites antes de guardar nada
        job_id = uuid.uuid4().hex
        meta = {"id": job_id, "nombre": name, "fecha": now(), "estado": "preparada",
                "archivos": [n for n, _ in uploads], "opciones": options, "error": ""}
        with self.lock:
            if self.closing:
                raise Conflict("El portal se está cerrando")
            with closing(self.database()) as con:
                if audit_id is None:
                    audit_id = auditoria.default_audit(con)
                elif not isinstance(audit_id, str) or not auditoria.audit_exists(con, audit_id):
                    raise ValueError("Elige una ficha de cliente existente")
                scope = auditoria.scope(con, audit_id)
        self._plan(meta, merged, scope)  # valida el límite de objetivos antes de escribir
        directory = self.directory(job_id)
        (directory / "entradas").mkdir(parents=True)
        imported = False
        try:
            paths = []
            for index, (_, content) in enumerate(uploads):
                paths.append(directory / "entradas" / f"nmap-{index:02d}.txt")
                paths[-1].write_text(content, encoding="utf-8")
            # Una importación grande tarda: sin el bloqueo global, el portal sigue
            # respondiendo. Las importaciones van de una en una entre sí.
            with self.imports, closing(self.database()) as con:
                auditoria.import_nmap(con, audit_id, job_id, name, merged, paths, self.root, meta["fecha"],
                                      {"archivos": meta["archivos"], "captura": options})
            imported = True
            with self.lock:
                # La ficha pudo editarse mientras tanto: se planifica con el alcance vigente.
                with closing(self.database()) as con:
                    scope = auditoria.scope(con, audit_id)
                self._plan(meta, merged, scope)
                write_scope_files(directory, scope)
                self.jobs[job_id] = meta
        except Exception:
            # Sin importación completa no queda una ejecución a medias.
            shutil.rmtree(directory, ignore_errors=True)
            if imported:
                with closing(self.database()) as con:
                    auditoria.delete_execution(con, job_id)
            raise
        return self.detail(job_id)

    @staticmethod
    def _plan(meta, hosts, scope):
        """Objetivos web de una ejecución: solo lo que está en alcance (docs/CONTRATOS.md 0.3)."""
        options = meta["opciones"]
        groups = cli.group_hosts(hosts, [str(net) for net in scope.include], options["puertos"], options["por_servicio"])
        planned, skipped = [], {scope.OUT: 0, scope.EXCLUDED: 0}
        for group in groups:
            kept = []
            for target in group["objetivos"]:
                status = scope.status(target["ip"])
                if status == scope.IN:
                    kept.append(target)
                else:
                    skipped[status] += 1
            if kept:
                planned.append({**group, "objetivos": kept})
        total = sum(len(g["objetivos"]) for g in planned)
        if total > 100_000:
            raise ValueError("Demasiados objetivos para una ejecución web; divide los archivos (máximo 100.000).")
        meta.update(grupos=planned, total=total, subredes=len(planned), fuera_alcance=skipped)

    def _imported(self, con, job_id, meta):
        """Garantiza que la ejecución está en la base y devuelve su ficha."""
        if not auditoria.has_execution(con, job_id):
            # Ejecuciones anteriores a la base: se importan desde sus Nmap guardados.
            inputs = sorted((self.directory(job_id) / "entradas").glob("nmap-*.txt"))
            if not inputs:
                raise FileNotFoundError("No se conservan los Nmap de esta ejecución para reconstruir el inventario.")
            hosts = parser.merge([parser.parse_file(item) for item in inputs])
            auditoria.import_nmap(con, auditoria.default_audit(con), job_id, meta["nombre"], hosts, inputs,
                                  self.root, meta["fecha"])
        return auditoria.audit_of(con, job_id)

    def _plan_unlaunched(self, con, meta):
        """Objetivos de una ejecución sin lanzar con el alcance vigente de su ficha; devuelve ese alcance."""
        scope = auditoria.scope(con, auditoria.audit_of(con, meta["id"]))
        self._plan(meta, auditoria.observed_hosts(con, meta["id"]), scope)
        return scope

    def _replan(self, job_id):
        """Recalcula una ejecución sin lanzar con el alcance vigente de su ficha."""
        meta = self._meta(job_id)
        with closing(self.database()) as con:
            self._imported(con, job_id, meta)
            scope = self._plan_unlaunched(con, meta)
        write_scope_files(self.directory(job_id), scope)

    def inventory(self, job_id):
        with self.lock:
            meta = self._meta(job_id)
            directory = self.directory(job_id)
            with closing(self.database()) as con:
                scope = auditoria.scope(con, self._imported(con, job_id, meta))
                hosts = auditoria.observed_hosts(con, job_id)
                cruce = auditoria.vuln_results(con, job_id)  # solo activos en el alcance vigente
            data = inventory.build(hosts, targets.read_networks_file(directory / "rangos.txt"))
            for asset in data["activos"]:
                asset["alcance"] = scope.status(asset["ip"])
            return inventory.add_vulns(data, cruce)

    def index_csv(self, job_id):
        """El índice de capturas (indice.csv) con lo último que dio el cruce de vulnerabilidades, sin escribir nada.

        Se compone al descargar, no al capturar: el cruce va después de la captura y puede repetirse, y un servicio
        que se excluye después deja de salir (vuln_results solo da los del alcance vigente).
        """
        with self.lock:
            meta = self._meta(job_id)
            manifest = self._manifest(meta)
            if manifest is None:  # sin manifiesto legible: se sirve el archivo tal cual (o falla si no existe)
                return (self.directory(job_id) / "resultado" / "indice.csv").read_bytes()
            with closing(self.database()) as con:
                columnas = vulnerabilidades.columnas_tcp(auditoria.vuln_results(con, job_id))
        return report.index_bytes(manifest, columnas)

    def audits(self):
        with self.lock, closing(self.database()) as con:
            return auditoria.audits(con)

    def create_audit(self, payload):
        if not isinstance(payload, dict):
            raise ValueError("Carga inválida")
        with self.lock, closing(self.database()) as con:
            audit_id = auditoria.create_audit(con, payload.get("nombre"), payload.get("incluir", ""), payload.get("excluir", ""))
            return next(a for a in auditoria.audits(con) if a["id"] == audit_id)

    def update_audit(self, audit_id, payload):
        if not isinstance(payload, dict):
            raise ValueError("Carga inválida")
        with self.lock:
            with closing(self.database()) as con:
                auditoria.update_audit(con, audit_id, payload.get("nombre"), payload.get("incluir", ""), payload.get("excluir", ""))
                owners = auditoria.audits_by_execution(con)
                scope = auditoria.scope(con, audit_id)
            self.scope_changes += 1
            # Lo ya lanzado no cambia. Lo preparado toma el alcance nuevo: se recalcula si ya se
            # abrió; si no, se calculará al abrirlo y basta con su alcance en disco (inventory).
            for job_id, meta in self.jobs.items():
                if meta["estado"] == "preparada" and owners.get(job_id) == audit_id:
                    if meta["grupos"] is None:
                        write_scope_files(self.directory(job_id), scope)
                    else:
                        self._replan(job_id)
            with closing(self.database()) as con:
                return next(a for a in auditoria.audits(con) if a["id"] == audit_id)

    def _manifest(self, meta):
        path = self.directory(meta["id"]) / "resultado" / report.MANIFEST
        try:
            return report.load_manifest(path.parent)
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _owners(self, job_ids):
        with closing(self.database()) as con:
            owners = auditoria.audits_by_execution(con)
            # Las ejecuciones que aún no están en la base se importarán a «Importadas».
            if any(job_id not in owners for job_id in job_ids):
                default = auditoria.default_audit(con)
                owners = {job_id: owners.get(job_id, default) for job_id in job_ids}
        return owners

    def list(self):
        """Lo que pinta el historial; los planes y los manifiestos solo hacen falta al abrir una ejecución."""
        with self.lock:
            rows = [{key: meta[key] for key in ("id", "nombre", "fecha", "estado")} for meta in self.jobs.values()]
        owners = self._owners([row["id"] for row in rows])
        return [row | {"auditoria": owners[row["id"]]} for row in sorted(rows, key=lambda r: r["fecha"], reverse=True)]

    def detail(self, job_id):
        with self.lock:
            meta = self._meta(job_id)
            draft = None
            if meta["grupos"] is None:
                draft = {key: meta[key] for key in ("id", "opciones", "estado", "error", "grupos")}
                changes = self.scope_changes
        if draft is not None:
            self._ensure_plan(draft)  # sin el bloqueo: en una ejecución grande tarda, y el portal sigue atendiendo
        with self.lock:
            meta = self._meta(job_id)
            if draft is not None and meta["grupos"] is None and changes == self.scope_changes:
                meta.update(draft)
            self._ensure_plan(meta)  # si el alcance cambió mientras tanto, se calcula aquí con el nuevo
            # Los planes se sustituyen y nunca se modifican en sitio: basta con copiar el primer nivel.
            meta = dict(meta)
        manifest = self._manifest(meta)
        groups = manifest["grupos"] if manifest else meta["grupos"]
        root = self.directory(job_id) / "resultado"
        done = sum(len(g["objetivos"]) for g in groups if g["estado"] in ("completo", "parcial", "error", "interrumpido"))
        response = {k: meta[k] for k in ("id", "nombre", "fecha", "estado", "total", "subredes", "error")} | {
            "capturas": sum(g.get("capturas", 0) for g in groups),
            "sin_captura": sum(g.get("sin_captura", 0) for g in groups),
            "procesadas": done,
        }
        response.update(archivos=meta["archivos"], opciones=meta["opciones"], grupos=[],
                        csv=(root / "indice.csv").is_file(), auditoria=self._owners([job_id])[job_id],
                        fuera_alcance=meta.get("fuera_alcance"))
        for index, group in enumerate(groups):
            rows = {r["url"]: r for r in group.get("resultados", [])}
            errors = gowitness.read_errors(report.inside(root, group["carpeta"]))
            live = {}
            if group["estado"] == "en_curso":
                try:
                    live = gowitness.read_results(report.inside(root, group["carpeta"]) / gowitness.DB_NAME)
                except (OSError, sqlite3.Error, ValueError):
                    pass
            targets = []
            for number, target in enumerate(group["objetivos"]):
                row = rows.get(target["url"], {})
                current = gowitness.find_result(live, target["url"])
                captured = bool(row.get("captura") or current)
                targets.append({
                    "ip": target["ip"], "puerto": target["port"], "url": target["url"],
                    "titulo": row.get("titulo", "") or (current or {}).get("title", ""),
                    "codigo": row.get("codigo_http", "") or (current or {}).get("response_code", ""),
                    "url_final": row.get("url_final", "") or (current or {}).get("final_url", ""),
                    "estado": "capturada" if captured else row.get("estado", group["estado"] if group["estado"] == "en_curso" else "pendiente"),
                    "error": "" if captured else gowitness.find_error(errors, target["url"]) or row.get("error", ""),
                    "imagen": f"/api/jobs/{job_id}/image/{index}/{number}" if captured else "",
                })
            response["grupos"].append({
                "rango": group["rango"], "subred": group["subred"], "estado": group["estado"],
                "capturas": sum(bool(t["imagen"]) for t in targets), "objetivos": targets, "error": group.get("error", ""),
            })
        response["capturas"] = sum(g["capturas"] for g in response["grupos"])
        with closing(self.database()) as con:
            response["analisis"] = auditoria.analysis_status(con, job_id)
            response["prioridades"] = auditoria.priorities(con, job_id)
            response["credenciales"] = auditoria.credential_status(con, job_id)
            response["credenciales_resultados"] = auditoria.credential_results(con, job_id)
            response["descubrimiento"] = auditoria.discovery_status(con, job_id)
            response["descubrimiento_resultados"] = auditoria.discovery_results(con, job_id)
            response["version"] = auditoria.version_status(con, job_id)
            response["versiones"] = auditoria.version_readings(con, job_id)
            response["vuln"] = auditoria.vuln_status(con, job_id)
            # En orden determinista (vulnerabilidades.orden) y con la prioridad de cada servicio.
            response["vulnerabilidades"] = vulnerabilidades.ordenar_servicios(auditoria.vuln_results(con, job_id))
        with self.lock:
            progress = self.analysis_progress.get(job_id)
            progreso_c = self.credential_progress.get(job_id)
            progreso_d = self.discovery_progress.get(job_id)
            progreso_v = self.version_progress.get(job_id)
            progreso_vuln = self.vuln_progress.get(job_id)
        if progress and response["analisis"] and response["analisis"]["estado"] in ACTIVE:
            response["analisis"]["progreso"] = progress
        if progreso_c and response["credenciales"] and response["credenciales"]["estado"] in ACTIVE:
            response["credenciales"]["progreso"] = progreso_c
        if progreso_d and response["descubrimiento"] and response["descubrimiento"]["estado"] in ACTIVE:
            response["descubrimiento"]["progreso"] = progreso_d
        if progreso_v and response["version"] and response["version"]["estado"] in ACTIVE:
            response["version"]["progreso"] = progreso_v
        if progreso_vuln and response["vuln"] and response["vuln"]["estado"] in ACTIVE:
            response["vuln"]["progreso"] = progreso_vuln
        return response

    def start(self, job_id):
        binary = gowitness.find_gowitness(self.binary_option)
        chrome = gowitness.find_chrome(self.chrome_option)
        with self.lock:
            meta = self._meta(job_id)
            if self.closing or meta["estado"] != "preparada":
                raise Conflict("Este trabajo ya está iniciado o finalizado")
            # El alcance puede haber cambiado desde que se preparó.
            self._replan(job_id)
            if meta["total"] == 0:
                raise Conflict("No hay objetivos web en el alcance de la ficha. Revisa sus rangos.")
            # La captura existe en la base antes de encolarse: sin registro no se conecta.
            with closing(self.database()) as con:
                auditoria.start_capture(con, job_id, meta["opciones"], meta["grupos"])
            meta.update(estado="en_cola", error="")
            self.pending.put(("captura", (job_id, binary, chrome)))
        return self.detail(job_id)

    def models(self):
        """Modelos descargados en el Ollama de este equipo y el que se propone; si Ollama no responde, por qué."""
        try:
            found, error = modelo.list_models(self.model_host), ""
        except ValueError as exc:
            found, error = [], str(exc)
        return {"modelos": found, "predeterminado": self.model_option, "error": error}

    def analyze(self, job_id, payload=None):
        """Encola el análisis con IA de los hosts en alcance de una ejecución; solo lee la base.

        El modelo puede llegar elegido desde el portal; si no, el de --modelo o DEDALO_MODELO.
        """
        model = payload.get("modelo", self.model_option) if isinstance(payload, dict) else self.model_option
        modelo.check_model(model)
        with self.lock:
            meta = self._meta(job_id)
            if self.closing or meta["estado"] in ACTIVE:
                raise Conflict("Espera a que termine la captura antes de analizar con IA.")
            with closing(self.database()) as con:
                status = auditoria.analysis_status(con, job_id)
                if status and status["estado"] in ACTIVE:
                    raise Conflict("Ya hay un análisis de esta ejecución en marcha.")
                analysis_id = auditoria.start_analysis(con, job_id, {"modelo": model, "servidor": self.model_host})
            self.pending.put(("analisis", (job_id, analysis_id, model)))
        return self.detail(job_id)

    def stop_analysis(self, job_id):
        """Cancela un análisis en cola, o pide que el que está en curso pare tras el host actual."""
        with self.lock:
            self._meta(job_id)
            with closing(self.database()) as con:
                if auditoria.stop_analysis(con, job_id) is None:
                    raise Conflict("Esta ejecución no tiene un análisis en marcha.")
        return self.detail(job_id)

    def _run_analysis(self, job_id, analysis_id, model):
        """Nunca tumba el hilo de la cola: si falla la base, cierra el análisis en error si puede."""
        try:
            self._analyse(job_id, analysis_id, model)
        except Exception as exc:
            print(f"Error del portal: no se pudo completar el análisis de {job_id}: {exc}", file=sys.stderr)
            try:
                with closing(self.database()) as con:
                    auditoria.set_state(con, analysis_id, "error",
                                        "No se pudo completar el análisis. Consulta la terminal del portal.")
            except Exception as again:
                # Al reabrir el portal, el análisis que quedó en cola o en curso se marca como interrumpido.
                print(f"Error del portal: no se pudo cerrar el análisis de {job_id}: {again}", file=sys.stderr)

    def _analyse(self, job_id, analysis_id, model):
        # Sin el bloqueo del portal: solo lee lo que la importación observó y el alcance vigente.
        with closing(self.database()) as con:
            if not auditoria.begin_analysis(con, analysis_id):
                return  # se canceló mientras esperaba en la cola, o otro lo sustituyó
            current = auditoria.scope(con, auditoria.audit_of(con, job_id))
            observed = auditoria.observed_hosts(con, job_id)
            cruce = auditoria.vuln_results(con, job_id)  # lo ya cruzado, si se hizo

        def generate(prompt):
            return modelo.generate(prompt, model, self.model_host, schema=prioridad.ESQUEMA)

        def stopping():
            # Antes de cada host: se cierra el portal, el usuario pidió parar (stop_analysis)
            # o borró la ejecución, y con ella el análisis: no queda nada que preguntar.
            if self.closing:
                return True
            with closing(self.database()) as con:
                status = auditoria.analysis_status(con, job_id)
            return status is None or status["estado"] == "deteniendo"

        def progress(done, total):
            with self.lock:
                self.analysis_progress[job_id] = {"hechos": done, "total": total}

        try:
            # Solo lo que está en alcance (el siguiente paso sugerido no debe proponerse fuera de él)
            # y tiene algún puerto abierto: sin servicios, el modelo no tiene nada que valorar. Como en el
            # inventario, cada servicio lleva lo que ya se sabe de sus vulnerabilidades (si hubo cruce).
            hosts = [a for a in inventory.add_vulns(inventory.build(observed, []), cruce)["activos"]
                     if a["servicios"] and current.status(a["ip"]) == current.IN]
            rows = prioridad.analizar(hosts, generate, parar=stopping, avance=progress)
            state, error = "completa", ""
        except prioridad.Interrumpido:
            state = "interrumpida"
            error = "El portal se cerró antes de terminar el análisis." if self.closing else "Detenido desde el portal antes de terminar."
        except Exception as exc:
            print(f"Error del portal: no se pudo analizar {job_id} con IA: {exc}", file=sys.stderr)
            state = "error"
            error = str(exc) if isinstance(exc, ValueError) else "No se pudo completar el análisis. Consulta la terminal del portal."
        finally:
            with self.lock:
                self.analysis_progress.pop(job_id, None)
        # Solo un análisis completo sustituye al anterior: si este falla, se sigue viendo el último bueno.
        with closing(self.database()) as con:
            if state == "completa":
                auditoria.finish_analysis(con, analysis_id, rows)
            else:
                auditoria.set_state(con, analysis_id, state, error)

    def version_config(self) -> dict:
        """El ajuste de la detección de versión: si está activa, con qué motor y modelo (y el aviso si es Claude)."""
        with closing(self.database()) as con:
            enabled = auditoria.get_config(con, "version_enabled", "0") == "1"
            engine = auditoria.get_config(con, "version_engine", "ollama")
            model = auditoria.get_config(con, "version_model", "")
        if not model:
            model = modelo.CLAUDE_DEFAULT if engine == "claude" else self.model_option
        cfg = {"enabled": enabled, "engine": engine, "model": model}
        if engine == "claude":
            cfg["aviso"] = VERSION_AVISO
        return cfg

    def set_version_config(self, payload) -> dict:
        """Guarda el ajuste de la detección. Apagada de serie; la activa el operador a conciencia."""
        if not isinstance(payload, dict):
            raise ValueError("Se esperaba un objeto")
        engine = payload.get("engine", "ollama")
        if engine not in ("ollama", "claude"):
            raise ValueError(f"Motor de IA no válido: {engine!r}")
        with closing(self.database()) as con:
            auditoria.set_config(con, "version_enabled", "1" if payload.get("enabled") else "0")
            auditoria.set_config(con, "version_engine", engine)
            auditoria.set_config(con, "version_model", str(payload.get("model", "") or ""))
        return self.version_config()

    def _maybe_queue_version(self, job_id):
        """Tras una captura, si la detección está activada y hay servicios capturados, la encola por detrás."""
        cfg = self.version_config()
        if not cfg["enabled"]:
            return
        with closing(self.database()) as con:
            capture_id = auditoria.capture_of(con, job_id)
            if not capture_id or not auditoria.captured_services(con, capture_id):
                return
            version_id = auditoria.start_version(con, job_id, {"engine": cfg["engine"], "model": cfg["model"]})
        self.pending.put(("version", (job_id, version_id, cfg["engine"], cfg["model"])))

    def _run_version(self, job_id, version_id, engine, model):
        """Nunca tumba el hilo de la cola: si falla, cierra la detección en error si puede."""
        try:
            self._detect(job_id, version_id, engine, model)
        except Exception as exc:
            print(f"Error del portal: no se pudo completar la detección de versión de {job_id}: {exc}", file=sys.stderr)
            try:
                with closing(self.database()) as con:
                    auditoria.set_state(con, version_id, "error",
                                        "No se pudo completar la detección. Consulta la terminal del portal.")
            except Exception as again:
                print(f"Error del portal: no se pudo cerrar la detección de {job_id}: {again}", file=sys.stderr)

    def _with_favicon(self, vivo, item, catalogo):
        """Añade datos['favicon'] si el servicio sigue en alcance en vivo y el favicon se identifica.

        `vivo` es un _AlcanceVivo de la ficha: el alcance se recomprueba EN VIVO justo antes de
        conectar (relee la base solo si cambió): una exclusión a mitad de la detección gana y ese
        servicio no se toca. Un fallo de red, de alcance o del catálogo no detiene la detección: se
        sigue con el resto de datos (TLS, HTML, cabeceras) tal cual los dejó la captura.
        """
        datos = dict(item["datos"])
        try:
            base_url = datos.get("final_url") or item["url"]
            ip = urlsplit(base_url).hostname
            if ip and vivo.status(ip) == targets.Scope.IN:
                objetivo = favicones.url_favicon(base_url, datos.get("html", ""))
                if objetivo is not None:
                    contenido = favicones.descargar(objetivo)
                    if contenido is not None:
                        entrada = favicones.identificar(contenido, catalogo)
                        if entrada is not None:
                            datos["favicon"] = entrada
        except (OSError, sqlite3.Error, ValueError) as exc:
            print(f"Error del portal: no se pudo traer el favicon de {item['url']}: {exc}", file=sys.stderr)
        return {**item, "datos": datos}

    def _detect(self, job_id, version_id, engine, model):
        # Lee lo que la captura ya guardó en disco y conecta solo para traer el favicon del propio
        # objetivo, en alcance (recomprobado en vivo; ver _with_favicon).
        with closing(self.database()) as con:
            if not auditoria.begin_version(con, version_id):
                return  # se canceló en la cola, o otra la sustituyó
            capture_id = auditoria.capture_of(con, job_id)
            servicios = auditoria.captured_services(con, capture_id) if capture_id else []
            audit_id = auditoria.audit_of(con, job_id)
        root = self.directory(job_id) / "resultado"
        datos = {}
        for base in root.rglob(gowitness.DB_NAME):
            try:
                datos.update(gowitness.read_fingerprint(base))
            except (OSError, sqlite3.Error, ValueError):
                continue
        items = [{"servicio_id": s["servicio_id"], "url": s["url"], "datos": found}
                 for s in servicios if (found := gowitness.find_result(datos, s["url"]))]
        catalogo_favicones = favicones.cargar()
        vivo = _AlcanceVivo(self, audit_id)
        items = [self._with_favicon(vivo, item, catalogo_favicones) for item in items]

        generate = modelo.generador(engine, model, self.model_host, schema=fingerprint.ESQUEMA)

        def stopping():
            if self.closing:
                return True
            with closing(self.database()) as con:
                status = auditoria.version_status(con, job_id)
            return status is None or status["estado"] == "deteniendo"

        def progress(done, total):
            with self.lock:
                self.version_progress[job_id] = {"hechos": done, "total": total}

        try:
            filas = fingerprint.detectar(items, generate, parar=stopping, avance=progress)
            state, error = "completa", ""
        except fingerprint.Interrumpido:
            state = "interrumpida"
            error = "El portal se cerró antes de terminar la detección." if self.closing else "Detenida desde el portal antes de terminar."
        except Exception as exc:
            print(f"Error del portal: no se pudo detectar la versión de {job_id} con IA: {exc}", file=sys.stderr)
            state = "error"
            error = str(exc) if isinstance(exc, ValueError) else "No se pudo completar la detección. Consulta la terminal del portal."
        finally:
            with self.lock:
                self.version_progress.pop(job_id, None)
        # Solo una detección completa sustituye a la anterior: si esta falla, se sigue viendo la última buena.
        with closing(self.database()) as con:
            if state == "completa":
                auditoria.finish_version(con, version_id, filas)
            else:
                auditoria.set_state(con, version_id, state, error)

    def actualizar_nvd(self):
        """Pone al día la base local de CVE (feeds de la NVD) y los ficheros de exploits (CISA KEV y Exploit-DB).

        Cada una se salta si se bajó hace menos de exploits.VIGENCIA_FUENTES y las dos respetan `sin_internet`. Un fallo
        no se propaga: el cruce sigue con lo que haya (la NVD incompleta se marca «sin datos»; sin KEV ni Exploit-DB no
        hay nivel «confirmado»).
        """
        with self.nvd_lock:
            try:
                with closing(self.database()) as con:
                    if not cve.base_reciente(con, datetime.now(timezone.utc), exploits.VIGENCIA_FUENTES):
                        cve.actualizar_base(con, self.root / CARPETA_VULNS / "nvd", self.sin_internet,
                                            log=lambda texto: print(texto, flush=True))
            except Exception as exc:
                print(f"Error del portal: no se pudo actualizar la base de la NVD: {exc}", file=sys.stderr)
            try:
                exploits.actualizar_fuentes(self.root / CARPETA_VULNS, self.sin_internet, log=lambda texto: print(texto, flush=True))
            except Exception as exc:
                print(f"Error del portal: no se pudieron actualizar las fuentes de exploits: {exc}", file=sys.stderr)

    def actualizar_nvd_en_segundo_plano(self):
        """Lanza actualizar_nvd en un hilo aparte al arrancar el portal; con `sin_internet` ni se intenta (None)."""
        if self.sin_internet:
            return None
        hilo = threading.Thread(target=self.actualizar_nvd, name="dedalo-nvd", daemon=True)
        hilo.start()
        return hilo

    def cross_vulns(self, job_id, payload=None):
        """Encola el cruce de vulnerabilidades de los servicios en alcance; solo lee la base al encolar."""
        with self.lock:
            meta = self._meta(job_id)
            if self.closing or meta["estado"] in ACTIVE:
                raise Conflict("Espera a que termine la captura antes de cruzar vulnerabilidades.")
            with closing(self.database()) as con:
                estado = auditoria.vuln_status(con, job_id)
                if estado and estado["estado"] in ACTIVE:
                    raise Conflict("Ya hay un cruce de vulnerabilidades de esta ejecución en marcha.")
                if not auditoria.scope(con, auditoria.audit_of(con, job_id)).include:
                    raise Conflict("Define el alcance de la ficha antes de cruzar vulnerabilidades.")
                vuln_id = auditoria.start_vuln(con, job_id, {})
            self.pending.put(("vuln", (job_id, vuln_id)))
        return self.detail(job_id)

    def stop_vulns(self, job_id):
        with self.lock:
            self._meta(job_id)
            with closing(self.database()) as con:
                if auditoria.stop_vuln(con, job_id) is None:
                    raise Conflict("Esta ejecución no tiene un cruce de vulnerabilidades en marcha.")
        return self.detail(job_id)

    def _run_vulns(self, job_id, vuln_id):
        """Nunca tumba el hilo de la cola: si falla, cierra el cruce en error si puede."""
        try:
            self._cruzar_vulns(job_id, vuln_id)
        except Exception as exc:
            print(f"Error del portal: no se pudo completar el cruce de vulnerabilidades de {job_id}: {exc}", file=sys.stderr)
            try:
                with closing(self.database()) as con:
                    auditoria.set_state(con, vuln_id, "error",
                                        "No se pudo completar el cruce. Consulta la terminal del portal.")
            except Exception as again:
                print(f"Error del portal: no se pudo cerrar el cruce de {job_id}: {again}", file=sys.stderr)

    def _cruzar_vulns(self, job_id, vuln_id):
        """Cruza cada servicio EN ALCANCE con sus CVE y exploits y lo guarda; ver vulnerabilidades.cruzar_servicio.

        El alcance se recomprueba EN VIVO (_AlcanceVivo) para cada servicio, justo antes de reunir sus CPE y de
        cruzarlos: ahí puede haber salida a internet (consulta online, PoC en GitHub), y el CPE de un host
        excluido, aunque sea a mitad del cruce, no sale. El servicio fuera de alcance no se cruza ni se guarda.
        """
        with closing(self.database()) as con:
            if not auditoria.begin_vuln(con, vuln_id):
                return  # se canceló en la cola, o otro lo sustituyó
            audit_id = auditoria.audit_of(con, job_id)
            servicios = auditoria.vuln_services(con, job_id)
        self.actualizar_nvd()  # antes de cruzar, para no usar una base vieja (no hace nada con sin_internet)
        datos = self.root / CARPETA_VULNS
        kev = exploits.cargar_kev(datos / exploits.KEV_FICHERO)
        exploitdb = exploits.cargar_exploitdb(datos / exploits.EXPLOITDB_FICHERO)
        vivo = _AlcanceVivo(self, audit_id)

        def parar():
            if self.closing:
                return True
            with closing(self.database()) as con:
                estado = auditoria.vuln_status(con, job_id)
            return estado is None or estado["estado"] == "deteniendo"

        def avance(hechos, total):
            with self.lock:
                self.vuln_progress[job_id] = {"hechos": hechos, "total": total}

        filas, respuestas = [], {}  # respuestas: lo ya cruzado por lista de CPE (varios servicios repiten el suyo)
        memo = vulnerabilidades.Memo()  # lo ya consultado fuera en este cruce, para no repetirlo entre servicios
        state, error = "completa", ""
        try:
            avance(0, len(servicios))
            for hechos, servicio in enumerate(servicios):
                if parar():
                    state = "interrumpida"
                    error = "El portal se cerró antes de terminar el cruce." if self.closing else "Detenido desde el portal antes de terminar."
                    break
                if vivo.status(servicio["ip"]) == targets.Scope.IN:
                    fuentes = {cpe: fuente for fuente, cpe in
                               vulnerabilidades.cpes_del_servicio(servicio["cpe"], servicio["lecturas"])}
                    clave = tuple(fuentes)
                    if clave not in respuestas:
                        with closing(self.database()) as con:
                            respuestas[clave] = vulnerabilidades.cruzar_servicio(
                                con, list(clave), kev, exploitdb, self.sin_internet, buscar_github=exploits.buscar_github,
                                memo=memo)
                    respuesta = respuestas[clave]
                    vulns = [v | {"origen_cpe": f"{fuentes[v['origen_cpe']]}|{v['origen_cpe']}"} for v in respuesta["vulns"]]
                    filas.append({"servicio_id": servicio["servicio_id"], "estado": respuesta["estado"], "vulns": vulns})
                avance(hechos + 1, len(servicios))
        except Exception as exc:
            print(f"Error del portal: no se pudo cruzar vulnerabilidades en {job_id}: {exc}", file=sys.stderr)
            state = "error"
            error = str(exc) if isinstance(exc, ValueError) else "No se pudo completar el cruce. Consulta la terminal del portal."
        finally:
            with self.lock:
                self.vuln_progress.pop(job_id, None)
        # Solo un cruce completo sustituye al anterior: si este falla o se detiene, se sigue viendo el último bueno.
        with closing(self.database()) as con:
            if state == "completa":
                auditoria.finish_vuln(con, vuln_id, filas)
            else:
                auditoria.set_state(con, vuln_id, state, error)

    def test_credentials(self, job_id, payload=None):
        """Encola la prueba de credenciales por defecto de los hosts en alcance; solo lee la base al encolar."""
        with self.lock:
            meta = self._meta(job_id)
            if self.closing or meta["estado"] in ACTIVE:
                raise Conflict("Espera a que termine la captura antes de probar credenciales.")
            with closing(self.database()) as con:
                estado = auditoria.credential_status(con, job_id)
                if estado and estado["estado"] in ACTIVE:
                    raise Conflict("Ya hay una prueba de credenciales de esta ejecución en marcha.")
                if not auditoria.scope(con, auditoria.audit_of(con, job_id)).include:
                    raise Conflict("Define el alcance de la ficha antes de probar credenciales.")
                test_id = auditoria.start_credential_test(con, job_id, {})
            self.pending.put(("credenciales", (job_id, test_id)))
        return self.detail(job_id)

    def stop_credentials(self, job_id):
        with self.lock:
            self._meta(job_id)
            with closing(self.database()) as con:
                if auditoria.stop_credential_test(con, job_id) is None:
                    raise Conflict("Esta ejecución no tiene una prueba de credenciales en marcha.")
        return self.detail(job_id)

    def _run_credentials(self, job_id, test_id):
        try:
            self._test_credentials(job_id, test_id)
        except Exception as exc:
            print(f"Error del portal: no se pudo completar la prueba de credenciales de {job_id}: {exc}", file=sys.stderr)
            try:
                with closing(self.database()) as con:
                    auditoria.set_state(con, test_id, "error",
                                        "No se pudo completar la prueba. Consulta la terminal del portal.")
            except Exception as again:
                print(f"Error del portal: no se pudo cerrar la prueba de {job_id}: {again}", file=sys.stderr)

    def _test_credentials(self, job_id, test_id):
        with closing(self.database()) as con:
            if not auditoria.begin_credential_test(con, test_id):
                return  # se canceló en la cola, o otra la sustituyó
            audit_id = auditoria.audit_of(con, job_id)
            current = auditoria.scope(con, audit_id)
            observed = auditoria.observed_hosts(con, job_id)
            entradas = catalogo.entradas(con)
            lecturas = auditoria.version_readings(con, job_id)  # fingerprint afinado desde la captura

        def parar():
            if self.closing:
                return True
            with closing(self.database()) as con:
                estado = auditoria.credential_status(con, job_id)
            return estado is None or estado["estado"] == "deteniendo"

        def avance(hechos, total):
            with self.lock:
                self.credential_progress[job_id] = {"hechos": hechos, "total": total}

        def probar(ip, objetivo):
            # El alcance se recomprueba EN VIVO justo antes de conectar: una exclusión a mitad gana.
            with closing(self.database()) as con:
                vigente = auditoria.scope(con, audit_id)
            if vigente.status(ip) != vigente.IN:
                raise ValueError("fuera de alcance")
            return probador.probar(ip, objetivo)

        try:
            hosts = [a for a in inventory.build(observed, [])["activos"]
                     if a["servicios"] and current.status(a["ip"]) == current.IN]
            for activo in hosts:  # añade a cada servicio lo que la detección afinó, para emparejar credenciales
                for servicio in activo["servicios"]:
                    servicio["lecturas"] = lecturas.get(f"{activo['ip']}:{servicio['puerto']}", [])
            rows = credenciales.probar_activos(hosts, entradas, probar, parar=parar, avance=avance, pausa=lambda: time.sleep(1))
            state, error = "completa", ""
        except credenciales.Interrumpido:
            state = "interrumpida"
            error = "El portal se cerró antes de terminar." if self.closing else "Detenido desde el portal antes de terminar."
        except Exception as exc:
            print(f"Error del portal: no se pudo probar credenciales en {job_id}: {exc}", file=sys.stderr)
            state = "error"
            error = str(exc) if isinstance(exc, ValueError) else "No se pudo completar la prueba. Consulta la terminal del portal."
        finally:
            with self.lock:
                self.credential_progress.pop(job_id, None)
        with closing(self.database()) as con:
            if state == "completa":
                auditoria.finish_credential_test(con, test_id, rows)
            else:
                auditoria.set_state(con, test_id, state, error)

    def networks(self):
        """Subredes de este equipo, para proponerlas como alcance. Solo mira las interfaces locales."""
        return {"redes": redes.detectar()}

    def add_credential(self, payload):
        """Añade una credencial de fábrica al catálogo compartido y lo recarga. Solo lee del payload."""
        if not isinstance(payload, dict):
            raise ValueError("Carga inválida")
        entrada = {"fabricante": payload.get("fabricante", ""), "producto": payload.get("producto", ""),
                   "version": payload.get("version", ""), "servicio": payload.get("servicio", ""),
                   "credenciales": payload.get("credenciales", []),
                   "fuente": payload.get("fuente", ""), "licencia": payload.get("licencia", "")}
        if isinstance(payload.get("receta"), dict):
            entrada["receta"] = payload["receta"]
        catalogo.agregar(self.catalogo_ruta, entrada)  # valida; ValueError -> 400
        with closing(self.database()) as con:
            catalogo.cargar(con, self.catalogo_ruta)
        return {"anadida": True}

    def discover(self, job_id, payload=None):
        """Encola el descubrimiento DNS de los hosts en alcance; solo lee la base al encolar."""
        modo = payload.get("modo", "nombres") if isinstance(payload, dict) else "nombres"
        if modo not in descubrimiento.MODES:
            raise ValueError(f"Modo de descubrimiento desconocido: {modo}")
        with self.lock:
            meta = self._meta(job_id)
            if self.closing or meta["estado"] in ACTIVE:
                raise Conflict("Espera a que termine la captura antes de descubrir.")
            with closing(self.database()) as con:
                estado = auditoria.discovery_status(con, job_id)
                if estado and estado["estado"] in ACTIVE:
                    raise Conflict("Ya hay un descubrimiento de esta ejecución en marcha.")
                if not auditoria.scope(con, auditoria.audit_of(con, job_id)).include:
                    raise Conflict("Define el alcance de la ficha antes de descubrir.")
                disc_id = auditoria.start_discovery(con, job_id, {"modo": modo})
            self.pending.put(("descubrimiento", (job_id, disc_id, modo)))
        return self.detail(job_id)

    def stop_discovery(self, job_id):
        with self.lock:
            self._meta(job_id)
            with closing(self.database()) as con:
                if auditoria.stop_discovery(con, job_id) is None:
                    raise Conflict("Esta ejecución no tiene un descubrimiento en marcha.")
        return self.detail(job_id)

    def _run_discovery(self, job_id, disc_id, modo):
        try:
            self._discover(job_id, disc_id, modo)
        except Exception as exc:
            print(f"Error del portal: no se pudo completar el descubrimiento de {job_id}: {exc}", file=sys.stderr)
            try:
                with closing(self.database()) as con:
                    auditoria.set_state(con, disc_id, "error",
                                        "No se pudo completar el descubrimiento. Consulta la terminal del portal.")
            except Exception as again:
                print(f"Error del portal: no se pudo cerrar el descubrimiento de {job_id}: {again}", file=sys.stderr)

    def _discover(self, job_id, disc_id, modo):
        with closing(self.database()) as con:
            if not auditoria.begin_discovery(con, disc_id):
                return  # se canceló en la cola, o otro lo sustituyó
            audit_id = auditoria.audit_of(con, job_id)
            alcance = auditoria.scope(con, audit_id)
        vivo = _AlcanceVivo(self, audit_id)

        def parar():
            if self.closing:
                return True
            with closing(self.database()) as con:
                estado = auditoria.discovery_status(con, job_id)
            return estado is None or estado["estado"] == "deteniendo"

        def avance(hechas, total):
            with self.lock:
                self.discovery_progress[job_id] = {"hechas": hechas, "total": total}

        try:
            direcciones = descubrimiento.expand([str(n) for n in alcance.include])
            filas = descubrimiento.sweep(direcciones, modo, self.dns_dominio, scope=vivo, stop=parar, progress=avance)
            rows = [fila | {"modo": modo} for fila in filas]
            state, error = "completa", ""
        except Exception as exc:
            print(f"Error del portal: no se pudo descubrir en {job_id}: {exc}", file=sys.stderr)
            rows, state = [], "error"
            error = str(exc) if isinstance(exc, ValueError) else "No se pudo completar el descubrimiento. Consulta la terminal del portal."
        finally:
            with self.lock:
                self.discovery_progress.pop(job_id, None)
        with closing(self.database()) as con:
            if state == "completa":
                auditoria.finish_discovery(con, disc_id, rows)
            else:
                auditoria.set_state(con, disc_id, state, error)

    def cancel(self, job_id):
        with self.lock:
            meta = self._meta(job_id)
            if meta.get("terminando"):
                # El motor ya acabó y se están guardando sus resultados: no hay nada que parar.
                raise Conflict("Este trabajo ya terminó y se están guardando sus resultados.")
            stopping = meta["estado"] in ("en_curso", "deteniendo")
            if meta["estado"] == "en_cola":
                state = "cancelada"
            elif stopping:
                # El fichero de parada va antes que la base, a propósito: si la base falla,
                # el motor para igualmente.
                (self.directory(job_id) / "parar").touch()
                state = "deteniendo"
            else:
                raise Conflict("Este trabajo no está en ejecución")
            # Luego la base: si no se puede guardar, el usuario lo ve y el estado mostrado no cambia.
            try:
                self._capture_state(job_id, state, strict=True)
            except Exception as exc:
                if not stopping:
                    raise  # cancelar un trabajo en cola no ha hecho nada todavía
                print(f"Error del portal: no se pudo guardar en la base la parada de {job_id}: {exc}", file=sys.stderr)
                raise Conflict("La parada está pedida y el motor se detendrá, pero no se pudo guardar el estado en la base. "
                               "Vuelve a pulsar «Detener» o consulta la terminal del portal.") from exc
            meta["estado"] = state
        return self.detail(job_id)

    def _worker(self):
        while True:
            item = self.pending.get()
            if item is None:
                return
            kind, payload = item
            if kind == "analisis":
                self._run_analysis(*payload)
                continue
            if kind == "credenciales":
                self._run_credentials(*payload)
                continue
            if kind == "descubrimiento":
                self._run_discovery(*payload)
                continue
            if kind == "version":
                self._run_version(*payload)
                continue
            if kind == "vuln":
                self._run_vulns(*payload)
                continue
            job_id, binary, chrome = payload
            with self.lock:
                meta = self.jobs.get(job_id)
                if meta is None or meta["estado"] != "en_cola":
                    continue
                # Dentro del bloqueo: una parada pedida justo ahora no queda pisada.
                self._capture_state(job_id, "en_curso")
                meta["estado"] = "en_curso"
                options = dict(meta["opciones"])
            directory = self.directory(job_id)
            command = [sys.executable, "-u", "-m", "dedalo", "capturar"]
            command += [str(p) for p in sorted((directory / "entradas").glob("nmap-*.txt"))]
            command += ["-r", str(directory / "rangos.txt"), "--solo-rangos", "--excluir", str(directory / "excluir.txt"),
                        "-o", str(directory / "resultado"),
                        "--gowitness", binary, "--stop-file", str(directory / "parar"),
                        "--puertos", options["puertos"], "--formato", options["formato"],
                        "--hilos", str(options["hilos"]), "--timeout", str(options["timeout"]),
                        "--delay", str(options["delay"]),
                        # Ejecuciones preparadas antes de existir estas opciones: valores por defecto.
                        "--driver", options.get("driver", gowitness.DRIVERS[0])]
            if not options.get("reintentar", True):
                command.append("--sin-reintento")
            if chrome:
                command += ["--chrome", chrome]
            if options["por_servicio"]:
                command.append("--por-servicio")
            if options["pagina_completa"]:
                command.append("--pagina-completa")
            if not options.get("barra_url", True):
                command.append("--sin-barra-url")
            error = ""
            try:
                with (directory / "proceso.log").open("w", encoding="utf-8") as output:
                    completed = subprocess.run(command, cwd=gowitness.PROJECT_ROOT, stdout=output,
                                               stderr=subprocess.STDOUT,
                                               env={**os.environ, "PYTHONIOENCODING": "utf-8"})
                status = {0: "completa", 3: "parcial", 130: "interrumpida"}.get(completed.returncode, "error")
                if status == "error":
                    error = "El motor no pudo completar la captura. Consulta el registro."
            except Exception as exc:
                status, error = "error", str(exc)
            # El motor ya acabó: desde aquí «Detener» no tiene nada que parar. Guardar los
            # resultados es lento (se calcula la huella de cada imagen) y va sin el bloqueo,
            # así que se marca antes bajo él: una parada pedida justo ahora no puede
            # escribir «deteniendo» después del estado final.
            with self.lock:
                meta["terminando"] = True
            # Si la base no se puede escribir ahora, al reabrir el portal la captura
            # sigue activa en ella y se cierra desde el manifiesto del motor.
            self._capture_state(job_id, status, error, record=True)
            with self.lock:
                meta.pop("terminando", None)
                meta.update(estado=status, error=error, fin=now())
            # Tras la captura, si la detección de versión está activada, se lanza por detrás (no la frena).
            try:
                self._maybe_queue_version(job_id)
            except Exception as exc:
                print(f"Error del portal: no se pudo encolar la detección de versión de {job_id}: {exc}", file=sys.stderr)

    def delete(self, job_id):
        with self.lock:
            meta = self._meta(job_id)
            if meta["estado"] in ACTIVE:
                raise Conflict("Detén la ejecución y espera a que termine antes de borrarla.")
            directory = self.directory(job_id)
            # Solo esta carpeta directa; nunca seguir un enlace a otra ejecución.
            if directory.parent != self.root or directory.name != job_id:
                raise ValueError("La carpeta no corresponde a esta ejecución")
            source = self.root / job_id
            if source.is_symlink() or source.is_junction():
                raise ValueError("No se puede borrar una ejecución enlazada a otra carpeta")
            # La carpeta se aparta antes de tocar la base, con un nombre que ni se carga ni se
            # migra al arrancar. Si la base falla, vuelve a su sitio y la ejecución sigue entera;
            # si algo queda a medias, el próximo arranque lo termina (_finish_deletes).
            trash = directory.with_name("." + job_id)  # un solo carácter más: rutas de Windows
            directory.rename(trash)
            try:
                with closing(self.database()) as con:
                    auditoria.delete_execution(con, job_id)
            except Exception:
                trash.rename(directory)
                raise
            del self.jobs[job_id]
        # Fuera del bloqueo: ya nadie llega a esa carpeta y borrar muchas capturas tarda.
        try:
            shutil.rmtree(trash)
        except OSError as exc:
            print(f"Aviso: la ejecución {job_id} se borró del historial, pero no su carpeta {trash}: {exc}. "
                  "Bórrala a mano.", file=sys.stderr)
        return {"eliminada": job_id}

    def _group(self, job_id, group_index):
        """Subred del manifiesto, su carpeta y sus capturas válidas."""
        with self.lock:
            meta = copy.deepcopy(self._meta(job_id))
        manifest = self._manifest(meta)
        if not manifest or not 0 <= group_index < len(manifest["grupos"]):
            raise FileNotFoundError("Captura no disponible")
        group = manifest["grupos"][group_index]
        directory = report.inside(self.directory(job_id) / "resultado", group["carpeta"])
        return group, directory, gowitness.read_results(directory / gowitness.DB_NAME)

    @staticmethod
    def _shot(directory, found, target):
        row = gowitness.find_result(found, target["url"])
        if not row:
            raise FileNotFoundError("Captura no disponible")
        path = gowitness.screenshot_path(directory, row["filename"])
        if path.suffix.lower() not in (".png", ".jpg", ".jpeg", ".webp"):
            raise ValueError("Formato de imagen no permitido")
        return path, row

    def image(self, job_id, group_index, target_index):
        group, directory, found = self._group(job_id, group_index)
        if not 0 <= target_index < len(group["objetivos"]):
            raise FileNotFoundError("Captura no disponible")
        return self._shot(directory, found, group["objetivos"][target_index])[0]

    def group_zip(self, job_id, group_index):
        """ZIP con todas las capturas de una subred, nombradas por IP y puerto."""
        group, directory, found = self._group(job_id, group_index)
        index = io.StringIO(newline="")
        writer = csv.writer(index)
        writer.writerow(["archivo", "ip", "puerto", "url", "url_final", "codigo_http", "titulo"])
        buffer = io.BytesIO()
        # Las imágenes ya están comprimidas: se guardan sin recomprimir.
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
            for target in group["objetivos"]:
                try:
                    path, row = self._shot(directory, found, target)
                except FileNotFoundError:
                    continue
                scheme = urlsplit(row["url"]).scheme  # el de la fila que respondió, no el del objetivo
                name = f"{target['ip'].replace(':', '_')}_{target['port']}_{scheme}{path.suffix.lower()}"
                archive.write(path, name)
                writer.writerow([report.csv_text(value) for value in (name, target["ip"], target["port"], target["url"],
                                 row["final_url"], row["response_code"], row["title"])])
            if not archive.namelist():
                raise FileNotFoundError("Esta subred no tiene capturas")
            archive.writestr("indice.csv", index.getvalue().encode("utf-8-sig"))
        subnet = re.sub(r"[^0-9A-Za-z.]", "_", group["subred"])
        return buffer.getvalue(), f"capturas_{subnet}.zip"

    def logs(self, job_id):
        with self.lock:
            meta = copy.deepcopy(self._meta(job_id))
        directory = self.directory(job_id)
        paths = [directory / "proceso.log"]
        manifest = self._manifest(meta)
        if manifest:
            paths += [report.inside(directory / "resultado", g["carpeta"]) / name
                      for g in manifest["grupos"] if g["estado"] in ("en_curso", "parcial", "error", "interrumpido")
                      for name in gowitness.LOGS]
        lines = []
        # El registro del proceso y los siete últimos de gowitness que existan.
        for path in paths[:1] + [p for p in paths[1:] if p.is_file()][-7:]:
            if path.is_file():
                with path.open("rb") as file:
                    file.seek(max(0, path.stat().st_size - 16000))
                    lines.append(path.parent.name + "/" + path.name + "\n" + file.read(16000).decode("utf-8", errors="replace"))
        return "\n\n".join(lines) or "Todavía no hay registros. El trabajo no ha comenzado."

    def close(self):
        with self.lock:
            self.closing = True
            for job_id, meta in self.jobs.items():
                # Si ya está guardando sus resultados no hay nada que parar: el join de abajo lo espera.
                if meta["estado"] in ACTIVE and not meta.get("terminando"):
                    try:
                        self.cancel(job_id)
                    except Exception as exc:
                        # La cola tiene que pararse igual; al reabrir se cierra desde el manifiesto.
                        print(f"Error del portal: no se pudo detener {job_id}: {exc}", file=sys.stderr)
            self.pending.put(None)
        self.worker.join()
        self.file_lock.close()


class PortalServer(ThreadingHTTPServer):
    daemon_threads = True
    # En Windows SO_REUSEADDR deja que dos portales escuchen a la vez en el mismo
    # puerto y el navegador acaba hablando con uno cualquiera. Allí se exige
    # uso exclusivo; en Linux se mantiene para poder reiniciar sin esperas.
    allow_reuse_address = os.name != "nt"

    def __init__(self, address, store):
        self.store = store
        super().__init__(address, PortalHandler)

    def server_bind(self):
        if os.name == "nt":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class PortalHandler(BaseHTTPRequestHandler):
    server_version = "dedalo"
    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def log_message(self, *args):
        pass

    def allowed(self):
        port = self.server.server_address[1]
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        host = self.headers.get("Host", "")
        if host not in hosts or self.headers.get("Sec-Fetch-Site") == "cross-site":
            return False
        origin = self.headers.get("Origin")
        return not origin or origin == "http://" + host

    def send_bytes(self, status, data, content_type="application/json; charset=utf-8", download=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
        self.end_headers()
        self.wfile.write(data)

    def reject(self, error, status):
        """Responde sin leer el cuerpo y cierra la conexión de forma ordenada.

        En Windows, cerrar con datos sin leer envía un RST y el cliente puede
        perder la respuesta. Tampoco se lee el cuerpo según Content-Length: un
        valor falso dejaría el hilo esperando. Se termina la escritura y se
        descarta lo que siga llegando hasta que el cliente cierre, con límite.
        """
        self.close_connection = True
        self.json({"error": error}, status)
        try:
            self.wfile.flush()
            self.connection.shutdown(socket.SHUT_WR)
            deadline, discarded = time.monotonic() + 2, 0
            while discarded <= MAX_BODY and (remaining := deadline - time.monotonic()) > 0:
                self.connection.settimeout(remaining)
                chunk = self.connection.recv(65536)
                if not chunk:
                    break
                discarded += len(chunk)
        except OSError:
            pass

    def json(self, value, status=200):
        self.send_bytes(status, json.dumps(value, ensure_ascii=False).encode("utf-8"))

    def do_GET(self):
        self.dispatch(False)

    def do_POST(self):
        self.dispatch(True)

    def dispatch(self, mutate):
        try:
            if not self.allowed():
                self.reject("Origen no permitido", 403)
                return
            store = self.server.store
            path = urlsplit(self.path).path
            parts = path.strip("/").split("/")
            if mutate:
                if self.headers.get("X-Dedalo-Token") != store.token:
                    self.reject("Sesión caducada; recarga la página", 403)
                    return
                if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                    self.reject("Se esperaba JSON", 415)
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    self.reject("Content-Length inválido", 400)
                    return
                if not 0 < length <= MAX_BODY:
                    self.reject("La carga debe ser menor de 32 MB", 413)
                    return
                data = self.rfile.read(length)
                if len(data) != length:
                    raise ValueError("La carga no llegó completa")
                payload = json.loads(data)
                if path == "/api/jobs":
                    self.json(store.create(payload), 201)
                    return
                if path == "/api/audits":
                    self.json(store.create_audit(payload), 201)
                    return
                if path == "/api/catalogo":
                    self.json(store.add_credential(payload))
                    return
                if path == "/api/version-config":
                    self.json(store.set_version_config(payload))
                    return
                if len(parts) == 3 and parts[:2] == ["api", "audits"] and re.fullmatch(r"[a-f0-9]{32}", parts[2]):
                    self.json(store.update_audit(parts[2], payload))
                    return
                if len(parts) == 4 and parts[:2] == ["api", "jobs"]:
                    if parts[3] == "start":
                        self.json(store.start(parts[2]), 202)
                        return
                    if parts[3] == "cancel":
                        self.json(store.cancel(parts[2]))
                        return
                    if parts[3] == "analizar":
                        self.json(store.analyze(parts[2], payload), 202)
                        return
                    if parts[3] == "detener-analisis":
                        self.json(store.stop_analysis(parts[2]))
                        return
                    if parts[3] == "probar-credenciales":
                        self.json(store.test_credentials(parts[2], payload), 202)
                        return
                    if parts[3] == "detener-credenciales":
                        self.json(store.stop_credentials(parts[2]))
                        return
                    if parts[3] == "descubrir":
                        self.json(store.discover(parts[2], payload), 202)
                        return
                    if parts[3] == "cruzar-vulnerabilidades":
                        self.json(store.cross_vulns(parts[2], payload), 202)
                        return
                    if parts[3] == "detener-vulnerabilidades":
                        self.json(store.stop_vulns(parts[2]))
                        return
                    if parts[3] == "detener-descubrimiento":
                        self.json(store.stop_discovery(parts[2]))
                        return
                    if parts[3] == "delete":
                        self.json(store.delete(parts[2]))
                        return
                raise FileNotFoundError("Ruta no encontrada")
            if path in STATIC_FILES:
                filename, content_type = STATIC_FILES[path]
                self.send_bytes(200, (STATIC / filename).read_bytes(), content_type)
                return
            if path == "/api/bootstrap":
                self.json({"token": store.token, "engine": store.engine(), "migration_failures": store.migration_failures})
                return
            if path == "/api/jobs":
                self.json(store.list())
                return
            if path == "/api/audits":
                self.json(store.audits())
                return
            if path == "/api/modelos":
                self.json(store.models())
                return
            if path == "/api/version-config":
                self.json(store.version_config())
                return
            if path == "/api/redes":
                self.json(store.networks())
                return
            if len(parts) >= 3 and parts[:2] == ["api", "jobs"]:
                job_id = parts[2]
                if len(parts) == 3:
                    self.json(store.detail(job_id))
                    return
                if len(parts) == 4 and parts[3] == "logs":
                    self.json({"text": store.logs(job_id)})
                    return
                if len(parts) == 4 and parts[3] == "inventory":
                    self.json(store.inventory(job_id))
                    return
                if len(parts) == 5 and parts[3] == "download" and parts[4] in ("inventory-csv", "inventory-json"):
                    data = store.inventory(job_id)
                    csv = parts[4] == "inventory-csv"
                    content = inventory.csv_bytes(data) if csv else json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
                    self.send_bytes(200, content, "text/csv; charset=utf-8" if csv else "application/json; charset=utf-8",
                                    "inventario.csv" if csv else "inventario.json")
                    return
                if len(parts) == 6 and parts[3] == "image":
                    image = store.image(job_id, int(parts[4]), int(parts[5]))
                    self.send_bytes(200, image.read_bytes(), mimetypes.guess_type(image.name)[0] or "image/png")
                    return
                if len(parts) == 6 and parts[3] == "download" and parts[4] == "captures":
                    content, filename = store.group_zip(job_id, int(parts[5]))
                    self.send_bytes(200, content, "application/zip", filename)
                    return
                if len(parts) == 5 and parts[3] == "download" and parts[4] in ("csv", "json"):
                    if parts[4] == "csv":
                        self.send_bytes(200, store.index_csv(job_id), "application/octet-stream", "indice.csv")
                        return
                    with store.lock:
                        store._meta(job_id)
                    filename = report.MANIFEST
                    artifact = store.directory(job_id) / "resultado" / filename
                    self.send_bytes(200, artifact.read_bytes(), "application/octet-stream", filename)
                    return
            raise FileNotFoundError("Ruta no encontrada")
        except FileNotFoundError as exc:
            self.json({"error": str(exc)}, 404)
        except Conflict as exc:
            self.json({"error": str(exc)}, 409)
        except (ValueError, TypeError, ParseError) as exc:
            self.json({"error": str(exc)}, 400)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # El cliente cortó (en Windows, al recargar llega como WinError 10053):
            # no queda a quién responder y un 500 fallaría por el mismo socket.
            pass
        except Exception as exc:
            print(f"Error del portal: {exc}", file=sys.stderr)
            self.json({"error": "No se pudo completar la operación. Consulta la terminal del portal."}, 500)


def ensure_gowitness(explicit):
    """Sin ruta indicada, se asegura del gowitness FIJADO: lo descarga si falta o si el que hay es de otra versión."""
    if explicit:
        return
    try:
        binario = gowitness.find_gowitness(None)
    except ValueError:
        binario = None
    if binario and gowitness.installed_version(binario) == gowitness.VERSION:
        return  # ya está la versión fijada
    if binario:
        # En WSL/Kali suele haber un gowitness del PATH de otra versión que no conoce los flags que usa Dédalo.
        print(f"El gowitness disponible no es la versión {gowitness.VERSION} que Dédalo necesita; descargando el oficial…", flush=True)
    try:
        gowitness.install_gowitness(log=lambda text: print(text, flush=True))
    except ValueError as exc:
        # El portal arranca igual; el aviso del motor explica cómo instalarlo.
        print(f"Aviso: {exc}", flush=True)


def serve_portal(args):
    ensure_gowitness(args.gowitness)
    if args.arrancar_ollama:
        # Antes que el portal: así su primera consulta de modelos ya encuentra a Ollama.
        _, message = modelo.ensure_running(args.ollama)
        if message:
            print(message, flush=True)
    store = PortalStore(args.datos, args.gowitness, args.chrome, model=args.modelo, ollama=args.ollama,
                        dns_dominio=args.dns_dominio, catalogo_ruta=args.catalogo or catalogo.RUTA,
                        sin_internet=True if args.sin_internet else None)  # None: decide DEDALO_SIN_INTERNET
    try:
        server = PortalServer(("127.0.0.1", args.puerto), store)
    except Exception as exc:
        store.close()
        if isinstance(exc, OSError) and (exc.errno == errno.EADDRINUSE or getattr(exc, "winerror", None) in (10013, 10048)):
            raise ValueError(f"El puerto {args.puerto} ya está en uso, probablemente por otro portal abierto. "
                             "Ciérralo o usa --puerto con otro número.") from exc
        raise
    url = f"http://127.0.0.1:{server.server_address[1]}"
    store.actualizar_nvd_en_segundo_plano()  # ya enlazado el puerto; por detrás, como Ollama: no espera a la descarga
    print(f"Portal dedalo: {url}\nDatos: {store.root}\nCtrl+C para cerrar.", flush=True)
    if args.abrir:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nCerrando; la captura activa terminará su subred actual.", flush=True)
    finally:
        server.server_close()
        store.close()
    return 0
