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

from . import auditoria, cli, db, gowitness, inventory, parser, report, targets

STATIC = Path(__file__).parent / "static"
MAX_BODY = 32 * 1024 * 1024
ACTIVE = {"en_cola", "en_curso", "deteniendo"}


class Conflict(ValueError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


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
    for key, default in (("por_servicio", False), ("pagina_completa", False), ("reintentar", True)):
        result[key] = raw.get(key, default)
        if type(result[key]) is not bool:
            raise ValueError(f"{key}: valor inválido")
    result["driver"] = raw.get("driver", gowitness.DRIVERS[0])
    if result["driver"] not in gowitness.DRIVERS:
        raise ValueError("Motor del navegador inválido")
    return result


class PortalStore:
    def __init__(self, root, binary=None, chrome=None):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.binary_option, self.chrome_option = binary, chrome
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
        try:
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

    def _migrate_folders(self):
        """Lleva a la base las ejecuciones que solo tenían trabajo.json (pasos 5 y 6 del plan).

        Cada carpeta se migra una sola vez y no se modifica. Si una no se puede
        migrar, se avisa en la terminal y su carpeta queda como estaba.
        """
        for path in sorted(self.root.glob("*/trabajo.json")):
            job_id = path.parent.name
            if not re.fullmatch(r"[a-f0-9]{32}", job_id):
                continue
            try:
                with closing(self.database()) as con:
                    if auditoria.has_execution(con, job_id) and "captura" in auditoria.portal_options(con, job_id):
                        continue
                    meta = json.loads(path.read_text(encoding="utf-8"))
                    if meta.get("id") != job_id:
                        continue
                    self._imported(con, job_id, meta)  # importa sus Nmap si era anterior a la base
                    if meta["estado"] != "preparada" and auditoria.capture_of(con, job_id) is None:
                        self._migrate_capture(con, job_id, meta)
                    # Con "captura" en sus opciones, la ejecución queda migrada.
                    auditoria.set_options(con, job_id, {"archivos": meta["archivos"], "captura": meta["opciones"]})
            except Exception as exc:
                print(f"Aviso: no se pudo pasar a la base la ejecución {job_id}: {exc}. Su carpeta se conserva.",
                      file=sys.stderr)

    def _migrate_capture(self, con, job_id, meta):
        """Una captura hecha antes de que la base las guardase, con sus resultados."""
        state, error = meta["estado"], meta.get("error", "")
        if state in ACTIVE:
            state, error = "interrumpida", "El portal se cerró antes de completar el trabajo."
        manifest = self._manifest(meta)
        result = self.directory(job_id) / "resultado"
        logs = self._result_logs(job_id, manifest) if manifest else []
        try:
            auditoria.import_capture_history(con, job_id, meta["opciones"], meta.get("grupos", []), state, error,
                                             meta["fecha"], meta.get("fin"), manifest, result, self.root, logs)
        except ValueError as exc:
            # Objetivos que no casan con el inventario: al menos se conserva el estado,
            # y las capturas se siguen viendo desde su carpeta.
            print(f"Aviso: la captura de {job_id} se registra sin sus resultados: {exc}", file=sys.stderr)
            auditoria.import_capture_history(con, job_id, meta["opciones"], [], state, error,
                                             meta["fecha"], meta.get("fin"), None, result, self.root)

    def _load(self):
        """Carga el historial desde la base y cierra lo que quedó a medias."""
        with closing(self.database()) as con:
            for row in auditoria.portal_jobs(con):
                options = json.loads(row["opciones"])
                if "captura" not in options or not (self.root / row["id"]).is_dir():
                    continue  # importación sin carpeta del portal, o que no se pudo migrar
                meta = {"id": row["id"], "nombre": row["nombre"], "fecha": row["creada"],
                        "archivos": options.get("archivos", []), "opciones": options["captura"],
                        "estado": row["estado"] or "preparada", "error": row["error"] or "", "fin": row["terminada"]}
                if meta["estado"] in ACTIVE:
                    self._close_interrupted(meta)
                try:
                    self._load_plan(con, meta, row)
                except (OSError, ValueError) as exc:
                    meta.update(grupos=[], total=0, subredes=0, fuera_alcance=None, error=str(exc))
                self.jobs[meta["id"]] = meta

    def _close_interrupted(self, meta):
        """El portal se cerró con esta captura activa: se toma el estado del motor si terminó."""
        # Si el portal murió sin cerrarse, su motor puede seguir conectando (en Windows el
        # proceso hijo sobrevive). Con el fichero de parada acaba la subred actual y no sigue.
        try:
            (self.directory(meta["id"]) / "parar").touch()
        except OSError as exc:
            print(f"Error del portal: no se pudo pedir al motor de {meta['id']} que pare: {exc}", file=sys.stderr)
        manifest = self._manifest(meta)
        if manifest and manifest.get("estado") in ("completa", "parcial", "interrumpida"):
            state, error = manifest["estado"], ""
        else:
            state, error = "interrumpida", "El portal se cerró antes de completar el trabajo."
        self._capture_state(meta["id"], state, error, record=True)
        meta.update(estado=state, error=error)

    def _load_plan(self, con, meta, row):
        """Objetivos de una ejecución: lo planificado si ya se lanzó, o lo que permite el alcance vigente."""
        hosts = auditoria.observed_hosts(con, meta["id"])
        if row["captura_id"] is None:
            self._plan(meta, hosts, auditoria.scope(con, row["auditoria_id"]))
            return
        # Lo lanzado no cambia: las URL quedaron en la base y la agrupación en su rangos.txt.
        planned = auditoria.planned_urls(con, row["captura_id"])
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
            for name in (gowitness.LOG_NAME, gowitness.RETRY_LOG)]

    def _capture_state(self, job_id, state, error="", record=False, strict=False):
        """Guarda en la base el estado de la captura de un trabajo y, si se pide, sus resultados.

        Con strict, un fallo se propaga (acciones del usuario). Si no, se avisa y no para
        la cola: al reabrir el portal, la captura activa se cierra desde el manifiesto.
        """
        try:
            with closing(self.database()) as con:
                capture_id = auditoria.capture_of(con, job_id)
                if capture_id is None:
                    return
                if record:
                    manifest = self._manifest({"id": job_id})
                    if manifest:
                        auditoria.record_captures(con, capture_id, manifest, self.directory(job_id) / "resultado",
                                                  self.root, self._result_logs(job_id, manifest))
                auditoria.set_state(con, capture_id, state, error)
        except Exception as exc:
            if strict:
                raise
            print(f"Error del portal: no se pudo registrar en la base la captura de {job_id}: {exc}", file=sys.stderr)

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

    def _replan(self, job_id):
        """Recalcula una ejecución sin lanzar con el alcance vigente de su ficha."""
        meta = self._meta(job_id)
        with closing(self.database()) as con:
            scope = auditoria.scope(con, self._imported(con, job_id, meta))
            hosts = auditoria.observed_hosts(con, job_id)
        self._plan(meta, hosts, scope)
        write_scope_files(self.directory(job_id), scope)

    def inventory(self, job_id):
        with self.lock:
            meta = self._meta(job_id)
            directory = self.directory(job_id)
            with closing(self.database()) as con:
                scope = auditoria.scope(con, self._imported(con, job_id, meta))
                hosts = auditoria.observed_hosts(con, job_id)
            data = inventory.build(hosts, targets.read_networks_file(directory / "rangos.txt"))
            for asset in data["activos"]:
                asset["alcance"] = scope.status(asset["ip"])
            return data

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
            # Lo ya lanzado no cambia; lo preparado se recalcula con el alcance nuevo.
            for job_id, meta in self.jobs.items():
                if meta["estado"] == "preparada" and owners.get(job_id) == audit_id:
                    self._replan(job_id)
            with closing(self.database()) as con:
                return next(a for a in auditoria.audits(con) if a["id"] == audit_id)

    def _manifest(self, meta):
        path = self.directory(meta["id"]) / "resultado" / report.MANIFEST
        try:
            return report.load_manifest(path.parent)
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def summary(self, meta):
        manifest = self._manifest(meta)
        groups = manifest["grupos"] if manifest else meta["grupos"]
        done = sum(len(g["objetivos"]) for g in groups if g["estado"] in ("completo", "parcial", "error", "interrumpido"))
        return {k: meta[k] for k in ("id", "nombre", "fecha", "estado", "total", "subredes", "error")} | {
            "capturas": sum(g.get("capturas", 0) for g in groups),
            "sin_captura": sum(g.get("sin_captura", 0) for g in groups),
            "procesadas": done,
        }

    def _owners(self, job_ids):
        with closing(self.database()) as con:
            owners = auditoria.audits_by_execution(con)
            # Las ejecuciones que aún no están en la base se importarán a «Importadas».
            if any(job_id not in owners for job_id in job_ids):
                default = auditoria.default_audit(con)
                owners = {job_id: owners.get(job_id, default) for job_id in job_ids}
        return owners

    def list(self):
        with self.lock:
            snapshots = copy.deepcopy(list(self.jobs.values()))
        owners = self._owners([meta["id"] for meta in snapshots])
        return [self.summary(meta) | {"auditoria": owners[meta["id"]]}
                for meta in sorted(snapshots, key=lambda m: m["fecha"], reverse=True)]

    def detail(self, job_id):
        with self.lock:
            meta = copy.deepcopy(self._meta(job_id))
        manifest = self._manifest(meta)
        groups = manifest["grupos"] if manifest else meta["grupos"]
        root = self.directory(job_id) / "resultado"
        response = self.summary(meta)
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
                current = live.get(gowitness.normalize_url(target["url"]))
                captured = bool(row.get("captura") or current)
                targets.append({
                    "ip": target["ip"], "puerto": target["port"], "url": target["url"],
                    "titulo": row.get("titulo", "") or (current or {}).get("title", ""),
                    "codigo": row.get("codigo_http", "") or (current or {}).get("response_code", ""),
                    "url_final": row.get("url_final", "") or (current or {}).get("final_url", ""),
                    "estado": "capturada" if captured else row.get("estado", group["estado"] if group["estado"] == "en_curso" else "pendiente"),
                    "error": "" if captured else errors.get(gowitness.normalize_url(target["url"]), row.get("error", "")),
                    "imagen": f"/api/jobs/{job_id}/image/{index}/{number}" if captured else "",
                })
            response["grupos"].append({
                "rango": group["rango"], "subred": group["subred"], "estado": group["estado"],
                "capturas": sum(bool(t["imagen"]) for t in targets), "objetivos": targets, "error": group.get("error", ""),
            })
        response["capturas"] = sum(g["capturas"] for g in response["grupos"])
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
            self.pending.put((job_id, binary, chrome))
        return self.detail(job_id)

    def cancel(self, job_id):
        with self.lock:
            meta = self._meta(job_id)
            if meta["estado"] == "en_cola":
                state = "cancelada"
            elif meta["estado"] in ("en_curso", "deteniendo"):
                (self.directory(job_id) / "parar").touch()
                state = "deteniendo"
            else:
                raise Conflict("Este trabajo no está en ejecución")
            # Primero la base: si no se puede guardar, el usuario lo ve y el estado no cambia.
            self._capture_state(job_id, state, strict=True)
            meta["estado"] = state
        return self.detail(job_id)

    def _worker(self):
        while True:
            item = self.pending.get()
            if item is None:
                return
            job_id, binary, chrome = item
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
            # Si la base no se puede escribir ahora, al reabrir el portal la captura
            # sigue activa en ella y se cierra desde el manifiesto del motor.
            self._capture_state(job_id, status, error, record=True)
            with self.lock:
                meta.update(estado=status, error=error, fin=now())

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
            shutil.rmtree(directory)
            with closing(self.database()) as con:
                auditoria.delete_execution(con, job_id)
            del self.jobs[job_id]
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
        row = found.get(gowitness.normalize_url(target["url"]))
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
                scheme = target["url"].split(":", 1)[0]
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
                      for name in (gowitness.LOG_NAME, gowitness.RETRY_LOG)]
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
                if meta["estado"] in ACTIVE:
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
                    if parts[3] == "delete":
                        self.json(store.delete(parts[2]))
                        return
                raise FileNotFoundError("Ruta no encontrada")
            if path in ("/", "/app.js", "/style.css"):
                filename = {"/": "index.html", "/app.js": "app.js", "/style.css": "style.css"}[path]
                self.send_bytes(200, (STATIC / filename).read_bytes(),
                                {"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8",
                                 "style.css": "text/css; charset=utf-8"}[filename])
                return
            if path == "/api/bootstrap":
                self.json({"token": store.token, "engine": store.engine()})
                return
            if path == "/api/jobs":
                self.json(store.list())
                return
            if path == "/api/audits":
                self.json(store.audits())
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
                    with store.lock:
                        store._meta(job_id)
                    filename = "indice.csv" if parts[4] == "csv" else report.MANIFEST
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
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            print(f"Error del portal: {exc}", file=sys.stderr)
            self.json({"error": "No se pudo completar la operación. Consulta la terminal del portal."}, 500)


def ensure_gowitness(explicit):
    """Sin ruta indicada, descarga el gowitness oficial si no hay ninguno."""
    if explicit:
        return
    try:
        gowitness.find_gowitness(None)
    except ValueError:
        try:
            gowitness.install_gowitness(log=lambda text: print(text, flush=True))
        except ValueError as exc:
            # El portal arranca igual; el aviso del motor explica cómo instalarlo.
            print(f"Aviso: {exc}", flush=True)


def serve_portal(args):
    ensure_gowitness(args.gowitness)
    store = PortalStore(args.datos, args.gowitness, args.chrome)
    try:
        server = PortalServer(("127.0.0.1", args.puerto), store)
    except Exception as exc:
        store.close()
        if isinstance(exc, OSError) and (exc.errno == errno.EADDRINUSE or getattr(exc, "winerror", None) in (10013, 10048)):
            raise ValueError(f"El puerto {args.puerto} ya está en uso, probablemente por otro portal abierto. "
                             "Ciérralo o usa --puerto con otro número.") from exc
        raise
    url = f"http://127.0.0.1:{server.server_address[1]}"
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
