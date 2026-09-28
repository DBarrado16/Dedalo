"""Portal local: cargas, cola persistente y galería sobre el motor CLI existente."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import threading
from urllib.parse import urlsplit
import uuid
import webbrowser
from xml.etree.ElementTree import ParseError

from . import cli, gowitness, parser, report

STATIC = Path(__file__).parent / "static"
MAX_BODY = 32 * 1024 * 1024
ACTIVE = {"en_cola", "en_curso", "deteniendo"}


class Conflict(ValueError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


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
    for key in ("por_servicio", "pagina_completa"):
        result[key] = raw.get(key, False)
        if type(result[key]) is not bool:
            raise ValueError(f"{key}: valor inválido")
    return result


class PortalStore:
    def __init__(self, root, binary=None, chrome=None):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.binary_option, self.chrome_option = binary, chrome
        self.lock = threading.RLock()
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
        self.jobs = {}
        for path in self.root.glob("*/trabajo.json"):
            if not re.fullmatch(r"[a-f0-9]{32}", path.parent.name):
                continue
            try:
                meta = json.loads(path.read_text(encoding="utf-8"))
                if meta["id"] != path.parent.name:
                    continue
                if meta["estado"] in ACTIVE:
                    meta.update(estado="interrumpida", error="El portal se cerró antes de completar el trabajo.")
                    atomic_json(path, meta)
                self.jobs[meta["id"]] = meta
            except (OSError, ValueError, KeyError, TypeError):
                continue
        self.worker = threading.Thread(target=self._worker, name="nmapshot-capturas", daemon=True)
        self.worker.start()

    def directory(self, job_id):
        if not re.fullmatch(r"[a-f0-9]{32}", job_id):
            raise FileNotFoundError("Trabajo no encontrado")
        return report.inside(self.root, job_id)

    def _meta(self, job_id):
        if job_id not in self.jobs:
            raise FileNotFoundError("Trabajo no encontrado")
        return self.jobs[job_id]

    def _save(self, meta):
        atomic_json(self.directory(meta["id"]) / "trabajo.json", meta)

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
        ranges = text_field(payload.get("rangos", ""), "Rangos", 256_000).lstrip("\ufeff")
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
        networks = [line.split("#", 1)[0].strip() for line in ranges.splitlines() if line.split("#", 1)[0].strip()]
        groups = cli.group_hosts(parser.merge(hosts), networks, options["puertos"], options["por_servicio"])
        total = sum(len(g["objetivos"]) for g in groups)
        if total > 100_000:
            raise ValueError("Demasiados objetivos para una ejecución web; divide los archivos (máximo 100.000).")
        job_id = uuid.uuid4().hex
        meta = {"id": job_id, "nombre": name, "fecha": now(), "estado": "preparada",
                "archivos": [n for n, _ in uploads], "opciones": options, "total": total,
                "subredes": len(groups), "error": "", "grupos": groups}
        with self.lock:
            if self.closing:
                raise Conflict("El portal se está cerrando")
            directory = self.directory(job_id)
            (directory / "entradas").mkdir(parents=True)
            for index, (_, content) in enumerate(uploads):
                (directory / "entradas" / f"nmap-{index:02d}.txt").write_text(content, encoding="utf-8")
            (directory / "rangos.txt").write_text(ranges, encoding="utf-8")
            self._save(meta)
            self.jobs[job_id] = meta
        return self.detail(job_id)

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

    def list(self):
        with self.lock:
            snapshots = copy.deepcopy(list(self.jobs.values()))
        return [self.summary(meta) for meta in sorted(snapshots, key=lambda m: m["fecha"], reverse=True)]

    def detail(self, job_id):
        with self.lock:
            meta = copy.deepcopy(self._meta(job_id))
        manifest = self._manifest(meta)
        groups = manifest["grupos"] if manifest else meta["grupos"]
        root = self.directory(job_id) / "resultado"
        response = self.summary(meta)
        response.update(archivos=meta["archivos"], opciones=meta["opciones"], grupos=[],
                        csv=(root / "indice.csv").is_file())
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
            if meta["total"] == 0:
                raise Conflict("No hay puertos web abiertos seleccionados")
            meta.update(estado="en_cola", error="")
            self._save(meta)
            self.pending.put((job_id, binary, chrome))
        return self.detail(job_id)

    def cancel(self, job_id):
        with self.lock:
            meta = self._meta(job_id)
            if meta["estado"] == "en_cola":
                meta["estado"] = "cancelada"
            elif meta["estado"] in ("en_curso", "deteniendo"):
                (self.directory(job_id) / "parar").touch()
                meta["estado"] = "deteniendo"
            else:
                raise Conflict("Este trabajo no está en ejecución")
            self._save(meta)
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
                meta["estado"] = "en_curso"
                self._save(meta)
                options = dict(meta["opciones"])
            directory = self.directory(job_id)
            command = [sys.executable, "-u", "-m", "nmapshot", "capturar"]
            command += [str(p) for p in sorted((directory / "entradas").glob("nmap-*.txt"))]
            command += ["-r", str(directory / "rangos.txt"), "-o", str(directory / "resultado"),
                        "--gowitness", binary, "--stop-file", str(directory / "parar"),
                        "--puertos", options["puertos"], "--formato", options["formato"],
                        "--hilos", str(options["hilos"]), "--timeout", str(options["timeout"]),
                        "--delay", str(options["delay"])]
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
            with self.lock:
                meta.update(estado=status, error=error, fin=now())
                self._save(meta)

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
            del self.jobs[job_id]
        return {"eliminada": job_id}

    def image(self, job_id, group_index, target_index):
        with self.lock:
            meta = copy.deepcopy(self._meta(job_id))
        manifest = self._manifest(meta)
        if not manifest:
            raise FileNotFoundError("Captura no disponible")
        try:
            if group_index < 0 or target_index < 0:
                raise IndexError
            group = manifest["grupos"][group_index]
            target = group["objetivos"][target_index]
        except IndexError:
            raise FileNotFoundError("Captura no disponible")
        directory = report.inside(self.directory(job_id) / "resultado", group["carpeta"])
        found = gowitness.read_results(directory / gowitness.DB_NAME)
        row = found.get(gowitness.normalize_url(target["url"]))
        if not row:
            raise FileNotFoundError("Captura no disponible")
        path = gowitness.screenshot_path(directory, row["filename"])
        if path.suffix.lower() not in (".png", ".jpg", ".jpeg", ".webp"):
            raise ValueError("Formato de imagen no permitido")
        return path

    def logs(self, job_id):
        with self.lock:
            meta = copy.deepcopy(self._meta(job_id))
        directory = self.directory(job_id)
        paths = [directory / "proceso.log"]
        manifest = self._manifest(meta)
        if manifest:
            paths += [report.inside(directory / "resultado", g["carpeta"]) / "gowitness.log"
                      for g in manifest["grupos"] if g["estado"] in ("en_curso", "parcial", "error", "interrumpido")]
        lines = []
        for path in paths[-8:]:
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
                    self.cancel(job_id)
            self.pending.put(None)
        self.worker.join()
        self.file_lock.close()


class PortalServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, store):
        self.store = store
        super().__init__(address, PortalHandler)


class PortalHandler(BaseHTTPRequestHandler):
    server_version = "nmapshot"
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

    def json(self, value, status=200):
        self.send_bytes(status, json.dumps(value, ensure_ascii=False).encode("utf-8"))

    def do_GET(self):
        self.dispatch(False)

    def do_POST(self):
        self.dispatch(True)

    def dispatch(self, mutate):
        try:
            if not self.allowed():
                self.json({"error": "Origen no permitido"}, 403)
                return
            store = self.server.store
            path = urlsplit(self.path).path
            parts = path.strip("/").split("/")
            if mutate:
                if self.headers.get("X-Nmapshot-Token") != store.token:
                    self.json({"error": "Sesión caducada; recarga la página"}, 403)
                    return
                if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                    self.json({"error": "Se esperaba JSON"}, 415)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_BODY:
                    self.json({"error": "La carga debe ser menor de 32 MB"}, 413)
                    return
                data = self.rfile.read(length)
                if len(data) != length:
                    raise ValueError("La carga no llegó completa")
                payload = json.loads(data)
                if path == "/api/jobs":
                    self.json(store.create(payload), 201)
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
            if len(parts) >= 3 and parts[:2] == ["api", "jobs"]:
                job_id = parts[2]
                if len(parts) == 3:
                    self.json(store.detail(job_id))
                    return
                if len(parts) == 4 and parts[3] == "logs":
                    self.json({"text": store.logs(job_id)})
                    return
                if len(parts) == 6 and parts[3] == "image":
                    image = store.image(job_id, int(parts[4]), int(parts[5]))
                    self.send_bytes(200, image.read_bytes(), mimetypes.guess_type(image.name)[0] or "image/png")
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


def serve_portal(args):
    store = PortalStore(args.datos, args.gowitness, args.chrome)
    try:
        server = PortalServer(("127.0.0.1", args.puerto), store)
    except Exception:
        store.close()
        raise
    url = f"http://127.0.0.1:{server.server_address[1]}"
    print(f"Portal nmapshot: {url}\nDatos: {store.root}\nCtrl+C para cerrar.", flush=True)
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
