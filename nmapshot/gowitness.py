"""Integración con gowitness v3 sin shell y con rutas SQLite relativas."""

from __future__ import annotations

import os
import json
import re
from pathlib import Path
import shutil
import sqlite3
import subprocess
from urllib.parse import urlsplit, urlunsplit

DB_NAME = "gowitness.sqlite3"
SHOTS_DIR = "capturas"
URLS_FILE = "urls.txt"
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _executable(explicit: str) -> str:
    path = Path(explicit).expanduser()
    if path.is_file():
        return str(path.resolve())
    found = shutil.which(explicit)
    if found:
        return str(Path(found).resolve())
    raise ValueError(f"No existe el ejecutable: {explicit}")


def find_gowitness(explicit: str | None) -> str:
    if explicit:
        return _executable(explicit)
    local = PROJECT_ROOT / "bin" / ("gowitness.exe" if os.name == "nt" else "gowitness")
    if local.is_file():
        return str(local)
    found = shutil.which("gowitness")
    if found:
        return str(Path(found).resolve())
    raise ValueError("No encuentro gowitness v3. Déjalo en bin/ o en el PATH, o usa --gowitness.")


def find_chrome(explicit: str | None) -> str | None:
    """None permite que gowitness descargue su propio navegador."""
    if explicit:
        return _executable(explicit)
    if os.name == "nt":
        for base, suffix in [
            ("ProgramFiles", "Google/Chrome/Application/chrome.exe"),
            ("ProgramFiles(x86)", "Google/Chrome/Application/chrome.exe"),
            ("LOCALAPPDATA", "Google/Chrome/Application/chrome.exe"),
        ]:
            if os.environ.get(base):
                path = Path(os.environ[base]) / suffix
                if path.is_file():
                    return str(path.resolve())
        # Chromium headless evita bloqueos de CaptureScreenshot observados
        # con Edge. Aprovechar instalaciones existentes sin descargar nada.
        if local := os.environ.get("LOCALAPPDATA"):
            shells = Path(local, "ms-playwright").glob("chromium_headless_shell-*/chrome-headless-shell-win64/chrome-headless-shell.exe")
            for path in sorted(shells, key=lambda p: int(p.parents[1].name.rsplit("-", 1)[-1]) if p.parents[1].name.rsplit("-", 1)[-1].isdigit() else 0, reverse=True):
                if path.is_file():
                    return str(path.resolve())
        for base in ("ProgramFiles(x86)", "ProgramFiles"):
            if os.environ.get(base):
                path = Path(os.environ[base]) / "Microsoft/Edge/Application/msedge.exe"
                if path.is_file():
                    return str(path.resolve())
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
        if found := shutil.which(name):
            return str(Path(found).resolve())
    return None


def scan_subnet(binary: str, workdir: str | Path, urls: list[str], opts: dict) -> None:
    directory = Path(workdir)
    (directory / SHOTS_DIR).mkdir(parents=True, exist_ok=True)
    # gowitness expande a 80 Y 443 las URLs sin puerto explícito. Escribirlo
    # siempre, incluso para los puertos estándar, limita la captura a nmap.
    exact_urls = [explicit_port(url) for url in urls]
    (directory / URLS_FILE).write_text("\n".join(exact_urls) + "\n", encoding="utf-8")
    cmd = [
        binary, "scan", "file", "-f", URLS_FILE,
        "--write-db", "--write-db-uri", f"sqlite://{DB_NAME}",
        "-s", SHOTS_DIR, "-t", str(opts["threads"]), "-T", str(opts["timeout"]),
        "--delay", str(opts["delay"]), "--screenshot-format", opts["format"],
        "--log-scan-errors", "--no-log-color",
    ]
    if opts.get("chrome"):
        cmd += ["--chrome-path", opts["chrome"]]
    if opts.get("fullpage"):
        cmd.append("--screenshot-fullpage")
    environment = os.environ.copy()
    if os.name == "nt" and Path(opts.get("chrome") or "").name.lower() == "msedge.exe":
        # Edge se relanza al heredar capas de compatibilidad y pierde el canal
        # DevTools que espera gowitness. El ajuste solo afecta a este proceso.
        environment.pop("__COMPAT_LAYER", None)
    with (directory / "gowitness.log").open("w", encoding="utf-8") as log:
        subprocess.run(cmd, cwd=directory, check=True, stdout=log, stderr=subprocess.STDOUT, env=environment)


def explicit_port(url: str) -> str:
    parts = urlsplit(url)
    if parts.port is not None:
        return url
    port = {"http": 80, "https": 443}[parts.scheme]
    return urlunsplit((parts.scheme, f"{parts.netloc}:{port}", parts.path or "/", parts.query, ""))


def normalize_url(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    if port and (parts.scheme, port) not in (("http", 80), ("https", 443)):
        host += f":{port}"
    return urlunsplit((parts.scheme.lower(), host.lower(), parts.path or "/", parts.query, ""))


def read_errors(directory: Path) -> dict[str, str]:
    """Recuperar el error de cada URL, también para ejecuciones antiguas."""
    errors = {}
    try:
        with (directory / "gowitness.log").open(encoding="utf-8", errors="replace") as log:
            for line in log:
                match = re.search(r'(?:failed to witness target|could not grab screenshot) target=(\S+) err=("(?:[^"\\]|\\.)*")', line)
                if not match:
                    continue
                try:
                    message = json.loads(match[2])
                    key = normalize_url(match[1])
                except (ValueError, KeyError):
                    continue
                if "ERR_NETWORK_ACCESS_DENIED" in message:
                    message = "Acceso a la red denegado (ERR_NETWORK_ACCESS_DENIED). Comprueba que el portal se haya iniciado con acceso a la red/VPN."
                elif "ERR_INVALID_AUTH_CREDENTIALS" in message:
                    message = "El servidor requiere autenticación HTTP (ERR_INVALID_AUTH_CREDENTIALS). El motor no utiliza las credenciales guardadas en tu navegador."
                errors[key] = message
    except OSError:
        pass
    return errors


def screenshot_path(directory: Path, filename: str) -> Path:
    """Los nombres que vienen de la base nunca pueden salir de capturas/."""
    base = (directory / SHOTS_DIR).resolve()
    path = (base / filename).resolve()
    if not filename or not path.is_relative_to(base) or path == base:
        raise ValueError(f"Ruta de captura inválida: {filename!r}")
    return path


def read_results(db_path: str | Path) -> dict[str, dict]:
    """URL original normalizada -> resultado con fichero de captura existente."""
    path = Path(db_path).resolve()
    if not path.is_file():
        return {}
    con = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "SELECT url, final_url, response_code, title, filename FROM results "
            "WHERE failed = 0 ORDER BY id"
        ).fetchall()
    finally:
        con.close()
    results = {}
    for row in rows:
        item = dict(row)
        if not item["filename"]:
            continue
        shot = screenshot_path(path.parent, item["filename"])
        if shot.is_file() and shot.stat().st_size:
            results[normalize_url(item["url"])] = item
    return results


def merge(binary: str, sources: list[str | Path], output: str | Path) -> None:
    path = Path(output).resolve()
    if path.exists():
        raise ValueError(f"La base de destino ya existe: {path}")
    cmd = [binary, "report", "merge", "--output-file", path.name, "--no-log-color"]
    for source in sources:
        cmd += ["--source-file", str(Path(source).resolve())]
    with (path.parent / "merge.log").open("w", encoding="utf-8") as log:
        subprocess.run(cmd, cwd=path.parent, check=True, stdout=log, stderr=subprocess.STDOUT)


def serve(binary: str, workdir: str | Path, host: str, port: int) -> None:
    cmd = [binary, "report", "server", "--db-uri", f"sqlite://{DB_NAME}",
           "--screenshot-path", SHOTS_DIR, "--host", host, "--port", str(port)]
    subprocess.run(cmd, cwd=workdir, check=True)
