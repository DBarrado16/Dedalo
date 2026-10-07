"""Integración con gowitness v3 sin shell y con rutas SQLite relativas."""

from __future__ import annotations

import hashlib
import os
import json
import platform
import re
from pathlib import Path
import shutil
import sqlite3
import subprocess
from urllib.parse import urlsplit, urlunsplit
import urllib.request

DB_NAME = "gowitness.sqlite3"
SHOTS_DIR = "capturas"
URLS_FILE = "urls.txt"
LOG_NAME = "gowitness.log"
# Segunda pasada con el otro motor para las URL cuya página cargó pero no dio imagen.
RETRY_URLS = "urls-reintento.txt"
RETRY_LOG = "gowitness-reintento.log"
# Motores de gowitness para manejar el navegador. gorod va primero: chromedp se
# queda sin imagen en páginas que gorod captura (probado con scanme.nmap.org y
# una espera de 3 s o más).
DRIVERS = ("gorod", "chromedp")
GRAB_FAILED = "could not grab screenshot"
PROJECT_ROOT = Path(__file__).resolve().parent.parent

VERSION = "3.2.0"
RELEASE_URL = "https://github.com/sensepost/gowitness/releases/download/{version}/{name}"
# Huellas SHA-256 que publica GitHub para cada binario oficial de la versión
# fijada. Al cambiar de versión hay que actualizarlas y repetir la integración.
RELEASES = {
    ("windows", "amd64"): ("gowitness-3.2.0-windows-amd64.exe", "6aaa0cfedd255685824402bad07a295013919d4417af06431978214cd4402f4c"),
    ("windows", "arm64"): ("gowitness-3.2.0-windows-arm64.exe", "c0cc196fa7650c06250009160586b407e70ce3ff00d37edbba71cfa26758630a"),
    ("linux", "amd64"): ("gowitness-3.2.0-linux-amd64", "d315bf505691ea64a87f6231a757acfee0a94c024ab3531f35b3c52dad15895e"),
    ("linux", "arm64"): ("gowitness-3.2.0-linux-arm64", "bea4bc2b7935909267540ab75b23fe840aa0ac971dd743a7300ed967449addf3"),
    ("linux", "arm"): ("gowitness-3.2.0-linux-arm", "bee9838858c51fe82b8375c4744b447cf2115c5a20db0893c7588e90ba42dd2e"),
    ("darwin", "amd64"): ("gowitness-3.2.0-darwin-amd64", "d4112b293d708ad92a1a22eec8c8164d2f267cc59a77ce90a982715c46a2f8bc"),
    ("darwin", "arm64"): ("gowitness-3.2.0-darwin-arm64", "30122eaca82ef08ad325cc2230d4e41ba0304f391cda0f86f40748cba987de6f"),
}
MAX_DOWNLOAD = 200 * 1024 * 1024


def _executable(explicit: str) -> str:
    path = Path(explicit).expanduser()
    if path.is_file():
        return str(path.resolve())
    found = shutil.which(explicit)
    if found:
        return str(Path(found).resolve())
    raise ValueError(f"No existe el ejecutable: {explicit}")


def local_binary() -> Path:
    return PROJECT_ROOT / "bin" / ("gowitness.exe" if os.name == "nt" else "gowitness")


def find_gowitness(explicit: str | None) -> str:
    if explicit:
        return _executable(explicit)
    local = local_binary()
    if local.is_file():
        return str(local)
    found = shutil.which("gowitness")
    if found:
        return str(Path(found).resolve())
    raise ValueError("No encuentro gowitness v3. Ejecuta «python -m dedalo instalar», déjalo en bin/ o en el PATH, o usa --gowitness.")


def release_for_this_system() -> tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    if arch is None and machine.startswith("arm"):
        arch = "arm"
    if (system, arch) not in RELEASES:
        raise ValueError(f"No hay un gowitness {VERSION} oficial para {platform.system()} {platform.machine()}; instálalo a mano.")
    return RELEASES[(system, arch)]


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def install_gowitness(destination: str | Path | None = None, log=print) -> str:
    """Descarga el binario oficial fijado y solo lo instala si su SHA-256 coincide."""
    name, expected = release_for_this_system()
    target = Path(destination) if destination else local_binary()
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(target.name + ".descarga")
    url = RELEASE_URL.format(version=VERSION, name=name)
    log(f"Descargando gowitness {VERSION} ({name}) desde GitHub...")
    digest, size = hashlib.sha256(), 0
    try:
        with urllib.request.urlopen(url, timeout=60) as response, partial.open("wb") as output:
            while chunk := response.read(1 << 20):
                size += len(chunk)
                if size > MAX_DOWNLOAD:
                    raise ValueError("La descarga de gowitness es mayor de lo esperado; se descarta.")
                digest.update(chunk)
                output.write(chunk)
        if digest.hexdigest() != expected:
            raise ValueError("La huella SHA-256 del gowitness descargado no coincide con la oficial; se descarta.")
        if os.name != "nt":
            partial.chmod(0o755)
        partial.replace(target)
    except OSError as exc:
        raise ValueError(f"No se pudo descargar gowitness: {exc}. Descárgalo a mano (ver README).") from exc
    finally:
        partial.unlink(missing_ok=True)
    log(f"gowitness {VERSION} verificado e instalado en {target}")
    return str(target)


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


def scan_subnet(binary: str, workdir: str | Path, urls: list[str], opts: dict,
                urls_file: str = URLS_FILE, log_name: str = LOG_NAME) -> None:
    """Captura las URL en la base de la subred; una segunda pasada añade filas a la misma base."""
    directory = Path(workdir)
    (directory / SHOTS_DIR).mkdir(parents=True, exist_ok=True)
    # gowitness expande a 80 Y 443 las URLs sin puerto explícito. Escribirlo
    # siempre, incluso para los puertos estándar, limita la captura a nmap.
    exact_urls = [explicit_port(url) for url in urls]
    (directory / urls_file).write_text("\n".join(exact_urls) + "\n", encoding="utf-8")
    cmd = [
        binary, "scan", "file", "-f", urls_file,
        "--write-db", "--write-db-uri", f"sqlite://{DB_NAME}",
        "-s", SHOTS_DIR, "-t", str(opts["threads"]), "-T", str(opts["timeout"]),
        "--delay", str(opts["delay"]), "--screenshot-format", opts["format"],
        "--driver", opts.get("driver") or DRIVERS[0],
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
    with (directory / log_name).open("w", encoding="utf-8") as log:
        subprocess.run(cmd, cwd=directory, check=True, stdout=log, stderr=subprocess.STDOUT, env=environment)


def other_driver(driver: str) -> str:
    return DRIVERS[1] if driver == DRIVERS[0] else DRIVERS[0]


def retry_candidates(directory: Path, urls: list[str]) -> list[str]:
    """URL cuya página respondió pero el navegador no pudo sacar la imagen.

    Solo ese fallo se reintenta con el otro motor: un error de conexión o de
    carga se repetiría igual y solo alargaría la subred.
    """
    failed = {key for key, kind, _ in _log_errors(Path(directory) / LOG_NAME) if kind == GRAB_FAILED}
    captured = read_results(Path(directory) / DB_NAME)
    return [url for url in urls if normalize_url(url) in failed and normalize_url(url) not in captured]


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


def _log_errors(path: Path):
    """(URL normalizada, tipo de fallo, mensaje) de cada error de un registro de gowitness."""
    try:
        with path.open(encoding="utf-8", errors="replace") as log:
            for line in log:
                match = re.search(r'(failed to witness target|could not grab screenshot) target=(\S+) err=("(?:[^"\\]|\\.)*")', line)
                if not match:
                    continue
                try:
                    yield normalize_url(match[2]), match[1], json.loads(match[3])
                except (ValueError, KeyError):
                    continue
    except OSError:
        return


def read_errors(directory: Path) -> dict[str, str]:
    """Recuperar el error de cada URL, también para ejecuciones antiguas.

    Si la URL se reintentó con el otro motor, prevalece el error del reintento.
    """
    errors = {}
    for name, prefix in ((LOG_NAME, ""), (RETRY_LOG, "También sin imagen al reintentar con el otro motor: ")):
        for key, _, message in _log_errors(Path(directory) / name):
            if "ERR_NETWORK_ACCESS_DENIED" in message:
                message = "Acceso a la red denegado (ERR_NETWORK_ACCESS_DENIED). Comprueba que el portal se haya iniciado con acceso a la red/VPN."
            elif "ERR_INVALID_AUTH_CREDENTIALS" in message:
                message = "El servidor requiere autenticación HTTP (ERR_INVALID_AUTH_CREDENTIALS). El motor no utiliza las credenciales guardadas en tu navegador."
            errors[key] = prefix + message
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
