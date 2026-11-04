"""Índices y estado persistente de una ejecución."""

from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path
import time

from . import gowitness

MANIFEST = "ejecucion.json"
# Lo que dio el cruce de vulnerabilidades (`vulnerabilidades.campos_exportacion`), al final del índice de capturas y
# del CSV del inventario; en blanco hasta que se haga el cruce.
COLUMNAS_VULN = ["vuln_estado", "vuln_prioridad", "vuln_cves", "vuln_severidades", "vuln_exploits", "vuln_enlaces"]
COLUMNS = ["rango", "subred", "ip", "puerto", "url", "estado", "codigo_http",
           "titulo", "url_final", "captura", "error"] + COLUMNAS_VULN


def _resolved(path: Path) -> Path:
    # En Windows, resolver una carpeta justo mientras se crea puede devolverla con el
    # prefijo de ruta larga \\?\; se quita para compararla con la base.
    text = str(path.resolve())
    if text.startswith("\\\\?\\UNC\\"):
        text = "\\\\" + text[8:]
    elif text.startswith("\\\\?\\"):
        text = text[4:]
    return Path(text)


# Lo que ocupa una ejecución por debajo de su carpeta de salida en el peor caso, con margen:
# <rango>/<subred>/capturas/https---255.255.255.255-65535-.barra.png (unos 100 caracteres).
HOLGURA_SALIDA = 105
# El portal captura en <datos>/<id de la ejecución, 32>/resultado.
HOLGURA_DATOS = 32 + 1 + len("resultado") + 1 + HOLGURA_SALIDA


def rutas_largas_activadas() -> bool:
    """Si Windows admite rutas de más de 260 caracteres (LongPathsEnabled); fuera de Windows, sí."""
    if os.name != "nt":
        return True
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\FileSystem") as clave:
            return winreg.QueryValueEx(clave, "LongPathsEnabled")[0] == 1
    except OSError:
        return False


def comprobar_longitud(carpeta: Path, holgura: int) -> None:
    """Rechaza una carpeta base con la que las capturas pasarían de 260 caracteres en Windows.

    Sin rutas largas, crear esos ficheros falla a mitad de la ejecución (o al subir el
    Nmap al portal) con un error que no dice la causa; mejor decirlo antes de empezar.
    """
    largo = len(str(Path(carpeta).resolve()))
    if largo + holgura > 259 and not rutas_largas_activadas():
        raise ValueError(
            f"La carpeta {carpeta} es demasiado larga para Windows ({largo} caracteres): con lo que Dédalo "
            f"crea dentro, las capturas pasarían del límite de 260. Usa una ruta de {259 - holgura} caracteres "
            "como mucho o activa las rutas largas de Windows (LongPathsEnabled).")


def inside(root: Path, relative: str) -> Path:
    base = _resolved(root)
    path = _resolved(base / relative)
    if Path(relative).is_absolute() or path == base or not path.is_relative_to(base):
        raise ValueError(f"Ruta fuera de la ejecución: {relative!r}")
    return path


def replace(temporary: Path, target: Path, attempts: int = 40) -> None:
    """Sustituye un archivo de forma atómica aunque alguien lo esté leyendo.

    En Windows, os.replace falla con acceso denegado mientras otro proceso tiene
    abierto el destino, y el portal lee el manifiesto en cada consulta de
    progreso. Las lecturas son breves: se reintenta durante unos dos segundos.
    """
    for attempt in range(attempts):
        try:
            os.replace(temporary, target)
            return
        except PermissionError:
            if os.name != "nt" or attempt == attempts - 1:
                raise
            time.sleep(0.05)


def save_manifest(root: Path, manifest: dict) -> None:
    temporary = root / (MANIFEST + ".tmp")
    temporary.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    replace(temporary, root / MANIFEST)


def load_manifest(root: Path) -> dict:
    manifest = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("version") != 1 or not isinstance(manifest.get("grupos"), list):
        raise ValueError("Formato de ejecucion.json no compatible")
    for group in manifest["grupos"]:
        inside(root, group["carpeta"])
    return manifest


def collect_group(root: Path, group: dict, error: str = "") -> None:
    directory = inside(root, group["carpeta"])
    found = gowitness.read_results(directory / gowitness.DB_NAME)
    errors = gowitness.read_errors(directory)
    rows, missing = [], []
    for target in group["objetivos"]:
        # Si solo respondió el otro esquema, la fila sigue siendo la del objetivo; la URL que
        # respondió se ve en url_final.
        result = gowitness.find_result(found, target["url"])
        shot = ""
        if result:
            shot = gowitness.screenshot_path(directory, result["filename"]).relative_to(root).as_posix()
        else:
            missing.append(target["url"])
        rows.append({
            "rango": group["rango"], "subred": group["subred"],
            "ip": target["ip"], "puerto": target["port"], "url": target["url"],
            "estado": "capturada" if result else "sin_captura",
            "codigo_http": result["response_code"] if result else "",
            "titulo": result["title"] if result else "",
            "url_final": result["final_url"] if result else "",
            "captura": shot, "error": "" if result else (gowitness.find_error(errors, target["url"]) or error or "Consultar gowitness.log"),
        })
    group["resultados"] = rows
    group["capturas"] = len(rows) - len(missing)
    group["sin_captura"] = len(missing)
    group["error"] = error
    group["estado"] = "error" if error else ("parcial" if missing else "completo")
    (directory / "sin_captura.txt").write_text(
        "".join(url + "\n" for url in missing), encoding="utf-8"
    )


def csv_text(value):
    # Títulos y otros textos proceden de webs: evitar fórmulas al abrirlos en Excel.
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _write_rows(file, manifest: dict, vulns: dict | None) -> None:
    """Escribe el índice. `vulns`: {(ip, "puerto"): columnas vuln_*} de los servicios cruzados (ver `vulnerabilidades.columnas_tcp`)."""
    writer = csv.DictWriter(file, fieldnames=COLUMNS)
    writer.writeheader()
    for group in manifest["grupos"]:
        rows = group.get("resultados")
        if rows is None:
            rows = [{
                "rango": group["rango"], "subred": group["subred"],
                "ip": target["ip"], "puerto": target["port"], "url": target["url"],
                "estado": "pendiente",
            } for target in group["objetivos"]]
        for row in rows:
            row = row | (vulns or {}).get((row["ip"], str(row["puerto"])), {})
            writer.writerow({key: csv_text(value) for key, value in row.items()})


def index_bytes(manifest: dict, vulns: dict | None = None) -> bytes:
    """El índice de capturas con las vulnerabilidades al día, sin escribir nada (lo usa la descarga del portal)."""
    output = io.StringIO(newline="")
    _write_rows(output, manifest, vulns)
    return output.getvalue().encode("utf-8-sig")


def write_index(root: Path, manifest: dict, vulns: dict | None = None) -> None:
    temporary = root / "indice.csv.tmp"
    with temporary.open("w", newline="", encoding="utf-8-sig") as file:
        _write_rows(file, manifest, vulns)
    replace(temporary, root / "indice.csv")
    save_manifest(root, manifest)
