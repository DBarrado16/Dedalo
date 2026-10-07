"""Índices y estado persistente de una ejecución."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
import time

from . import gowitness

MANIFEST = "ejecucion.json"
COLUMNS = ["rango", "subred", "ip", "puerto", "url", "estado", "codigo_http",
           "titulo", "url_final", "captura", "error"]


def _resolved(path: Path) -> Path:
    # En Windows, resolver una carpeta justo mientras se crea puede devolverla con el
    # prefijo de ruta larga \\?\; se quita para compararla con la base.
    text = str(path.resolve())
    if text.startswith("\\\\?\\UNC\\"):
        text = "\\\\" + text[8:]
    elif text.startswith("\\\\?\\"):
        text = text[4:]
    return Path(text)


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
        result = found.get(gowitness.normalize_url(target["url"]))
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
            "captura": shot, "error": "" if result else (errors.get(gowitness.normalize_url(target["url"])) or error or "Consultar gowitness.log"),
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


def write_index(root: Path, manifest: dict) -> None:
    temporary = root / "indice.csv.tmp"
    with temporary.open("w", newline="", encoding="utf-8-sig") as file:
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
                writer.writerow({key: csv_text(value) for key, value in row.items()})
    replace(temporary, root / "indice.csv")
    save_manifest(root, manifest)
