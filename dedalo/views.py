"""Preparar vistas de gowitness sin alterar los resultados de otras subredes."""

from __future__ import annotations

from datetime import datetime
import filecmp
import ipaddress
import os
from pathlib import Path
import shutil
import uuid

from . import gowitness, report


def select_groups(manifest: dict, selector: str | None) -> list[dict]:
    groups = manifest["grupos"]
    if selector is None:
        return groups
    if selector != "fuera_de_rango":
        selector = str(ipaddress.ip_network(selector, strict=False))
    selected = [g for g in groups if selector in (g["rango"], g["subred"])]
    if not selected:
        raise ValueError(f"No hay resultados para {selector}. Usa ver --listar.")
    return selected


def _merge_batches(binary: str, sources: list[Path], destination: Path) -> None:
    # Mantener la línea de comandos corta incluso con cientos de /24 en Windows.
    round_number = 0
    while len(sources) > 16:
        folder = destination.parent / "partes"
        folder.mkdir(exist_ok=True)
        batch_outputs = []
        for offset in range(0, len(sources), 16):
            output = folder / f"{round_number}-{offset}.sqlite3"
            gowitness.merge(binary, sources[offset:offset + 16], output)
            batch_outputs.append(output)
        sources = batch_outputs
        round_number += 1
    gowitness.merge(binary, sources, destination)


def prepare_view(binary: str, root: Path, groups: list[dict]) -> Path:
    available = []
    expected = set()
    for group in groups:
        directory = report.inside(root, group["carpeta"])
        results = gowitness.read_results(directory / gowitness.DB_NAME)
        if results:
            available.append((directory, results))
            expected.update(results)
    if not available:
        raise ValueError("No hay capturas disponibles en esta selección.")
    if len(available) == 1:
        return available[0][0]

    # Una vista nueva evita modificar una base que otro visor pueda tener abierta.
    view = report.inside(root, ".vistas/" + datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8])
    (view / gowitness.SHOTS_DIR).mkdir(parents=True)
    for directory, results in available:
        for row in results.values():
            source = gowitness.screenshot_path(directory, row["filename"])
            destination = gowitness.screenshot_path(view, row["filename"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                if not filecmp.cmp(source, destination, shallow=False):
                    raise ValueError(f"Dos capturas diferentes tienen el mismo nombre: {row['filename']}")
                continue
            try:
                os.link(source, destination)
            except OSError:
                shutil.copy2(source, destination)
    _merge_batches(binary, [d / gowitness.DB_NAME for d, _ in available], view / gowitness.DB_NAME)
    actual = set(gowitness.read_results(view / gowitness.DB_NAME))
    if expected != actual:
        raise ValueError(f"La vista combinada no contiene todas las capturas; consulta {view / 'merge.log'}")
    return view
