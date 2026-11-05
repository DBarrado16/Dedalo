"""Lanzar Nmap desde el portal: localizar el binario, presets, ejecución y filtrado de resultados."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess

from .gowitness import _executable


def find_nmap(explicit: str | None) -> str:
    """Ruta absoluta al ejecutable de Nmap; sin ninguno, ValueError con ayuda."""
    if explicit:
        return _executable(explicit)
    if os.name == "nt":
        for base in ("ProgramFiles(x86)", "ProgramFiles"):
            if os.environ.get(base):
                path = Path(os.environ[base]) / "Nmap" / "nmap.exe"
                if path.is_file():
                    return str(path.resolve())
    found = shutil.which("nmap")
    # Uno en la carpeta actual no cuenta: en Windows shutil.which también mira ahí
    # (como en gowitness.find_gowitness y modelo.find_ollama).
    if found and Path(found).resolve().parent != Path.cwd().resolve():
        return str(Path(found).resolve())
    path = Path("/usr/bin/nmap")
    if path.is_file():
        return str(path)
    raise ValueError("No se encuentra Nmap. Instálalo (https://nmap.org/download) o indica su ruta.")


def nmap_version(binary: str) -> str | None:
    """La versión que dice `nmap --version` (p. ej. '7.95'), o None si no responde."""
    try:
        resultado = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError):
        return None
    encontrado = re.search(r"Nmap version ([\d.]+)", (resultado.stdout or "") + (resultado.stderr or ""))
    return encontrado.group(1) if encontrado else None
