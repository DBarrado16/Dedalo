"""Quemar una barra de direcciones (estilo navegador) con la URL en una captura.

No conecta con nada: recompone una imagen ya capturada. Se usa Chrome (el que ya detecta
Dédalo) para fotografiar un HTML con la barra + la imagen, y así no hace falta ninguna
librería de imágenes. El tamaño se lee de la cabecera PNG, sin dependencias.
"""

from __future__ import annotations

import base64
import html
import os
from pathlib import Path
import struct
import subprocess
import tempfile

ALTO_BARRA = 52  # alto de la barra en píxeles

_PLANTILLA = """<!doctype html><meta charset=utf-8><style>
 *{{margin:0;box-sizing:border-box;font-family:Segoe UI,Arial,sans-serif}}
 .bar{{height:52px;background:#f1f3f4;display:flex;align-items:center;padding:0 12px;gap:12px;border-bottom:1px solid #e3e5e8}}
 .nav{{display:flex;gap:2px;color:#5f6368}}
 .nav span{{width:30px;height:30px;display:flex;align-items:center;justify-content:center;border-radius:50%;font-size:17px}}
 .url{{flex:1;background:#fff;border-radius:18px;height:34px;display:flex;align-items:center;gap:9px;padding:0 15px;color:#202124;font-size:13px;border:1px solid #dfe1e5;overflow:hidden;white-space:nowrap}}
 .lock{{color:#5f6368;font-size:12px}}
 .menu{{width:30px;text-align:center;color:#5f6368;font-size:18px}}
 img{{display:block;width:{ancho}px}}
</style><div class=bar>
 <div class=nav><span>&#8592;</span><span>&#8594;</span><span>&#8635;</span></div>
 <div class=url><span class=lock>&#128274;</span>{url}</div>
 <span class=menu>&#8942;</span></div>
 <img src="data:image/png;base64,{datos}">"""


def dimensiones_png(ruta: Path) -> tuple[int, int]:
    """Ancho y alto del PNG, leídos del IHDR. ValueError si no es un PNG."""
    datos = Path(ruta).read_bytes()
    if datos[:8] != b"\x89PNG\r\n\x1a\n" or datos[12:16] != b"IHDR":
        raise ValueError(f"No es un PNG: {ruta}")
    ancho, alto = struct.unpack(">II", datos[16:24])
    return ancho, alto


def componer(imagen: Path, url: str, chrome: str, ejecutar=subprocess.run) -> None:
    """Sustituye `imagen` por un PNG con la barra de direcciones (URL) quemada encima.

    Si Chrome falla, deja `imagen` intacta y lanza ValueError. `ejecutar` se inyecta en los tests.
    """
    imagen = Path(imagen)
    ancho, alto = dimensiones_png(imagen)
    datos = base64.b64encode(imagen.read_bytes()).decode()
    cuerpo = _PLANTILLA.format(ancho=ancho, url=html.escape(url), datos=datos)
    fd_html, ruta_html = tempfile.mkstemp(dir=imagen.parent, suffix=".barra.html")
    os.close(fd_html)
    envoltorio = Path(ruta_html)
    salida = imagen.with_name(imagen.stem + ".barra.png")
    try:
        envoltorio.write_text(cuerpo, encoding="utf-8")
        ejecutar([chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                  f"--screenshot={salida}", f"--window-size={ancho},{alto + ALTO_BARRA}", envoltorio.as_uri()],
                 check=True, capture_output=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        os.replace(salida, imagen)
    except (OSError, subprocess.SubprocessError) as exc:
        salida.unlink(missing_ok=True)
        raise ValueError(f"No se pudo componer la barra de URL en {imagen.name}: {exc}") from exc
    finally:
        envoltorio.unlink(missing_ok=True)
