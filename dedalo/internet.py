"""Único punto por el que Dédalo sale a internet (NVD y GitHub): una petición GET con librería estándar.

No decide cuándo salir: quien llama comprueba antes el interruptor `sin_internet` (y el alcance, si el
dato viene de un activo) y no llama aquí si está activado. Va sin el proxy del sistema (como modelo.py y
probador.py) y verifica los certificados HTTPS; solo se descarga o se consulta, nunca se ejecuta nada.
"""

from __future__ import annotations

import urllib.request

AGENTE = "Dedalo"

# Sin ProxyHandler, urllib usaría HTTP_PROXY o el proxy de Windows.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def peticion(url: str, cabeceras: dict[str, str] | None = None, timeout: float = 30):
    """Abre `url` con GET y devuelve la respuesta (úsala con `with`).

    Lanza `urllib.error.URLError`/`HTTPError` (son `OSError`) si falla o responde con error.
    """
    solicitud = urllib.request.Request(url, headers={"User-Agent": AGENTE, **(cabeceras or {})})
    return _OPENER.open(solicitud, timeout=timeout)
