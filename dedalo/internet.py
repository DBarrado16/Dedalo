"""Único punto por el que Dédalo sale a internet (NVD, CISA KEV, Exploit-DB y GitHub): peticiones GET con librería estándar.

No decide cuándo salir: quien llama comprueba antes el interruptor `sin_internet` (y el alcance, si el
dato viene de un activo) y no llama aquí si está activado. Va sin el proxy del sistema (como modelo.py y
probador.py) y verifica los certificados HTTPS; solo se descarga o se consulta, nunca se ejecuta nada.
"""

from __future__ import annotations

import http.client
import json
from pathlib import Path
import urllib.request

AGENTE = "Dedalo"
_TROZO = 1 << 20  # las descargas se leen y escriben de MB en MB: un feed grande no pasa entero por memoria

# Sin ProxyHandler, urllib usaría HTTP_PROXY o el proxy de Windows.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def peticion(url: str, cabeceras: dict[str, str] | None = None, timeout: float = 30):
    """Abre `url` con GET y devuelve la respuesta (úsala con `with`).

    Lanza `urllib.error.URLError`/`HTTPError` (son `OSError`) si falla o responde con error.
    """
    solicitud = urllib.request.Request(url, headers={"User-Agent": AGENTE, **(cabeceras or {})})
    return _OPENER.open(solicitud, timeout=timeout)


def leer_json(url: str, tope: int, cabeceras: dict[str, str] | None = None, timeout: float = 30):
    """El JSON de `url` (GET), con o sin BOM y leído con tope de bytes.

    None si no se pudo: error de red o HTTP (403/429 incluidos), respuesta mayor que `tope` o que no es JSON.
    """
    try:
        with peticion(url, cabeceras, timeout) as respuesta:
            crudo = respuesta.read(tope + 1)
        if len(crudo) > tope:
            return None
        return json.loads(crudo.decode("utf-8-sig"))
    except (OSError, ValueError, http.client.HTTPException):
        return None


def descargar(url: str, ruta: Path, tope: int, comprobar=None, por_lineas: bool = False, timeout: float = 60) -> None:
    """Baja `url` a `ruta` por trozos, sin pasar de `tope` bytes y solo si llega COMPLETA.

    `read` no avisa si el servidor cierra antes del Content-Length, así que se compara lo recibido con él; sin
    Content-Length, un fichero `por_lineas` (un CSV) debe acabar en salto de línea (una fila cortada no lo hace).
    Se escribe en `<ruta>.descarga`, que `comprobar(parcial)` puede revisar o reescribir (ValueError si no vale), y
    solo entonces sustituye a `ruta`: nunca queda un fichero a medias, y uno bueno anterior sobrevive a una descarga
    fallida. Lanza OSError, ValueError o `http.client.HTTPException` si falla.
    """
    parcial = ruta.with_name(ruta.name + ".descarga")
    try:
        recibido, final = 0, b""
        with peticion(url, timeout=timeout) as respuesta, parcial.open("wb") as salida:
            cabeceras = getattr(respuesta, "headers", None)
            anunciado = cabeceras.get("Content-Length") if cabeceras is not None else None
            while trozo := respuesta.read(_TROZO):
                recibido += len(trozo)
                if recibido > tope:
                    raise ValueError("la descarga es mayor de lo esperado")
                salida.write(trozo)
                final = trozo[-1:]
        if anunciado is not None:
            if not str(anunciado).strip().isdigit() or int(anunciado) != recibido:
                raise ValueError(f"descarga incompleta: se recibieron {recibido} bytes de {anunciado}")
        elif por_lineas and final != b"\n":
            raise ValueError("descarga incompleta: el fichero acaba en mitad de una fila")
        if comprobar is not None:
            comprobar(parcial)
        parcial.replace(ruta)
    finally:
        parcial.unlink(missing_ok=True)
