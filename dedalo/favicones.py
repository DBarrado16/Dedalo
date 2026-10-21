"""Huella del favicon de un servicio, estilo Shodan, y su catálogo local de productos conocidos.

La huella es el MurmurHash3 x86 de 32 bits (con signo, como mmh3.hash) sobre el favicon pasado por
base64 con saltos de línea cada 76 caracteres: así lo calcula Shodan (http.favicon.hash) y lo que
se publica en bases como Censys/Shodan dumps. Se escribe a mano, sin paquetes de pip, como el DNS
de descubrimiento.py. El catálogo es un fichero JSON versionado (como credenciales.json), ampliable
a mano; una entrada mal formada se ignora, nunca rompe la carga.
"""

from __future__ import annotations

import base64
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import sys
import urllib.error
from urllib.parse import urljoin, urlsplit

from . import probador

RUTA = Path(__file__).resolve().parent / "datos" / "favicons.json"
_PUERTOS_POR_DEFECTO = {"http": 80, "https": 443}


def _mmh3_x86_32(datos: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 de 32 bits, con signo (igual que mmh3.hash por defecto). Implementación de referencia."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    longitud = len(datos)
    h1 = seed & 0xFFFFFFFF
    final = (longitud // 4) * 4
    for i in range(0, final, 4):
        k1 = datos[i] | (datos[i + 1] << 8) | (datos[i + 2] << 16) | (datos[i + 3] << 24)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF  # ROTL32(k1, 15)
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF  # ROTL32(h1, 13)
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF
    resto = longitud & 3
    k1 = 0
    if resto == 3:
        k1 ^= datos[final + 2] << 16
    if resto >= 2:
        k1 ^= datos[final + 1] << 8
    if resto >= 1:
        k1 ^= datos[final]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= longitud
    # fmix32: termina de esparcir los bits para que no queden patrones del contenido original
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1  # con signo, como mmh3.hash


def mmh3_shodan(contenido: bytes) -> int:
    """Huella de Shodan: MurmurHash3 x86 32-bit, con signo, del favicon en base64 a 76 columnas."""
    return _mmh3_x86_32(base64.encodebytes(contenido))


def sha256_hex(contenido: bytes) -> str:
    return hashlib.sha256(contenido).hexdigest()


def cargar(ruta: Path = RUTA) -> dict:
    """Catálogo indexado: {"mmh3": {valor: entrada}, "sha256": {valor: entrada}}.

    Lee el JSON {"entradas": [{"mmh3": int, "sha256": str?, "producto": str, ...}]}. Una entrada
    sin "producto" (texto no vacío) se ignora, igual que catalogo._filas con las credenciales.
    Si el fichero no se puede leer o no es JSON válido, avisa por stderr y devuelve el catálogo
    vacío: un catálogo roto no debe tumbar la detección de versión.
    """
    por_mmh3: dict[int, dict] = {}
    por_sha256: dict[str, dict] = {}
    try:
        datos = json.loads(Path(ruta).read_text("utf-8"))
        entradas = datos.get("entradas", [])
        if not isinstance(entradas, list):
            raise ValueError("«entradas» no es una lista")
    except (OSError, ValueError, AttributeError) as exc:  # JSONDecodeError y UnicodeDecodeError son ValueError
        print(f"Error del portal: no se pudo cargar el catálogo de favicons {ruta}: {exc}", file=sys.stderr)
        return {"mmh3": por_mmh3, "sha256": por_sha256}
    for entrada in entradas:
        if not isinstance(entrada, dict):
            continue
        producto = entrada.get("producto")
        if not isinstance(producto, str) or not producto:
            continue
        mmh3_valor = entrada.get("mmh3")
        if isinstance(mmh3_valor, int) and not isinstance(mmh3_valor, bool):
            por_mmh3[mmh3_valor] = entrada
        sha256_valor = entrada.get("sha256")
        if isinstance(sha256_valor, str) and sha256_valor:
            por_sha256[sha256_valor] = entrada
    return {"mmh3": por_mmh3, "sha256": por_sha256}


def identificar(contenido: bytes, catalogo: dict) -> dict | None:
    """La entrada del catálogo que case por mmh3 o, si no, por sha256; None si no hay ninguna."""
    entrada = catalogo.get("mmh3", {}).get(mmh3_shodan(contenido))
    if entrada is not None:
        return entrada
    return catalogo.get("sha256", {}).get(sha256_hex(contenido))


class _BuscadorIcono(HTMLParser):
    """El primer <link rel="...icon..." href="..."> del HTML; el resto del documento no importa."""
    def __init__(self):
        super().__init__()
        self.href = None

    def handle_starttag(self, tag, attrs):
        if self.href is not None or tag.lower() != "link":
            return
        attrs = dict(attrs)
        rel = (attrs.get("rel") or "").lower().split()
        if "icon" in rel and attrs.get("href"):
            self.href = attrs["href"]


def _extremo(url: str) -> tuple[str | None, int]:
    """(host, puerto) de una URL, con el puerto por defecto de su esquema si no lo trae explícito."""
    partes = urlsplit(url)
    return partes.hostname, partes.port or _PUERTOS_POR_DEFECTO.get(partes.scheme, 0)


def url_favicon(base_url: str, html: str) -> str | None:
    """URL del favicon del propio objetivo: el <link rel=icon> del HTML, o /favicon.ico si no hay.

    HTML es dato no confiable del objetivo: aquí solo se lee un atributo, nunca se ejecuta nada de
    su contenido. Devuelve None si la URL resuelta no queda en el mismo host:puerto que `base_url`
    (un href a otro dominio, por ejemplo un CDN, queda fuera de alcance y no se descarga).
    """
    buscador = _BuscadorIcono()
    buscador.feed(html or "")
    href = buscador.href
    url = urljoin(base_url, href) if href else urljoin(base_url, "/favicon.ico")
    if _extremo(url) != _extremo(base_url):
        return None
    return url


def descargar(url: str, timeout: float = 5, tope: int = 100_000) -> bytes | None:
    """Trae como mucho `tope` bytes de `url` con el opener de probador (sin proxy, sin verificar TLS,
    sin seguir redirecciones). None si falla la conexión, si el Content-Type no es de imagen o si
    el cuerpo supera `tope`: el favicon es dato no confiable y no debe colgar ni crecer sin límite.
    """
    try:
        with probador._OPENER.open(url, timeout=timeout) as respuesta:
            tipo = respuesta.headers.get("Content-Type", "")
            if "image" not in tipo.lower():
                return None
            contenido = respuesta.read(tope + 1)
    except (urllib.error.URLError, OSError, ValueError):
        return None
    if len(contenido) > tope:
        return None
    return contenido
