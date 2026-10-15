"""Detectar las subredes de las interfaces del propio equipo, para proponerlas como alcance.

Solo mira las interfaces locales (lee ipconfig / ip addr); no conecta con ningún objetivo.
Es una sugerencia: rellena los rangos de la ficha, que el usuario revisa.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys

_CIDR = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{2,}:[0-9a-fA-F:]*)/(\d{1,3})\b")
_IPV4 = re.compile(r"IPv4\D{0,40}?(\d{1,3}(?:\.\d{1,3}){3})")   # «IPv4» es ASCII: nunca se rompe
_DOTTED = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


def _red(direccion: str, prefijo) -> ipaddress._BaseNetwork | None:
    try:
        return ipaddress.ip_network(f"{direccion}/{prefijo}", strict=False)
    except ValueError:
        return None


def _es_mascara(valor: str) -> bool:
    """¿Es `valor` una máscara de red (unos seguidos de ceros, como 255.255.255.0)?"""
    try:
        n = int(ipaddress.IPv4Address(valor))
    except ipaddress.AddressValueError:
        return False
    complemento = n ^ 0xFFFFFFFF
    return n != 0 and (complemento & (complemento + 1)) == 0


def cidrs(texto: str) -> list[str]:
    """CIDR de las interfaces, de la salida de ipconfig o de ip addr; sin loopback ni link-local.

    En ipconfig cada «IPv4» se empareja con la siguiente máscara reconocida por su VALOR, no por su
    etiqueta: así funciona en cualquier idioma y aunque la consola devuelva los acentos rotos.
    """
    nets = set()
    for direccion, prefijo in _CIDR.findall(texto):          # ip -o addr: 10.30.4.7/24
        nets.add(_red(direccion, prefijo))
    mascaras = [(m.start(), m.group()) for m in _DOTTED.finditer(texto) if _es_mascara(m.group())]
    for ip in _IPV4.finditer(texto):                         # ipconfig: IPv4 + su máscara, por valor
        siguiente = next((valor for pos, valor in mascaras if pos >= ip.end()), None)
        if siguiente:
            nets.add(_red(ip.group(1), siguiente))
    nets.discard(None)
    return [str(n) for n in sorted(nets, key=lambda n: (n.version, int(n.network_address)))
            if not (n.is_loopback or n.is_link_local)]


def _ejecutar() -> str:
    comando = ["ipconfig"] if sys.platform.startswith("win") else ["ip", "-o", "addr"]
    return subprocess.run(comando, capture_output=True, text=True, timeout=10,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout


def detectar() -> list[str]:
    """Las subredes del equipo, o lista vacía si no se pudieron leer (se teclea a mano)."""
    try:
        return cidrs(_ejecutar())
    except (OSError, ValueError, subprocess.SubprocessError):
        return []
