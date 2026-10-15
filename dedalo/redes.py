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
_IPV4 = re.compile(r"IPv4.*?:\s*(\d{1,3}(?:\.\d{1,3}){3})")
_MASK = re.compile(r"(?:Subnet Mask|M[aá]scara).*?:\s*(\d{1,3}(?:\.\d{1,3}){3})")


def _red(direccion: str, prefijo) -> ipaddress._BaseNetwork | None:
    try:
        return ipaddress.ip_network(f"{direccion}/{prefijo}", strict=False)
    except ValueError:
        return None


def cidrs(texto: str) -> list[str]:
    """CIDR de las interfaces, de la salida de ipconfig o de ip addr; sin loopback ni link-local."""
    nets = set()
    for direccion, prefijo in _CIDR.findall(texto):          # ip -o addr: 10.30.4.7/24
        nets.add(_red(direccion, prefijo))
    for direccion, mask in zip(_IPV4.findall(texto), _MASK.findall(texto)):  # ipconfig: IPv4 + máscara
        nets.add(_red(direccion, mask))
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
