"""De hosts de nmap a URLs que capturar, y de IPs a subredes."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .parser import Host

# Puerto -> esquema. Por defecto, lo que se pidió: 80 por http y 443 por https.
DEFAULT_PORTS = {80: "http", 443: "https"}


@dataclass
class Target:
    ip: str
    port: int
    scheme: str
    hostnames: list[str]
    service: str = ""
    product: str = ""

    @property
    def url(self) -> str:
        host = f"[{self.ip}]" if ":" in self.ip else self.ip
        default = (self.scheme == "http" and self.port == 80) or (self.scheme == "https" and self.port == 443)
        return f"{self.scheme}://{host}/" if default else f"{self.scheme}://{host}:{self.port}/"


def parse_port_map(spec: str) -> dict[int, str]:
    """'8080=http,8443=https' -> {8080: 'http', 8443: 'https'}"""
    result: dict[int, str] = {}
    for item in filter(None, (s.strip() for s in spec.split(","))):
        if "=" not in item:
            raise ValueError(f"'{item}': se esperaba PUERTO=http o PUERTO=https")
        port, scheme = item.split("=", 1)
        scheme = scheme.strip().lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"'{item}': el esquema tiene que ser http o https")
        number = int(port)
        if not 1 <= number <= 65535:
            raise ValueError(f"'{item}': el puerto debe estar entre 1 y 65535")
        result[number] = scheme
    return result


def _scheme_from_service(service: str, tunnel: str) -> str | None:
    """Esquema según lo que detectó nmap (-sV), o None si no parece web."""
    s = service.lower()
    if "http" not in s:
        return None
    if tunnel == "ssl" or s in ("https", "https-alt", "ssl/http"):
        return "https"
    return "http"


def select_targets(hosts: list[Host], port_map: dict[int, str], by_service: bool = False) -> list[Target]:
    targets: list[Target] = []
    for h in hosts:
        for number, port in sorted(h.ports.items()):
            scheme = port_map.get(number)
            if scheme is None and by_service:
                scheme = _scheme_from_service(port.service, port.tunnel)
            if scheme is None:
                continue
            targets.append(
                Target(
                    ip=h.ip,
                    port=number,
                    scheme=scheme,
                    hostnames=list(h.hostnames),
                    service=(f"{port.tunnel}/{port.service}" if port.tunnel else port.service),
                    product=port.product,
                )
            )
    return targets


OUT_OF_RANGE = "fuera_de_rango"


class SubnetResolver:
    """Coloca cada IP en dos niveles: el rango del cliente que la contiene
    (el más específico de la lista, p. ej. un /17) y, dentro de él, su /24.

    Una IP que no cae en ningún rango va a OUT_OF_RANGE, con su /24 igual.
    Si un rango de la lista ya es más pequeño que el corte (p. ej. un /26),
    no se trocea: la subred es el propio rango."""

    def __init__(self, ranges: list[str] | None = None, cut_v4: int = 24, cut_v6: int = 64):
        self.cut_v4 = cut_v4
        self.cut_v6 = cut_v6
        nets = [ipaddress.ip_network(n.strip(), strict=False) for n in (ranges or []) if n.strip()]
        # Los más específicos primero, para que un /20 gane al /17 que lo contiene.
        self.ranges = sorted(nets, key=lambda n: n.prefixlen, reverse=True)

    def resolve(self, ip: str) -> tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]:
        addr = ipaddress.ip_address(ip)
        cut = self.cut_v4 if addr.version == 4 else self.cut_v6
        for net in self.ranges:
            if net.version == addr.version and addr in net:
                if net.prefixlen >= cut:
                    return str(net), net
                return str(net), ipaddress.ip_network(f"{ip}/{cut}", strict=False)
        return OUT_OF_RANGE, ipaddress.ip_network(f"{ip}/{cut}", strict=False)


def read_networks_file(path: str) -> list[str]:
    with open(path, encoding="utf-8-sig") as fh:
        return [line.split("#", 1)[0].strip() for line in fh if line.split("#", 1)[0].strip()]
