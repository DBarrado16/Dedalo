"""Lectura de la salida de nmap: XML (-oX), grepable (-oG) y normal (-oN).

Todas las variantes se reducen a lo mismo: por cada host, la lista de puertos
TCP y UDP abiertos con el servicio que nmap le haya puesto. El formato se detecta
por el contenido, no por la extensión.
"""

from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


@dataclass
class Port:
    number: int
    service: str = ""
    tunnel: str = ""  # "ssl" cuando nmap detecta TLS delante del servicio
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: list[str] = field(default_factory=list)
    scripts: list[dict] = field(default_factory=list)


@dataclass
class Host:
    ip: str
    hostnames: list[str] = field(default_factory=list)
    ports: dict[int, Port] = field(default_factory=dict)
    udp_ports: dict[int, Port] = field(default_factory=dict)
    scripts: list[dict] = field(default_factory=list)


def _scripts(node):
    return [{"id": item.get("id", ""), "output": item.get("output", "")}
            for item in node.findall("script")]


def parse_file(path: str) -> list[Host]:
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        text = fh.read()
    return parse_text(text)


def parse_text(text: str) -> list[Host]:
    text = text.lstrip("\ufeff")
    head = text.lstrip()[:500]
    if head.startswith("<?xml") or "<nmaprun" in head:
        return _parse_xml(text)
    if re.search(r"^Host: \S+", text, re.MULTILINE):
        return _parse_grepable(text)
    if "Nmap scan report for " in text or re.search(r"(?:# )?Nmap (?:done|\d)", text):
        return _parse_normal(text)
    raise ValueError("No se reconoce una salida de nmap (XML, grepable o normal)")


def _host(hosts: dict[str, Host], ip: str) -> Host:
    ip = str(ipaddress.ip_address(ip))
    if ip not in hosts:
        hosts[ip] = Host(ip=ip)
    return hosts[ip]


def _port_number(value: str) -> int:
    number = int(value)
    if not 1 <= number <= 65535:
        raise ValueError(f"Puerto fuera de rango: {value}")
    return number


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _parse_xml(text: str) -> list[Host]:
    root = ET.fromstring(text)
    if root.tag != "nmaprun":
        raise ValueError("El XML no es un documento de nmap")
    hosts: dict[str, Host] = {}

    for node in root.iter("host"):
        status = node.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ip = None
        for addr in node.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr")
                break
        if not ip:
            continue

        host = _host(hosts, ip)
        host.scripts = _scripts(node.find("hostscript")) if node.find("hostscript") is not None else []
        for hn in node.findall("hostnames/hostname"):
            name = hn.get("name")
            if name and name not in host.hostnames:
                host.hostnames.append(name)

        for p in node.findall("ports/port"):
            protocol = p.get("protocol")
            if protocol not in ("tcp", "udp"):
                continue
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            number = _port_number(p.get("portid", ""))
            ports = host.ports if protocol == "tcp" else host.udp_ports
            ports[number] = Port(
                number=number,
                service=(svc.get("name", "") if svc is not None else ""),
                tunnel=(svc.get("tunnel", "") if svc is not None else ""),
                product=(svc.get("product", "") if svc is not None else ""),
                version=(svc.get("version", "") if svc is not None else ""),
                extrainfo=(svc.get("extrainfo", "") if svc is not None else ""),
                cpe=([c.text for c in svc.findall("cpe") if c.text] if svc is not None else []),
                scripts=_scripts(p),
            )

    return list(hosts.values())


# Host: 10.0.0.5 (web01.local)	Ports: 80/open/tcp//http//nginx/, 443/open/tcp//ssl|http///
_GNMAP_HOST = re.compile(r"^Host: (\S+) \(([^)]*)\)")
_GNMAP_PORTS = re.compile(r"Ports: (.*?)(?:\t|$)")


def _parse_grepable(text: str) -> list[Host]:
    hosts: dict[str, Host] = {}

    for line in text.splitlines():
        m = _GNMAP_HOST.match(line)
        if not m:
            continue
        ip, name = m.group(1), m.group(2)
        if "Status: Down" in line:
            continue

        host = _host(hosts, ip)
        if name and name not in host.hostnames:
            host.hostnames.append(name)

        pm = _GNMAP_PORTS.search(line)
        if not pm:
            continue
        for entry in pm.group(1).split(", "):
            parts = entry.strip().split("/")
            if len(parts) < 7 or parts[1] != "open" or parts[2] not in ("tcp", "udp"):
                continue
            service = parts[4]
            tunnel = ""
            if "|" in service:  # ssl|http
                tunnel, service = service.split("|", 1)
            number = _port_number(parts[0])
            ports = host.ports if parts[2] == "tcp" else host.udp_ports
            ports[number] = Port(number=number, service=service, tunnel=tunnel, product=parts[6])

    return list(hosts.values())


# Nmap scan report for web01.local (10.0.0.5)  /  Nmap scan report for 10.0.0.5
_NORMAL_HOST = re.compile(r"^Nmap scan report for (?:(\S+) \(([^)]+)\)|(\S+))\s*$")
# 443/tcp open  ssl/http  nginx 1.18
_NORMAL_PORT = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)?\s*(.*)$")


def _parse_normal(text: str) -> list[Host]:
    hosts: dict[str, Host] = {}
    current: Host | None = None

    for line in text.splitlines():
        m = _NORMAL_HOST.match(line)
        if m:
            if m.group(2):
                name, ip = m.group(1), m.group(2)
            else:
                name, ip = "", m.group(3)
            if not _is_ip(ip):
                current = None
                continue
            current = _host(hosts, ip)
            if name and name not in current.hostnames:
                current.hostnames.append(name)
            continue

        if current is None:
            continue
        if line.startswith("Host is down"):
            hosts.pop(current.ip, None)
            current = None
            continue
        pm = _NORMAL_PORT.match(line)
        if not pm:
            continue
        service = pm.group(3) or ""
        tunnel = ""
        if "/" in service:  # ssl/http
            tunnel, service = service.split("/", 1)
        number = _port_number(pm.group(1))
        ports = current.ports if pm.group(2) == "tcp" else current.udp_ports
        ports[number] = Port(
            number=number, service=service.rstrip("?"), tunnel=tunnel, product=pm.group(4).strip()
        )

    return list(hosts.values())


def merge(host_lists: list[list[Host]]) -> list[Host]:
    """Une varios escaneos; un mismo host acumula los puertos de todos."""
    hosts: dict[str, Host] = {}
    for lst in host_lists:
        for h in lst:
            target = _host(hosts, h.ip)
            for name in h.hostnames:
                if name not in target.hostnames:
                    target.hostnames.append(name)
            target.ports.update(h.ports)
            target.udp_ports.update(h.udp_ports)
            for script in h.scripts:
                if script not in target.scripts:
                    target.scripts.append(script)
    return list(hosts.values())
