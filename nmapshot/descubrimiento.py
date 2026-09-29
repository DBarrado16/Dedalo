"""Descubrimiento DNS sobre el alcance de una ficha: nombres inversos y servidores DNS.

Dos modos, equivalentes a los de `nslookup IP` y `nslookup dominio IP`:

- `nombres`: pregunta al DNS del equipo cómo se llama cada IP (PTR). No conecta
  con los objetivos; habla solo con el resolvedor del sistema.
- `servidores`: pregunta a cada IP por un dominio. Sí conecta con los objetivos
  (UDP 53), así que solo se ejecuta sobre direcciones en alcance.

Sin dependencias externas: el resolvedor del sistema para el modo `nombres` y una
consulta DNS mínima construida a mano para el modo `servidores`.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ipaddress
import secrets
import socket
import struct
import threading
import time

from . import targets

MODES = ("nombres", "servidores")
MAX_ADDRESSES = 65_536
# Códigos de respuesta DNS que interesa distinguir en el informe.
RCODES = {0: "correcta", 1: "error de formato", 2: "fallo del servidor",
          3: "dominio inexistente", 4: "no implementado", 5: "consulta rechazada"}
OUT_OF_SCOPE = {targets.Scope.EXCLUDED: "Excluida del alcance: no se consulta",
                targets.Scope.OUT: "Fuera de alcance: no se consulta"}


def expand(networks: list[str], limit: int = MAX_ADDRESSES) -> list[str]:
    """Rangos CIDR -> direcciones individuales, en orden y sin duplicados."""
    nets = [ipaddress.ip_network(item, strict=False) for item in networks if str(item).strip()]
    total = sum(net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses for net in nets)
    if total > limit:
        raise ValueError(f"El descubrimiento admite hasta {limit:,} direcciones y este alcance tiene {total:,}. "
                         "Acota los rangos autorizados de la ficha.".replace(",", "."))
    found: dict[str, None] = {}
    for net in nets:
        for address in (net.hosts() if net.num_addresses > 2 else net):
            found[str(address)] = None
    return list(found)


def reverse_name(ip: str) -> tuple[str, str]:
    """(nombre, error) del DNS del equipo para una IP. Sin nombre no es un error."""
    try:
        return socket.gethostbyaddr(ip)[0], ""
    except (socket.herror, socket.gaierror):
        return "", ""
    except OSError as exc:
        return "", str(exc)


def query_packet(domain: str, query_id: int) -> bytes:
    """Consulta DNS mínima de tipo A, sin recursión forzada de más."""
    try:
        labels = [part for part in domain.encode("idna").split(b".") if part]
    except UnicodeError:
        labels = []
    if not labels or any(len(part) > 63 for part in labels):
        raise ValueError(f"Dominio inválido: {domain!r}")
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)  # RD=1, una pregunta
    question = b"".join(bytes([len(part)]) + part for part in labels) + b"\0"
    return header + question + struct.pack(">HH", 1, 1)  # tipo A, clase IN


def dns_server(ip: str, domain: str, timeout: float = 2.0, port: int = 53) -> tuple[bool, str, str]:
    """(responde, detalle, error) al preguntar a IP:53 por un dominio."""
    query_id = secrets.randbelow(0x10000)
    packet = query_packet(domain, query_id)
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            # Socket conectado: el sistema descarta respuestas de otra IP o puerto,
            # así que una respuesta ajena nunca se atribuye a esta dirección.
            sock.connect((ip, port))
            sock.send(packet)
            # Descartar respuestas que no correspondan a esta consulta, sin pasar del límite.
            deadline = time.monotonic() + timeout
            while (remaining := deadline - time.monotonic()) > 0:
                sock.settimeout(remaining)
                data = sock.recv(4096)
                if len(data) >= 12 and data[:2] == packet[:2] and data[2] & 0x80:
                    flags, _questions, answers = struct.unpack(">HHH", data[2:8])
                    code = flags & 0x0F
                    detail = RCODES.get(code, f"código {code}")
                    return True, f"{detail}; {answers} respuesta(s)", ""
    except (socket.timeout, ConnectionResetError, ConnectionRefusedError):
        # Sin respuesta, o puerto cerrado (Windows: reset; Linux: refused): no es un
        # servidor DNS, y no es un fallo.
        return False, "", ""
    except OSError as exc:
        return False, "", str(exc)
    return False, "", ""


class _Pacer:
    """Separa el inicio de cada consulta para no saturar al servidor DNS."""

    def __init__(self, delay: float):
        self.delay, self.lock, self.next = delay, threading.Lock(), 0.0

    def wait(self) -> None:
        if self.delay <= 0:
            return
        with self.lock:
            now = time.monotonic()
            pause = max(0.0, self.next - now)
            self.next = max(now, self.next) + self.delay
        if pause:
            time.sleep(pause)


def sweep(addresses: list[str], mode: str, domain: str = "", *, scope=None, timeout: float = 2.0,
          delay: float = 0.0, workers: int = 4, stop=None, progress=None) -> list[dict]:
    """Recorre las direcciones en uno de los dos modos, en el orden recibido.

    `scope` (un targets.Scope o cualquier objeto con `status(ip)`) se consulta
    justo antes de cada consulta (docs/CONTRATOS.md 0.3): lo que no está en
    alcance se devuelve con el motivo y sin consultar. Es obligatorio en el modo
    `servidores`, que conecta con los objetivos.

    `stop()` devuelve True para cancelar entre consultas y `progress(hechas, total)`
    informa del avance. Las direcciones no consultadas por cancelación no aparecen.
    """
    if mode not in MODES:
        raise ValueError(f"Modo de descubrimiento desconocido: {mode!r}")
    if mode == "servidores":
        if scope is None:
            raise ValueError("El modo «servidores» conecta con los objetivos y necesita el alcance de la ficha")
        query_packet(domain, 0)  # valida el dominio antes de abrir ningún socket
    pacer = _Pacer(delay)
    done = threading.Lock()
    state = {"hechas": 0}

    def run(ip):
        if stop and stop():
            return None
        pacer.wait()
        if stop and stop():
            return None
        status = scope.status(ip) if scope is not None else targets.Scope.IN
        if status != targets.Scope.IN:
            row = {"ip": ip, "encontrado": False, "nombre": "", "detalle": "", "error": OUT_OF_SCOPE[status]}
        elif mode == "nombres":
            name, error = reverse_name(ip)
            row = {"ip": ip, "encontrado": bool(name), "nombre": name, "detalle": "", "error": error}
        else:
            answered, detail, error = dns_server(ip, domain, timeout)
            row = {"ip": ip, "encontrado": answered, "nombre": "", "detalle": detail, "error": error}
        with done:
            state["hechas"] += 1
            if progress:
                progress(state["hechas"], len(addresses))
        return row

    with ThreadPoolExecutor(max_workers=max(1, min(workers, 32))) as pool:
        return [row for row in pool.map(run, addresses) if row is not None]
