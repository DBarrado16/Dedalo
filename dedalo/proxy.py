"""Proxy local de alcance para el navegador de la captura (docs/CONTRATOS.md 0.3).

Este módulo trae la regla de paso y las fuentes de alcance; el servidor del proxy
se apoya en ellas para decidir, justo antes de conectar, si una IP se contacta."""

from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path

from . import targets

EXCLUIDA = "excluida"
FUERA = "fuera_de_alcance"
ILEGIBLE = "alcance_ilegible"

# Espera total máxima ante un alcance vivo a medias de escribir o reemplazar.
_REINTENTO_TOTAL = 0.2
_REINTENTO_PAUSA = 0.02


def decidir(ip: str, alcance: targets.Scope | None) -> str | None:
    """Motivo por el que NO se contacta con `ip`, o None si pasa.

    Orden: excluida corta; en alcance pasa; una IP pública pasa; el resto corta.
    Sin alcance legible no pasa nada, tampoco lo público (falla en cerrado)."""
    if alcance is None:
        return ILEGIBLE
    estado = alcance.status(ip)
    if estado == alcance.EXCLUDED:
        return EXCLUIDA
    if estado == alcance.IN:
        return None
    direccion = ipaddress.ip_address(ip)
    # ::ffff:a.b.c.d llega al mismo equipo que a.b.c.d: se juzga como IPv4.
    direccion = getattr(direccion, "ipv4_mapped", None) or direccion
    return None if direccion.is_global else FUERA


def elegir_ip(direcciones: list[str], alcance: targets.Scope | None) -> tuple[str | None, str | None]:
    """Primera IP que pasa la regla y, si ninguna, el motivo de la primera (None si no hay ninguna)."""
    primer_motivo = None
    for ip in direcciones:
        motivo = decidir(ip, alcance)
        if motivo is None:
            return ip, None
        if primer_motivo is None:
            primer_motivo = motivo
    return None, primer_motivo


def alcance_de_consola(ips_objetivo: list[str], rangos: list[str], solo_rangos: bool,
                       excluidos: list[str]) -> targets.Scope:
    """Alcance de una captura lanzada por consola: sus IP objetivo (como /32 o /128),
    más los rangos si se pidió limitarse a ellos, menos lo excluido."""
    incluir = [str(ipaddress.ip_network(ip)) for ip in ips_objetivo]
    if solo_rangos:
        incluir += list(rangos)
    return targets.Scope(incluir, list(excluidos))


class AlcanceFijo:
    """Alcance que no cambia durante la captura."""

    def __init__(self, scope: targets.Scope):
        self._scope = scope

    def actual(self) -> targets.Scope:
        return self._scope


class AlcanceVivo:
    """Alcance vigente leído de un fichero (el de `web.write_live_scope`), que se relee si cambia."""

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._firma = None
        self._scope = None

    def actual(self) -> targets.Scope | None:
        """El alcance vigente, o None si el fichero no se puede leer (entonces se corta todo)."""
        limite = time.monotonic() + _REINTENTO_TOTAL
        while True:
            try:
                estado = self._path.stat()
                firma = (estado.st_mtime_ns, estado.st_size)
                if firma != self._firma or self._scope is None:
                    datos = json.loads(self._path.read_text(encoding="utf-8"))
                    self._scope = targets.Scope(datos["incluir"], datos["excluir"])
                    self._firma = firma
                return self._scope
            except (OSError, ValueError, KeyError, TypeError):
                # Lo último leído ya no vale: si sigue ilegible, no se contacta con nadie.
                self._firma = None
                self._scope = None
                if time.monotonic() >= limite:
                    return None
                time.sleep(_REINTENTO_PAUSA)
