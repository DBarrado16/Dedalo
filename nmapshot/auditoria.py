"""Datos de auditoría en la base: importaciones de Nmap y lo que observaron."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid

from .parser import Host, Port

IMPORTED = "Importadas"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_audit(con: sqlite3.Connection) -> str:
    """Auditoría de las ejecuciones del portal que no eligen otra."""
    row = con.execute("SELECT id FROM auditoria WHERE nombre = ? ORDER BY creada LIMIT 1", (IMPORTED,)).fetchone()
    if row:
        return row["id"]
    audit_id = uuid.uuid4().hex
    with con:
        con.execute("INSERT INTO auditoria (id, nombre, creada, notas) VALUES (?, ?, ?, ?)",
                    (audit_id, IMPORTED, now(), "Ejecuciones del portal sin una auditoría elegida."))
    return audit_id


def has_execution(con: sqlite3.Connection, execution_id: str) -> bool:
    return con.execute("SELECT 1 FROM ejecucion WHERE id = ?", (execution_id,)).fetchone() is not None


def _id(con, select, insert, values):
    con.execute(insert, values)
    return con.execute(select, values).fetchone()[0]


def import_nmap(con: sqlite3.Connection, audit_id: str, execution_id: str, name: str,
                hosts: list[Host], files: list[Path], root: Path, created: str | None = None) -> None:
    """Registra una importación completa en una transacción: todo o nada.

    `hosts` ya viene unido con parser.merge; `files` son los Nmap originales
    guardados dentro de `root`, que quedan como evidencia con su huella.
    """
    stamp = now()
    with con:
        con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, nombre, estado, creada, iniciada, terminada) "
                    "VALUES (?, ?, 'importacion', ?, 'completa', ?, ?, ?)",
                    (execution_id, audit_id, name, created or stamp, stamp, stamp))
        for path in files:
            data = Path(path).read_bytes()
            con.execute("INSERT INTO evidencia (ejecucion_id, tipo, ruta, sha256, bytes, creada) VALUES (?, 'nmap', ?, ?, ?, ?)",
                        (execution_id, Path(path).resolve().relative_to(Path(root).resolve()).as_posix(),
                         hashlib.sha256(data).hexdigest(), len(data), stamp))
        for host in hosts:
            asset = _id(con, "SELECT id FROM activo WHERE auditoria_id = ? AND ip = ?",
                        "INSERT INTO activo (auditoria_id, ip) VALUES (?, ?) ON CONFLICT DO NOTHING", (audit_id, host.ip))
            con.execute("INSERT INTO observacion_activo (ejecucion_id, activo_id, nombres, scripts) VALUES (?, ?, ?, ?)",
                        (execution_id, asset, json.dumps(host.hostnames, ensure_ascii=False), json.dumps(host.scripts, ensure_ascii=False)))
            for protocol, ports in (("tcp", host.ports), ("udp", host.udp_ports)):
                for number, port in ports.items():
                    service = _id(con, "SELECT id FROM servicio WHERE activo_id = ? AND protocolo = ? AND puerto = ?",
                                  "INSERT INTO servicio (activo_id, protocolo, puerto) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
                                  (asset, protocol, number))
                    con.execute("INSERT INTO observacion (ejecucion_id, servicio_id, nombre, tunel, producto, version, detalle, cpe, scripts) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                (execution_id, service, port.service, port.tunnel, port.product, port.version, port.extrainfo,
                                 json.dumps(port.cpe, ensure_ascii=False), json.dumps(port.scripts, ensure_ascii=False)))


def observed_hosts(con: sqlite3.Connection, execution_id: str) -> list[Host]:
    """Los hosts tal como los vio una ejecución, en el formato del parser."""
    hosts = {}
    for row in con.execute("SELECT a.id, a.ip, o.nombres, o.scripts FROM observacion_activo o "
                           "JOIN activo a ON a.id = o.activo_id WHERE o.ejecucion_id = ?", (execution_id,)):
        hosts[row["id"]] = Host(row["ip"], hostnames=json.loads(row["nombres"]), scripts=json.loads(row["scripts"]))
    for row in con.execute("SELECT s.activo_id, s.protocolo, s.puerto, o.* FROM observacion o "
                           "JOIN servicio s ON s.id = o.servicio_id WHERE o.ejecucion_id = ?", (execution_id,)):
        port = Port(row["puerto"], service=row["nombre"], tunnel=row["tunel"], product=row["producto"],
                    version=row["version"], extrainfo=row["detalle"], cpe=json.loads(row["cpe"]), scripts=json.loads(row["scripts"]))
        host = hosts[row["activo_id"]]
        (host.ports if row["protocolo"] == "tcp" else host.udp_ports)[row["puerto"]] = port
    return list(hosts.values())


def delete_execution(con: sqlite3.Connection, execution_id: str) -> None:
    """Borra una ejecución y los activos y servicios que solo ella había visto."""
    with con:
        con.execute("DELETE FROM ejecucion WHERE id = ?", (execution_id,))
        con.execute("DELETE FROM servicio WHERE NOT EXISTS (SELECT 1 FROM observacion WHERE servicio_id = servicio.id) "
                    "AND NOT EXISTS (SELECT 1 FROM captura WHERE servicio_id = servicio.id)")
        con.execute("DELETE FROM activo WHERE NOT EXISTS (SELECT 1 FROM observacion_activo WHERE activo_id = activo.id) "
                    "AND NOT EXISTS (SELECT 1 FROM servicio WHERE activo_id = activo.id)")
