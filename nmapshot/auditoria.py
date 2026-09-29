"""Datos de auditoría en la base: importaciones de Nmap y lo que observaron."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid

from . import targets
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


def _audit_name(name) -> str:
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 120:
        raise ValueError("El nombre de la ficha debe tener entre 1 y 120 caracteres")
    return name.strip()


def _scope_rules(include, exclude) -> list[tuple[str, str, str]]:
    if not isinstance(include, str) or not isinstance(exclude, str) or len(include) + len(exclude) > 512_000:
        raise ValueError("Alcance inválido o demasiado largo")
    return ([("incluir", cidr, reason) for cidr, reason in targets.parse_scope_lines(include)] +
            [("excluir", cidr, reason) for cidr, reason in targets.parse_scope_lines(exclude)])


def create_audit(con: sqlite3.Connection, name, include, exclude="") -> str:
    """Nueva ficha de cliente con su alcance; todo o nada."""
    name, rules = _audit_name(name), _scope_rules(include, exclude)
    audit_id = uuid.uuid4().hex
    with con:
        con.execute("INSERT INTO auditoria (id, nombre, creada) VALUES (?, ?, ?)", (audit_id, name, now()))
        con.executemany("INSERT INTO alcance (auditoria_id, tipo, cidr, motivo) VALUES (?, ?, ?, ?)",
                        [(audit_id, *rule) for rule in rules])
    return audit_id


def update_audit(con: sqlite3.Connection, audit_id: str, name, include, exclude="") -> None:
    """Renombra y sustituye el alcance. No borra datos: solo cambia lo que se puede contactar."""
    name, rules = _audit_name(name), _scope_rules(include, exclude)
    with con:
        if not con.execute("UPDATE auditoria SET nombre = ? WHERE id = ?", (name, audit_id)).rowcount:
            raise FileNotFoundError("Ficha no encontrada")
        con.execute("DELETE FROM alcance WHERE auditoria_id = ?", (audit_id,))
        con.executemany("INSERT INTO alcance (auditoria_id, tipo, cidr, motivo) VALUES (?, ?, ?, ?)",
                        [(audit_id, *rule) for rule in rules])


def audits(con: sqlite3.Connection) -> list[dict]:
    """Fichas con su alcance y cuántas importaciones tienen, la más reciente primero."""
    result = []
    for row in con.execute("SELECT a.id, a.nombre, a.creada, (SELECT COUNT(*) FROM ejecucion e WHERE e.auditoria_id = a.id "
                           "AND e.tipo = 'importacion') AS ejecuciones FROM auditoria a ORDER BY a.creada DESC"):
        rules = con.execute("SELECT tipo, cidr, motivo FROM alcance WHERE auditoria_id = ? ORDER BY id", (row["id"],)).fetchall()
        result.append({"id": row["id"], "nombre": row["nombre"], "creada": row["creada"], "ejecuciones": row["ejecuciones"],
                       "incluir": [{"cidr": r["cidr"], "motivo": r["motivo"]} for r in rules if r["tipo"] == "incluir"],
                       "excluir": [{"cidr": r["cidr"], "motivo": r["motivo"]} for r in rules if r["tipo"] == "excluir"]})
    return result


def audit_exists(con: sqlite3.Connection, audit_id: str) -> bool:
    return con.execute("SELECT 1 FROM auditoria WHERE id = ?", (audit_id,)).fetchone() is not None


def audit_of(con: sqlite3.Connection, execution_id: str) -> str | None:
    row = con.execute("SELECT auditoria_id FROM ejecucion WHERE id = ?", (execution_id,)).fetchone()
    return row["auditoria_id"] if row else None


def audits_by_execution(con: sqlite3.Connection) -> dict[str, str]:
    return {row["id"]: row["auditoria_id"] for row in con.execute("SELECT id, auditoria_id FROM ejecucion")}


def scope(con: sqlite3.Connection, audit_id: str) -> targets.Scope:
    rules = con.execute("SELECT tipo, cidr FROM alcance WHERE auditoria_id = ?", (audit_id,)).fetchall()
    return targets.Scope([r["cidr"] for r in rules if r["tipo"] == "incluir"],
                         [r["cidr"] for r in rules if r["tipo"] == "excluir"])


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
