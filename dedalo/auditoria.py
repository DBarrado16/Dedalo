"""Datos de auditoría en la base: importaciones de Nmap y lo que observaron."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid

from . import report, targets
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
                hosts: list[Host], files: list[Path], root: Path, created: str | None = None,
                options: dict | None = None) -> None:
    """Registra una importación completa en una transacción: todo o nada.

    `hosts` ya viene unido con parser.merge; `files` son los Nmap originales
    guardados dentro de `root`, que quedan como evidencia con su huella.
    `options` guarda lo que el portal necesita de la ejecución (ver portal_options).
    """
    stamp = now()
    with con:
        con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, nombre, estado, opciones, creada, iniciada, terminada) "
                    "VALUES (?, ?, 'importacion', ?, 'completa', ?, ?, ?, ?)",
                    (execution_id, audit_id, name, json.dumps(options or {}, ensure_ascii=False),
                     created or stamp, stamp, stamp))
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


FINAL = {"completa", "parcial", "error", "cancelada", "interrumpida"}


def _service_id(con: sqlite3.Connection, audit_id: str, ip: str, port: int) -> int:
    row = con.execute("SELECT s.id FROM servicio s JOIN activo a ON a.id = s.activo_id "
                      "WHERE a.auditoria_id = ? AND a.ip = ? AND s.protocolo = 'tcp' AND s.puerto = ?",
                      (audit_id, ip, port)).fetchone()
    if row is None:
        raise ValueError(f"{ip}:{port}/tcp no está en el inventario de la ficha")
    return row[0]


def _derived(con: sqlite3.Connection, import_id: str, kind: str) -> sqlite3.Row | None:
    """La última ejecución de un tipo (captura, análisis) que salió de una importación, si la hay.

    «Última» por orden de inserción (rowid), no por `creada`: si el reloj del equipo retrocede,
    un análisis recién pedido no puede quedar por detrás del anterior.
    """
    return con.execute("SELECT id, estado, error FROM ejecucion WHERE origen_id = ? AND tipo = ? "
                       "ORDER BY rowid DESC LIMIT 1", (import_id, kind)).fetchone()


def capture_of(con: sqlite3.Connection, import_id: str) -> str | None:
    """La ejecución de captura que salió de una importación, si ya se lanzó."""
    row = _derived(con, import_id, "captura")
    return row["id"] if row else None


def start_capture(con: sqlite3.Connection, import_id: str, options: dict, groups: list[dict],
                  created: str | None = None) -> str:
    """Crea la ejecución de captura en cola, con cada URL planificada como pendiente.

    Cada URL queda ligada al servicio que la originó, así que desde cualquier
    imagen se llega al Nmap original (docs/MODELO_DATOS.md, Trazabilidad).
    """
    source = con.execute("SELECT auditoria_id, nombre FROM ejecucion WHERE id = ? AND tipo = 'importacion'",
                         (import_id,)).fetchone()
    if source is None:
        raise FileNotFoundError("Importación no encontrada")
    capture_id, stamp = uuid.uuid4().hex, created or now()
    with con:
        con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, origen_id, nombre, estado, opciones, creada) "
                    "VALUES (?, ?, 'captura', ?, ?, 'en_cola', ?, ?)",
                    (capture_id, source["auditoria_id"], import_id, source["nombre"],
                     json.dumps(options, ensure_ascii=False), stamp))
        con.executemany("INSERT INTO captura (ejecucion_id, servicio_id, url, estado) VALUES (?, ?, ?, 'pendiente')",
                        [(capture_id, _service_id(con, source["auditoria_id"], target["ip"], target["port"]), target["url"])
                         for group in groups for target in group["objetivos"]])
    return capture_id


def start_analysis(con: sqlite3.Connection, import_id: str, options: dict, created: str | None = None) -> str:
    """Crea en cola un análisis con IA de una importación.

    El último análisis completo se sigue mostrando hasta que este termine bien (finish_analysis);
    los intentos que fallaron o se interrumpieron ya no hacen falta.
    """
    source = con.execute("SELECT auditoria_id, nombre FROM ejecucion WHERE id = ? AND tipo = 'importacion'",
                         (import_id,)).fetchone()
    if source is None:
        raise FileNotFoundError("Importación no encontrada")
    analysis_id = uuid.uuid4().hex
    with con:
        con.execute("DELETE FROM ejecucion WHERE origen_id = ? AND tipo = 'analisis' AND estado <> 'completa'",
                    (import_id,))
        con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, origen_id, nombre, estado, opciones, creada) "
                    "VALUES (?, ?, 'analisis', ?, ?, 'en_cola', ?, ?)",
                    (analysis_id, source["auditoria_id"], import_id, source["nombre"],
                     json.dumps(options, ensure_ascii=False), created or now()))
    return analysis_id


def begin_analysis(con: sqlite3.Connection, analysis_id: str) -> bool:
    """Pasa a en curso un análisis que sigue en cola; False si entretanto se canceló o se sustituyó."""
    with con:
        return _set_state(con, analysis_id, "en_curso", only_from="en_cola")


def stop_analysis(con: sqlite3.Connection, import_id: str) -> str | None:
    """Cancela el análisis en cola de una importación o pide que pare el que está en curso.

    Devuelve el estado nuevo (`cancelada` o `deteniendo`), o None si no había ninguno en marcha.
    Uno en curso termina la pregunta del host actual; el hilo de la cola lo cierra después.
    """
    row = _derived(con, import_id, "analisis")
    if row is None:
        return None
    with con:
        if _set_state(con, row["id"], "cancelada", "Se canceló antes de empezar.", only_from="en_cola"):
            return "cancelada"
        if _set_state(con, row["id"], "deteniendo", only_from="en_curso"):
            return "deteniendo"
    return None


def analysis_status(con: sqlite3.Connection, import_id: str) -> dict | None:
    """Estado y error del último análisis pedido de una importación, o None si no se pidió ninguno."""
    row = _derived(con, import_id, "analisis")
    return {"estado": row["estado"], "error": row["error"]} if row else None


def close_interrupted_analyses(con: sqlite3.Connection) -> None:
    """Al arrancar, un análisis que seguía en cola, en curso o parando se quedó a medias al cerrarse el portal."""
    with con:
        con.execute("UPDATE ejecucion SET estado = 'interrumpida', terminada = ?, "
                    "error = 'El portal se cerró antes de terminar el análisis.' "
                    "WHERE tipo IN ('analisis', 'credenciales', 'descubrimiento', 'version') AND estado IN ('en_cola', 'en_curso', 'deteniendo')", (now(),))


def finish_analysis(con: sqlite3.Connection, analysis_id: str, rows: list[dict]) -> None:
    """Guarda lo que el análisis dijo de cada activo, lo da por completo y solo entonces sustituye al anterior.

    Todo en una transacción: si algo falla, sigue valiendo el último análisis completo.
    Una IP que no es de su ficha se ignora.
    """
    with con:
        for row in rows:
            con.execute("INSERT INTO prioridad (ejecucion_id, activo_id, orden, rol, nivel, motivo, siguiente) "
                        "SELECT e.id, a.id, ?, ?, ?, ?, ? FROM ejecucion e "
                        "JOIN activo a ON a.auditoria_id = e.auditoria_id AND a.ip = ? WHERE e.id = ?",
                        (row["orden"], row["rol"], row["nivel"], row["motivo"], row["siguiente"], row["ip"], analysis_id))
        _set_state(con, analysis_id, "completa")
        con.execute("DELETE FROM ejecucion WHERE tipo = 'analisis' AND id <> ? "
                    "AND origen_id = (SELECT origen_id FROM ejecucion WHERE id = ?)", (analysis_id, analysis_id))


def priorities(con: sqlite3.Connection, import_id: str) -> list[dict]:
    """Lo que dijo el análisis de una importación, en el orden en que se muestra.

    Solo los activos en el alcance vigente: si se excluye uno después, la exclusión gana.
    """
    rows = [dict(row) for row in con.execute(
        "SELECT a.ip, p.rol, p.nivel, p.motivo, p.siguiente FROM prioridad p "
        "JOIN ejecucion e ON e.id = p.ejecucion_id JOIN activo a ON a.id = p.activo_id "
        "WHERE e.origen_id = ? AND e.tipo = 'analisis' ORDER BY p.orden", (import_id,))]
    if not rows:
        return rows
    current = scope(con, audit_of(con, import_id))
    return [row for row in rows if current.status(row["ip"]) == current.IN]


def start_version(con: sqlite3.Connection, import_id: str, options: dict, created: str | None = None) -> str:
    """Crea en cola una detección de versión de una importación; la última completa se conserva hasta que esta termine bien."""
    source = con.execute("SELECT auditoria_id, nombre FROM ejecucion WHERE id = ? AND tipo = 'importacion'",
                         (import_id,)).fetchone()
    if source is None:
        raise FileNotFoundError("Importación no encontrada")
    version_id = uuid.uuid4().hex
    with con:
        con.execute("DELETE FROM ejecucion WHERE origen_id = ? AND tipo = 'version' AND estado <> 'completa'",
                    (import_id,))
        con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, origen_id, nombre, estado, opciones, creada) "
                    "VALUES (?, ?, 'version', ?, ?, 'en_cola', ?, ?)",
                    (version_id, source["auditoria_id"], import_id, source["nombre"],
                     json.dumps(options, ensure_ascii=False), created or now()))
    return version_id


def begin_version(con: sqlite3.Connection, version_id: str) -> bool:
    """Pasa a en curso una detección que sigue en cola; False si entretanto se canceló o se sustituyó."""
    with con:
        return _set_state(con, version_id, "en_curso", only_from="en_cola")


def stop_version(con: sqlite3.Connection, import_id: str) -> str | None:
    """Cancela la detección en cola de una importación o pide que pare la que está en curso."""
    row = _derived(con, import_id, "version")
    if row is None:
        return None
    with con:
        if _set_state(con, row["id"], "cancelada", "Se canceló antes de empezar.", only_from="en_cola"):
            return "cancelada"
        if _set_state(con, row["id"], "deteniendo", only_from="en_curso"):
            return "deteniendo"
    return None


def version_status(con: sqlite3.Connection, import_id: str) -> dict | None:
    """Estado y error de la última detección pedida de una importación, o None si no se pidió ninguna."""
    row = _derived(con, import_id, "version")
    return {"estado": row["estado"], "error": row["error"]} if row else None


def captured_services(con: sqlite3.Connection, capture_id: str) -> list[dict]:
    """Servicios capturados con éxito de una ejecución de captura: {servicio_id, url}."""
    return [{"servicio_id": row["servicio_id"], "url": row["url"]} for row in con.execute(
        "SELECT servicio_id, url FROM captura WHERE ejecucion_id = ? AND estado = 'capturada' ORDER BY id",
        (capture_id,))]


def finish_version(con: sqlite3.Connection, version_id: str, filas: list[dict]) -> None:
    """Guarda las lecturas de cada servicio, la da por completa y solo entonces sustituye a la anterior.

    Todo en una transacción: si algo falla, sigue valiendo la última detección completa. Un servicio
    que no es de su auditoría se ignora (el JOIN no casa).
    """
    with con:
        for fila in filas:
            con.execute("INSERT INTO deteccion (ejecucion_id, servicio_id, origen, producto, version, confianza, detalle) "
                        "SELECT e.id, s.id, ?, ?, ?, ?, ? FROM ejecucion e "
                        "JOIN servicio s ON s.id = ? JOIN activo a ON a.id = s.activo_id AND a.auditoria_id = e.auditoria_id "
                        "WHERE e.id = ?",
                        (fila["origen"], fila["producto"], fila.get("version", ""), fila.get("confianza"),
                         fila.get("detalle", ""), fila["servicio_id"], version_id))
        _set_state(con, version_id, "completa")
        con.execute("DELETE FROM ejecucion WHERE tipo = 'version' AND id <> ? "
                    "AND origen_id = (SELECT origen_id FROM ejecucion WHERE id = ?)", (version_id, version_id))


def detections(con: sqlite3.Connection, import_id: str) -> dict[int, list[dict]]:
    """Las lecturas de producto/versión de una importación, por servicio; solo activos en alcance vigente."""
    filas = [dict(row) for row in con.execute(
        "SELECT d.servicio_id, a.ip, d.origen, d.producto, d.version, d.confianza FROM deteccion d "
        "JOIN ejecucion e ON e.id = d.ejecucion_id JOIN servicio s ON s.id = d.servicio_id "
        "JOIN activo a ON a.id = s.activo_id WHERE e.origen_id = ? AND e.tipo = 'version' ORDER BY d.id", (import_id,))]
    if not filas:
        return {}
    current = scope(con, audit_of(con, import_id))
    salida: dict[int, list[dict]] = {}
    for fila in filas:
        if current.status(fila["ip"]) != current.IN:
            continue
        salida.setdefault(fila["servicio_id"], []).append(
            {"origen": fila["origen"], "producto": fila["producto"], "version": fila["version"],
             "confianza": fila["confianza"]})
    return salida


def start_credential_test(con, import_id: str, options: dict, created: str | None = None) -> str:
    """Crea en cola una prueba de credenciales; el último intento completo se conserva hasta que esta termine bien."""
    source = con.execute("SELECT auditoria_id, nombre FROM ejecucion WHERE id = ? AND tipo = 'importacion'",
                         (import_id,)).fetchone()
    if source is None:
        raise FileNotFoundError("Importación no encontrada")
    test_id = uuid.uuid4().hex
    with con:
        con.execute("DELETE FROM ejecucion WHERE origen_id = ? AND tipo = 'credenciales' AND estado <> 'completa'",
                    (import_id,))
        con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, origen_id, nombre, estado, opciones, creada) "
                    "VALUES (?, ?, 'credenciales', ?, ?, 'en_cola', ?, ?)",
                    (test_id, source["auditoria_id"], import_id, source["nombre"],
                     json.dumps(options, ensure_ascii=False), created or now()))
    return test_id


def begin_credential_test(con, test_id: str) -> bool:
    with con:
        return _set_state(con, test_id, "en_curso", only_from="en_cola")


def stop_credential_test(con, import_id: str) -> str | None:
    row = _derived(con, import_id, "credenciales")
    if row is None:
        return None
    with con:
        if _set_state(con, row["id"], "cancelada", "Se canceló antes de empezar.", only_from="en_cola"):
            return "cancelada"
        if _set_state(con, row["id"], "deteniendo", only_from="en_curso"):
            return "deteniendo"
    return None


def credential_status(con, import_id: str) -> dict | None:
    row = _derived(con, import_id, "credenciales")
    return {"estado": row["estado"], "error": row["error"]} if row else None


def finish_credential_test(con, test_id: str, rows: list[dict]) -> None:
    """Guarda los resultados, da la prueba por completa y solo entonces sustituye a la anterior, en una transacción."""
    with con:
        for row in rows:
            con.execute("INSERT INTO credencial_resultado (ejecucion_id, activo_id, orden, puerto, protocolo, servicio, "
                        "estado, usuario, clave, detalle) SELECT e.id, a.id, ?, ?, ?, ?, ?, ?, ?, ? FROM ejecucion e "
                        "JOIN activo a ON a.auditoria_id = e.auditoria_id AND a.ip = ? WHERE e.id = ?",
                        (row["orden"], row["puerto"], row["protocolo"], row["servicio"], row["estado"],
                         row["usuario"], row["clave"], row["detalle"], row["ip"], test_id))
        _set_state(con, test_id, "completa")
        con.execute("DELETE FROM ejecucion WHERE tipo = 'credenciales' AND id <> ? "
                    "AND origen_id = (SELECT origen_id FROM ejecucion WHERE id = ?)", (test_id, test_id))


def credential_results(con, import_id: str) -> list[dict]:
    """Lo que dieron las pruebas de una importación, en orden; solo activos en el alcance vigente."""
    rows = [dict(r) for r in con.execute(
        "SELECT a.ip, r.puerto, r.protocolo, r.servicio, r.estado, r.usuario, r.clave, r.detalle "
        "FROM credencial_resultado r JOIN ejecucion e ON e.id = r.ejecucion_id JOIN activo a ON a.id = r.activo_id "
        "WHERE e.origen_id = ? AND e.tipo = 'credenciales' ORDER BY r.orden", (import_id,))]
    if not rows:
        return rows
    current = scope(con, audit_of(con, import_id))
    return [r for r in rows if current.status(r["ip"]) == current.IN]


def start_discovery(con, import_id: str, options: dict, created: str | None = None) -> str:
    """Crea en cola un descubrimiento; el último completo se conserva hasta que este termine bien."""
    source = con.execute("SELECT auditoria_id, nombre FROM ejecucion WHERE id = ? AND tipo = 'importacion'",
                         (import_id,)).fetchone()
    if source is None:
        raise FileNotFoundError("Importación no encontrada")
    disc_id = uuid.uuid4().hex
    with con:
        con.execute("DELETE FROM ejecucion WHERE origen_id = ? AND tipo = 'descubrimiento' AND estado <> 'completa'",
                    (import_id,))
        con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, origen_id, nombre, estado, opciones, creada) "
                    "VALUES (?, ?, 'descubrimiento', ?, ?, 'en_cola', ?, ?)",
                    (disc_id, source["auditoria_id"], import_id, source["nombre"],
                     json.dumps(options, ensure_ascii=False), created or now()))
    return disc_id


def begin_discovery(con, disc_id: str) -> bool:
    with con:
        return _set_state(con, disc_id, "en_curso", only_from="en_cola")


def stop_discovery(con, import_id: str) -> str | None:
    row = _derived(con, import_id, "descubrimiento")
    if row is None:
        return None
    with con:
        if _set_state(con, row["id"], "cancelada", "Se canceló antes de empezar.", only_from="en_cola"):
            return "cancelada"
        if _set_state(con, row["id"], "deteniendo", only_from="en_curso"):
            return "deteniendo"
    return None


def discovery_status(con, import_id: str) -> dict | None:
    row = _derived(con, import_id, "descubrimiento")
    return {"estado": row["estado"], "error": row["error"]} if row else None


def finish_discovery(con, disc_id: str, rows: list[dict]) -> None:
    """Vuelca lo encontrado a observaciones (nombres y servidores DNS) y da el descubrimiento por completo."""
    audit_id = con.execute("SELECT auditoria_id FROM ejecucion WHERE id = ?", (disc_id,)).fetchone()["auditoria_id"]
    with con:
        for row in rows:
            if not row["encontrado"]:
                continue
            asset = _id(con, "SELECT id FROM activo WHERE auditoria_id = ? AND ip = ?",
                        "INSERT INTO activo (auditoria_id, ip) VALUES (?, ?) ON CONFLICT DO NOTHING", (audit_id, row["ip"]))
            if row["modo"] == "nombres":
                con.execute("INSERT INTO observacion_activo (ejecucion_id, activo_id, nombres, scripts) VALUES (?, ?, ?, '[]')",
                            (disc_id, asset, json.dumps([row["nombre"]], ensure_ascii=False)))
            else:
                service = _id(con, "SELECT id FROM servicio WHERE activo_id = ? AND protocolo = 'udp' AND puerto = 53",
                              "INSERT INTO servicio (activo_id, protocolo, puerto) VALUES (?, 'udp', 53) ON CONFLICT DO NOTHING",
                              (asset,))
                con.execute("INSERT INTO observacion (ejecucion_id, servicio_id, nombre, tunel, producto, version, detalle, cpe, scripts) "
                            "VALUES (?, ?, 'domain', '', '', '', ?, '[]', '[]')", (disc_id, service, row["detalle"]))
        _set_state(con, disc_id, "completa")
        con.execute("DELETE FROM ejecucion WHERE tipo = 'descubrimiento' AND id <> ? "
                    "AND origen_id = (SELECT origen_id FROM ejecucion WHERE id = ?)", (disc_id, disc_id))


def discovery_results(con, import_id: str) -> list[dict]:
    """Lo que encontró el descubrimiento de una importación; solo activos en el alcance vigente."""
    disc = _derived(con, import_id, "descubrimiento")
    if disc is None:
        return []
    nombres = con.execute("SELECT a.ip, o.nombres AS dato FROM observacion_activo o "
                          "JOIN activo a ON a.id = o.activo_id WHERE o.ejecucion_id = ?", (disc["id"],)).fetchall()
    servidores = con.execute("SELECT a.ip, o.detalle FROM observacion o JOIN servicio s ON s.id = o.servicio_id "
                             "JOIN activo a ON a.id = s.activo_id WHERE o.ejecucion_id = ?", (disc["id"],)).fetchall()
    filas = [{"ip": r["ip"], "modo": "nombres", "nombre": (nn[0] if (nn := json.loads(r["dato"])) else ""), "detalle": ""}
             for r in nombres]
    filas += [{"ip": r["ip"], "modo": "servidores", "nombre": "", "detalle": r["detalle"]} for r in servidores]
    current = scope(con, audit_of(con, import_id))
    return [f for f in filas if current.status(f["ip"]) == current.IN]


def _set_state(con: sqlite3.Connection, execution_id: str, state: str, error: str = "",
               only_from: str | None = None) -> bool:
    """Como set_state, dentro de la transacción de quien la llama.

    Con `only_from`, solo cambia si la ejecución sigue en ese estado (un UPDATE condicional:
    otro hilo que la cambie a la vez no queda pisado). Devuelve si cambió.
    """
    stamp = now()
    guard, values = ("", ()) if only_from is None else (" AND estado = ?", (only_from,))
    return con.execute("UPDATE ejecucion SET estado = ?, error = ?, "
                       "iniciada = CASE WHEN ? = 'en_curso' THEN COALESCE(iniciada, ?) ELSE iniciada END, "
                       "terminada = CASE WHEN ? THEN ? ELSE terminada END WHERE id = ?" + guard,
                       (state, error, state, stamp, state in FINAL, stamp, execution_id, *values)).rowcount == 1


def set_state(con: sqlite3.Connection, execution_id: str, state: str, error: str = "") -> None:
    """Cambia el estado de una ejecución y anota cuándo empezó y terminó."""
    with con:
        _set_state(con, execution_id, state, error)


def _evidence(con, execution_id: str, kind: str, path: Path, root: Path, stamp: str) -> int:
    data = path.read_bytes()
    route = path.resolve().relative_to(root.resolve()).as_posix()
    con.execute("INSERT INTO evidencia (ejecucion_id, tipo, ruta, sha256, bytes, creada) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (ejecucion_id, ruta) DO UPDATE SET sha256 = excluded.sha256, bytes = excluded.bytes",
                (execution_id, kind, route, hashlib.sha256(data).hexdigest(), len(data), stamp))
    return con.execute("SELECT id FROM evidencia WHERE ejecucion_id = ? AND ruta = ?", (execution_id, route)).fetchone()[0]


def record_captures(con: sqlite3.Connection, execution_id: str, manifest: dict, result_dir: Path, root: Path,
                    logs: list[Path] = ()) -> list[str]:
    """Vuelca en la base los resultados del manifiesto del motor; se puede repetir.

    Las subredes a las que no llegó la captura dejan sus URL como pendientes.
    Cada imagen y cada registro quedan como evidencia con su huella.

    Una imagen que el manifiesto cita y ya no está en disco no impide registrar el
    resto. Su URL queda `sin_captura`: `capturada` significa que hay una imagen
    guardada como evidencia, y `pendiente` que no se llegó a intentar. Conserva lo
    que vio el motor (código, título, URL final), sin evidencia y con el motivo en
    `error`. Devuelve las rutas de las imágenes que faltaban.
    """
    audit_id = con.execute("SELECT auditoria_id FROM ejecucion WHERE id = ?", (execution_id,)).fetchone()[0]
    stamp = now()
    missing = []
    with con:
        for group in manifest["grupos"]:
            for row in group.get("resultados") or []:
                shot, error = None, row.get("error") or ""
                if row.get("estado") == "capturada" and row.get("captura"):
                    try:
                        shot = _evidence(con, execution_id, "captura", report.inside(result_dir, row["captura"]), root, stamp)
                        error = ""
                    except FileNotFoundError:
                        missing.append(row["captura"])
                        error = error or "La imagen no está en disco."
                code = row.get("codigo_http")
                con.execute(
                    "INSERT INTO captura (ejecucion_id, servicio_id, url, estado, url_final, codigo_http, titulo, error, evidencia_id, fecha) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (ejecucion_id, url) DO UPDATE SET "
                    "estado = excluded.estado, url_final = excluded.url_final, codigo_http = excluded.codigo_http, "
                    "titulo = excluded.titulo, error = excluded.error, evidencia_id = excluded.evidencia_id, fecha = excluded.fecha",
                    (execution_id, _service_id(con, audit_id, row["ip"], int(row["puerto"])), row["url"],
                     "capturada" if shot else "sin_captura", row.get("url_final") or "",
                     int(code) if str(code or "").isdigit() else None, row.get("titulo") or "",
                     error, shot, stamp))
        for path in logs:
            if Path(path).is_file():
                _evidence(con, execution_id, "registro", Path(path), root, stamp)
    return missing


def portal_options(con: sqlite3.Connection, import_id: str) -> dict:
    """Lo que el portal guarda de una ejecución: {"archivos": [...], "captura": {...}}.

    Sin la clave "captura", la ejecución todavía no se ha migrado desde su
    trabajo.json (docs/MODELO_DATOS.md, paso 6).
    """
    row = con.execute("SELECT opciones FROM ejecucion WHERE id = ?", (import_id,)).fetchone()
    return json.loads(row["opciones"]) if row else {}


def set_options(con: sqlite3.Connection, execution_id: str, options: dict) -> None:
    with con:
        con.execute("UPDATE ejecucion SET opciones = ? WHERE id = ?", (json.dumps(options, ensure_ascii=False), execution_id))


def portal_jobs(con: sqlite3.Connection) -> list[sqlite3.Row]:
    """Cada importación con su captura, si ya se lanzó: el historial del portal."""
    return con.execute(
        "SELECT i.id, i.nombre, i.creada, i.opciones, c.estado, c.error, c.terminada FROM ejecucion i "
        "LEFT JOIN ejecucion c ON c.origen_id = i.id AND c.tipo = 'captura' "
        "WHERE i.tipo = 'importacion' ORDER BY i.creada").fetchall()


def planned_urls(con: sqlite3.Connection, capture_id: str) -> set[str]:
    """Las URL que se planificaron al lanzar una captura."""
    return {row[0] for row in con.execute("SELECT url FROM captura WHERE ejecucion_id = ?", (capture_id,))}


def import_capture_history(con: sqlite3.Connection, import_id: str, options: dict, groups: list[dict],
                           state: str, error: str, created: str, finished: str | None,
                           manifest: dict | None, result_dir: Path, root: Path,
                           logs: list[Path] = ()) -> tuple[str, list[str]]:
    """Registra una captura hecha antes de que la base las guardase (paso 5 del plan).

    Todo o nada: si falla, no queda una captura a medias en la base. Devuelve su id y
    las imágenes del manifiesto que ya no estaban en disco (ver record_captures).
    """
    capture_id = start_capture(con, import_id, options, groups, created)
    missing = []
    try:
        if manifest:
            missing = record_captures(con, capture_id, manifest, result_dir, root, logs)
        with con:
            con.execute("UPDATE ejecucion SET estado = ?, error = ?, iniciada = ?, terminada = ? WHERE id = ?",
                        (state, error, (manifest or {}).get("inicio"), finished or (manifest or {}).get("fin"), capture_id))
    except Exception:
        with con:
            con.execute("DELETE FROM ejecucion WHERE id = ?", (capture_id,))
        raise
    return capture_id, missing
