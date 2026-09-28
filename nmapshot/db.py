"""Base SQLite propia de Dedalo: conexión y migraciones numeradas.

El esquema y su significado están en docs/MODELO_DATOS.md. Una migración ya
publicada nunca se edita: los cambios se añaden como una migración nueva.
"""

from __future__ import annotations

from pathlib import Path
import sqlite3

FILENAME = "dedalo.sqlite3"

MIGRATIONS = {
    1: """
CREATE TABLE auditoria (
  id        TEXT PRIMARY KEY,
  nombre    TEXT NOT NULL,
  creada    TEXT NOT NULL,
  notas     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE alcance (
  id           INTEGER PRIMARY KEY,
  auditoria_id TEXT NOT NULL REFERENCES auditoria(id) ON DELETE CASCADE,
  tipo         TEXT NOT NULL CHECK (tipo IN ('incluir', 'excluir')),
  cidr         TEXT NOT NULL,
  motivo       TEXT NOT NULL DEFAULT '',
  UNIQUE (auditoria_id, tipo, cidr)
);

CREATE TABLE ejecucion (
  id           TEXT PRIMARY KEY,
  auditoria_id TEXT NOT NULL REFERENCES auditoria(id) ON DELETE CASCADE,
  tipo         TEXT NOT NULL CHECK (tipo IN ('importacion', 'captura')),
  origen_id    TEXT REFERENCES ejecucion(id),
  nombre       TEXT NOT NULL,
  estado       TEXT NOT NULL CHECK (estado IN ('preparada', 'en_cola', 'en_curso', 'deteniendo', 'completa',
                                               'parcial', 'error', 'cancelada', 'interrumpida')),
  opciones     TEXT NOT NULL DEFAULT '{}',
  creada       TEXT NOT NULL,
  iniciada     TEXT,
  terminada    TEXT,
  error        TEXT NOT NULL DEFAULT ''
);

CREATE TABLE activo (
  id           INTEGER PRIMARY KEY,
  auditoria_id TEXT NOT NULL REFERENCES auditoria(id) ON DELETE CASCADE,
  ip           TEXT NOT NULL,
  UNIQUE (auditoria_id, ip)
);

CREATE TABLE servicio (
  id        INTEGER PRIMARY KEY,
  activo_id INTEGER NOT NULL REFERENCES activo(id) ON DELETE CASCADE,
  protocolo TEXT NOT NULL CHECK (protocolo IN ('tcp', 'udp')),
  puerto    INTEGER NOT NULL CHECK (puerto BETWEEN 1 AND 65535),
  UNIQUE (activo_id, protocolo, puerto)
);

CREATE TABLE observacion_activo (
  id           INTEGER PRIMARY KEY,
  ejecucion_id TEXT NOT NULL REFERENCES ejecucion(id) ON DELETE CASCADE,
  activo_id    INTEGER NOT NULL REFERENCES activo(id) ON DELETE CASCADE,
  nombres      TEXT NOT NULL DEFAULT '[]',
  scripts      TEXT NOT NULL DEFAULT '[]',
  UNIQUE (ejecucion_id, activo_id)
);

CREATE TABLE observacion (
  id           INTEGER PRIMARY KEY,
  ejecucion_id TEXT NOT NULL REFERENCES ejecucion(id) ON DELETE CASCADE,
  servicio_id  INTEGER NOT NULL REFERENCES servicio(id) ON DELETE CASCADE,
  estado       TEXT NOT NULL DEFAULT 'open',
  nombre       TEXT NOT NULL DEFAULT '',
  tunel        TEXT NOT NULL DEFAULT '',
  producto     TEXT NOT NULL DEFAULT '',
  version      TEXT NOT NULL DEFAULT '',
  detalle      TEXT NOT NULL DEFAULT '',
  cpe          TEXT NOT NULL DEFAULT '[]',
  scripts      TEXT NOT NULL DEFAULT '[]',
  UNIQUE (ejecucion_id, servicio_id)
);

CREATE TABLE evidencia (
  id           INTEGER PRIMARY KEY,
  ejecucion_id TEXT NOT NULL REFERENCES ejecucion(id) ON DELETE CASCADE,
  tipo         TEXT NOT NULL CHECK (tipo IN ('nmap', 'captura', 'registro')),
  ruta         TEXT NOT NULL,
  sha256       TEXT NOT NULL,
  bytes        INTEGER NOT NULL,
  creada       TEXT NOT NULL,
  UNIQUE (ejecucion_id, ruta)
);

CREATE TABLE captura (
  id           INTEGER PRIMARY KEY,
  ejecucion_id TEXT NOT NULL REFERENCES ejecucion(id) ON DELETE CASCADE,
  servicio_id  INTEGER NOT NULL REFERENCES servicio(id) ON DELETE CASCADE,
  url          TEXT NOT NULL,
  estado       TEXT NOT NULL CHECK (estado IN ('pendiente', 'capturada', 'sin_captura')),
  url_final    TEXT NOT NULL DEFAULT '',
  codigo_http  INTEGER,
  titulo       TEXT NOT NULL DEFAULT '',
  error        TEXT NOT NULL DEFAULT '',
  evidencia_id INTEGER REFERENCES evidencia(id) ON DELETE SET NULL,
  fecha        TEXT,
  UNIQUE (ejecucion_id, url)
);

CREATE INDEX ejecucion_auditoria ON ejecucion (auditoria_id);
CREATE INDEX observacion_servicio ON observacion (servicio_id);
CREATE INDEX observacion_activo_activo ON observacion_activo (activo_id);
CREATE INDEX captura_servicio ON captura (servicio_id);
""",
}


def migrate(con: sqlite3.Connection) -> int:
    """Aplica en orden las migraciones pendientes; cada una es todo o nada."""
    latest = max(MIGRATIONS)
    current = con.execute("PRAGMA user_version").fetchone()[0]
    if current > latest:
        raise ValueError(f"La base de datos es de una versión más nueva de Dedalo (esquema {current}); actualiza el programa.")
    for version in range(current + 1, latest + 1):
        try:
            con.executescript(f"BEGIN;\n{MIGRATIONS[version]}\nPRAGMA user_version = {version};\nCOMMIT;")
        except sqlite3.Error:
            if con.in_transaction:
                con.rollback()
            raise
    return latest


def connect(root: str | Path) -> sqlite3.Connection:
    """Abre (o crea) la base de una carpeta de datos, ya migrada."""
    con = sqlite3.connect(Path(root).resolve() / FILENAME, timeout=30)
    con.row_factory = sqlite3.Row
    try:
        # foreign_keys se activa en cada conexión; WAL permite leer mientras se escribe.
        con.execute("PRAGMA foreign_keys = ON")
        con.execute("PRAGMA journal_mode = WAL")
        migrate(con)
    except Exception:
        con.close()
        raise
    return con
