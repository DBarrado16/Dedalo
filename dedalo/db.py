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
    # Ejecuciones de descubrimiento y, al borrar una importación, también las
    # capturas que salieron de ella. SQLite no cambia un CHECK: se reconstruye.
    2: """
CREATE TABLE nueva_ejecucion (
  id           TEXT PRIMARY KEY,
  auditoria_id TEXT NOT NULL REFERENCES auditoria(id) ON DELETE CASCADE,
  tipo         TEXT NOT NULL CHECK (tipo IN ('importacion', 'captura', 'descubrimiento')),
  origen_id    TEXT REFERENCES ejecucion(id) ON DELETE CASCADE,
  nombre       TEXT NOT NULL,
  estado       TEXT NOT NULL CHECK (estado IN ('preparada', 'en_cola', 'en_curso', 'deteniendo', 'completa',
                                               'parcial', 'error', 'cancelada', 'interrumpida')),
  opciones     TEXT NOT NULL DEFAULT '{}',
  creada       TEXT NOT NULL,
  iniciada     TEXT,
  terminada    TEXT,
  error        TEXT NOT NULL DEFAULT ''
);
INSERT INTO nueva_ejecucion (id, auditoria_id, tipo, origen_id, nombre, estado, opciones, creada, iniciada, terminada, error)
  SELECT id, auditoria_id, tipo, origen_id, nombre, estado, opciones, creada, iniciada, terminada, error FROM ejecucion;
DROP TABLE ejecucion;
ALTER TABLE nueva_ejecucion RENAME TO ejecucion;
CREATE INDEX ejecucion_auditoria ON ejecucion (auditoria_id);
CREATE INDEX ejecucion_origen ON ejecucion (origen_id);
""",
    # Análisis con IA de una importación: rol, prioridad y siguiente paso de cada activo.
    3: """
CREATE TABLE nueva_ejecucion (
  id           TEXT PRIMARY KEY,
  auditoria_id TEXT NOT NULL REFERENCES auditoria(id) ON DELETE CASCADE,
  tipo         TEXT NOT NULL CHECK (tipo IN ('importacion', 'captura', 'descubrimiento', 'analisis')),
  origen_id    TEXT REFERENCES ejecucion(id) ON DELETE CASCADE,
  nombre       TEXT NOT NULL,
  estado       TEXT NOT NULL CHECK (estado IN ('preparada', 'en_cola', 'en_curso', 'deteniendo', 'completa',
                                               'parcial', 'error', 'cancelada', 'interrumpida')),
  opciones     TEXT NOT NULL DEFAULT '{}',
  creada       TEXT NOT NULL,
  iniciada     TEXT,
  terminada    TEXT,
  error        TEXT NOT NULL DEFAULT ''
);
INSERT INTO nueva_ejecucion (id, auditoria_id, tipo, origen_id, nombre, estado, opciones, creada, iniciada, terminada, error)
  SELECT id, auditoria_id, tipo, origen_id, nombre, estado, opciones, creada, iniciada, terminada, error FROM ejecucion;
DROP TABLE ejecucion;
ALTER TABLE nueva_ejecucion RENAME TO ejecucion;
CREATE INDEX ejecucion_auditoria ON ejecucion (auditoria_id);
CREATE INDEX ejecucion_origen ON ejecucion (origen_id);
CREATE TABLE prioridad (
  id           INTEGER PRIMARY KEY,
  ejecucion_id TEXT NOT NULL REFERENCES ejecucion(id) ON DELETE CASCADE,
  activo_id    INTEGER NOT NULL REFERENCES activo(id) ON DELETE CASCADE,
  orden        INTEGER NOT NULL,
  rol          TEXT NOT NULL DEFAULT '',
  nivel        TEXT NOT NULL CHECK (nivel IN ('alta', 'media', 'baja', 'sin_analisis')),
  motivo       TEXT NOT NULL DEFAULT '',
  siguiente    TEXT NOT NULL DEFAULT '',
  UNIQUE (ejecucion_id, activo_id)
);
CREATE INDEX prioridad_activo ON prioridad (activo_id);
""",
    # Credenciales por defecto (bloque 6): catálogo curado + prueba activa.
    4: """
CREATE TABLE nueva_ejecucion (
  id           TEXT PRIMARY KEY,
  auditoria_id TEXT NOT NULL REFERENCES auditoria(id) ON DELETE CASCADE,
  tipo         TEXT NOT NULL CHECK (tipo IN ('importacion', 'captura', 'descubrimiento', 'analisis', 'credenciales')),
  origen_id    TEXT REFERENCES ejecucion(id) ON DELETE CASCADE,
  nombre       TEXT NOT NULL,
  estado       TEXT NOT NULL CHECK (estado IN ('preparada', 'en_cola', 'en_curso', 'deteniendo', 'completa',
                                               'parcial', 'error', 'cancelada', 'interrumpida')),
  opciones     TEXT NOT NULL DEFAULT '{}',
  creada       TEXT NOT NULL,
  iniciada     TEXT,
  terminada    TEXT,
  error        TEXT NOT NULL DEFAULT ''
);
INSERT INTO nueva_ejecucion (id, auditoria_id, tipo, origen_id, nombre, estado, opciones, creada, iniciada, terminada, error)
  SELECT id, auditoria_id, tipo, origen_id, nombre, estado, opciones, creada, iniciada, terminada, error FROM ejecucion;
DROP TABLE ejecucion;
ALTER TABLE nueva_ejecucion RENAME TO ejecucion;
CREATE INDEX ejecucion_auditoria ON ejecucion (auditoria_id);
CREATE INDEX ejecucion_origen ON ejecucion (origen_id);
CREATE TABLE config (
  clave TEXT PRIMARY KEY,
  valor TEXT NOT NULL
);
CREATE TABLE credencial_catalogo (
  id           INTEGER PRIMARY KEY,
  fabricante   TEXT NOT NULL DEFAULT '',
  producto     TEXT NOT NULL,
  version      TEXT NOT NULL DEFAULT '',
  servicio     TEXT NOT NULL CHECK (servicio IN ('http-basic', 'http-form', 'ftp')),
  usuario      TEXT NOT NULL,
  clave        TEXT NOT NULL,
  receta       TEXT NOT NULL DEFAULT '',
  fuente       TEXT NOT NULL DEFAULT '',
  licencia     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX credencial_catalogo_servicio ON credencial_catalogo (servicio);
CREATE TABLE credencial_resultado (
  id           INTEGER PRIMARY KEY,
  ejecucion_id TEXT NOT NULL REFERENCES ejecucion(id) ON DELETE CASCADE,
  activo_id    INTEGER NOT NULL REFERENCES activo(id) ON DELETE CASCADE,
  orden        INTEGER NOT NULL,
  puerto       INTEGER NOT NULL,
  protocolo    TEXT NOT NULL DEFAULT 'tcp',
  servicio     TEXT NOT NULL,
  estado       TEXT NOT NULL CHECK (estado IN ('entrada', 'fallo', 'error')),
  usuario      TEXT NOT NULL DEFAULT '',
  clave        TEXT NOT NULL DEFAULT '',
  detalle      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX credencial_resultado_activo ON credencial_resultado (activo_id);
""",
    # Detección de producto/versión desde la captura (gowitness + IA): tipo de ejecución
    # `version` y tabla `deteccion` (varias lecturas por servicio, con su origen).
    5: """
CREATE TABLE nueva_ejecucion (
  id           TEXT PRIMARY KEY,
  auditoria_id TEXT NOT NULL REFERENCES auditoria(id) ON DELETE CASCADE,
  tipo         TEXT NOT NULL CHECK (tipo IN ('importacion', 'captura', 'descubrimiento', 'analisis', 'credenciales', 'version')),
  origen_id    TEXT REFERENCES ejecucion(id) ON DELETE CASCADE,
  nombre       TEXT NOT NULL,
  estado       TEXT NOT NULL CHECK (estado IN ('preparada', 'en_cola', 'en_curso', 'deteniendo', 'completa',
                                               'parcial', 'error', 'cancelada', 'interrumpida')),
  opciones     TEXT NOT NULL DEFAULT '{}',
  creada       TEXT NOT NULL,
  iniciada     TEXT,
  terminada    TEXT,
  error        TEXT NOT NULL DEFAULT ''
);
INSERT INTO nueva_ejecucion (id, auditoria_id, tipo, origen_id, nombre, estado, opciones, creada, iniciada, terminada, error)
  SELECT id, auditoria_id, tipo, origen_id, nombre, estado, opciones, creada, iniciada, terminada, error FROM ejecucion;
DROP TABLE ejecucion;
ALTER TABLE nueva_ejecucion RENAME TO ejecucion;
CREATE INDEX ejecucion_auditoria ON ejecucion (auditoria_id);
CREATE INDEX ejecucion_origen ON ejecucion (origen_id);
CREATE TABLE deteccion (
  id           INTEGER PRIMARY KEY,
  ejecucion_id TEXT NOT NULL REFERENCES ejecucion(id) ON DELETE CASCADE,
  servicio_id  INTEGER NOT NULL REFERENCES servicio(id) ON DELETE CASCADE,
  origen       TEXT NOT NULL CHECK (origen IN ('gowitness', 'ia')),
  producto     TEXT NOT NULL DEFAULT '',
  version      TEXT NOT NULL DEFAULT '',
  confianza    INTEGER,
  detalle      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX deteccion_servicio ON deteccion (servicio_id);
""",
    # Cruce de vulnerabilidades por CPE: tipo de ejecución `vuln`, base local de CVE
    # (`cve` + reglas de aplicabilidad `cve_cpe`) y lo que el cruce halla por servicio
    # (`vulnerabilidad`). La fecha de la última actualización de la base NVD va en
    # `config` (clave `nvd_actualizada`; la de cada feed anual, en `nvd_feed_<año>`).
    6: """
CREATE TABLE nueva_ejecucion (
  id           TEXT PRIMARY KEY,
  auditoria_id TEXT NOT NULL REFERENCES auditoria(id) ON DELETE CASCADE,
  tipo         TEXT NOT NULL CHECK (tipo IN ('importacion', 'captura', 'descubrimiento', 'analisis', 'credenciales', 'version', 'vuln')),
  origen_id    TEXT REFERENCES ejecucion(id) ON DELETE CASCADE,
  nombre       TEXT NOT NULL,
  estado       TEXT NOT NULL CHECK (estado IN ('preparada', 'en_cola', 'en_curso', 'deteniendo', 'completa',
                                               'parcial', 'error', 'cancelada', 'interrumpida')),
  opciones     TEXT NOT NULL DEFAULT '{}',
  creada       TEXT NOT NULL,
  iniciada     TEXT,
  terminada    TEXT,
  error        TEXT NOT NULL DEFAULT ''
);
INSERT INTO nueva_ejecucion (id, auditoria_id, tipo, origen_id, nombre, estado, opciones, creada, iniciada, terminada, error)
  SELECT id, auditoria_id, tipo, origen_id, nombre, estado, opciones, creada, iniciada, terminada, error FROM ejecucion;
DROP TABLE ejecucion;
ALTER TABLE nueva_ejecucion RENAME TO ejecucion;
CREATE INDEX ejecucion_auditoria ON ejecucion (auditoria_id);
CREATE INDEX ejecucion_origen ON ejecucion (origen_id);
CREATE TABLE cve (
  id        TEXT PRIMARY KEY,
  publicada TEXT NOT NULL DEFAULT '',
  severidad TEXT NOT NULL DEFAULT '',
  cvss      REAL,
  resumen   TEXT NOT NULL DEFAULT ''
);
CREATE TABLE cve_cpe (
  id         INTEGER PRIMARY KEY,
  cve_id     TEXT NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
  parte      TEXT NOT NULL DEFAULT '',
  vendor     TEXT NOT NULL DEFAULT '',
  producto   TEXT NOT NULL,
  v_ini      TEXT,
  v_ini_incl INTEGER NOT NULL DEFAULT 0,
  v_fin      TEXT,
  v_fin_incl INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX cve_cpe_producto ON cve_cpe (producto);
CREATE INDEX cve_cpe_cve ON cve_cpe (cve_id);
CREATE TABLE vulnerabilidad (
  id            INTEGER PRIMARY KEY,
  ejecucion_id  TEXT NOT NULL REFERENCES ejecucion(id) ON DELETE CASCADE,
  servicio_id   INTEGER NOT NULL REFERENCES servicio(id) ON DELETE CASCADE,
  cve_id        TEXT NOT NULL,
  severidad     TEXT NOT NULL DEFAULT '',
  exploit_nivel TEXT NOT NULL DEFAULT '',
  enlaces       TEXT NOT NULL DEFAULT '[]',
  origen_cpe    TEXT NOT NULL DEFAULT '',
  estado        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX vulnerabilidad_servicio ON vulnerabilidad (servicio_id);
CREATE INDEX vulnerabilidad_ejecucion ON vulnerabilidad (ejecucion_id);
""",
}


def migrate(con: sqlite3.Connection) -> int:
    """Aplica en orden las migraciones pendientes; cada una es todo o nada.

    SQLite no permite cambiar un CHECK: hay que reconstruir la tabla (crear
    `nueva_X`, copiar, DROP X, renombrar). Con las claves foráneas activas, ese
    DROP borraría en cascada todo lo que cuelga de X, y PRAGMA foreign_keys no
    tiene efecto dentro de una transacción. Por eso se desactivan antes de
    empezar y cada migración comprueba las referencias antes de confirmarse.
    """
    latest = max(MIGRATIONS)
    current = con.execute("PRAGMA user_version").fetchone()[0]
    if current > latest:
        raise ValueError(f"La base de datos es de una versión más nueva de Dedalo (esquema {current}); actualiza el programa.")
    if current == latest:
        return latest
    enforced = con.execute("PRAGMA foreign_keys").fetchone()[0]
    con.execute("PRAGMA foreign_keys = OFF")
    try:
        for version in range(current + 1, latest + 1):
            try:
                con.executescript(f"BEGIN;\n{MIGRATIONS[version]}\nPRAGMA user_version = {version};")
                if con.execute("PRAGMA foreign_key_check").fetchone():
                    raise sqlite3.IntegrityError(f"La migración {version} deja referencias rotas; no se aplica.")
                con.commit()
            except sqlite3.Error:
                if con.in_transaction:
                    con.rollback()
                raise
    finally:
        con.execute(f"PRAGMA foreign_keys = {'ON' if enforced else 'OFF'}")
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
