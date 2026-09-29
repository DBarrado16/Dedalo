# Modelo de datos (bloque 1)

Propuesta para la base SQLite propia de Dedalo. Sustituye a los `trabajo.json` e `inventario.json` sueltos como fuente de verdad. Los archivos pesados (Nmap originales, capturas, bases de gowitness) siguen en disco y la base guarda su ruta y su huella.

## Piezas y relaciones

```text
auditoria ─┬─ alcance (reglas incluir/excluir)
           ├─ ejecucion (importacion, captura, ...)
           │     ├─ observacion_activo ──┐
           │     ├─ observacion ─────────┤  (qué vio esta ejecución)
           │     ├─ captura              │
           │     └─ evidencia (archivos) │
           └─ activo (una IP) ◄──────────┘
                 └─ servicio (protocolo + puerto)
```

- **Activo** y **servicio** dicen *qué existe*. Son únicos: una IP aparece una sola vez por auditoría y un puerto una sola vez por activo, aunque lo vean diez ejecuciones.
- **Observación** dice *quién lo vio, cuándo y cómo*. Si dos escaneos describen distinto el mismo servicio, se guardan las dos observaciones y no se pisan.
- **Captura** es el intento de capturar una URL, haya salido bien o no.
- **Evidencia** es un archivo que respalda algo: el Nmap original, una imagen o un registro.

## Tablas

```sql
CREATE TABLE auditoria (
  id        TEXT PRIMARY KEY,          -- uuid hex
  nombre    TEXT NOT NULL,
  creada    TEXT NOT NULL,             -- ISO 8601 UTC
  notas     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE alcance (
  id           INTEGER PRIMARY KEY,
  auditoria_id TEXT NOT NULL REFERENCES auditoria(id) ON DELETE CASCADE,
  tipo         TEXT NOT NULL CHECK (tipo IN ('incluir', 'excluir')),
  cidr         TEXT NOT NULL,          -- normalizado: 10.10.5.20/32
  motivo       TEXT NOT NULL DEFAULT '',
  UNIQUE (auditoria_id, tipo, cidr)
);

CREATE TABLE ejecucion (
  id           TEXT PRIMARY KEY,       -- uuid hex; en importaciones coincide con la carpeta de portal_datos
  auditoria_id TEXT NOT NULL REFERENCES auditoria(id) ON DELETE CASCADE,
  tipo         TEXT NOT NULL CHECK (tipo IN ('importacion', 'captura')),
  origen_id    TEXT REFERENCES ejecucion(id),   -- captura -> importación de la que salen sus objetivos
  nombre       TEXT NOT NULL,
  estado       TEXT NOT NULL CHECK (estado IN (...)),  -- los nueve estados de CONTRATOS.md 0.4
  opciones     TEXT NOT NULL DEFAULT '{}',      -- JSON: hilos, timeout, formato...
  creada       TEXT NOT NULL,
  iniciada     TEXT,
  terminada    TEXT,
  error        TEXT NOT NULL DEFAULT ''
);

CREATE TABLE activo (
  id           INTEGER PRIMARY KEY,
  auditoria_id TEXT NOT NULL REFERENCES auditoria(id) ON DELETE CASCADE,
  ip           TEXT NOT NULL,          -- forma canónica de ipaddress
  UNIQUE (auditoria_id, ip)
);

CREATE TABLE servicio (
  id        INTEGER PRIMARY KEY,
  activo_id INTEGER NOT NULL REFERENCES activo(id) ON DELETE CASCADE,
  protocolo TEXT NOT NULL CHECK (protocolo IN ('tcp', 'udp')),
  puerto    INTEGER NOT NULL CHECK (puerto BETWEEN 1 AND 65535),
  UNIQUE (activo_id, protocolo, puerto)
);

-- Lo que una ejecución vio del host: nombres DNS y scripts NSE de host.
-- También registra hosts activos sin puertos abiertos.
CREATE TABLE observacion_activo (
  id           INTEGER PRIMARY KEY,
  ejecucion_id TEXT NOT NULL REFERENCES ejecucion(id) ON DELETE CASCADE,
  activo_id    INTEGER NOT NULL REFERENCES activo(id) ON DELETE CASCADE,
  nombres      TEXT NOT NULL DEFAULT '[]',   -- JSON
  scripts      TEXT NOT NULL DEFAULT '[]',   -- JSON [{id, output}]
  UNIQUE (ejecucion_id, activo_id)
);

-- Lo que una ejecución vio de un puerto.
CREATE TABLE observacion (
  id           INTEGER PRIMARY KEY,
  ejecucion_id TEXT NOT NULL REFERENCES ejecucion(id) ON DELETE CASCADE,
  servicio_id  INTEGER NOT NULL REFERENCES servicio(id) ON DELETE CASCADE,
  estado       TEXT NOT NULL DEFAULT 'open',
  nombre       TEXT NOT NULL DEFAULT '',     -- ssh, http, microsoft-ds...
  tunel        TEXT NOT NULL DEFAULT '',     -- ssl
  producto     TEXT NOT NULL DEFAULT '',
  version      TEXT NOT NULL DEFAULT '',
  detalle      TEXT NOT NULL DEFAULT '',
  cpe          TEXT NOT NULL DEFAULT '[]',   -- JSON
  scripts      TEXT NOT NULL DEFAULT '[]',   -- JSON
  UNIQUE (ejecucion_id, servicio_id)
);

CREATE TABLE evidencia (
  id           INTEGER PRIMARY KEY,
  ejecucion_id TEXT NOT NULL REFERENCES ejecucion(id) ON DELETE CASCADE,
  tipo         TEXT NOT NULL CHECK (tipo IN ('nmap', 'captura', 'registro')),
  ruta         TEXT NOT NULL,          -- relativa a la carpeta de datos del portal
  sha256       TEXT NOT NULL,
  bytes        INTEGER NOT NULL,
  creada       TEXT NOT NULL,
  UNIQUE (ejecucion_id, ruta)
);

-- Un intento de captura por URL y ejecución, con o sin imagen.
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
```

La migración 1 añade índices para las búsquedas habituales: ejecuciones por auditoría, observaciones por servicio y por activo, y capturas por servicio. El esquema exacto está en `nmapshot/db.py`.

La situación de alcance de un activo (en alcance, excluido o fuera) **no se guarda**: se calcula con las reglas vigentes. Así, cambiar el alcance nunca deja datos desactualizados.

## Trazabilidad

Desde cualquier imagen se llega a su origen:

```text
evidencia (imagen) ← captura → servicio 443/tcp → activo 10.10.5.3 → auditoría
                       └→ ejecución de captura → origen_id → importación → evidencia (Nmap original)
```

## Archivos y migraciones

- La base se guarda en `portal_datos/dedalo.sqlite3`, ya excluida de git por `*.sqlite3`.
- Se abre con `PRAGMA foreign_keys = ON` y `journal_mode = WAL`, que permite leer mientras se escribe.
- Las migraciones son funciones numeradas en `nmapshot/db.py` (`1: esquema inicial`, `2: …`). La base guarda su versión en `PRAGMA user_version` y al abrirla se aplican en una transacción las que falten. Nunca se edita una migración ya publicada; se añade otra.
- Cambiar un `CHECK` (por ejemplo, añadir el tipo `descubrimiento`) obliga a reconstruir la tabla: `CREATE TABLE nueva_X`, copiar, `DROP TABLE X`, `ALTER TABLE nueva_X RENAME TO X`. `migrate()` desactiva las claves foráneas durante las migraciones para que ese `DROP` no borre en cascada lo que depende de la tabla, y rechaza la migración si `PRAGMA foreign_key_check` encuentra referencias rotas.
- **Migración del historial:** la primera vez se crea la auditoría «Importadas». Cada carpeta antigua de `portal_datos/` genera una ejecución `importacion` (con sus Nmap como evidencia) y, si se capturó, una `captura` con sus resultados e imágenes. Las carpetas originales no se modifican.

## Plan de trabajo

1. ✅ `db.py`: conexión, migración 1 y pruebas de que el esquema se crea, se reabre y rechaza datos inválidos.
2. ✅ Importación (`auditoria.py`): de un Nmap a activos, servicios y observaciones, sustituyendo a `inventario.json`. Las ejecuciones antiguas se importan al consultar su inventario.
3. ✅ Auditorías y alcance en el portal («fichas de cliente»): crear, elegir y editar reglas; revisar objetivos marcando su situación. La consola aplica el alcance con `--solo-rangos` y `--excluir` justo antes de capturar.
4. Capturas: registrar cada intento y evidencia en la base y aplicar la regla de solo en alcance.
5. Migración del historial.
6. Retirar la lectura de `trabajo.json` e `inventario.json` cuando todo lo anterior esté probado.
