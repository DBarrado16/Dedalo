# Modelo de datos (bloque 1)

Base SQLite propia de Dedalo. Es la única fuente de verdad del portal: sustituye a los `trabajo.json` e `inventario.json` sueltos. Los archivos pesados (Nmap originales, capturas, bases de gowitness) siguen en disco y la base guarda su ruta y su huella.

## Piezas y relaciones

```text
auditoria ─┬─ alcance (reglas incluir/excluir)
           ├─ ejecucion (importacion, captura, ...)
           │     ├─ observacion_activo ──┐
           │     ├─ observacion ─────────┤  (qué vio esta ejecución)
           │     ├─ captura              │
           │     ├─ prioridad (análisis) │
           │     └─ evidencia (archivos) │
           └─ activo (una IP) ◄──────────┘
                 └─ servicio (protocolo + puerto)
```

- **Activo** y **servicio** dicen *qué existe*. Son únicos: una IP aparece una sola vez por auditoría y un puerto una sola vez por activo, aunque lo vean diez ejecuciones.
- **Observación** dice *quién lo vio, cuándo y cómo*. Si dos escaneos describen distinto el mismo servicio, se guardan las dos observaciones y no se pisan.
- **Captura** es el intento de capturar una URL, haya salido bien o no.
- **Evidencia** es un archivo que respalda algo: el Nmap original, una imagen o un registro.
- **Prioridad** es lo que un análisis con IA dijo de un activo de su importación: rol probable, nivel (alta, media, baja, o `sin_analisis` si la respuesta del modelo no valía), motivo y siguiente paso sugerido. Es una opinión asesora: no cambia nada del inventario. Una importación guarda su último análisis completo y, como mucho, un intento posterior; el intento solo sustituye al completo, en la misma transacción en que guarda sus prioridades, si termina bien.
- **Resultado de credenciales** es lo que una prueba de credenciales por defecto obtuvo de cada servicio en alcance: si entró (con qué usuario y clave), no entró o error. El catálogo de contraseñas de fábrica vive en `credencial_catalogo`, volcado desde un fichero versionado del repo. Como el análisis, una importación guarda su última prueba completa y, como mucho, un intento posterior; solo se sustituye al terminar bien.
- **Resultado del descubrimiento** son las observaciones que deja una ejecución `descubrimiento`: los nombres hallados (DNS inverso) van al activo como `observacion_activo.nombres`, y cada IP que responde como servidor DNS se anota como un servicio `udp/53` con su `observacion`. No hay tablas ni migración nuevas: reutiliza las de observación, igual que una importación.

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
  tipo         TEXT NOT NULL CHECK (tipo IN ('importacion', 'captura', 'descubrimiento', 'analisis')),
  origen_id    TEXT REFERENCES ejecucion(id) ON DELETE CASCADE,  -- captura o análisis -> importación de la que salen
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

-- Un intento de captura por URL y ejecución, con o sin imagen (sin_captura también si la imagen ya no estaba en disco).
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

-- Lo que un análisis con IA (ejecución 'analisis') dijo de cada activo, en el orden en que se muestra.
CREATE TABLE prioridad (
  id           INTEGER PRIMARY KEY,
  ejecucion_id TEXT NOT NULL REFERENCES ejecucion(id) ON DELETE CASCADE,
  activo_id    INTEGER NOT NULL REFERENCES activo(id) ON DELETE CASCADE,
  orden        INTEGER NOT NULL,
  rol          TEXT NOT NULL DEFAULT '',
  nivel        TEXT NOT NULL CHECK (nivel IN ('alta', 'media', 'baja', 'sin_analisis')),
  motivo       TEXT NOT NULL DEFAULT '',
  siguiente    TEXT NOT NULL DEFAULT '',   -- siguiente paso sugerido; texto asesor, nada lo ejecuta
  UNIQUE (ejecucion_id, activo_id)
);

-- Catálogo curado de credenciales por defecto, volcado del fichero dedalo/datos/credenciales.json
-- al arrancar (se refresca cuando su huella cambia; la huella se guarda en config).
CREATE TABLE credencial_catalogo (
  id           INTEGER PRIMARY KEY,
  fabricante   TEXT NOT NULL DEFAULT '',
  producto     TEXT NOT NULL,            -- debe aparecer en el producto o el título del servicio
  version      TEXT NOT NULL DEFAULT '', -- patrón opcional (fnmatch); vacío = cualquiera
  servicio     TEXT NOT NULL CHECK (servicio IN ('http-basic', 'http-form', 'ftp')),
  usuario      TEXT NOT NULL,
  clave        TEXT NOT NULL,
  receta       TEXT NOT NULL DEFAULT '', -- JSON del login por formulario (solo http-form)
  fuente       TEXT NOT NULL DEFAULT '',
  licencia     TEXT NOT NULL DEFAULT ''
);

-- Lo que una prueba de credenciales (ejecución 'credenciales') obtuvo de cada servicio.
CREATE TABLE credencial_resultado (
  id           INTEGER PRIMARY KEY,
  ejecucion_id TEXT NOT NULL REFERENCES ejecucion(id) ON DELETE CASCADE,
  activo_id    INTEGER NOT NULL REFERENCES activo(id) ON DELETE CASCADE,
  orden        INTEGER NOT NULL,
  puerto       INTEGER NOT NULL,
  protocolo    TEXT NOT NULL DEFAULT 'tcp',
  servicio     TEXT NOT NULL,
  estado       TEXT NOT NULL CHECK (estado IN ('entrada', 'fallo', 'error')),
  usuario      TEXT NOT NULL DEFAULT '',  -- con qué se entró, solo si estado = 'entrada'
  clave        TEXT NOT NULL DEFAULT '',
  detalle      TEXT NOT NULL DEFAULT ''
);

-- Pares clave/valor del portal (p. ej. la huella del catálogo cargado).
CREATE TABLE config (
  clave TEXT PRIMARY KEY,
  valor TEXT NOT NULL
);
```

La migración 1 añade índices para las búsquedas habituales: ejecuciones por auditoría, observaciones por servicio y por activo, y capturas por servicio. La migración 2 reconstruye `ejecucion` para admitir el tipo `descubrimiento` y para que borrar una importación borre también las capturas que salieron de ella; añade el índice por `origen_id`. La migración 3 la reconstruye otra vez para admitir el tipo `analisis` y crea la tabla `prioridad` con un índice por activo (el de ejecución ya lo da su `UNIQUE`). La migración 4 la reconstruye para admitir el tipo `credenciales` y crea `credencial_catalogo` (con índice por servicio), `credencial_resultado` (con índice por activo) y `config`. El esquema exacto está en `dedalo/db.py`.

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
- Las migraciones son funciones numeradas en `dedalo/db.py` (`1: esquema inicial`, `2: …`). La base guarda su versión en `PRAGMA user_version` y al abrirla se aplican en una transacción las que falten. Nunca se edita una migración ya publicada; se añade otra.
- Cambiar un `CHECK` (por ejemplo, añadir el tipo `descubrimiento`) obliga a reconstruir la tabla: `CREATE TABLE nueva_X`, copiar, `DROP TABLE X`, `ALTER TABLE nueva_X RENAME TO X`. `migrate()` desactiva las claves foráneas durante las migraciones para que ese `DROP` no borre en cascada lo que depende de la tabla, y rechaza la migración si `PRAGMA foreign_key_check` encuentra referencias rotas.
- **Migración del historial:** la primera vez se crea la auditoría «Importadas». Cada carpeta antigua de `portal_datos/` genera una ejecución `importacion` (con sus Nmap como evidencia) y, si se capturó, una `captura` con sus resultados e imágenes. Las carpetas originales no se modifican (salvo el fichero `parar` de una ejecución que estaba activa; ver el paso 5).

## Plan de trabajo

1. ✅ `db.py`: conexión, migración 1 y pruebas de que el esquema se crea, se reabre y rechaza datos inválidos.
2. ✅ Importación (`auditoria.py`): de un Nmap a activos, servicios y observaciones, sustituyendo a `inventario.json`. Las ejecuciones antiguas se importan al consultar su inventario.
3. ✅ Auditorías y alcance en el portal («fichas de cliente»): crear, elegir y editar reglas; revisar objetivos marcando su situación. La consola aplica el alcance con `--solo-rangos` y `--excluir` justo antes de capturar.
4. ✅ Capturas: al iniciar, el portal crea la ejecución `captura` (con `origen_id` en la importación) y cada URL en alcance como `pendiente`, ligada a su servicio. Los cambios de estado se reflejan en la base; al terminar se vuelcan los resultados, las imágenes como evidencia `captura` y los registros como `registro`, con su SHA-256. Si una imagen que cita el manifiesto ya no está en disco, su URL queda `sin_captura` (`capturada` exige una imagen guardada como evidencia, y `pendiente` significa que no se llegó a intentar), con lo que vio el motor, sin evidencia y con el motivo en `error`; el resto se registra y la terminal lo avisa. Si los resultados no se pueden volcar, el estado final se guarda igualmente. Si el portal se cierra a mitad, al reabrirlo se completa desde el manifiesto del motor. La consola no escribe en la base; el alcance lo sigue aplicando el motor justo antes de conectar.
5. ✅ Migración del historial: al arrancar, cada carpeta que solo tenga `trabajo.json` se lleva a la base una sola vez. Se importan sus Nmap si hacía falta y, si se capturó, se registra su captura con el estado, los objetivos planificados, los resultados del manifiesto del motor y las evidencias. Sus opciones toman los valores por defecto de una ejecución nueva en lo que falte (`options_from`). Si sus objetivos no casan con el inventario o su manifiesto no se puede registrar, se registra solo el estado; una imagen que falte en disco no cuenta como fallo (ver el paso 4). Las carpetas no se modifican, salvo que la ejecución estuviera activa al cerrarse: entonces se crea su fichero `parar` para que su motor, si siguiera vivo, no conecte con más subredes, igual que al reabrir una captura activa (paso 6). Lo que no se puede migrar (por ejemplo, un `trabajo.json` cuyo `id` no coincide con el de su carpeta) se avisa en la terminal y en el portal (`migration_failures`, en `/api/bootstrap`), y la carpeta se conserva y se reintenta en el siguiente arranque.
6. ✅ `trabajo.json` e `inventario.json` ya no se leen ni se escriben (salvo `trabajo.json` en la migración del paso 5). Cada ejecución del portal es una `importacion` cuyo campo `opciones` guarda `{"archivos": [...], "captura": {...}}`; su estado es el de su `captura`, o `preparada` si aún no se lanzó. Los objetivos se recalculan la primera vez que se abre la ejecución, no al arrancar: con el alcance vigente si no se lanzó, y con las URL de `captura` y el `rangos.txt` de la carpeta si ya se lanzó. El historial (`/api/jobs`) solo lleva id, nombre, fecha, estado y auditoría. Una captura que quedó activa al cerrarse el portal se cierra al reabrirlo con el estado final del manifiesto, o como `interrumpida`, y se pide a su motor que pare. Cada ejecución se carga por separado: si una no se puede leer (al arrancar, o al abrirla si lo que falla es el cálculo de sus objetivos), aparece igualmente en el historial, con el motivo y sin objetivos (y, si no se había lanzado, con estado `Error`; solo en el portal, la base no cambia), se avisa en la terminal y el resto arranca con normalidad.
