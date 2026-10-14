# Credenciales por defecto (bloque 6) — plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dédalo lleva un catálogo curado de credenciales por defecto y, cuando el operador lo pide con un botón, las prueba contra los servicios en alcance (HTTP Basic/Digest, login por formulario y FTP) con topes y pausas, y enseña dónde se entró.

**Architecture:** Lógica pura separada de la red, como el motor de IA: `catalogo.py` (fichero versionado → SQLite), `credenciales.py` (emparejar fingerprint→credenciales y el bucle de prueba, sin red) y `probador.py` (los tres probadores con librería estándar). La ejecución es un tipo nuevo `credenciales` que calca el ciclo de vida de `analisis` (misma cola, progreso, parar, una por importación, sustituir solo al terminar bien, filtro de alcance al mostrar).

**Tech Stack:** Python ≥3.12, solo librería estándar (`urllib`, `http.cookiejar`, `ftplib`, `ssl`, `fnmatch`, `json`, `sqlite3`). SQLite WAL. Frontend en `dedalo/static/` (HTML/CSS/JS a mano).

**Spec:** `docs/superpowers/specs/2026-10-14-credenciales-por-defecto-design.md`

## Global Constraints

- Python ≥ 3.12; paquete y comando `dedalo`.
- **Solo librería estándar.** Nada de pip; lo que sería una dependencia se escribe a mano.
- **Alcance:** solo se conecta con IP en alcance, comprobado **justo antes de conectar**, no solo al planificar; el código que conecta llega con un test que lo demuestra. La exclusión siempre gana.
- **Migraciones:** un cambio de esquema es una migración nueva y numerada en `dedalo/db.py`; las publicadas (1, 2, 3) no se tocan. La nueva es la **4**.
- **Portal local de un usuario:** escucha en `127.0.0.1`, verifica `Origin` y `X-Dedalo-Token`; sin cuentas.
- **Datos reales:** para probar, solo `ejemplos/` y `tests/`. No se abren ni se tocan `portal_datos/`, `salida/`, `pruebas_locales/`, `*.sqlite3` ni capturas.
- **CRLF en Windows:** editar con la herramienta de edición o en binario; nunca `sed -i`.
- **Pruebas:** `python -m unittest discover -s tests` termina en `OK`, sin red ni navegador. Los probadores se prueban con servicios de mentira en loopback (como `tests/test_modelo.py::FakeOllama`).
- **Commits** terminan con `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

## Review Focus

- **Host excluido después de probar:** un activo que se excluye tras la prueba deja de salir en los resultados (la exclusión gana al mostrar). → test en Task 6.
- **Servicio que bloquea:** tras N rechazos seguidos se abandona ese servicio y se respeta la pausa; nunca una ráfaga. → test en Task 5.
- **Panel HTTPS autofirmado:** un panel con certificado autofirmado (lo normal en aparatos) se prueba igual; no se verifica el certificado. → test en Task 4.
- **Entrada del catálogo o receta mal formada:** no tumba la ejecución; esa entrada se ignora (catálogo) o ese servicio queda `error` (prueba). → tests en Task 2 y Task 5.
- **Volver a probar tras un fallo:** si la nueva prueba falla o se interrumpe, se sigue viendo el último resultado completo (como el análisis). → test en Task 6.

---

### Task 1: Migración 4 — tipo `credenciales` y tablas

**Files:**
- Modify: `dedalo/db.py` (añadir la clave `4` a `MIGRATIONS`, tras la `3`)
- Test: `tests/test_db.py`

**Interfaces:**
- Produces: esquema 4 con `ejecucion.tipo` que admite `'credenciales'`; tablas `credencial_catalogo`, `credencial_resultado`, `config`; índices `credencial_catalogo_servicio`, `credencial_resultado_activo`.

- [ ] **Step 1: Write the failing test** en `tests/test_db.py` (añade estos tests a la clase existente que abre una base con `db.connect`):

```python
def test_migration_4_adds_credential_tables_and_type(self):
    with closing(db.connect(self.root)) as con:
        self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0], 4)
        tablas = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertLessEqual({"credencial_catalogo", "credencial_resultado", "config"}, tablas)
        indices = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        self.assertLessEqual({"credencial_catalogo_servicio", "credencial_resultado_activo"}, indices)
        audit = auditoria.default_audit(con)
        con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, nombre, estado, creada) "
                    "VALUES ('c1', ?, 'credenciales', 'x', 'en_cola', ?)", (audit, auditoria.now()))
        with self.assertRaises(sqlite3.IntegrityError):
            con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, nombre, estado, creada) "
                        "VALUES ('c2', ?, 'inventado', 'x', 'en_cola', ?)", (audit, auditoria.now()))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_db -v`
Expected: FAIL (user_version es 3; no existen las tablas).

- [ ] **Step 3: Write the migration.** En `dedalo/db.py`, dentro de `MIGRATIONS`, tras la entrada `3: """..."""`, añade la `4`. Reconstruye `ejecucion` para ampliar el CHECK de `tipo` (SQLite no permite cambiar un CHECK), igual que hizo la migración 3:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_db -v`
Expected: PASS.

- [ ] **Step 5: Run the whole suite and commit**

Run: `python -m unittest discover -s tests`
Expected: OK (las bases de los tests se crean ya en el esquema 4).

```bash
git add dedalo/db.py tests/test_db.py
git commit -m "Add migration 4: credenciales execution type and tables

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Catálogo — fichero versionado volcado a SQLite

**Files:**
- Create: `dedalo/datos/credenciales.json` (semilla curada)
- Create: `dedalo/catalogo.py`
- Test: `tests/test_catalogo.py`

**Interfaces:**
- Consumes: tabla `credencial_catalogo`, `config` (Task 1).
- Produces:
  - `catalogo.cargar(con, ruta=RUTA) -> int` — si la huella del fichero cambió, vacía y recarga `credencial_catalogo`; devuelve el número de filas cargadas. Idempotente.
  - `catalogo.entradas(con) -> list[dict]` — filas del catálogo como dicts (`fabricante, producto, version, servicio, usuario, clave, receta` ya decodificada a dict|None, `fuente, licencia`).
  - `catalogo.RUTA` — `Path` a `dedalo/datos/credenciales.json`.

- [ ] **Step 1: Write the failing test** en `tests/test_catalogo.py`:

```python
import json
from pathlib import Path
import tempfile
import unittest

from dedalo import catalogo, db


class CatalogoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.con = db.connect(self.root)

    def tearDown(self):
        self.con.close()
        self.temp.cleanup()

    def fichero(self, entradas):
        ruta = self.root / "credenciales.json"
        ruta.write_text(json.dumps({"version": "test", "entradas": entradas}, ensure_ascii=False), encoding="utf-8")
        return ruta

    def test_loads_entries_and_decodes_the_recipe(self):
        ruta = self.fichero([
            {"fabricante": "Cisco", "producto": "RV340", "servicio": "http-form",
             "credenciales": [{"usuario": "cisco", "clave": "cisco"}],
             "receta": {"ruta": "/login", "campo_usuario": "user", "campo_clave": "pwd"}},
            {"producto": "vsftpd", "servicio": "ftp", "credenciales": [{"usuario": "anonymous", "clave": ""}]},
        ])
        self.assertEqual(catalogo.cargar(self.con, ruta), 2)
        filas = catalogo.entradas(self.con)
        self.assertEqual({f["producto"] for f in filas}, {"RV340", "vsftpd"})
        cisco = next(f for f in filas if f["producto"] == "RV340")
        self.assertEqual(cisco["receta"]["campo_usuario"], "user")

    def test_reload_only_happens_when_the_file_changes(self):
        ruta = self.fichero([{"producto": "A", "servicio": "ftp", "credenciales": [{"usuario": "a", "clave": "b"}]}])
        self.assertEqual(catalogo.cargar(self.con, ruta), 1)
        self.assertEqual(catalogo.cargar(self.con, ruta), 0)  # misma huella: no recarga
        self.fichero([{"producto": "B", "servicio": "ftp", "credenciales": [{"usuario": "c", "clave": "d"}]}])
        self.assertEqual(catalogo.cargar(self.con, ruta), 1)
        self.assertEqual([f["producto"] for f in catalogo.entradas(self.con)], ["B"])

    def test_a_bad_entry_is_skipped_not_fatal(self):
        ruta = self.fichero([
            {"servicio": "ftp", "credenciales": [{"usuario": "a", "clave": "b"}]},  # sin producto: se ignora
            {"producto": "X", "servicio": "telnet", "credenciales": [{"usuario": "a", "clave": "b"}]},  # servicio no válido
            {"producto": "Y", "servicio": "ftp", "credenciales": [{"usuario": "a", "clave": "b"}]},  # válida
        ])
        self.assertEqual(catalogo.cargar(self.con, ruta), 1)
        self.assertEqual([f["producto"] for f in catalogo.entradas(self.con)], ["Y"])

    def test_the_shipped_catalog_loads(self):
        self.assertGreater(catalogo.cargar(self.con, catalogo.RUTA), 0)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_catalogo -v`
Expected: FAIL (`No module named 'dedalo.catalogo'`).

- [ ] **Step 3: Write `dedalo/catalogo.py`:**

```python
"""Catálogo curado de credenciales por defecto: fichero versionado volcado a SQLite.

La fuente de verdad es dedalo/datos/credenciales.json (revisable en git, licencia auditable).
Al arrancar se vuelca a la tabla credencial_catalogo; se recarga solo si el fichero cambió.
No contacta con nada.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

RUTA = Path(__file__).resolve().parent / "datos" / "credenciales.json"
SERVICIOS = ("http-basic", "http-form", "ftp")
_CAMPOS = ("fabricante", "producto", "version", "servicio", "usuario", "clave", "receta", "fuente", "licencia")


def _filas(datos: dict):
    """Una fila por credencial de cada entrada válida; las entradas mal formadas se ignoran."""
    for entrada in datos.get("entradas", []):
        if not isinstance(entrada, dict):
            continue
        producto, servicio = entrada.get("producto"), entrada.get("servicio")
        if not isinstance(producto, str) or not producto or servicio not in SERVICIOS:
            continue
        receta = json.dumps(entrada["receta"], ensure_ascii=False) if isinstance(entrada.get("receta"), dict) else ""
        for cred in entrada.get("credenciales", []):
            if not isinstance(cred, dict) or not isinstance(cred.get("usuario"), str) or not isinstance(cred.get("clave"), str):
                continue
            yield (entrada.get("fabricante", ""), producto, entrada.get("version", ""), servicio,
                   cred["usuario"], cred["clave"], receta, entrada.get("fuente", ""), entrada.get("licencia", ""))


def cargar(con, ruta: Path = RUTA) -> int:
    """Vuelca el fichero a credencial_catalogo si su huella cambió; devuelve cuántas filas cargó (0 si no recargó)."""
    datos = ruta.read_bytes()
    huella = hashlib.sha256(datos).hexdigest()
    guardada = con.execute("SELECT valor FROM config WHERE clave = 'catalogo_huella'").fetchone()
    if guardada and guardada[0] == huella:
        return 0
    filas = list(_filas(json.loads(datos)))
    with con:
        con.execute("DELETE FROM credencial_catalogo")
        con.executemany("INSERT INTO credencial_catalogo (fabricante, producto, version, servicio, usuario, clave, "
                        "receta, fuente, licencia) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", filas)
        con.execute("INSERT INTO config (clave, valor) VALUES ('catalogo_huella', ?) "
                    "ON CONFLICT (clave) DO UPDATE SET valor = excluded.valor", (huella,))
    return len(filas)


def entradas(con) -> list[dict]:
    filas = con.execute(f"SELECT {', '.join(_CAMPOS)} FROM credencial_catalogo ORDER BY id").fetchall()
    return [{**dict(fila), "receta": json.loads(fila["receta"]) if fila["receta"] else None} for fila in filas]
```

- [ ] **Step 4: Write the seed `dedalo/datos/credenciales.json`** (semilla pequeña para la demo; cubre los tres probadores y el laboratorio). Origen/licencia documentados por entrada:

```json
{
  "version": "2026-10-14",
  "nota": "Credenciales por defecto curadas a mano para la demo. Ampliar desde recopilaciones públicas tras revisar su licencia.",
  "entradas": [
    {"fabricante": "Genérico", "producto": "Panel de administración", "servicio": "http-form",
     "credenciales": [{"usuario": "admin", "clave": "admin"}, {"usuario": "admin", "clave": "password"}],
     "receta": {"ruta": "/login", "campo_usuario": "usuario", "campo_clave": "clave", "exito": {"texto_falla": "incorrect"}},
     "fuente": "curado a mano", "licencia": "propio"},
    {"fabricante": "Genérico", "producto": "lighttpd", "servicio": "http-basic",
     "credenciales": [{"usuario": "admin", "clave": "admin"}],
     "fuente": "curado a mano", "licencia": "propio"},
    {"fabricante": "Genérico", "producto": "vsftpd", "servicio": "ftp",
     "credenciales": [{"usuario": "anonymous", "clave": "anonymous"}, {"usuario": "ftp", "clave": "ftp"}],
     "fuente": "curado a mano", "licencia": "propio"}
  ]
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m unittest tests.test_catalogo -v`
Expected: PASS (incluido `test_the_shipped_catalog_loads`).

- [ ] **Step 6: Commit**

```bash
git add dedalo/catalogo.py dedalo/datos/credenciales.json tests/test_catalogo.py
git commit -m "Add the curated default-credentials catalog loaded into SQLite

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Emparejar fingerprint → credenciales

**Files:**
- Create: `dedalo/credenciales.py`
- Test: `tests/test_credenciales.py`

**Interfaces:**
- Consumes: la forma de un servicio del inventario (`inventory.build`): `{puerto, protocolo, servicio, tunel, producto, version, detalle, cpe, scripts}`.
- Produces:
  - `credenciales.tipos_de(servicio: dict) -> set[str]` — qué clases de login admite ese puerto: `{"http-basic","http-form"}` para web, `{"ftp"}` para FTP, `set()` si ninguna.
  - `credenciales.es_https(servicio: dict) -> bool`.
  - `credenciales.objetivos(activo: dict, entradas: list[dict]) -> list[dict]` — por cada servicio del activo, las credenciales del catálogo que le pegan por tipo, producto (subcadena, sin distinguir mayúsculas, en producto + título web) y versión (patrón `fnmatch`, vacío = cualquiera). Cada objetivo: `{"puerto","protocolo","servicio","https","usuario","clave","receta"}`. Si nada casa, no genera objetivos.

- [ ] **Step 1: Write the failing test** en `tests/test_credenciales.py`:

```python
import unittest

from dedalo import credenciales


def servicio(puerto, nombre, producto="", version="", tunel="", titulo=""):
    scripts = [{"id": "http-title", "output": titulo}] if titulo else []
    return {"puerto": puerto, "protocolo": "tcp", "servicio": nombre, "tunel": tunel,
            "producto": producto, "version": version, "detalle": "", "cpe": [], "scripts": scripts}


CATALOGO = [
    {"producto": "Panel de administración", "version": "", "servicio": "http-form", "usuario": "admin", "clave": "admin",
     "receta": {"ruta": "/login", "campo_usuario": "usuario", "campo_clave": "clave"}},
    {"producto": "lighttpd", "version": "1.*", "servicio": "http-basic", "usuario": "admin", "clave": "admin", "receta": None},
    {"producto": "vsftpd", "version": "", "servicio": "ftp", "usuario": "ftp", "clave": "ftp", "receta": None},
]


class MatchTests(unittest.TestCase):
    def test_a_web_port_takes_basic_and_form_an_ftp_port_takes_ftp(self):
        self.assertEqual(credenciales.tipos_de(servicio(8443, "https", tunel="ssl")), {"http-basic", "http-form"})
        self.assertEqual(credenciales.tipos_de(servicio(80, "http")), {"http-basic", "http-form"})
        self.assertEqual(credenciales.tipos_de(servicio(21, "ftp")), {"ftp"})
        self.assertEqual(credenciales.tipos_de(servicio(22, "ssh")), set())

    def test_https_is_detected_by_tunnel_name_or_port(self):
        self.assertTrue(credenciales.es_https(servicio(8443, "http", tunel="ssl")))
        self.assertTrue(credenciales.es_https(servicio(443, "http")))
        self.assertFalse(credenciales.es_https(servicio(80, "http")))

    def test_only_matching_products_and_versions_become_targets(self):
        activo = {"ip": "10.30.1.21", "servicios": [
            servicio(8443, "https", producto="lighttpd", version="1.4.69", tunel="ssl", titulo="Panel de administración"),
            servicio(21, "ftp", producto="vsftpd", version="3.0.5"),
            servicio(3389, "ms-wbt-server"),  # RDP: ninguna
        ]}
        objetivos = credenciales.objetivos(activo, CATALOGO)
        servicios = sorted({(o["puerto"], o["servicio"]) for o in objetivos})
        # El 8443 casa con el panel (form, por el título) y con lighttpd (basic, por el producto y versión 1.*); el 21 con vsftpd.
        self.assertEqual(servicios, [(21, "ftp"), (8443, "http-basic"), (8443, "http-form")])
        self.assertTrue(all(o["https"] for o in objetivos if o["puerto"] == 8443))

    def test_a_version_that_does_not_match_is_left_out(self):
        activo = {"ip": "x", "servicios": [servicio(80, "http", producto="lighttpd", version="2.0.0")]}
        self.assertEqual(credenciales.objetivos(activo, CATALOGO), [])  # lighttpd pide 1.*
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_credenciales -v`
Expected: FAIL (`No module named 'dedalo.credenciales'`).

- [ ] **Step 3: Write the matching half of `dedalo/credenciales.py`:**

```python
"""Credenciales por defecto: empareja el fingerprint de cada servicio con el catálogo y prueba.

No contacta con ningún objetivo: eso lo hace probador.py. Aquí solo se decide qué credenciales
tocan a cada servicio y se recorre la lista llamando a un probador que se pasa como argumento.
"""

from __future__ import annotations

import fnmatch

_WEB = {"http", "https", "http-proxy", "http-alt", "https-alt"}
_FTP = {"ftp", "ftp-data"}


def _titulo(servicio: dict) -> str:
    return next((s.get("output", "") for s in servicio.get("scripts", []) if s.get("id") == "http-title"), "")


def es_https(servicio: dict) -> bool:
    return servicio.get("tunel") == "ssl" or servicio.get("servicio") == "https" or servicio.get("puerto") == 443


def tipos_de(servicio: dict) -> set[str]:
    if servicio.get("protocolo") != "tcp":
        return set()
    if servicio.get("servicio") in _WEB or servicio.get("tunel") == "ssl" or _titulo(servicio):
        return {"http-basic", "http-form"}
    if servicio.get("servicio") in _FTP or servicio.get("puerto") == 21:
        return {"ftp"}
    return set()


def _casa(entrada: dict, servicio: dict) -> bool:
    texto = f"{servicio.get('producto', '')} {_titulo(servicio)}".lower()
    if entrada["producto"].lower() not in texto:
        return False
    patron = entrada["version"]
    return not patron or fnmatch.fnmatch((servicio.get("version") or ""), patron)


def objetivos(activo: dict, entradas: list[dict]) -> list[dict]:
    """Por cada servicio del activo, las credenciales del catálogo que le pegan (tipo, producto y versión)."""
    salida = []
    for servicio in activo.get("servicios", []):
        tipos = tipos_de(servicio)
        for entrada in entradas:
            if entrada["servicio"] in tipos and _casa(entrada, servicio):
                salida.append({"puerto": servicio["puerto"], "protocolo": servicio.get("protocolo", "tcp"),
                               "servicio": entrada["servicio"], "https": es_https(servicio),
                               "usuario": entrada["usuario"], "clave": entrada["clave"], "receta": entrada["receta"]})
    return salida
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_credenciales -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add dedalo/credenciales.py tests/test_credenciales.py
git commit -m "Match each service's fingerprint to its default credentials

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Probadores (HTTP Basic/Digest, formulario, FTP)

**Files:**
- Create: `dedalo/probador.py`
- Test: `tests/test_probador.py`

**Interfaces:**
- Produces:
  - `probador.probar(ip: str, objetivo: dict, timeout: float = 8) -> bool` — intenta entrar con `objetivo["usuario"]/["clave"]` según `objetivo["servicio"]`; `True` si entró, `False` si las credenciales no valen. Lanza `OSError`/`ValueError` si el servicio no responde o la receta es inservible.
  - Conexión **directa, sin proxy del sistema**; en HTTPS **no se verifica el certificado** (aparatos con certificado autofirmado).

- [ ] **Step 1: Write the failing test** en `tests/test_probador.py` (servidores de mentira en loopback, al estilo de `tests/test_modelo.py::FakeOllama`):

```python
import base64
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import threading
import unittest

from dedalo import probador
from tests.test_dedalo import ROOT


class Panel(BaseHTTPRequestHandler):
    def do_GET(self):  # HTTP Basic: admin/admin
        if self.headers.get("Authorization") == "Basic " + base64.b64encode(b"admin:admin").decode():
            self.send_response(200); self.end_headers()
        else:
            self.send_response(401); self.send_header("WWW-Authenticate", "Basic realm=x"); self.end_headers()

    def do_POST(self):  # formulario: usuario=admin&clave=admin
        cuerpo = self.rfile.read(int(self.headers["Content-Length"])).decode()
        if "usuario=admin" in cuerpo and "clave=admin" in cuerpo:
            self.send_response(302); self.send_header("Location", "/panel"); self.end_headers()
        else:
            self.send_response(200); self.end_headers(); self.wfile.write(b"login incorrect")

    def log_message(self, *a):
        pass


@contextmanager
def sirviendo(handler):
    servidor = HTTPServer(("127.0.0.1", 0), handler)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True); hilo.start()
    try:
        yield servidor.server_address[1]
    finally:
        servidor.shutdown(); servidor.server_close(); hilo.join()


@contextmanager
def sirviendo_https(handler):
    servidor = HTTPServer(("127.0.0.1", 0), handler)
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # certificado autofirmado de prueba
    contexto.load_cert_chain(ROOT / "tests/fixtures/local-cert.pem", ROOT / "tests/fixtures/local-key.pem")
    servidor.socket = contexto.wrap_socket(servidor.socket, server_side=True)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True); hilo.start()
    try:
        yield servidor.server_address[1]
    finally:
        servidor.shutdown(); servidor.server_close(); hilo.join()


class ProbadorTests(unittest.TestCase):
    def objetivo(self, servicio, puerto, usuario, clave, receta=None, https=False):
        return {"puerto": puerto, "protocolo": "tcp", "servicio": servicio, "https": https,
                "usuario": usuario, "clave": clave, "receta": receta}

    def test_http_basic_true_with_the_right_password_false_with_the_wrong_one(self):
        with sirviendo(Panel) as puerto:
            self.assertTrue(probador.probar("127.0.0.1", self.objetivo("http-basic", puerto, "admin", "admin")))
            self.assertFalse(probador.probar("127.0.0.1", self.objetivo("http-basic", puerto, "admin", "malo")))

    def test_http_form_reads_the_recipe_success_signal(self):
        receta = {"ruta": "/login", "campo_usuario": "usuario", "campo_clave": "clave", "exito": {"texto_falla": "incorrect"}}
        with sirviendo(Panel) as puerto:
            self.assertTrue(probador.probar("127.0.0.1", self.objetivo("http-form", puerto, "admin", "admin", receta)))
            self.assertFalse(probador.probar("127.0.0.1", self.objetivo("http-form", puerto, "admin", "malo", receta)))

    def test_an_unreachable_service_raises(self):
        with self.assertRaises(OSError):
            probador.probar("127.0.0.1", self.objetivo("http-basic", 1, "admin", "admin"), timeout=1)

    def test_a_self_signed_https_panel_is_probed_without_verifying(self):
        with sirviendo_https(Panel) as puerto:
            self.assertTrue(probador.probar("127.0.0.1", self.objetivo("http-basic", puerto, "admin", "admin", https=True)))
```

Para FTP, añade un test con un servidor FTP de mentira mínimo (acepta `USER`/`PASS` y responde `230` a `ftp/ftp`, `530` a lo demás) sobre un socket en loopback; comprueba `True` con `ftp/ftp` y `False` con una clave mala. Si montar el FTP falso resulta frágil, prueba `probador._ftp` parcheando `ftplib.FTP` por un doble que registra `login(usuario, clave)` y lanza `error_perm` con la clave mala.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_probador -v`
Expected: FAIL (`No module named 'dedalo.probador'`).

- [ ] **Step 3: Write `dedalo/probador.py`:**

```python
"""Los tres probadores de credenciales por defecto, con librería estándar.

Conexión directa (sin el proxy del sistema) a la red auditada; en HTTPS no se verifica el
certificado, porque los aparatos suelen llevar uno autofirmado. El alcance lo comprueba quien
llama, justo antes (credenciales.py / web.py): aquí solo se intenta un login.
"""

from __future__ import annotations

import base64
import ftplib
import http.client
import ssl
import urllib.error
import urllib.parse
import urllib.request

# Sin proxy: el tráfico va a la red auditada, no a un proxy del sistema.
_SIN_PROXY = urllib.request.ProxyHandler({})
_SIN_VERIFICAR = ssl.create_default_context()
_SIN_VERIFICAR.check_hostname = False
_SIN_VERIFICAR.verify_mode = ssl.CERT_NONE


def _url(ip: str, objetivo: dict, ruta: str = "/") -> str:
    esquema = "https" if objetivo["https"] else "http"
    anfitrion = f"[{ip}]" if ":" in ip else ip
    return f"{esquema}://{anfitrion}:{objetivo['puerto']}{ruta}"


def _abrir(request, timeout):
    opener = urllib.request.build_opener(_SIN_PROXY, urllib.request.HTTPSHandler(context=_SIN_VERIFICAR))
    return opener.open(request, timeout=timeout)


def _http_basic(ip, objetivo, timeout) -> bool:
    token = base64.b64encode(f"{objetivo['usuario']}:{objetivo['clave']}".encode()).decode()
    request = urllib.request.Request(_url(ip, objetivo), headers={"Authorization": "Basic " + token})
    try:
        with _abrir(request, timeout) as respuesta:
            return respuesta.status < 400
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return False
        raise


def _http_form(ip, objetivo, timeout) -> bool:
    receta = objetivo.get("receta") or {}
    if not receta.get("campo_usuario") or not receta.get("campo_clave"):
        raise ValueError("la receta del formulario no dice los campos de usuario/clave")
    campos = {receta["campo_usuario"]: objetivo["usuario"], receta["campo_clave"]: objetivo["clave"],
              **(receta.get("campos_fijos") or {})}
    datos = urllib.parse.urlencode(campos).encode()
    request = urllib.request.Request(_url(ip, objetivo, receta.get("ruta", "/")), data=datos)
    exito = receta.get("exito") or {}
    try:
        with _abrir(request, timeout) as respuesta:  # urllib sigue los 3xx; mira la respuesta final
            cuerpo = respuesta.read(65536).decode("utf-8", "replace").lower()
    except urllib.error.HTTPError as exc:
        return exc.code == exito.get("codigo")
    if exito.get("texto_falla"):
        return exito["texto_falla"].lower() not in cuerpo
    if exito.get("codigo"):
        return respuesta.status == exito["codigo"]
    return respuesta.status < 400  # sin señal en la receta: entró si no hubo error


def _ftp(ip, objetivo, timeout) -> bool:
    cliente = ftplib.FTP(timeout=timeout)
    cliente.connect(ip, objetivo["puerto"])
    try:
        cliente.login(objetivo["usuario"], objetivo["clave"])
        return True
    except ftplib.error_perm:
        return False
    finally:
        try:
            cliente.close()
        except OSError:
            pass


_PROBADORES = {"http-basic": _http_basic, "http-form": _http_form, "ftp": _ftp}


def probar(ip: str, objetivo: dict, timeout: float = 8) -> bool:
    return _PROBADORES[objetivo["servicio"]](ip, objetivo, timeout)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_probador -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add dedalo/probador.py tests/test_probador.py
git commit -m "Add the three stdlib credential probers (HTTP Basic, form, FTP)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Bucle de prueba con topes, pausas y parada

**Files:**
- Modify: `dedalo/credenciales.py` (añadir el bucle `probar_activos` y la excepción `Interrumpido`)
- Test: `tests/test_credenciales.py`

**Interfaces:**
- Consumes: `credenciales.objetivos` (Task 3); un `probar(ip, objetivo) -> bool` como el de `probador.probar` (inyectado, para poder probar sin red).
- Produces:
  - `credenciales.Interrumpido` (Exception).
  - `credenciales.probar_activos(activos, entradas, probar, parar=lambda: False, avance=lambda h, t: None, intentos=5, pausa=lambda: None) -> list[dict]` — por cada servicio con objetivos, prueba sus credenciales hasta que una entra o se agotan o se superan `intentos` rechazos; una fila de resultado por servicio: `{ip, puerto, protocolo, servicio, estado ('entrada'|'fallo'|'error'), usuario, clave, detalle, orden}`. `parar` se consulta antes de cada servicio (lanza `Interrumpido`); `avance(hechos, total)` al empezar y tras cada servicio; `pausa()` entre intentos.

- [ ] **Step 1: Write the failing test** en `tests/test_credenciales.py`:

```python
class LoopTests(unittest.TestCase):
    def activo(self, ip="10.30.1.21"):
        return {"ip": ip, "servicios": [servicio(8443, "https", producto="lighttpd", version="1.4", tunel="ssl",
                                                  titulo="Panel de administración"), servicio(21, "ftp", producto="vsftpd")]}

    def test_records_entry_failure_and_counts_progress(self):
        vistos = []
        def probar(ip, objetivo):
            return objetivo["clave"] == "admin" and objetivo["servicio"] == "http-basic"
        avances = []
        filas = credenciales.probar_activos([self.activo()], CATALOGO, probar,
                                            avance=lambda h, t: avances.append((h, t)))
        por_servicio = {(f["puerto"], f["servicio"]): f["estado"] for f in filas}
        self.assertEqual(por_servicio[(8443, "http-basic")], "entrada")
        self.assertEqual(por_servicio[(8443, "http-form")], "fallo")
        self.assertEqual(por_servicio[(21, "ftp")], "fallo")
        entrada = next(f for f in filas if f["estado"] == "entrada")
        self.assertEqual((entrada["usuario"], entrada["clave"]), ("admin", "admin"))
        self.assertEqual(avances[0], (0, 3))
        self.assertEqual(avances[-1], (3, 3))

    def test_a_prober_error_is_recorded_without_stopping_the_run(self):
        def probar(ip, objetivo):
            if objetivo["servicio"] == "ftp":
                raise OSError("sin respuesta")
            return False
        filas = credenciales.probar_activos([self.activo()], CATALOGO, probar)
        ftp = next(f for f in filas if f["servicio"] == "ftp")
        self.assertEqual(ftp["estado"], "error")
        self.assertEqual(len(filas), 3)  # los otros servicios se probaron igual

    def test_stops_a_service_after_too_many_refusals(self):
        intentos = []
        def probar(ip, objetivo):
            intentos.append(objetivo["clave"]); return False
        entradas = [{"producto": "lighttpd", "version": "", "servicio": "http-basic", "usuario": "a", "clave": c, "receta": None}
                    for c in ("1", "2", "3", "4", "5")]
        credenciales.probar_activos([{"ip": "x", "servicios": [servicio(80, "http", producto="lighttpd")]}],
                                    entradas, probar, intentos=2)
        self.assertEqual(len(intentos), 2)  # se abandona tras 2 rechazos, no prueba las 5

    def test_parar_before_a_service_raises_interrumpido(self):
        with self.assertRaises(credenciales.Interrumpido):
            credenciales.probar_activos([self.activo()], CATALOGO, lambda ip, o: False, parar=lambda: True)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_credenciales -v`
Expected: FAIL (`probar_activos`/`Interrumpido` no existen).

- [ ] **Step 3: Add the loop to `dedalo/credenciales.py`:**

```python
class Interrumpido(Exception):
    """Se pidió parar la prueba de credenciales (por ejemplo, porque se cierra el portal)."""


def probar_activos(activos, entradas, probar, parar=lambda: False, avance=lambda hechos, total: None,
                   intentos=5, pausa=lambda: None) -> list[dict]:
    """Prueba, servicio por servicio, las credenciales que le tocan; una fila de resultado por servicio."""
    trabajos = [(activo["ip"], obj) for activo in activos for obj in objetivos(activo, entradas)]
    # Un servicio puede tener varias credenciales; se agrupan para contar «servicios», no intentos.
    por_servicio: dict = {}
    for ip, obj in trabajos:
        por_servicio.setdefault((ip, obj["puerto"], obj["servicio"]), []).append(obj)
    filas, total = [], len(por_servicio)
    avance(0, total)
    for (ip, puerto, servicio), objs in por_servicio.items():
        if parar():
            raise Interrumpido()
        fila = {"ip": ip, "puerto": puerto, "protocolo": objs[0]["protocolo"], "servicio": servicio,
                "estado": "fallo", "usuario": "", "clave": "", "detalle": ""}
        for numero, obj in enumerate(objs):
            if numero >= intentos:
                fila["detalle"] = f"Se abandonó tras {intentos} intentos sin entrar."
                break
            if numero:
                pausa()
            try:
                if probar(ip, obj):
                    fila.update(estado="entrada", usuario=obj["usuario"], clave=obj["clave"])
                    break
            except Exception as exc:  # servicio caído, receta inservible: ese servicio queda en error
                fila.update(estado="error", detalle=str(exc))
                break
        filas.append(fila)
        avance(len(filas), total)
    return [fila | {"orden": orden} for orden, fila in enumerate(_ordenar(filas))]


def _ordenar(filas):
    # Lo importante arriba: primero donde se entró, luego por IP y puerto.
    prioridad = {"entrada": 0, "fallo": 1, "error": 1}
    return sorted(filas, key=lambda f: (prioridad[f["estado"]], f["ip"], f["puerto"]))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_credenciales -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add dedalo/credenciales.py tests/test_credenciales.py
git commit -m "Test credentials service by service with caps, pauses and stop

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Ejecución en la base (auditoria.py)

**Files:**
- Modify: `dedalo/auditoria.py`
- Test: `tests/test_auditoria.py`

**Interfaces:**
- Consumes: `_derived`, `_set_state`, `set_state`, `now`, `scope`, `audit_of`, `start_analysis`/`finish_analysis` como patrón (ya existen).
- Produces (calcan las de análisis, con tipo `credenciales`):
  - `start_credential_test(con, import_id, options) -> str` — crea en cola; borra los intentos anteriores no `completa`.
  - `begin_credential_test(con, test_id) -> bool` — `en_cola`→`en_curso` (reusa `_set_state(..., only_from="en_cola")`).
  - `stop_credential_test(con, import_id) -> str | None` — `cancelada` (en cola) o `deteniendo` (en curso), o None.
  - `credential_status(con, import_id) -> dict | None` — `{estado, error}`.
  - `finish_credential_test(con, test_id, rows) -> None` — guarda en `credencial_resultado`, marca `completa` y sustituye al anterior, en una transacción.
  - `credential_results(con, import_id) -> list[dict]` — filas ordenadas, solo activos en alcance vigente.
  - `close_interrupted_analyses` pasa a cerrar también las de `credenciales`.

- [ ] **Step 1: Write the failing test** en `tests/test_auditoria.py` (reusa los ayudantes `load_in_scope`, `now`, y añade una fila de resultado de ejemplo):

```python
def credential_row(self, ip, order, estado="entrada", servicio="http-form"):
    return {"ip": ip, "orden": order, "puerto": 8443, "protocolo": "tcp", "servicio": servicio,
            "estado": estado, "usuario": "admin", "clave": "admin", "detalle": ""}

def test_credential_test_keeps_results_and_replaces_only_on_complete(self):
    self.load_in_scope("lunes")
    self.assertEqual((auditoria.credential_status(self.con, "lunes"), auditoria.credential_results(self.con, "lunes")), (None, []))
    first = auditoria.start_credential_test(self.con, "lunes", {})
    self.assertTrue(auditoria.begin_credential_test(self.con, first))
    auditoria.finish_credential_test(self.con, first, [self.credential_row("192.0.2.10", 0)])
    self.assertEqual(auditoria.credential_status(self.con, "lunes"), {"estado": "completa", "error": ""})
    self.assertEqual([r["ip"] for r in auditoria.credential_results(self.con, "lunes")], ["192.0.2.10"])
    second = auditoria.start_credential_test(self.con, "lunes", {})  # vuelve a probar
    auditoria.set_state(self.con, second, "error", "sin respuesta")
    self.assertEqual(auditoria.credential_status(self.con, "lunes")["estado"], "error")
    self.assertEqual([r["ip"] for r in auditoria.credential_results(self.con, "lunes")], ["192.0.2.10"])  # el bueno sigue

def test_a_host_excluded_after_the_credential_test_is_left_out(self):
    self.load_in_scope("lunes")
    test = auditoria.start_credential_test(self.con, "lunes", {})
    auditoria.finish_credential_test(self.con, test, [self.credential_row("192.0.2.10", 0), self.credential_row("192.0.2.20", 1)])
    auditoria.update_audit(self.con, self.audit, "Laboratorio", "192.0.2.0/24", "192.0.2.20")
    self.assertEqual([r["ip"] for r in auditoria.credential_results(self.con, "lunes")], ["192.0.2.10"])

def test_stopping_and_closing_a_credential_test(self):
    self.load_in_scope("lunes")
    self.assertIsNone(auditoria.stop_credential_test(self.con, "lunes"))
    test = auditoria.start_credential_test(self.con, "lunes", {})
    self.assertEqual(auditoria.stop_credential_test(self.con, "lunes"), "cancelada")
    self.assertFalse(auditoria.begin_credential_test(self.con, test))
    other = auditoria.start_credential_test(self.con, "lunes", {})
    auditoria.begin_credential_test(self.con, other)
    self.assertEqual(auditoria.stop_credential_test(self.con, "lunes"), "deteniendo")
    auditoria.close_interrupted_analyses(self.con)
    self.assertEqual(auditoria.credential_status(self.con, "lunes")["estado"], "interrumpida")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_auditoria -v`
Expected: FAIL (las funciones `*_credential_test` no existen).

- [ ] **Step 3: Add the functions to `dedalo/auditoria.py`** (junto a las de análisis; reusan `_derived`, `_set_state`, `now`, `scope`, `audit_of`). El patrón es el mismo que `start_analysis`/`begin_analysis`/`stop_analysis`/`analysis_status`/`finish_analysis`/`priorities` cambiando `'analisis'`→`'credenciales'`, la tabla `prioridad`→`credencial_resultado` y sus columnas:

```python
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
```

Y amplía `close_interrupted_analyses` para cerrar también las de credenciales — cambia su `WHERE` a:

```python
                    "WHERE tipo IN ('analisis', 'credenciales') AND estado IN ('en_cola', 'en_curso', 'deteniendo')", (now(),))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_auditoria -v`
Expected: PASS.

- [ ] **Step 5: Run the whole suite and commit**

Run: `python -m unittest discover -s tests`
Expected: OK.

```bash
git add dedalo/auditoria.py tests/test_auditoria.py
git commit -m "Store the credential-test execution, mirroring the analysis

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Lanzar la prueba desde el portal (web.py)

**Files:**
- Modify: `dedalo/web.py`
- Test: `tests/test_web.py`

**Interfaces:**
- Consumes: `auditoria.start_credential_test/begin/stop/status/finish/credential_results`, `catalogo.cargar/entradas`, `credenciales.probar_activos`, `probador.probar`, `inventory.build`, `auditoria.observed_hosts`.
- Produces: `PortalStore.test_credentials(job_id, payload=None)`, `PortalStore.stop_credentials(job_id)`, `PortalStore.models`-style nada; `detail` añade `response["credenciales"]` (estado + `progreso`) y `response["credenciales_resultados"]`. Rutas POST `…/probar-credenciales` y `…/detener-credenciales`.

- [ ] **Step 1: Write the failing test** en `tests/test_web.py` (reusa `self.create`, `self.request`, `self.settled`/`self.until`, `redirect_stderr`):

```python
def credential_probe(self, resultado):
    """Prueba de credenciales falsa, sin red: `resultado(ip, objetivo) -> bool`."""
    return patch("dedalo.web.probador.probar", side_effect=resultado)

def test_credential_test_needs_the_token_and_same_origin(self):
    job = self.create()
    with patch("dedalo.web.probador.probar") as probar:
        for route in ("probar-credenciales", "detener-credenciales"):
            for headers in ({"X-Dedalo-Token": "wrong"}, {"Origin": "https://example.org"}):
                self.assertEqual(self.request("/api/jobs/" + job["id"] + "/" + route, {}, headers)[0], 403)
        self.assertIsNone(self.store.detail(job["id"])["credenciales"])
    probar.assert_not_called()

def test_running_a_credential_test_stores_what_got_in(self):
    job = self.create()
    def probar(ip, objetivo):
        return objetivo["clave"] == "admin"
    with self.credential_probe(probar):
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/probar-credenciales", {})[0], 202)
        detail = self.settled_credentials(job["id"])
    self.assertEqual(detail["credenciales"]["estado"], "completa")
    # al menos un «entró» si el laboratorio de prueba tiene un servicio web con admin/admin
    self.assertTrue(any(r["estado"] == "entrada" for r in detail["credenciales_resultados"]) or detail["credenciales_resultados"] == [])

def test_a_credential_test_in_progress_is_not_restarted(self):
    job = self.create()
    self.store.jobs[job["id"]]["estado"] = "en_curso"
    self.assertEqual(self.request("/api/jobs/" + job["id"] + "/probar-credenciales", {})[0], 409)
    self.store.jobs[job["id"]]["estado"] = "preparada"
```

Añade un ayudante `settled_credentials(self, job_id)` igual que `settled`, mirando `detail(job_id)["credenciales"]["estado"]`. El fixture de `self.create()` (ejemplos/escaneo.xml) puede no tener servicios que casen; por eso el test acepta lista vacía. La prueba de que «entró» de verdad va mejor con el laboratorio en integración (Task 9) o con un activo construido a mano; si prefieres pinta aquí un `observed_hosts` con un servicio `http` producto `lighttpd` para forzar un objetivo.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_web -v -k credential`
Expected: FAIL (ni las rutas ni los métodos existen).

- [ ] **Step 3: Implement in `dedalo/web.py`.** Calca `analyze`/`stop_analysis`/`_run_analysis`/`_analyse` cambiando el modelo por el catálogo y el probador. En `__init__`, junto a `self.analysis_progress = {}`, añade `self.credential_progress = {}`. En `_load`, tras `auditoria.close_interrupted_analyses(con)`, añade `catalogo.cargar(con)` (vuelca el catálogo al abrir). Importa `catalogo, credenciales, probador` arriba. Métodos:

```python
    def test_credentials(self, job_id, payload=None):
        """Encola la prueba de credenciales por defecto de los hosts en alcance; solo lee la base al encolar."""
        with self.lock:
            meta = self._meta(job_id)
            if self.closing or meta["estado"] in ACTIVE:
                raise Conflict("Espera a que termine la captura antes de probar credenciales.")
            with closing(self.database()) as con:
                estado = auditoria.credential_status(con, job_id)
                if estado and estado["estado"] in ACTIVE:
                    raise Conflict("Ya hay una prueba de credenciales de esta ejecución en marcha.")
                test_id = auditoria.start_credential_test(con, job_id, {})
            self.pending.put(("credenciales", (job_id, test_id)))
        return self.detail(job_id)

    def stop_credentials(self, job_id):
        with self.lock:
            self._meta(job_id)
            with closing(self.database()) as con:
                if auditoria.stop_credential_test(con, job_id) is None:
                    raise Conflict("Esta ejecución no tiene una prueba de credenciales en marcha.")
        return self.detail(job_id)

    def _run_credentials(self, job_id, test_id):
        try:
            self._test_credentials(job_id, test_id)
        except Exception as exc:
            print(f"Error del portal: no se pudo completar la prueba de credenciales de {job_id}: {exc}", file=sys.stderr)
            try:
                with closing(self.database()) as con:
                    auditoria.set_state(con, test_id, "error",
                                        "No se pudo completar la prueba. Consulta la terminal del portal.")
            except Exception as again:
                print(f"Error del portal: no se pudo cerrar la prueba de {job_id}: {again}", file=sys.stderr)

    def _test_credentials(self, job_id, test_id):
        with closing(self.database()) as con:
            if not auditoria.begin_credential_test(con, test_id):
                return  # se canceló en la cola, o otra la sustituyó
            current = auditoria.scope(con, auditoria.audit_of(con, job_id))
            observed = auditoria.observed_hosts(con, job_id)
            entradas = catalogo.entradas(con)

        def parar():
            if self.closing:
                return True
            with closing(self.database()) as con:
                estado = auditoria.credential_status(con, job_id)
            return estado is None or estado["estado"] == "deteniendo"

        def avance(hechos, total):
            with self.lock:
                self.credential_progress[job_id] = {"hechos": hechos, "total": total}

        def probar(ip, objetivo):
            # El alcance se recomprueba justo antes de conectar: la exclusión gana.
            if current.status(ip) != current.IN:
                raise ValueError("fuera de alcance")
            return probador.probar(ip, objetivo)

        try:
            hosts = [a for a in inventory.build(observed, [])["activos"]
                     if a["servicios"] and current.status(a["ip"]) == current.IN]
            rows = credenciales.probar_activos(hosts, entradas, probar, parar=parar, avance=avance, pausa=lambda: time.sleep(1))
            state, error = "completa", ""
        except credenciales.Interrumpido:
            state = "interrumpida"
            error = "El portal se cerró antes de terminar." if self.closing else "Detenido desde el portal antes de terminar."
        except Exception as exc:
            print(f"Error del portal: no se pudo probar credenciales en {job_id}: {exc}", file=sys.stderr)
            state = "error"
            error = str(exc) if isinstance(exc, ValueError) else "No se pudo completar la prueba. Consulta la terminal del portal."
        finally:
            with self.lock:
                self.credential_progress.pop(job_id, None)
        with closing(self.database()) as con:
            if state == "completa":
                auditoria.finish_credential_test(con, test_id, rows)
            else:
                auditoria.set_state(con, test_id, state, error)
```

En `detail`, junto a las líneas de `analisis`/`prioridades`:

```python
            response["credenciales"] = auditoria.credential_status(con, job_id)
            response["credenciales_resultados"] = auditoria.credential_results(con, job_id)
```

y tras leerlo, adjunta el progreso (como el del análisis):

```python
        with self.lock:
            progreso_c = self.credential_progress.get(job_id)
        if progreso_c and response["credenciales"] and response["credenciales"]["estado"] in ACTIVE:
            response["credenciales"]["progreso"] = progreso_c
```

En `_worker`, junto al `if kind == "analisis"`:

```python
            if kind == "credenciales":
                self._run_credentials(*payload)
                continue
```

En el router (`dispatch`, rama `mutate`), junto a `analizar`/`detener-analisis`:

```python
                    if parts[3] == "probar-credenciales":
                        self.json(store.test_credentials(parts[2], payload), 202)
                        return
                    if parts[3] == "detener-credenciales":
                        self.json(store.stop_credentials(parts[2]))
                        return
```

Comprueba que `import time` ya está en `web.py` (lo usa `reject`); si no, añádelo.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_web -v -k credential`
Expected: PASS.

- [ ] **Step 5: Run the whole suite and commit**

Run: `python -m unittest discover -s tests`
Expected: OK.

```bash
git add dedalo/web.py tests/test_web.py
git commit -m "Launch credential testing from the portal, mirroring the analysis

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: Pestaña «Credenciales» en el portal

**Files:**
- Modify: `dedalo/static/index.html`, `dedalo/static/app.js`, `dedalo/static/style.css`
- Test: `tests/test_web.py` (cableado de la página)

**Interfaces:**
- Consumes: `detail` con `credenciales` (+ `progreso`) y `credenciales_resultados`; rutas `probar-credenciales`/`detener-credenciales` (Task 7).

- [ ] **Step 1: Write the failing test** en `tests/test_web.py` (amplía `test_page_has_the_prioritisation_tab` o añade uno nuevo):

```python
def test_page_has_the_credentials_tab(self):
    page, script = self.request("/")[1], self.request("/app.js")[1]
    for needle in (b'data-tab="credentials"', b'id="credential-tools"', b'id="test-credentials"', b'id="stop-credentials"'):
        self.assertIn(needle, page)
    self.assertIn(b'action("probar-credenciales")', script)
    self.assertIn(b'action("detener-credenciales")', script)
    self.assertIn(b"escapeHtml(item.usuario)", script)  # lo que devuelve el objetivo nunca entra como HTML
    self.assertIn(b"confirm(", script)  # la prueba activa pide confirmación
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_web -v -k credentials_tab`
Expected: FAIL.

- [ ] **Step 3: Implement the tab.** En `index.html`: añade la pestaña `<button role="tab" ... data-tab="credentials">Credenciales</button>` junto a la de Priorización, y un bloque de herramientas calcado de `#priority-tools`:

```html
    <div id="credential-tools" class="inventory-tools" hidden><p>Prueba contra los servicios en alcance las contraseñas de fábrica que le tocan a cada equipo según lo que parece ser. Se conecta de verdad: solo cuando lo pides y confirmas.</p><div class="actions"><button id="stop-credentials" class="secondary danger" type="button" hidden>Detener tras este servicio</button><button id="test-credentials" class="secondary danger" type="button">Probar credenciales</button></div><p id="credential-hint" class="model-hint" hidden></p></div>
```

En `app.js`:
- En `render()`, muestra `#credential-tools` solo en `activeTab === "credentials"`, deja `#filters`/`.tab-actions` ocultas también ahí (como con `priority`), y gestiona los botones `test-credentials`/`stop-credentials` igual que `analyze-job`/`stop-analysis` (texto con progreso `Probando ${h} de ${t}…`, estado `deteniendo`→«Parada solicitada…», `en_cola`→«Cancelar»).
- Añade `renderCredentials()` calcado de `renderPriority()`: lee `current.credenciales` (estado) y `current.credenciales_resultados`; los `entrada` arriba, resaltados; **todo texto del objetivo pasa por `escapeHtml`** (ip, usuario, clave, servicio, detalle). Mensajes de estado (en cola / probando / deteniendo / error / sin resultados) como en el análisis.
- En `renderResults()`, `if (activeTab === "credentials") { renderCredentials(); return; }`.
- El botón «Probar credenciales» pide confirmación antes de lanzar:

```javascript
$("test-credentials").addEventListener("click", () => {
  if (confirm("Esto intentará entrar en los servicios en alcance de esta ejecución con sus contraseñas de fábrica. ¿Seguir?")) action("probar-credenciales");
});
$("stop-credentials").addEventListener("click", () => action("detener-credenciales"));
```

En `style.css`: reutiliza `.priority-list`/`.badge`; añade una clase para el «entró» resaltado (p. ej. `.badge.entrada { background: var(--bad); }`) usando **solo variables de tema ya existentes**.

- [ ] **Step 4: Run tests and the contrast check**

Run: `python -m unittest tests.test_web -v -k credentials_tab`
Expected: PASS.
Run: `python design/check-contrast.py`
Expected: sin fallos de contraste.

- [ ] **Step 5: Commit**

```bash
git add dedalo/static/index.html dedalo/static/app.js dedalo/static/style.css tests/test_web.py
git commit -m "Add the Credenciales tab with its button and confirmation

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 9: Laboratorio de la demo y documentación

**Files:**
- Modify: `ejemplos/laboratorio.xml` (añadir un servicio FTP y uno con HTTP Basic sin romper los tests de `tests/test_prioridad.py`)
- Modify: `README.md`, `docs/CONTRATOS.md`, `docs/MODELO_DATOS.md`
- Test: `tests/test_prioridad.py` (el fixture del laboratorio debe seguir verde)

**Interfaces:**
- Consumes: todo lo anterior.

- [ ] **Step 1: Comprueba qué fija el fixture del laboratorio.** Lee `tests/test_prioridad.py::test_the_lab_fixture_has_the_demo_hosts_in_the_demo_order` y mira qué da por sentado (hosts, orden por nivel, número de servicios). Los cambios del XML deben dejar ese test verde.

- [ ] **Step 2: Añade servicios al laboratorio** editando `ejemplos/laboratorio.xml` con la herramienta de edición (CRLF): al host del panel (`10.30.1.21`) un puerto con HTTP Basic (p. ej. 8080 con producto `lighttpd` y sin http-title, para que case con la entrada `http-basic` del catálogo), y al servidor de ficheros (`10.30.2.20`) un puerto 21 `ftp` con producto `vsftpd`. Mantén los 4 hosts y su orden; si el test del fixture cuenta servicios y cambia un desempate, ajústalo en el mismo paso.

- [ ] **Step 3: Run the lab test**

Run: `python -m unittest tests.test_prioridad -v`
Expected: PASS (el fixture sigue con sus 4 hosts en el orden de la demo).

- [ ] **Step 4: Documentación.**
  - `README.md`: una sección «Credenciales por defecto» (qué hace, el botón y su confirmación, que se conecta de verdad y con límites, que la libreta viaja en el repo y se vuelca a la base, cómo probarlo con el laboratorio).
  - `docs/CONTRATOS.md`: §0.4, `credenciales` pasa de «tipo futuro» a fila real (qué hace, que **sí** conecta y con qué límites, qué escribe) y sus estados; §0.1, bloque 6 implementado; la frase de «tipos futuros» se actualiza.
  - `docs/MODELO_DATOS.md`: las tablas nuevas (`credencial_catalogo`, `credencial_resultado`, `config`) y la migración 4.

- [ ] **Step 5: Run the whole suite and the integration smoke, then commit**

Run: `python -m unittest discover -s tests`
Expected: OK.
(Las de integración con red/navegador no cubren credenciales; la prueba real contra el laboratorio con servicios de verdad la hace Doro.)

```bash
git add ejemplos/laboratorio.xml README.md docs/CONTRATOS.md docs/MODELO_DATOS.md tests/test_prioridad.py
git commit -m "Seed the lab with FTP and Basic services; document block 6

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Cierre

- `/simplify` → `/code-review` sobre toda la rama; y las revisiones de Trail of Bits que aplican por tocar red, entrada de usuario, ficheros y datos externos: `differential-review`, `sharp-edges`, `insecure-defaults` y `supply-chain-risk-auditor` (por las listas de credenciales importadas; para la demo la semilla es propia, pero la revisión queda encauzada para cuando se importen listas públicas).
- Prueba real contra el laboratorio (servicios de verdad en loopback) la hace Doro desde el portal, con el doble clic.
- Al terminar: ficha, nota de tarea y `04-IA/registro.md` del Brain al día; lista de ficheros a Doro para su «ok» antes de commit; recordar `git push nas` / `nas-vpn`.
