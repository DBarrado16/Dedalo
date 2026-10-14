# Integrar el descubrimiento DNS en el portal — plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** El portal lanza sobre el alcance de una ficha el descubrimiento DNS que ya existe en `dedalo/descubrimiento.py` (modos `nombres` y `servidores`), muestra el resultado en una pestaña «Descubrimiento», y ofrece un botón «Detectar mis redes» que propone como alcance las subredes del propio equipo.

**Architecture:** Una ejecución nueva de tipo `descubrimiento` (ya admitido desde la migración 2) que calca el ciclo de vida de `analisis`/`credenciales`: misma cola `self.pending`, un `_worker`, estados, parar/progreso. El `_worker` llama a `descubrimiento.sweep(...)`. El alcance se recomprueba **en vivo** antes de cada consulta (un envoltorio con `status(ip)` que relee el alcance de la ficha, cacheado por `store.scope_changes`). Los resultados se guardan como **observaciones** (`observacion_activo.nombres` para nombres; `servicio(udp,53)` + `observacion` para servidores), **sin migración**. «Detectar mis redes» lee `ipconfig`/`ip -o addr` con `subprocess` y calcula los CIDR con `ipaddress`.

**Tech Stack:** Python ≥ 3.12, solo librería estándar (`socket`, `struct`, `ipaddress`, `subprocess`, `sqlite3`, `concurrent.futures`). Frontend en `dedalo/static/` (HTML/CSS/JS a mano).

**Spec:** `docs/superpowers/specs/2026-10-14-integrar-dns-design.md`

## Global Constraints

- Python ≥ 3.12; paquete y comando `dedalo`. **Solo librería estándar**, sin pip.
- **Alcance:** solo se conecta con IP en alcance, recomprobado **justo antes de cada consulta** (no solo al planificar); la exclusión siempre gana; sin reglas `incluir`, no se lanza nada. Todo código que conecte llega con un test que lo demuestra. (docs/CONTRATOS.md §0.3)
- **Migraciones** inmutables; esta función **no añade ninguna** (el tipo `descubrimiento` existe desde la migración 2; los resultados van a tablas de observación ya existentes).
- **Portal local** en `127.0.0.1`, con `Origin` y `X-Dedalo-Token` en las peticiones que mutan.
- **Datos reales:** probar solo con `ejemplos/` y `tests/`; no abrir `portal_datos/`, `salida/`, `pruebas_locales/`, `*.sqlite3`, capturas.
- **CRLF en Windows:** editar con la herramienta de edición, nunca `sed -i`.
- **Pruebas:** `python -m unittest discover -s tests` termina en `OK`, sin red ni navegador (el `sweep` se simula; el detectar-redes se prueba con la salida de `ipconfig`/`ip` simulada).
- **Commits** terminan con `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

## Review Focus

- **Exclusión a mitad de un barrido:** un host excluido durante un `servidores` deja de consultarse al momento (alcance vivo, no una foto fija). → test en Task 3.
- **Ficha sin reglas `incluir`:** lanzar descubrimiento se rechaza antes de encolar con «Define el alcance de la ficha». → test en Task 3.
- **`detectar` cuando el comando falla o no está:** `ipconfig`/`ip` ausente o con error no tumba el portal; devuelve lista vacía y el usuario teclea a mano. → test en Task 2.
- **Dominio inválido en `servidores`:** `sweep` ya valida el dominio antes de abrir sockets; el portal debe mostrarlo como error de la ejecución, no caerse. → test en Task 3.
- **Nombres/servidores repetidos entre ejecuciones:** volver a descubrir no duplica activos/servicios (se reutilizan por `(auditoria,ip)` y `(activo,proto,puerto)`). → test en Task 1.

---

### Task 1: auditoría — ciclo de vida del descubrimiento y volcado a observaciones

**Files:**
- Modify: `dedalo/auditoria.py`
- Test: `tests/test_auditoria.py`

**Interfaces:**
- Consumes: `_derived`, `_set_state`, `set_state`, `now`, `scope`, `audit_of`, `_id` (ya existen).
- Produces (calcan las de análisis/credenciales, con tipo `descubrimiento`):
  - `start_discovery(con, import_id, options) -> str`
  - `begin_discovery(con, discovery_id) -> bool`
  - `stop_discovery(con, import_id) -> str | None`
  - `discovery_status(con, import_id) -> dict | None`
  - `finish_discovery(con, discovery_id, rows) -> None` — vuelca las filas de `sweep` a observaciones y marca `completa`, sustituyendo a la anterior, en una transacción. `rows` son filas `{"ip","encontrado","nombre","detalle","error"}` más `"modo"` (lo añade el portal).
  - `discovery_results(con, import_id) -> list[dict]` — para la pestaña: las observaciones de la última ejecución de descubrimiento, solo de activos en alcance vigente.
  - `close_interrupted_analyses` pasa a cerrar también `descubrimiento`.

- [ ] **Step 1: Write the failing test** en `tests/test_auditoria.py` (reusa `load_in_scope`):

```python
def discovery_row(self, ip, modo, encontrado=True, nombre="", detalle=""):
    return {"ip": ip, "modo": modo, "encontrado": encontrado, "nombre": nombre, "detalle": detalle, "error": ""}

def test_discovery_names_become_asset_observations(self):
    self.load_in_scope("lunes")
    disc = auditoria.start_discovery(self.con, "lunes", {"modo": "nombres"})
    self.assertTrue(auditoria.begin_discovery(self.con, disc))
    auditoria.finish_discovery(self.con, disc, [self.discovery_row("192.0.2.10", "nombres", nombre="dc.local"),
                                               self.discovery_row("203.0.113.9", "nombres", nombre="fuera")])
    self.assertEqual(auditoria.discovery_status(self.con, "lunes"), {"estado": "completa", "error": ""})
    res = auditoria.discovery_results(self.con, "lunes")
    # 203.0.113.9 no está en el alcance 192.0.2.0/24: no sale
    self.assertEqual([(r["ip"], r["nombre"]) for r in res], [("192.0.2.10", "dc.local")])

def test_discovery_servers_become_a_udp53_service(self):
    self.load_in_scope("lunes")
    disc = auditoria.start_discovery(self.con, "lunes", {"modo": "servidores"})
    auditoria.begin_discovery(self.con, disc)
    auditoria.finish_discovery(self.con, disc, [self.discovery_row("192.0.2.10", "servidores", detalle="correcta; 1 respuesta(s)")])
    fila = con_servicio = self.con.execute(
        "SELECT s.protocolo, s.puerto, o.nombre, o.detalle FROM observacion o JOIN servicio s ON s.id = o.servicio_id "
        "JOIN activo a ON a.id = s.activo_id WHERE a.ip = '192.0.2.10'").fetchone()
    self.assertEqual((fila["protocolo"], fila["puerto"], fila["nombre"]), ("udp", 53, "domain"))
    self.assertEqual([r["detalle"] for r in auditoria.discovery_results(self.con, "lunes")], ["correcta; 1 respuesta(s)"])

def test_re_discovering_does_not_duplicate_assets_or_services(self):
    self.load_in_scope("lunes")
    for _ in range(2):
        disc = auditoria.start_discovery(self.con, "lunes", {"modo": "servidores"})
        auditoria.begin_discovery(self.con, disc)
        auditoria.finish_discovery(self.con, disc, [self.discovery_row("192.0.2.77", "servidores", detalle="correcta; 0 respuesta(s)")])
    self.assertEqual(self.con.execute("SELECT COUNT(*) FROM activo WHERE ip = '192.0.2.77'").fetchone()[0], 1)
    self.assertEqual(self.con.execute("SELECT COUNT(*) FROM servicio s JOIN activo a ON a.id=s.activo_id "
                                      "WHERE a.ip='192.0.2.77' AND s.puerto=53").fetchone()[0], 1)

def test_only_found_rows_are_stored(self):
    self.load_in_scope("lunes")
    disc = auditoria.start_discovery(self.con, "lunes", {"modo": "nombres"})
    auditoria.begin_discovery(self.con, disc)
    auditoria.finish_discovery(self.con, disc, [self.discovery_row("192.0.2.10", "nombres", encontrado=False)])
    self.assertEqual(auditoria.discovery_results(self.con, "lunes"), [])  # lo no encontrado no se guarda
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_auditoria -v`
Expected: FAIL (`start_discovery` no existe).

- [ ] **Step 3: Add the functions to `dedalo/auditoria.py`** (junto a las de credenciales; `start/begin/stop/status` calcan a `start_credential_test`/`begin_credential_test`/`stop_credential_test`/`credential_status` cambiando `'credenciales'`→`'descubrimiento'`):

```python
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
    nombres = con.execute("SELECT a.ip, 'nombres' AS modo, o.nombres AS dato, '' AS detalle FROM observacion_activo o "
                          "JOIN activo a ON a.id = o.activo_id WHERE o.ejecucion_id = ?", (disc["id"],)).fetchall()
    servidores = con.execute("SELECT a.ip, 'servidores' AS modo, '' AS dato, o.detalle FROM observacion o "
                             "JOIN servicio s ON s.id = o.servicio_id JOIN activo a ON a.id = s.activo_id "
                             "WHERE o.ejecucion_id = ?", (disc["id"],)).fetchall()
    filas = [{"ip": r["ip"], "modo": "nombres", "nombre": json.loads(r["dato"])[0] if r["dato"] else "", "detalle": ""} for r in nombres]
    filas += [{"ip": r["ip"], "modo": "servidores", "nombre": "", "detalle": r["detalle"]} for r in servidores]
    current = scope(con, audit_of(con, import_id))
    return [f for f in filas if current.status(f["ip"]) == current.IN]
```

Y amplía `close_interrupted_analyses` para incluir `descubrimiento` en su `WHERE`:

```python
                    "WHERE tipo IN ('analisis', 'credenciales', 'descubrimiento') AND estado IN ('en_cola', 'en_curso', 'deteniendo')", (now(),))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_auditoria -v`
Expected: PASS.

- [ ] **Step 5: Run the whole suite and commit**

Run: `python -m unittest discover -s tests`
Expected: OK.

```bash
git add dedalo/auditoria.py tests/test_auditoria.py
git commit -m "Store DNS discovery as asset observations, mirroring the analysis

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Detectar las redes del equipo

**Files:**
- Create: `dedalo/redes.py`
- Test: `tests/test_redes.py`

**Interfaces:**
- Produces:
  - `redes.cidrs(texto: str) -> list[str]` — CIDR (como texto) sacados de la salida de `ipconfig` o de `ip -o addr`; sin loopback ni link-local; ordenados y sin duplicados.
  - `redes.detectar() -> list[str]` — ejecuta el comando del sistema y devuelve `cidrs(salida)`; lista vacía si falla. No conecta con nada.

- [ ] **Step 1: Write the failing test** en `tests/test_redes.py`:

```python
import unittest
from unittest.mock import patch

from dedalo import redes

IPCONFIG = """
Adaptador de Ethernet Ethernet:
   Dirección IPv4. . . . . . . . . . . . . . : 192.168.1.50
   Máscara de subred . . . . . . . . . . . . : 255.255.255.0
Adaptador de túnel Loopback:
   Dirección IPv4. . . . . . . . . . . . . . : 127.0.0.1
   Máscara de subred . . . . . . . . . . . . : 255.0.0.0
"""

IP_ADDR = ("1: lo    inet 127.0.0.1/8 scope host lo\\n"
           "2: eth0  inet 10.30.4.7/24 brd 10.30.4.255 scope global eth0\\n"
           "3: eth0  inet6 fe80::1/64 scope link\\n")


class RedesTests(unittest.TestCase):
    def test_parses_ipconfig_and_drops_loopback(self):
        self.assertEqual(redes.cidrs(IPCONFIG), ["192.168.1.0/24"])

    def test_parses_ip_addr_and_drops_loopback_and_link_local(self):
        self.assertEqual(redes.cidrs(IP_ADDR), ["10.30.4.0/24"])

    def test_detectar_returns_empty_when_the_command_fails(self):
        with patch("dedalo.redes._ejecutar", side_effect=OSError("no ipconfig")):
            self.assertEqual(redes.detectar(), [])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_redes -v`
Expected: FAIL (`No module named 'dedalo.redes'`).

- [ ] **Step 3: Write `dedalo/redes.py`:**

```python
"""Detectar las subredes de las interfaces del propio equipo, para proponerlas como alcance.

Solo mira las interfaces locales (lee ipconfig / ip addr); no conecta con ningún objetivo.
Es una sugerencia: rellena los rangos de la ficha, que el usuario revisa.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys

_CIDR = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{2,}:[0-9a-fA-F:]*)/(\d{1,3})\b")
_IPV4 = re.compile(r"IPv4.*?:\s*(\d{1,3}(?:\.\d{1,3}){3})")
_MASK = re.compile(r"(?:Subnet Mask|M[aá]scara).*?:\s*(\d{1,3}(?:\.\d{1,3}){3})")


def _red(direccion: str, prefijo) -> ipaddress._BaseNetwork | None:
    try:
        return ipaddress.ip_network(f"{direccion}/{prefijo}", strict=False)
    except ValueError:
        return None


def cidrs(texto: str) -> list[str]:
    """CIDR de las interfaces, de la salida de ipconfig o de ip addr; sin loopback ni link-local."""
    nets = set()
    for direccion, prefijo in _CIDR.findall(texto):          # ip -o addr: 10.30.4.7/24
        nets.add(_red(direccion, prefijo))
    for direccion, mask in zip(_IPV4.findall(texto), _MASK.findall(texto)):  # ipconfig: IPv4 + máscara
        nets.add(_red(direccion, mask))
    nets.discard(None)
    return [str(n) for n in sorted(nets, key=lambda n: (n.version, int(n.network_address)))
            if not (n.is_loopback or n.is_link_local)]


def _ejecutar() -> str:
    comando = ["ipconfig"] if sys.platform.startswith("win") else ["ip", "-o", "addr"]
    return subprocess.run(comando, capture_output=True, text=True, timeout=10,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout


def detectar() -> list[str]:
    """Las subredes del equipo, o lista vacía si no se pudieron leer (se teclea a mano)."""
    try:
        return cidrs(_ejecutar())
    except (OSError, ValueError, subprocess.SubprocessError):
        return []
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_redes -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add dedalo/redes.py tests/test_redes.py
git commit -m "Detect the host's own subnets from ipconfig / ip addr

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Lanzar el descubrimiento desde el portal

**Files:**
- Modify: `dedalo/web.py`, `dedalo/cli.py`
- Test: `tests/test_web.py`

**Interfaces:**
- Consumes: Task 1 (auditoría), Task 2 (`redes.detectar`), `descubrimiento.sweep/expand/MODES`.
- Produces: `PortalStore.discover(job_id, payload)`, `PortalStore.stop_discovery(job_id)`, `PortalStore.networks()`; `detail` añade `response["descubrimiento"]` (+ `progreso`) y `response["descubrimiento_resultados"]`; rutas POST `…/descubrir` y `…/detener-descubrimiento`, GET `/api/redes`; opción `--dns-dominio`.

- [ ] **Step 1: Write the failing test** en `tests/test_web.py` (reusa `self.create`, `self.request`, `self.until`, `redirect_stderr`, y `FTP_DOS`/el patrón de import a medida ya usado en credenciales):

```python
def settled_discovery(self, job_id):
    self.until(lambda: self.store.detail(job_id)["descubrimiento"]["estado"] not in ("en_cola", "en_curso", "deteniendo"))
    return self.store.detail(job_id)

def test_discovery_needs_the_token_and_same_origin(self):
    job = self.create()
    with patch("dedalo.web.descubrimiento.sweep") as sweep:
        for route in ("descubrir", "detener-descubrimiento"):
            for headers in ({"X-Dedalo-Token": "wrong"}, {"Origin": "https://example.org"}):
                self.assertEqual(self.request("/api/jobs/" + job["id"] + "/" + route, {}, headers)[0], 403)
        self.assertIsNone(self.store.detail(job["id"])["descubrimiento"])
    sweep.assert_not_called()

def test_discovery_needs_the_scope_defined(self):
    audit = self.store.create_audit({"nombre": "Sin alcance", "incluir": ""})
    job = json.loads(self.request("/api/jobs", payload() | {"auditoria": audit["id"]})[1])
    self.assertEqual(self.request("/api/jobs/" + job["id"] + "/descubrir", {"modo": "nombres"})[0], 409)

def test_names_discovery_stores_results(self):
    job = self.create()
    def sweep(addresses, mode, domain="", *, scope=None, timeout=2.0, delay=0.0, workers=4, stop=None, progress=None):
        return [{"ip": a, "encontrado": True, "nombre": "host-" + a.split(".")[-1], "detalle": "", "error": ""} for a in addresses[:1]]
    with patch("dedalo.web.descubrimiento.sweep", side_effect=sweep):
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/descubrir", {"modo": "nombres"})[0], 202)
        detail = self.settled_discovery(job["id"])
    self.assertEqual(detail["descubrimiento"]["estado"], "completa")
    self.assertTrue(all(r["modo"] == "nombres" for r in detail["descubrimiento_resultados"]))

def test_a_host_excluded_mid_sweep_is_not_queried(self):
    job = self.create()  # audit incluir 10.10.0.0/17
    consultados, started, release = [], threading.Event(), threading.Event()
    def sweep(addresses, mode, domain="", *, scope=None, timeout=2.0, delay=0.0, workers=4, stop=None, progress=None):
        for ip in addresses:
            if scope.status(ip) != web.targets.Scope.IN:  # el portal pasa un alcance VIVO
                continue
            consultados.append(ip)
            if len(consultados) == 1:
                started.set(); release.wait(10)
        return [{"ip": ip, "encontrado": False, "nombre": "", "detalle": "", "error": ""} for ip in consultados]
    with patch("dedalo.web.descubrimiento.sweep", side_effect=sweep), \
            patch("dedalo.web.descubrimiento.expand", return_value=["10.10.0.1", "10.10.0.2"]):
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/descubrir", {"modo": "servidores"})[0], 202)
        started.wait(10)
        self.store.update_audit(self.audit["id"], {"nombre": "Cliente de prueba", "incluir": "10.10.0.0/17", "excluir": "10.10.0.2"})
        release.set()
        self.settled_discovery(job["id"])
    self.assertNotIn("10.10.0.2", consultados)

def test_networks_route_lists_detected_subnets(self):
    with patch("dedalo.web.redes.detectar", return_value=["10.30.4.0/24"]):
        status, content = self.request("/api/redes")
    self.assertEqual((status, json.loads(content)), (200, {"redes": ["10.30.4.0/24"]}))

def test_a_sweep_error_ends_the_discovery_in_error(self):
    job = self.create()
    with patch("dedalo.web.descubrimiento.sweep", side_effect=ValueError("Dominio inválido: 'x y'")), \
            redirect_stderr(io.StringIO()):
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/descubrir", {"modo": "servidores"})[0], 202)
        detail = self.settled_discovery(job["id"])
    self.assertEqual(detail["descubrimiento"]["estado"], "error")
    self.assertIn("Dominio", detail["descubrimiento"]["error"])  # el mensaje de sweep, no un genérico
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_web -v -k discovery`
Expected: FAIL (ni rutas ni métodos existen).

- [ ] **Step 3: Implement in `dedalo/web.py`.** Importa arriba `descubrimiento, redes` junto a los demás módulos. En `__init__`, junto a `self.credential_progress = {}`, añade `self.discovery_progress = {}`, y guarda el dominio: `self.dns_dominio = dns_dominio`. Cambia la firma de `PortalStore.__init__` para aceptar `dns_dominio="example.com"` y `serve_portal` para pasar `dns_dominio=args.dns_dominio`. En `cli.py`, junto a `--ollama`, añade:

```python
    portal.add_argument("--dns-dominio", default="example.com",
                        help="Dominio que el descubrimiento usa para sondear servidores DNS (modo servidores)")
```

Un envoltorio de alcance vivo-cacheado (clase a nivel de módulo en `web.py`), que `sweep` usa como `scope`:

```python
class _AlcanceVivo:
    """status(ip) con el alcance VIGENTE de la ficha; relee solo cuando cambia store.scope_changes."""

    def __init__(self, store, audit_id):
        self._store, self._audit_id = store, audit_id
        self._lock, self._contador, self._scope = threading.Lock(), None, None

    def status(self, ip):
        with self._lock:
            if self._store.scope_changes != self._contador:
                with closing(self._store.database()) as con:
                    self._scope = auditoria.scope(con, self._audit_id)
                self._contador = self._store.scope_changes
            return self._scope.status(ip)
```

Métodos de `PortalStore` (calcan `test_credentials`/`stop_credentials`/`_run_credentials`/`_test_credentials`):

```python
    def networks(self):
        return {"redes": redes.detectar()}

    def discover(self, job_id, payload=None):
        modo = payload.get("modo", "nombres") if isinstance(payload, dict) else "nombres"
        if modo not in descubrimiento.MODES:
            raise ValueError(f"Modo de descubrimiento desconocido: {modo}")
        with self.lock:
            meta = self._meta(job_id)
            if self.closing or meta["estado"] in ACTIVE:
                raise Conflict("Espera a que termine la captura antes de descubrir.")
            with closing(self.database()) as con:
                estado = auditoria.discovery_status(con, job_id)
                if estado and estado["estado"] in ACTIVE:
                    raise Conflict("Ya hay un descubrimiento de esta ejecución en marcha.")
                if not auditoria.scope(con, auditoria.audit_of(con, job_id)).include:
                    raise Conflict("Define el alcance de la ficha antes de descubrir.")
                disc_id = auditoria.start_discovery(con, job_id, {"modo": modo})
            self.pending.put(("descubrimiento", (job_id, disc_id, modo)))
        return self.detail(job_id)

    def stop_discovery(self, job_id):
        with self.lock:
            self._meta(job_id)
            with closing(self.database()) as con:
                if auditoria.stop_discovery(con, job_id) is None:
                    raise Conflict("Esta ejecución no tiene un descubrimiento en marcha.")
        return self.detail(job_id)

    def _run_discovery(self, job_id, disc_id, modo):
        try:
            self._discover(job_id, disc_id, modo)
        except Exception as exc:
            print(f"Error del portal: no se pudo completar el descubrimiento de {job_id}: {exc}", file=sys.stderr)
            try:
                with closing(self.database()) as con:
                    auditoria.set_state(con, disc_id, "error",
                                        "No se pudo completar el descubrimiento. Consulta la terminal del portal.")
            except Exception as again:
                print(f"Error del portal: no se pudo cerrar el descubrimiento de {job_id}: {again}", file=sys.stderr)

    def _discover(self, job_id, disc_id, modo):
        with closing(self.database()) as con:
            if not auditoria.begin_discovery(con, disc_id):
                return
            audit_id = auditoria.audit_of(con, job_id)
            alcance = auditoria.scope(con, audit_id)
        vivo = _AlcanceVivo(self, audit_id)

        def parar():
            if self.closing:
                return True
            with closing(self.database()) as con:
                estado = auditoria.discovery_status(con, job_id)
            return estado is None or estado["estado"] == "deteniendo"

        def avance(hechas, total):
            with self.lock:
                self.discovery_progress[job_id] = {"hechos": hechas, "total": total}

        try:
            direcciones = descubrimiento.expand([str(n) for n in alcance.include])
            filas = descubrimiento.sweep(direcciones, modo, self.dns_dominio, scope=vivo,
                                         stop=parar, progress=avance)
            rows = [fila | {"modo": modo} for fila in filas]
            state, error = "completa", ""
        except Exception as exc:
            print(f"Error del portal: no se pudo descubrir en {job_id}: {exc}", file=sys.stderr)
            rows, state = [], "error"
            error = str(exc) if isinstance(exc, ValueError) else "No se pudo completar el descubrimiento. Consulta la terminal del portal."
        finally:
            with self.lock:
                self.discovery_progress.pop(job_id, None)
        with closing(self.database()) as con:
            if state == "completa":
                auditoria.finish_discovery(con, disc_id, rows)
            else:
                auditoria.set_state(con, disc_id, state, error)
```

En `detail`, junto a las líneas de credenciales:

```python
            response["descubrimiento"] = auditoria.discovery_status(con, job_id)
            response["descubrimiento_resultados"] = auditoria.discovery_results(con, job_id)
```

y tras el bloqueo, el progreso:

```python
            progreso_d = self.discovery_progress.get(job_id)
        if progreso_d and response["descubrimiento"] and response["descubrimiento"]["estado"] in ACTIVE:
            response["descubrimiento"]["progreso"] = progreso_d
```

En `_worker`, junto a la rama `"credenciales"`:

```python
            if kind == "descubrimiento":
                self._run_discovery(*payload)
                continue
```

En el router: la ruta GET `/api/redes` junto a `/api/modelos`:

```python
            if path == "/api/redes":
                self.json(store.networks())
                return
```

y las POST junto a las de credenciales:

```python
                    if parts[3] == "descubrir":
                        self.json(store.discover(parts[2], payload), 202)
                        return
                    if parts[3] == "detener-descubrimiento":
                        self.json(store.stop_discovery(parts[2]))
                        return
```

Ajusta el test de arranque `test_second_portal_cannot_share_the_port` (y cualquier `argparse.Namespace` a mano) para incluir `dns_dominio="example.com"`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_web -v -k discovery`
Expected: PASS.

- [ ] **Step 5: Run the whole suite and commit**

Run: `python -m unittest discover -s tests`
Expected: OK.

```bash
git add dedalo/web.py dedalo/cli.py tests/test_web.py
git commit -m "Launch DNS discovery from the portal with a live scope

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Pestaña «Descubrimiento»

**Files:**
- Modify: `dedalo/static/index.html`, `dedalo/static/app.js`, `dedalo/static/style.css`
- Test: `tests/test_web.py` (cableado de la página)

**Interfaces:**
- Consumes: `detail` con `descubrimiento` (+ `progreso`) y `descubrimiento_resultados`; rutas `descubrir`/`detener-descubrimiento` (Task 3).

- [ ] **Step 1: Write the failing test** en `tests/test_web.py`:

```python
def test_page_has_the_discovery_tab(self):
    page, script = self.request("/")[1], self.request("/app.js")[1]
    for needle in (b'data-tab="discovery"', b'id="discovery-tools"', b'id="discover-job"',
                   b'id="stop-discovery"', b'id="discovery-mode"'):
        self.assertIn(needle, page)
    self.assertIn(b'action("descubrir", {modo: $("discovery-mode").value})', script)
    self.assertIn(b'action("detener-descubrimiento")', script)
    self.assertIn(b"escapeHtml(item.nombre)", script)  # lo que devuelve el objetivo nunca entra como HTML
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_web -v -k discovery_tab`
Expected: FAIL.

- [ ] **Step 3: Implement.** En `index.html`, añade la pestaña `<button role="tab" aria-selected="false" data-tab="discovery">Descubrimiento</button>` junto a «Credenciales», y un bloque de herramientas calcado de `#credential-tools`:

```html
    <div id="discovery-tools" class="inventory-tools" hidden><p>Pregunta por los nombres (DNS inverso) o por los servidores DNS de las IP en alcance de la ficha. El modo «servidores» se conecta a cada IP por UDP 53.</p><div class="actions"><label class="model-choice">Modo<select id="discovery-mode" aria-label="Modo de descubrimiento"><option value="nombres">Nombres (DNS inverso)</option><option value="servidores">Servidores DNS</option></select></label><button id="stop-discovery" class="secondary danger" type="button" hidden>Detener</button><button id="discover-job" class="secondary" type="button">Descubrir</button></div></div>
```

En `app.js`:
- En `render()`, muestra `#discovery-tools` solo en `activeTab === "discovery"`, oculta `#filters`/`.tab-actions` también ahí, y gestiona los botones `discover-job`/`stop-discovery` igual que `test-credentials`/`stop-credentials` (texto con progreso `Descubriendo ${h} de ${t}…`, `en_cola`→«Cancelar», `deteniendo`→«Parada solicitada…»), leyendo `current.descubrimiento`.
- Añade `renderDiscovery()` calcado de `renderCredentials()`: lee `current.descubrimiento` y `current.descubrimiento_resultados`; cada fila muestra `item.ip` y, según `item.modo`, el nombre o el detalle del servidor DNS; **todo texto pasa por `escapeHtml`**. Mensajes de estado como en credenciales.
- En `renderResults()`, `if (activeTab === "discovery") { renderDiscovery(); return; }`.
- Cableado:

```javascript
$("discover-job").addEventListener("click", () => action("descubrir", {modo: $("discovery-mode").value}));
$("stop-discovery").addEventListener("click", () => action("detener-descubrimiento"));
```

En `style.css`: reutiliza `.priority-list` y las clases de `.badge` existentes (sin colores nuevos).

- [ ] **Step 4: Run tests and the contrast check**

Run: `python -m unittest tests.test_web -v -k discovery_tab`
Expected: PASS.
Run: `python design/check-contrast.py`
Expected: sin fallos.

- [ ] **Step 5: Commit**

```bash
git add dedalo/static/index.html dedalo/static/app.js dedalo/static/style.css tests/test_web.py
git commit -m "Add the Descubrimiento tab

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Botón «Detectar mis redes» en la ficha y en Descubrimiento

**Files:**
- Modify: `dedalo/static/index.html`, `dedalo/static/app.js`
- Test: `tests/test_web.py`

**Interfaces:**
- Consumes: `GET /api/redes` (Task 3); el formulario de ficha (`#audit-include`) y la pestaña Descubrimiento (Task 4).

- [ ] **Step 1: Write the failing test** en `tests/test_web.py`:

```python
def test_page_has_the_detect_networks_buttons(self):
    page, script = self.request("/")[1], self.request("/app.js")[1]
    self.assertIn(b'id="detect-networks"', page)          # en el formulario de ficha
    self.assertIn(b'id="detect-networks-scope"', page)    # en la pestaña Descubrimiento
    self.assertIn(b'request("/api/redes")', script)
    self.assertIn(b'"audit-include"', script)             # rellena los rangos autorizados
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_web -v -k detect_networks`
Expected: FAIL.

- [ ] **Step 3: Implement.** En `index.html`, dentro del formulario de ficha, junto a `#audit-include` y su `#audit-include-file`, añade:

```html
        <button id="detect-networks" class="link-button" type="button">Detectar mis redes</button>
```

En `#discovery-tools` (Task 4), añade un botón `<button id="detect-networks-scope" class="secondary" type="button" title="Propone como alcance las redes de este equipo">Detectar mis redes</button>`.

En `app.js`, una función que pide las redes y rellena un destino, y su cableado:

```javascript
async function detectNetworks(fill) {
  try {
    const data = await request("/api/redes");
    if (!data.redes.length) { notice("No se detectaron redes en este equipo; escríbelas a mano."); return; }
    fill(data.redes);
  } catch (error) { notice("No se pudieron detectar las redes: " + error.message); }
}
$("detect-networks").addEventListener("click", () => detectNetworks(redes => {
  // Añade las que falten a los rangos autorizados, sin pisar lo que haya escrito.
  const actuales = $("audit-include").value.split("\n").map(s => s.trim()).filter(Boolean);
  $("audit-include").value = [...new Set([...actuales, ...redes])].join("\n");
}));
$("detect-networks-scope").addEventListener("click", () => detectNetworks(redes =>
  notice("Redes de este equipo: " + redes.join(", ") + ". Añádelas al alcance de la ficha para descubrir en ellas.")));
```

(El botón de la pestaña solo informa de las redes; el alcance se edita en la ficha, que es donde vive. Si prefieres que también las meta en la ficha abierta, se enlaza igual que `#detect-networks`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_web -v -k detect_networks`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add dedalo/static/index.html dedalo/static/app.js tests/test_web.py
git commit -m "Add a Detectar mis redes button in the ficha form and Descubrimiento

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Contrato y documentación

**Files:**
- Modify: `docs/CONTRATOS.md`, `docs/MODELO_DATOS.md`, `README.md`

**Interfaces:**
- Consumes: todo lo anterior.

- [ ] **Step 1: Documentación.**
  - `docs/CONTRATOS.md`: §0.1, mover el descubrimiento de red (bloque 2) de «queda para después» a implementado (el modo DNS). §0.4, añadir la fila `descubrimiento` a la tabla de tipos (qué hace: nombres por el resolvedor del sistema o servidores DNS por UDP 53; conecta solo en alcance en el modo `servidores`; escribe observaciones) y quitar `descubrimiento` de «tipos futuros».
  - `docs/MODELO_DATOS.md`: una línea en «Piezas y relaciones» de que el descubrimiento escribe observaciones (nombres en `observacion_activo`, servidores como `servicio(udp,53)` + `observacion`), sin tablas nuevas ni migración.
  - `README.md`: una sección «Descubrimiento de red» (los dos modos, el botón, que `servidores` conecta y solo en alcance, el dominio de sondeo `--dns-dominio`, y el botón «Detectar mis redes»).

- [ ] **Step 2: Run the whole suite and commit**

Run: `python -m unittest discover -s tests`
Expected: OK.

```bash
git add docs/CONTRATOS.md docs/MODELO_DATOS.md README.md
git commit -m "Document DNS discovery in the portal (block 2, DNS part)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Cierre

- `/simplify` → `/code-review` sobre toda la rama; y las revisiones de Trail of Bits que aplican por tocar red y entrada: `differential-review` y `sharp-edges`.
- Prueba real: Doro lanza el descubrimiento desde el portal sobre una ficha con alcance real (sus redes, detectadas con el botón).
- Al terminar: ficha, nota de tarea y `04-IA/registro.md` del Brain al día; lista de ficheros a Doro para su «ok»; recordar `git push nas`.
