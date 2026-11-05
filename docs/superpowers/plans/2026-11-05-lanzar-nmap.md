# Lanzar Nmap desde el portal · plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Que el portal lance Nmap sobre el alcance en vivo de una ficha, con presets fijos, y que el resultado entre como una importación más.

**Architecture:** Un módulo nuevo `dedalo/escaneo.py` (solo librería estándar) con los presets, el troceo del alcance en bloques /24 y el lanzamiento de Nmap sin shell. `dedalo/web.py` mete el escaneo en la misma cola que el resto de ejecuciones, vigila el alcance vivo durante cada trozo y, al terminar, importa los XML por el camino que ya existe (`parser` + `auditoria.import_nmap`). Una migración nueva añade el tipo de ejecución `escaneo`.

**Tech Stack:** Python ≥ 3.12, solo librería estándar (`subprocess`, `ipaddress`, `xml.etree`, `sqlite3`, `threading`). Nmap externo lanzado sin shell.

**Spec:** `docs/superpowers/specs/2026-11-04-lanzar-nmap-design.md`

## Global Constraints

- Solo librería estándar; nada de pip (AGENTS.md).
- Solo se contacta lo que está en alcance, comprobado en vivo justo antes de conectar; la exclusión siempre gana (CONTRATOS §0.3). El código nuevo que conecta llega con un test que lo demuestra.
- A Nmap nunca le llega texto escrito por el usuario en la línea de comandos: las opciones las fija el código y las IP van en ficheros que escribe Dédalo con `ipaddress`.
- Nmap se lanza sin shell y con la carpeta de trabajo = la carpeta del escaneo.
- Un cambio de esquema es una migración nueva y numerada en `dedalo/db.py`; las publicadas (1–8) no se tocan.
- Checkout CRLF en Windows: editar con la herramienta de edición, nunca `sed -i`.
- Solo IPv4 en esta versión; las reglas `incluir` IPv6 se ignoran al escanear.
- Ningún script NSE (`-sC`, `--script`).
- No se instala ni se descarga Nmap.
- Pruebas: `python -m unittest discover -s tests` termina en OK sin red ni Nmap real, con un Nmap falso.

## Review Focus

- **`-Pn` en un rango grande** (preset `vpn`): Nmap marca `up` todas las IP; los hosts `up` por `user-set` sin puertos abiertos no deben llegar a la importación → Task 4.
- **Host que responde en todos los puertos** (tarpit/cortafuegos): más de 1.000 puertos abiertos entra sin puertos y con una observación, para no reventar el límite del inventario → Task 4.
- **Exclusión a mitad de un trozo**: si una IP del trozo en curso deja de estar en alcance, se mata Nmap y se relanza el trozo sin ella → Task 7.
- **Alcance ilegible a mitad**: no se lanza el trozo siguiente; se importa lo ya terminado como `parcial` (o `error` si no hay nada) → Task 7.
- **Portal cerrado con Nmap corriendo**: el proceso se mata al cerrar; el escaneo queda `interrumpida` y al reabrir se importa lo ya terminado → Task 8.

---

## Task 1: Encontrar el binario de Nmap

**Files:**
- Create: `dedalo/escaneo.py`
- Test: `tests/test_escaneo.py`

**Interfaces:**
- Produces: `find_nmap(explicit: str | None) -> str` (ruta absoluta al ejecutable; `ValueError` con texto de ayuda si no hay); `nmap_version(binary: str) -> str | None` (p. ej. `"7.95"`, o `None` si no responde).

- [ ] **Step 1: Write the failing test**

```python
def test_find_nmap_usa_explicito_si_existe(tmp_path):
    fake = tmp_path / "nmap"; fake.write_text(""); 
    assert escaneo.find_nmap(str(fake)) == str(fake.resolve())

def test_find_nmap_sin_ninguno_explica(monkeypatch):
    monkeypatch.setattr(escaneo.shutil, "which", lambda n: None)
    monkeypatch.setattr(escaneo.os, "name", "posix")
    monkeypatch.setattr(escaneo.Path, "is_file", lambda self: False)
    with pytest.raises(ValueError, match="No se encuentra Nmap"):
        escaneo.find_nmap(None)
```

- [ ] **Step 2: Run** `python -m unittest tests.test_escaneo -v` — FAIL (módulo/función no existe).

- [ ] **Step 3: Implement** `find_nmap` y `nmap_version` en `dedalo/escaneo.py`.

Patrón de `gowitness.find_chrome`/`find_gowitness` y `modelo.find_ollama`: si `explicit`, resolver con un helper como `gowitness._executable`; si no, en Windows probar `C:\Program Files (x86)\Nmap\nmap.exe` y `C:\Program Files\Nmap\nmap.exe` (desde `ProgramFiles(x86)`/`ProgramFiles`), luego `shutil.which("nmap")` descartando la carpeta actual (`Path(found).resolve().parent != Path.cwd().resolve()`), y `/usr/bin/nmap`. `nmap_version` ejecuta `[binary, "--version"]` con `subprocess.run(capture_output=True, text=True, timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))` y saca el número con un regex `r"Nmap version ([\d.]+)"`.

- [ ] **Step 4: Run the test** — PASS.
- [ ] **Step 5: Commit** (`feat(escaneo): encontrar el binario de Nmap`).

---

## Task 2: Presets y troceo del alcance en /24

**Files:**
- Modify: `dedalo/escaneo.py`
- Test: `tests/test_escaneo.py`

**Interfaces:**
- Consumes: `targets.Scope`.
- Produces:
  - `PRESETS: dict[str, dict]` con claves `rapido`, `completo`, `vpn`; cada valor `{"etiqueta": str, "args": list[str]}` con las opciones fijas del spec (sin `-oX/-iL/--excludefile`, que se añaden por trozo).
  - `COMUNES: list[str]` = `["-n"]`.
  - `trocear(include: list[str]) -> list[ipaddress.IPv4Network]`: las redes IPv4 de `include` divididas en bloques /24 alineados (una red menor de /24 es un trozo de su tamaño; redes IPv6 se ignoran). Sin solapar y en orden.
  - `objetivos_del_trozo(bloque: IPv4Network, scope: Scope) -> tuple[list[str], list[str]]`: `(en_alcance, excluidas)`, cada una lista de IPv4 del bloque; `en_alcance` son las `scope.status(ip) == scope.IN`, `excluidas` las `scope.EXCLUDED` del bloque (para `--excludefile`). Las `OUT` no van en ninguna.

- [ ] **Step 1: Write the failing test**

```python
def test_trocear_un_16_da_256():
    assert len(escaneo.trocear(["10.0.0.0/16"])) == 256

def test_trocear_un_26_da_1_trozo():
    t = escaneo.trocear(["10.0.0.0/26"]); assert len(t) == 1 and t[0].prefixlen == 26

def test_trocear_ignora_ipv6():
    assert escaneo.trocear(["2001:db8::/32", "10.0.0.0/24"]) == [ipaddress.ip_network("10.0.0.0/24")]

def test_objetivos_del_trozo_respeta_alcance():
    sc = targets.Scope(["10.0.0.0/24"], ["10.0.0.5/32"])
    dentro, excl = escaneo.objetivos_del_trozo(ipaddress.ip_network("10.0.0.0/24"), sc)
    assert "10.0.0.5" not in dentro and "10.0.0.5" in excl and "10.0.0.1" in dentro

def test_presets_son_los_tres():
    assert set(escaneo.PRESETS) == {"rapido", "completo", "vpn"}
    assert "-sT" in escaneo.PRESETS["vpn"]["args"] and "-Pn" in escaneo.PRESETS["vpn"]["args"]
```

- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** `PRESETS`, `COMUNES`, `trocear`, `objetivos_del_trozo`. `trocear` usa `ipaddress.ip_network(n).subnets(new_prefix=24)` cuando el prefijo es < 24, y la red tal cual cuando es ≥ 24. Los valores de `args` son los del spec, verbatim.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** (`feat(escaneo): presets y troceo del alcance en /24`).

---

## Task 3: Lanzar Nmap sobre un trozo

**Files:**
- Modify: `dedalo/escaneo.py`
- Test: `tests/test_escaneo.py`, `tests/fake_nmap.py` (nuevo: Nmap falso)

**Interfaces:**
- Produces: `escanear_trozo(nmap: str, preset: str, dentro: list[str], excluidas: list[str], carpeta: Path, *, parar=None) -> dict`. Escribe `carpeta/objetivos.txt` (un IPv4 por línea, de `dentro`), `carpeta/excluir.txt` (de `excluidas`) y un XML `carpeta/salida.xml`; lanza Nmap sin shell, con `cwd=carpeta`, argumentos `[nmap, *COMUNES, *PRESETS[preset]["args"], "-oX", "salida.xml", "-iL", "objetivos.txt"]` y `--excludefile excluir.txt` solo si `excluidas`. Devuelve `{"comando": list[str], "codigo": int, "inicio": str, "fin": str, "relanzado": bool}`. Con `parar()` que devuelve `True`, mata el proceso (`terminate`, y `kill` a los 5 s) y marca `relanzado`.
- `tests/fake_nmap.py`: lee `-iL` y `--excludefile`, escribe un `salida.xml` mínimo válido de nmap (un `<host>` `up` por IP con un puerto abierto de prueba) y vuelca sus argumentos a `carpeta/args.json`. Permite simular tardanza con una variable de entorno para probar la parada.

- [ ] **Step 1: Write the failing test**

```python
def test_escanear_trozo_no_pasa_excluidas_a_nmap(tmp_path):
    r = escaneo.escanear_trozo(FAKE, "rapido", ["10.0.0.1","10.0.0.2"], ["10.0.0.9"], tmp_path)
    args = json.loads((tmp_path/"args.json").read_text())
    assert "10.0.0.9" not in (tmp_path/"objetivos.txt").read_text()
    assert "--excludefile" in args and "10.0.0.9" in (tmp_path/"excluir.txt").read_text()
    assert r["codigo"] == 0 and (tmp_path/"salida.xml").is_file()

def test_escanear_trozo_sin_excluidas_no_pone_excludefile(tmp_path):
    escaneo.escanear_trozo(FAKE, "rapido", ["10.0.0.1"], [], tmp_path)
    assert "--excludefile" not in json.loads((tmp_path/"args.json").read_text())

def test_escanear_trozo_no_usa_shell(tmp_path, monkeypatch):
    visto = {}
    orig = escaneo.subprocess.Popen
    def espia(args, **kw): visto.update(kw); return orig(args, **kw)
    monkeypatch.setattr(escaneo.subprocess, "Popen", espia)
    escaneo.escanear_trozo(FAKE, "rapido", ["10.0.0.1"], [], tmp_path)
    assert visto.get("shell", False) is False and str(visto.get("cwd")) == str(tmp_path)
```

- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** `escanear_trozo` y `tests/fake_nmap.py`. `Popen` con lista de argumentos, `shell=False`, `cwd=carpeta`, `creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)`. El sondeo de `parar()` es un bucle con `proc.poll()` y una espera corta; al parar, `terminate()` y, si sigue vivo tras 5 s, `kill()`.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** (`feat(escaneo): lanzar Nmap sobre un trozo, sin shell`).

---

## Task 4: Filtrar el resultado antes de importar

**Files:**
- Modify: `dedalo/escaneo.py`
- Test: `tests/test_escaneo.py`

**Interfaces:**
- Consumes: `parser.Host`, `parser.Port`.
- Produces: `limpiar_hosts(hosts: list[Host], tope_puertos: int = 1000) -> list[Host]`. Descarta los hosts sin puertos TCP ni UDP abiertos (los que `-Pn` dio por `up` sin saber nada). A un host con más de `tope_puertos` puertos TCP abiertos le vacía los puertos y le añade un script de host `{"id": "dedalo-todos-los-puertos", "output": "responde en todos los puertos (N abiertos)"}` con N el número real. Devuelve la lista filtrada.
- Nota: el parser actual no distingue `up` por `user-set` de `up` real; con `-Pn` todos los hosts vivos sin puertos son fantasma, así que el criterio es «sin puertos abiertos», que vale para los dos presets.

- [ ] **Step 1: Write the failing test**

```python
def test_limpiar_quita_hosts_sin_puertos():
    h = [parser.Host(ip="10.0.0.1"), parser.Host(ip="10.0.0.2", ports={80: parser.Port(80)})]
    assert [x.ip for x in escaneo.limpiar_hosts(h)] == ["10.0.0.2"]

def test_limpiar_vacia_host_con_demasiados_puertos():
    h = parser.Host(ip="10.0.0.3", ports={n: parser.Port(n) for n in range(1, 1500)})
    out = escaneo.limpiar_hosts([h], tope_puertos=1000)[0]
    assert out.ports == {} and any(s["id"] == "dedalo-todos-los-puertos" for s in out.scripts)
```

- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** `limpiar_hosts`.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** (`feat(escaneo): descartar hosts fantasma y tarpits`).

---

## Task 5: Migración 9 — tipo de ejecución `escaneo`

**Files:**
- Modify: `dedalo/db.py` (añadir la clave `9` a `MIGRATIONS`)
- Test: `tests/test_db.py`

**Interfaces:**
- Produces: tras migrar, `ejecucion.tipo` acepta `'escaneo'`.

- [ ] **Step 1: Write the failing test**

```python
def test_migracion_9_acepta_escaneo(tmp_path):
    con = db.connect(tmp_path)
    con.execute("INSERT INTO auditoria (id, nombre, creada) VALUES ('a','x','t')")
    con.execute("INSERT INTO ejecucion (id,auditoria_id,tipo,nombre,estado,creada) "
                "VALUES ('e','a','escaneo','x','en_cola','t')")  # no lanza
    assert con.execute("PRAGMA user_version").fetchone()[0] >= 9
```

- [ ] **Step 2: Run** `python -m unittest tests.test_db -v` — FAIL (CHECK rechaza `'escaneo'`).
- [ ] **Step 3: Implement** la migración `9`: reconstruir `ejecucion` como la migración 6, con `'escaneo'` añadido al `CHECK (tipo IN (...))`. Copiar **todas** las columnas, incluida `manifiesto_registrado` (añadida en la 7). Recrear los índices `ejecucion_auditoria` y `ejecucion_origen`. Dejar intactas las migraciones 1–8.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** (`feat(db): migración 9, tipo de ejecución escaneo`).

---

## Task 6: `auditoria` — ciclo de vida del escaneo

**Files:**
- Modify: `dedalo/auditoria.py`
- Test: `tests/test_auditoria.py`

**Interfaces:**
- Consumes: migración 9.
- Produces (siguiendo el patrón de `start_discovery`/`begin_discovery`/`stop_discovery`/`discovery_status`, pero ligado a la **ficha**, no a una importación):
  - `start_scan(con, audit_id: str, options: dict, created=None) -> str`: crea una ejecución `escaneo` `en_cola` con `auditoria_id = audit_id`, `origen_id = NULL`, nombre `"Escaneo Nmap · …"`; `options` guarda `{"rangos": [...], "presets": [...], "capturar": bool}`. `ValueError` si la ficha no existe.
  - `begin_scan(con, scan_id) -> bool` (de `en_cola` a `en_curso`).
  - `stop_scan(con, scan_id) -> str | None` (como `stop_discovery`, sobre el id del escaneo).
  - `scan_status(con, scan_id) -> dict | None` → `{"estado", "error", "importacion": str|None}` leyendo `opciones`.
  - `link_scan_import(con, scan_id, import_id)`: escribe `import_id` en `opciones` del escaneo e, inversamente, el `scan_id` en `opciones` de la importación. **No** usa `origen_id` (su FK borra en cascada).

- [ ] **Step 1: Write the failing test**

```python
def test_start_scan_crea_en_cola():
    sid = auditoria.start_scan(con, aud, {"rangos":["10.0.0.0/24"],"presets":["rapido"],"capturar":False})
    assert auditoria.scan_status(con, sid)["estado"] == "en_cola"

def test_link_scan_import_no_usa_cascada():
    auditoria.link_scan_import(con, sid, imp)
    assert auditoria.scan_status(con, sid)["importacion"] == imp
    con.execute("DELETE FROM ejecucion WHERE id = ?", (sid,))  # borrar escaneo
    assert auditoria.has_execution(con, imp)  # la importación sigue
```

- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** las funciones.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** (`feat(auditoria): ciclo de vida del escaneo`).

---

## Task 7: `web.py` — escaneo en la cola, con alcance vivo

**Files:**
- Modify: `dedalo/web.py`
- Test: `tests/test_web.py`

**Interfaces:**
- Consumes: `escaneo.*`, `auditoria.start_scan/begin_scan/stop_scan/scan_status/link_scan_import`, `_AlcanceVivo`, `write_live_scope`.
- Produces en `PortalStore`:
  - `scan(audit_id, payload) -> dict`: valida `payload` (rangos ⊆ reglas `incluir` de la ficha; presets ⊆ `escaneo.PRESETS`; `capturar` bool); exige `scope.include` o `Conflict`; cuenta las IPv4 en alcance y si pasan de 65.536, `ValueError`; comprueba `find_nmap` y da `Conflict` con ayuda si no está; `start_scan`, encola `("escaneo", (scan_id, audit_id))`, devuelve la ficha del escaneo. Bajo `self.lock`.
  - `stop_scan(scan_id) -> dict`.
  - `_run_scan(scan_id, audit_id)` y `_scan(scan_id, audit_id)`: el worker (nueva rama `"escaneo"` en `_worker`). `_scan` recorre presets × trozos; antes de cada trozo relee el alcance vivo (`_AlcanceVivo`/`auditoria.scope`), calcula objetivos; si el alcance no se lee, termina (ver abajo). Durante el trozo, un hilo vigila `self.scope_changes`; si una IP del trozo en curso deja de estar en alcance, pide `parar()` y relanza el trozo. Al final, une los XML de todos los trozos (`parser.parse_file` + `parser.merge`), `escaneo.limpiar_hosts`, `auditoria.import_nmap` (misma ficha), `link_scan_import`, y si `capturar`, encola la captura de esa importación con las opciones por defecto.
  - Estados: todos terminados → `completa`; algún trozo con error pero con XML válidos → `parcial`; alcance ilegible a mitad → importar lo hecho y `parcial`, o `error` si nada; parado por el usuario → importar lo terminado y `parcial`, o `cancelada`/`interrumpida` si nada.
  - Registro de evidencia: `escaneo.json` en la carpeta del escaneo (versión de Nmap, ruta, y por trozo/preset el comando, inicio, fin, código y `relanzado`) y la salida de Nmap por trozo.

- [ ] **Step 1: Write the failing tests** (con `fake_nmap` como `--nmap`):

```python
def test_scan_sin_incluir_no_lanza():
    with pytest.raises(Conflict): store.scan(aud_sin_rangos, {"rangos":[], "presets":["rapido"], "capturar":False})

def test_scan_no_pasa_excluidas_a_nmap():
    # ejecuta un escaneo de un /24 con una IP excluida y comprueba que no está en ningún objetivos.txt
    ...

def test_scan_exclusion_a_mitad_relanza_el_trozo():
    # fake_nmap espera; durante la espera se excluye una IP del trozo; el trozo se relanza sin ella
    ...

def test_scan_varios_presets_una_sola_importacion():
    sid = run_scan(presets=["rapido","vpn"]); imp = auditoria.scan_status(con, sid)["importacion"]
    assert imp and len(evidencia_xml(sid)) == 2  # un XML por preset (un trozo)

def test_scan_capturar_al_terminar_encola_captura():
    run_scan(capturar=True); assert hay_captura_en_cola_para(imp)
```

- [ ] **Step 2: Run** `python -m unittest tests.test_web -v` — FAIL.
- [ ] **Step 3: Implement** `scan`, `stop_scan`, `_run_scan`, `_scan`, y la rama `"escaneo"` en `_worker`. La vigilancia del alcance reutiliza `self.scope_changes` (sube con cada edición de ficha) y `auditoria.scope`; comparar las IP del trozo en curso contra el alcance nuevo.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** (`feat(web): escaneo Nmap en la cola, con alcance vivo`).

---

## Task 8: Cierre y reapertura a mitad de escaneo

**Files:**
- Modify: `dedalo/web.py`
- Test: `tests/test_web.py`

**Interfaces:**
- Produces: en `close()`, un escaneo en curso mata su proceso de Nmap (no sobrevive al portal) y queda `interrumpida`. En `_load()`/reconciliación al arrancar, un escaneo `interrumpida` con trozos XML terminados que no se importaron se importa entonces y queda `parcial`; sin nada, queda como está. `cancel`/`delete` tratan `escaneo` como un tipo activo más (parar antes de borrar).

- [ ] **Step 1: Write the failing test**

```python
def test_cerrar_con_escaneo_mata_nmap_y_deja_interrumpida():
    # arranca un escaneo con fake_nmap lento, store.close(); el proceso no queda vivo y el estado es interrumpida
    ...

def test_reabrir_importa_trozos_terminados():
    # un escaneo interrumpida con un XML terminado -> al reabrir el portal queda parcial con su importación
    ...
```

- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** el cierre (guardar el `Popen` vivo del escaneo en el store para poder matarlo en `close()`) y la reconciliación al arrancar.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** (`feat(web): cerrar y reabrir a mitad de escaneo`).

---

## Task 9: API, CLI y portal (botón, diálogo, progreso)

**Files:**
- Modify: `dedalo/web.py` (rutas), `dedalo/cli.py` (`--nmap`), `dedalo/static/index.html`, `dedalo/static/app.js`, `dedalo/static/estilos.css`
- Test: `tests/test_web.py` (rutas), `tests/test_dedalo.py` (CLI)

**Interfaces:**
- Consumes: `store.scan`, `store.stop_scan`.
- Produces:
  - POST `/api/audits/{audit_id}/escanear` → `store.scan`; POST `/api/jobs/{scan_id}/detener-escaneo` → `store.stop_scan`.
  - `web` y `capturar` ganan `--nmap` (ruta del ejecutable), que llega al `PortalStore` (`nmap_option`) y lo usa `find_nmap`.
  - Diálogo «Escanear con Nmap» en la ficha: casillas de rangos (de las reglas `incluir` IPv4), casillas de presets (`Rápido` marcado), casilla «Capturar las webs al terminar» (desmarcada), un resumen con nº de IP, trozos y estimación, y aviso si `vpn`/`completo` con > 1.024 IP. Botón deshabilitado con explicación si no hay alcance o no hay Nmap.
  - Progreso en el historial: preset actual y «trozo N de M».
  - `estimar(presets, n_ips) -> str`: heurística por preset (orden de magnitud). **(decisión del constructor)** la fórmula exacta.

- [ ] **Step 1: Write the failing test** (ruta y CLI):

```python
def test_ruta_escanear_llama_scan(monkeypatch):
    # POST /api/audits/<id>/escanear con Origin y token correctos invoca store.scan con el payload
    ...
def test_cli_web_acepta_nmap():
    args = cli.build_parser().parse_args(["web","--nmap","/usr/bin/nmap"]); assert args.nmap == "/usr/bin/nmap"
```

- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** rutas, `--nmap`, y la UI siguiendo `DESIGN.md`. Tras tocar colores, `python design/check-contrast.py`.
- [ ] **Step 4: Run** los tests y revisar el portal a mano (el subagente no tiene navegador: lo comprueba el master).
- [ ] **Step 5: Commit** (`feat(web): botón y API de escaneo con Nmap`).

---

## Task 10: Documentación

**Files:**
- Modify: `docs/CONTRATOS.md` (§0.1, §0.3 regla 2, §0.4), `docs/MODELO_DATOS.md`, `README.md`
- Test: ninguno (documentación).

- [ ] **Step 1:** §0.1: el bloque 3 (escaneo con Nmap) pasa de «Queda para después» a «Incluye». §0.3 regla 2: añadir cómo comprueba el alcance el escaneo (troceo /24, alcance vivo por trozo, parar y relanzar) y su límite (intervalo de vigilancia + tiempo de salida del proceso). §0.4: fila del tipo `escaneo` en la tabla de tipos, y quitarlo de «Tipos futuros».
- [ ] **Step 2:** `docs/MODELO_DATOS.md`: el tipo `escaneo`, la migración 9 y el vínculo escaneo↔importación en `opciones`.
- [ ] **Step 3:** `README.md`: cómo instalar Nmap (con Npcap en Windows), `--nmap`, los tres presets y el límite de 65.536 IP.
- [ ] **Step 4:** Revisar que el código no contradice CONTRATOS (regla «contrato = código»).
- [ ] **Step 5: Commit** (`docs: lanzar Nmap desde el portal`).

---

## Cierre

Tras la última tarea: `python -m unittest discover -s tests` en OK. La prueba de integración con Nmap real queda pendiente (en KmelloFumon no hay Nmap; instalarlo con Npcap o probar en Kali) — se anota, no bloquea. Después, `/simplify` → `/code-review` y las skills de Trail of Bits que apliquen (toca red y proceso externo): differential-review, insecure-defaults, sharp-edges, static-analysis, supply-chain-risk-auditor.
