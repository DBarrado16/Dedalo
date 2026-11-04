# Proxy de alcance (H1) · plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Que el navegador de la captura no pueda tocar nada excluido ni ninguna IP interna fuera de alcance, y que el portal enseñe junto a cada web lo que se le cortó.

**Architecture:** Un proxy local de librería estándar (`dedalo/proxy.py`) que arranca `cli.capture` y que gowitness recibe con `--chrome-proxy`. Decide cada conexión con el alcance vigente, conecta a la IP que comprobó y anota lo cortado en un JSON Lines por pasada. Al recoger la subred, `report.collect_group` cruza esos ficheros con `network_logs` de gowitness para atribuir cada corte a su web; el manifiesto, la base (migración 8), el CSV y el portal lo muestran.

**Tech Stack:** Python ≥ 3.12, solo librería estándar (`socket`, `socketserver`/`threading`, `ipaddress`, `json`, `sqlite3`), gowitness 3.2.0, JS sin dependencias en `dedalo/static/`.

**Spec:** `docs/superpowers/specs/2026-11-04-proxy-alcance-design.md`

## Global Constraints

- Sin paquetes de pip.
- Regla de paso, en este orden: excluida → corta; en alcance → pasa; `ipaddress.ip_address(x).is_global` → pasa; resto → corta. IPv6 mapeada se juzga como su IPv4.
- Motivos de corte, exactos: `excluida`, `fuera_de_alcance`, `alcance_ilegible`.
- Alcance vivo ilegible: reintento breve (≈200 ms en total) y, si sigue, se corta todo (también lo público).
- Respuestas del proxy: cortado → `HTTP/1.1 403 Forbidden` sin cuerpo; no se pudo conectar → `502 Bad Gateway` sin cuerpo; nunca cerrar sin responder.
- HTTP plano: una petición por conexión de cliente, `Connection: close` hacia el servidor.
- Se conecta a la IP comprobada; nunca se vuelve a resolver.
- Escucha solo en `127.0.0.1`, puerto 0.
- Migración nueva **8**; las publicadas no se tocan.
- En Windows el checkout es CRLF: editar con la herramienta de edición, nunca `sed -i`.
- No abrir `portal_datos/`, `salida/`, `pruebas_locales/`, `RESUMEN.md`, `*.sqlite3` reales ni capturas.
- `python -m unittest discover -s tests` termina en `OK`, sin red ni navegador.

## Review Focus

1. **Puerto cerrado o caído tras el proxy.** Hoy da `ERR_CONNECTION_REFUSED`/`ERR_CONNECTION_TIMED_OUT`; con el proxy daría `ERR_TUNNEL_CONNECTION_FAILED`. El usuario espera el mismo mensaje que hoy y que no se dispare la pasada de esquema. → Task 2 anota los fallos de conexión (`rechazada`, `sin_respuesta`) y Task 4 traduce el error de esa URL objetivo; tests en ambas.
2. **Nombre que resuelve a varias IP, una excluida.** Debe usar una que pase y no tocar la excluida. → Task 1, `test_nombre_con_una_ip_excluida_usa_otra`.
3. **Petición HTTP plana reutilizando la conexión al proxy para otro host.** No debe llegar al primer servidor. → Task 2, `test_http_una_peticion_por_conexion`.
4. **Fichero de alcance vivo sustituido justo al leerlo (Windows).** No debe cortar capturas en alcance. → Task 1, `test_alcance_vivo_reintenta_un_fallo_momentaneo`.
5. **Manifiesto viejo sin `bloqueos` reconciliado o migrado.** No debe romper el volcado. → Task 5, `test_manifiesto_sin_bloqueos_se_registra`.

---

### Task 1: Regla de paso y fuentes de alcance

**Files:**
- Create: `dedalo/proxy.py`
- Test: `tests/test_proxy.py`

**Interfaces:**
- Produces:
  - `EXCLUIDA = "excluida"`, `FUERA = "fuera_de_alcance"`, `ILEGIBLE = "alcance_ilegible"`.
  - `decidir(ip: str, alcance: targets.Scope | None) -> str | None`: motivo de corte o `None` si pasa. `alcance=None` significa ilegible → `ILEGIBLE`.
  - `class AlcanceVivo(path: str | Path)`: `.actual() -> targets.Scope | None`; relee si cambia `st_mtime_ns`/tamaño, reintenta hasta ~200 ms ante `OSError`/JSON a medias, `None` si sigue ilegible.
  - `class AlcanceFijo(scope: targets.Scope)`: `.actual() -> targets.Scope`.
  - `alcance_de_consola(ips_objetivo: list[str], rangos: list[str], solo_rangos: bool, excluidos: list[str]) -> targets.Scope`: incluir = IP de los objetivos (como /32 o /128) + `rangos` si `solo_rangos`; excluir = `excluidos`.
  - `elegir_ip(direcciones: list[str], alcance) -> tuple[str | None, str | None]`: primera IP que pasa y, si ninguna, el motivo de la primera.

- [ ] **Step 1: Tests de la regla**

```python
def test_regla_de_paso(self):
    s = targets.Scope(["10.10.0.0/16", "8.8.8.0/24"], ["10.10.5.20/32", "1.1.1.1/32"])
    self.assertEqual(proxy.decidir("10.10.5.20", s), proxy.EXCLUIDA)
    self.assertEqual(proxy.decidir("1.1.1.1", s), proxy.EXCLUIDA)      # pública pero excluida
    self.assertIsNone(proxy.decidir("10.10.1.1", s))                      # en alcance
    self.assertIsNone(proxy.decidir("8.8.4.4", s))                        # pública
    self.assertEqual(proxy.decidir("192.168.1.1", s), proxy.FUERA)
    self.assertEqual(proxy.decidir("100.64.0.1", s), proxy.FUERA)        # CGNAT no es global
    self.assertEqual(proxy.decidir("::ffff:10.10.5.20", s), proxy.EXCLUIDA)
    self.assertEqual(proxy.decidir("8.8.4.4", None), proxy.ILEGIBLE)

def test_nombre_con_una_ip_excluida_usa_otra(self):
    s = targets.Scope(["10.10.0.0/16"], ["10.10.5.20/32"])
    self.assertEqual(proxy.elegir_ip(["10.10.5.20", "10.10.5.21"], s), ("10.10.5.21", None))
    self.assertEqual(proxy.elegir_ip(["10.10.5.20"], s), (None, proxy.EXCLUIDA))

def test_consola_con_excluir_no_abre_lo_interno(self):
    s = proxy.alcance_de_consola(["10.0.0.5"], [], False, ["10.0.0.9/32"])
    self.assertIsNone(proxy.decidir("10.0.0.5", s))
    self.assertEqual(proxy.decidir("10.0.0.6", s), proxy.FUERA)
```

Más: `test_alcance_vivo_relee_si_cambia`, `test_alcance_vivo_ilegible_corta_todo` (fichero borrado → `actual()` es `None`), `test_alcance_vivo_reintenta_un_fallo_momentaneo` (parchear `Path.read_text` para que falle una vez con `PermissionError` y luego devuelva el JSON → `actual()` no es `None`). Formato del fichero: el de `web.write_live_scope` (`{"incluir": [...], "excluir": [...]}`).

- [ ] **Step 2:** `python -m unittest tests.test_proxy -v` → falla (no existe el módulo).
- [ ] **Step 3:** Implementar en `dedalo/proxy.py` con `targets.Scope` (reusar su normalización de IPv6 mapeada, no duplicarla).
- [ ] **Step 4:** `python -m unittest tests.test_proxy -v` → OK.
- [ ] **Step 5:** Commit `feat(proxy): regla de paso del navegador y fuentes de alcance`.

### Task 2: Servidor proxy

**Files:**
- Modify: `dedalo/proxy.py`
- Test: `tests/test_proxy.py`

**Interfaces:**
- Consumes: Task 1.
- Produces:
  - `class Proxy(alcance, timeout: float, resolver=socket.getaddrinfo, conectar=socket.create_connection)` con `.iniciar() -> int` (puerto en `127.0.0.1`), `.parar()`, `.registro(path: Path | None)` (fichero JSON Lines de la pasada en curso; `None` = no anotar), y `.url -> str` (`"http://127.0.0.1:PUERTO"`).
  - Línea de corte: `{"destino": "host:puerto", "ip": str|null, "puerto": int, "motivo": str}`.
  - Línea de fallo de conexión: `{"destino": "host:puerto", "ip": str, "puerto": int, "fallo": "rechazada" | "sin_respuesta" | "error"}`.
  - `timeout` de conexión: el de gowitness (`opts["timeout"]`) menos 1 s, mínimo 1 s; si vence, `fallo: sin_respuesta` y `502`.

- [ ] **Step 1: Tests con sockets locales** (servidor de eco en `127.0.0.1` dentro del alcance del test; destinos cortados con `conectar` parcheado para fallar si se llama: así se demuestra que no se contacta).
  - `test_connect_en_alcance_hace_tunel`: `CONNECT 127.0.0.1:P` → `200 Connection Established` y los bytes van y vuelven.
  - `test_connect_excluido_403_sin_conectar`: `CONNECT 10.10.5.20:443` excluida → línea de estado `403`, `conectar` no llamado, una línea en el registro con `motivo == "excluida"`.
  - `test_http_absoluto_se_reenvia_en_forma_de_origen`: el servidor recibe `GET /ruta HTTP/1.1` con `Connection: close` y sin `Proxy-Connection`.
  - `test_http_una_peticion_por_conexion`: dos peticiones por la misma conexión de cliente a hosts distintos → el primer servidor solo ve una; el proxy cierra tras la primera respuesta.
  - `test_nombre_se_resuelve_y_conecta_a_la_ip_comprobada`: `resolver` falso devuelve `10.10.1.1`; `conectar` recibe `("10.10.1.1", puerto)`.
  - `test_puerto_cerrado_502_y_fallo_anotado`: `conectar` lanza `ConnectionRefusedError` → `502`, línea con `fallo == "rechazada"`; `TimeoutError` → `sin_respuesta`.
  - `test_publico_pasa_y_no_se_anota`.
- [ ] **Step 2:** Ejecutar → falla.
- [ ] **Step 3:** Implementar con `socketserver.ThreadingTCPServer` (hilos demonio) y un túnel bidireccional de dos hilos o `selectors`; leer cabeceras con tope (64 KiB) y responder `400` si no son válidas. Escribir el registro con un `threading.Lock`.
- [ ] **Step 4:** Ejecutar → OK; `python -m unittest discover -s tests` → OK.
- [ ] **Step 5:** Commit `feat(proxy): proxy local que corta lo excluido y lo interno fuera de alcance`.

### Task 3: La captura pasa por el proxy

**Files:**
- Modify: `dedalo/gowitness.py` (`scan_subnet`), `dedalo/cli.py` (`capture`)
- Test: `tests/test_dedalo.py`

**Interfaces:**
- Consumes: `proxy.Proxy`, `proxy.AlcanceVivo`, `proxy.AlcanceFijo`, `proxy.alcance_de_consola`.
- Produces:
  - `scan_subnet(..., opts)` añade `--chrome-proxy opts["proxy"]` si `opts.get("proxy")`.
  - Constantes en `gowitness.py`: `PROXY_LOG = "proxy.jsonl"`, `SCHEME_PROXY_LOG = "proxy-esquema.jsonl"`, `RETRY_PROXY_LOG = "proxy-reintento.jsonl"`, `PROXY_LOGS = (PROXY_LOG, SCHEME_PROXY_LOG, RETRY_PROXY_LOG)`.
  - `cli.capture` crea el `Proxy` tras planificar (con `AlcanceVivo(args.alcance_vivo)` si hay, si no `AlcanceFijo(alcance_de_consola(...))`), lo arranca antes de la primera subred, pone `engine["proxy"] = proxy.url`, llama a `proxy.registro(directory / PROXY_LOG)` (o el de esquema/reintento) justo antes de cada `scan_subnet`, y lo para en un `finally`.

- [ ] **Step 1: Tests**
  - `test_scan_subnet_pasa_el_proxy`: con `opts["proxy"] = "http://127.0.0.1:9"` el comando lleva `--chrome-proxy http://127.0.0.1:9`.
  - `test_capture_usa_el_proxy_en_cada_pasada`: con `scan_subnet` falso que guarda `opts["proxy"]` y el registro activo del proxy en cada llamada: todas las pasadas llevan el proxy; el registro es `proxy.jsonl`, `proxy-esquema.jsonl`, `proxy-reintento.jsonl` según la pasada; el proxy se para también si `scan_subnet` lanza.
  - `test_capture_en_consola_corta_lo_no_planificado`: sin `--alcance-vivo` y con `--excluir`, el `Proxy` recibe un alcance donde una IP privada no planificada da `fuera_de_alcance`.
- [ ] **Step 2:** Ejecutar → falla.
- [ ] **Step 3:** Implementar. El `timeout` del proxy sale de `opts["timeout"]`.
- [ ] **Step 4:** `python -m unittest discover -s tests` → OK.
- [ ] **Step 5:** Commit `feat(captura): el navegador de gowitness sale por el proxy de alcance`.

### Task 4: Atribuir los cortes a cada web y mantener los mensajes

**Files:**
- Modify: `dedalo/gowitness.py`, `dedalo/report.py` (`collect_group`, `COLUMNS`, `_write_rows`)
- Test: `tests/test_dedalo.py` (o `tests/test_bloqueos.py` si queda más claro)

**Interfaces:**
- Consumes: constantes de Task 3; formato de líneas de Task 2.
- Produces:
  - `gowitness.read_blocked(directory: Path) -> tuple[dict[str, list[dict]], list[dict]]`: (URL de resultado normalizada → cortes de esa página, cortes sin página). Lee los tres `PROXY_LOGS` y `network_logs` de `gowitness.sqlite3` (unido a `results` por `result_id`); un corte se atribuye a la página si alguna de sus peticiones tiene ese `host:puerto` (puerto por defecto del esquema si no viene). Cada corte: `{"destino", "ip", "puerto", "motivo"}`, sin duplicados por página.
  - `gowitness.read_failures(directory: Path) -> dict[str, str]`: `"ip:puerto"` → `rechazada` | `sin_respuesta` | `error`.
  - En `collect_group`, cada fila lleva `bloqueos: list[dict]`; el grupo, `bloqueos_sin_pagina: list[dict]`.
  - `read_errors` (lo usan `collect_group` y el detalle del portal) traduce dentro: si el mensaje de una URL contiene `net::ERR_TUNNEL_CONNECTION_FAILED` o `net::ERR_HTTP_RESPONSE_CODE_FAILURE` y `read_failures` tiene el `ip:puerto` de esa URL, ese código se sustituye por el que daría Chrome sin proxy: `rechazada` → `net::ERR_CONNECTION_REFUSED`, `sin_respuesta` → `net::ERR_CONNECTION_TIMED_OUT`. El resto del mensaje queda igual que hoy.
  - `COLUMNS` gana `"cortado_fuera_alcance"` al final: destinos separados por `; ` con su motivo, p. ej. `10.20.0.5:443 (excluida)`.

- [ ] **Step 1: Tests** con una `gowitness.sqlite3` sintética (crear solo `results` y `network_logs` con las columnas comprobadas en el spec) y ficheros JSON Lines en una carpeta temporal:
  - `test_corte_se_atribuye_a_la_pagina_que_lo_pidio` (dos páginas, un corte cada una).
  - `test_corte_sin_pagina_va_a_la_subred` (corte sin petición en `network_logs`).
  - `test_puerto_cerrado_tras_el_proxy_conserva_el_mensaje_de_hoy`.
  - `test_csv_lleva_lo_cortado`.
  - `test_sin_ficheros_del_proxy_no_cambia_nada` (salidas antiguas).
- [ ] **Step 2:** Ejecutar → falla.
- [ ] **Step 3:** Implementar; abrir la base de gowitness en solo lectura como `read_results`.
- [ ] **Step 4:** `python -m unittest discover -s tests` → OK.
- [ ] **Step 5:** Commit `feat(captura): cada web lleva lo que el proxy le cortó`.

### Task 5: Guardarlo en la base (migración 8)

**Files:**
- Modify: `dedalo/db.py` (migración 8), `dedalo/auditoria.py` (`record_captures`), `docs/MODELO_DATOS.md`
- Test: `tests/test_db.py` (migración) y `tests/test_auditoria.py` (`record_captures`)

**Interfaces:**
- Consumes: `bloqueos` de cada fila del manifiesto (Task 4).
- Produces: tabla

```sql
CREATE TABLE captura_bloqueo (
  id         INTEGER PRIMARY KEY,
  captura_id INTEGER NOT NULL REFERENCES captura(id) ON DELETE CASCADE,
  destino    TEXT NOT NULL,
  ip         TEXT,
  puerto     INTEGER,
  motivo     TEXT NOT NULL CHECK (motivo IN ('excluida', 'fuera_de_alcance', 'alcance_ilegible'))
);
CREATE INDEX captura_bloqueo_captura ON captura_bloqueo (captura_id);
```

  `record_captures` borra y reinserta los de cada captura que vuelca (repetible). `auditoria.capture_blocks(con, execution_id) -> dict[str, list[dict]]` (url → cortes) para quien lo necesite.

- [ ] **Step 1: Tests:** `test_migracion_8_crea_captura_bloqueo`, `test_record_captures_guarda_los_cortes_y_se_puede_repetir` (dos volcados → mismas filas), `test_borrar_la_ejecucion_borra_sus_cortes`, `test_manifiesto_sin_bloqueos_se_registra`.
- [ ] **Step 2:** Ejecutar → falla.
- [ ] **Step 3:** Implementar; documentar tabla y migración en `docs/MODELO_DATOS.md` (párrafo de migraciones y paso 4 de capturas).
- [ ] **Step 4:** `python -m unittest discover -s tests` → OK.
- [ ] **Step 5:** Commit `feat(base): migración 8, cortes del proxy por captura`.

### Task 6: Verlo en el portal

**Files:**
- Modify: `dedalo/web.py` (detalle del trabajo), `dedalo/static/app.js`, `dedalo/static/*.css` si hace falta
- Test: `tests/test_web.py`

**Interfaces:**
- Consumes: `bloqueos` por fila y `bloqueos_sin_pagina` por grupo del manifiesto.
- Produces: en la respuesta del detalle, cada objetivo lleva `bloqueos` y cada grupo `bloqueos_sin_pagina` (listas, vacías por defecto).

- [ ] **Step 1: Test** `test_detalle_lleva_los_cortes_del_proxy`: manifiesto con un corte en una fila y otro sin página → el detalle los devuelve en esos campos.
- [ ] **Step 2:** Ejecutar → falla. **Step 3:** Implementar `web.py`.
- [ ] **Step 4: Interfaz** con las skills del proyecto (frontend-design → avoid-ai-design → webapp-testing) y `DESIGN.md`:
  - En cada tarjeta, bajo la URL: «Intentó contactar con 10.20.0.5:443 (excluida); se cortó.», una línea por destino; `alcance_ilegible` se dice «No se pudo comprobar el alcance; se cortó 10.20.0.5:443.»
  - En la cabecera de cada subred, si hay `bloqueos_sin_pagina`: «En esta subred se cortaron conexiones a: …».
  - Una marca visible en las tarjetas con cortes. Todo texto del servidor pasa por `escapeHtml`.
  - Si se tocan colores: `python design/check-contrast.py`.
- [ ] **Step 5:** `python -m unittest discover -s tests` → OK; commit `feat(portal): aviso de lo que se cortó junto a cada web`.

### Task 7: Contrato, documentación e integración

**Files:**
- Modify: `docs/CONTRATOS.md` §0.3 regla 2, `docs/SEGURIDAD.md` (H1), `README.md`, `tests/integration_local.py`

- [ ] **Step 1:** CONTRATOS §0.3 regla 2: sustituir el «Límite conocido» por la regla del proxy (tabla de paso y motivos) y los límites que quedan (loopback, WebRTC, resolvedor del sistema, tráfico de fondo del navegador), tal como en el spec. SEGURIDAD: H1 **Arreglado** con esos límites. README: una línea en capturas.
- [ ] **Step 2:** `integration_local`: la web de prueba (en `127.0.0.1`) carga `http://10.255.255.1:81/x.png` (fuera del alcance `127.0.0.0/8` de la prueba). Comprobar en el manifiesto que esa web lleva un corte `10.255.255.1:81` con `fuera_de_alcance`, y que los casos de hoy (puerto cerrado, esquema equivocado) dan el mismo `estado` y error que antes del cambio. El destino no se contacta nunca: el proxy corta antes de conectar.
- [ ] **Step 3:** Ejecutar `python -m tests.integration_local` y `integration_web` (README, «Pruebas») en KmelloFumon → OK.
- [ ] **Step 4:** `python -m unittest discover -s tests` → OK; commit `docs: H1 cerrado con el proxy de alcance`.
