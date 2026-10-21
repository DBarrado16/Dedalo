# Cruce de vulnerabilidades por CPE · plan

> **Para agentes:** ejecutar con superpowers:subagent-driven-development, tarea a tarea, en TDD. Pasos con checkbox.

**Objetivo:** por cada servicio con CPE (de Nmap o de la detección de alta confianza), mostrar sus CVE y marcar las que tienen exploit conocido, para priorizar el ataque y que salga en las exportaciones.

**Arquitectura:** `cve.py` (base NVD local + consulta + matching por versión), `exploits.py` (KEV/Exploit-DB locales + GitHub en vivo, dos niveles), `vulnerabilidades.py` (orquesta el cruce de un servicio y el orden determinista). La ejecución, la migración y la persistencia siguen el patrón de la detección de versión (`auditoria.py`/`web.py`). Las descargas y consultas HTTP con `urllib` (patrón de `probador`/`modelo`).

**Spec:** docs/superpowers/specs/2026-10-21-cruce-vulns-cpe-design.md

## Restricciones globales
- Solo librería estándar, sin pip. Comentarios y textos en español. CRLF: editar con Edit, nunca `sed -i`.
- **Local-first con interruptor:** las salidas a internet (descarga/actualización NVD, fallback NVD online, GitHub en vivo) son automáticas por defecto y se apagan con un interruptor **global**, off de fábrica, fijable por variable de entorno/flag **antes** del primer arranque. Con el interruptor activado, cero red: solo datos locales.
- **Alcance (CONTRATOS §0.3):** el cruce solo toca activos **en alcance**, recomprobado **en vivo** antes de cualquier salida a internet; el CPE de un excluido nunca sale. Test que lo demuestre.
- **Exploits en dos niveles:** confirmado (CISA KEV / Exploit-DB) vs. PoC sin verificar (GitHub). Nunca ejecutar ni descargar el exploit, solo enlazar.
- Migración nueva y numerada (6) en `dedalo/db.py`; las publicadas (1-5) no se tocan. Patrón: reconstruir `ejecucion` para añadir el tipo `vuln` (como la 5).
- No abrir `portal_datos/`, `salida/`, `pruebas_locales/`, `RESUMEN.md`, `*.sqlite3` ni capturas. Probar con `tests/` y datos de prueba inyectados; **sin red en los tests unitarios** (fuentes simuladas).
- `python -m unittest discover -s tests` termina en `OK`.

## Review Focus
1. CPE sin versión: no debe inflar la prioridad; se marca «sin filtrar por versión» (Tarea 3).
2. Versión en el borde del rango (`versionEndExcluding` = la propia versión): no casa (Tarea 3).
3. Activo excluido/fuera de alcance: su CPE nunca sale a la NVD ni a GitHub (Tareas 7 y 8).
4. Interruptor de internet activado: ni se actualiza la base ni hay fallback ni GitHub; el cruce usa lo local y marca «sin datos» si no hay (Tareas 2, 5, 7).
5. Base vacía o descarga a medias: el cruce guarda «sin datos», distinto de «sin vulnerabilidades» (Tarea 7).

---

### Tarea 1: interruptor global de salidas a internet

**Ficheros:** `dedalo/web.py` (lectura del ajuste al construir `PortalStore`, como `catalogo_ruta`/`model_host`), `dedalo/cli.py` (flag `--sin-internet`), docstring/README donde liste los ajustes. Test en `tests/test_web.py`.

**Produce:** `PortalStore.sin_internet: bool`, leído de (en orden) el flag `--sin-internet`, la variable de entorno `DEDALO_SIN_INTERNET`, o `False`. Un método/propiedad `self.sin_internet` que el resto consulta antes de cualquier salida a internet.

**Pasos (TDD):**
- [ ] Test que falla: construir `PortalStore` con `DEDALO_SIN_INTERNET=1` (y con el flag) deja `sin_internet=True`; sin nada, `False`.
- [ ] Ejecutar: falla.
- [ ] Implementar.
- [ ] `python -m unittest discover -s tests` → `OK`. Commit.

### Tarea 2: base local de CVE (almacenamiento y consulta por CPE)

**Ficheros:** crear `dedalo/cve.py`; migración 6 en `dedalo/db.py` (tablas de CVE; ver abajo); tests en `tests/test_cve.py`.

**Interfaces producidas:**
- Esquema (migración 6, **completa y todo-o-nada**): reconstruye `ejecucion` para añadir `vuln` al CHECK de tipo (como la 5) y crea las tablas `cve` (`id` TEXT PK = CVE-id, `publicada` TEXT, `severidad` TEXT, `cvss` REAL, `resumen` TEXT), `cve_cpe` (`cve_id` REFERENCES cve, `parte` TEXT, `vendor` TEXT, `producto` TEXT, `v_ini` TEXT, `v_ini_incl` INT, `v_fin` TEXT, `v_fin_incl` INT) con índice por `producto`, y `vulnerabilidad` (`id` INTEGER PK, `ejecucion_id` REFERENCES ejecucion, `servicio_id` REFERENCES servicio, `cve_id` TEXT, `severidad` TEXT, `exploit_nivel` TEXT, `enlaces` TEXT, `origen_cpe` TEXT, `estado` TEXT) con índice por `servicio_id`. La tabla `vulnerabilidad` la crea esta migración pero la usa la Tarea 7. La fecha de última actualización de la base NVD va en `config` (clave `nvd_actualizada`).
- `guardar_cves(con, items: list[dict]) -> None`: inserta/actualiza CVE y sus reglas cpe (idempotente).
- `comparar_versiones(a: str, b: str) -> int`: -1/0/1 comparando por componentes numéricos y, a falta, lexicográfico. Escrita a mano (sin pip).
- `cves_de(con, cpe: str) -> list[dict]`: CVE cuyo `producto` (y `vendor` si el cpe lo trae) casan y cuya **versión del cpe cae en el rango** (`v_ini`/`v_fin` con sus `incl`). Si el cpe **no trae versión**, devuelve las del producto con una marca `sin_version=True` en cada fila.

**Pasos (TDD):**
- [ ] Test que falla: `comparar_versiones` ("2.4.9","2.4.10")=-1, ("1.0","1.0.0")=0, iguales=0.
- [ ] Test que falla: con una base poblada por `guardar_cves`, `cves_de("cpe:/a:apache:http_server:2.4.59")` devuelve las CVE cuyo rango incluye 2.4.59 y excluye las de rango `<=2.4.58`; borde `versionEndExcluding=2.4.59` no casa.
- [ ] Test que falla: `cves_de` de un cpe sin versión marca `sin_version=True`.
- [ ] Ejecutar: fallan.
- [ ] Implementar la migración 6 completa (reconstruir `ejecucion` con `vuln`, y crear `cve`, `cve_cpe` y `vulnerabilidad`) y `cve.py`.
- [ ] `python -m unittest discover -s tests` → `OK`. Commit.

### Tarea 3: construir CPE desde la detección de alta confianza

**Ficheros:** `dedalo/cve.py` (`cpe_desde_deteccion`), tests en `tests/test_cve.py`.

**Consume:** las filas de `deteccion` (producto, versión, confianza, origen) que ya expone `auditoria` (ver `captured_services`/`_derived` del tipo `version`).

**Produce:** `cpe_desde_deteccion(producto: str, version: str) -> str | None`: normaliza el nombre del producto a un cpe `cpe:/a:*:<producto>:<version>` (minúsculas, espacios→`_`), o `None` si el producto está vacío. El vendor va como `*` (comodín): `cves_de` ya casa por `producto`. El umbral de confianza (qué es «alta») lo decide el llamador (Tarea 7), no esta función.

**Pasos (TDD):**
- [ ] Test que falla: `cpe_desde_deteccion("Apache httpd","2.4.59")` → `cpe:/a:*:apache_httpd:2.4.59`; producto vacío → `None`.
- [ ] Ejecutar: falla. Implementar. Tests → `OK`. Commit.

### Tarea 4: fuentes de exploit locales (CISA KEV + Exploit-DB), dos niveles

**Ficheros:** crear `dedalo/exploits.py`; tests en `tests/test_exploits.py`.

**Produce:**
- `cargar_kev(ruta) -> set[str]` y `cargar_exploitdb(ruta) -> dict[str, list[str]]` (CVE→enlaces), leídos de ficheros locales ya descargados; entradas mal formadas se ignoran (patrón `catalogo`/`favicones`).
- `exploit_de(cve_id, kev: set, edb: dict) -> dict`: `{"nivel": "confirmado"|"ninguno", "enlaces": [...]}`. `confirmado` si está en KEV o en Exploit-DB.

**Pasos (TDD):**
- [ ] Test que falla: un CVE en KEV da `nivel="confirmado"`; uno en Exploit-DB, `confirmado` con sus enlaces; uno en ninguno, `ninguno`.
- [ ] Ejecutar: falla. Implementar. Tests → `OK`. Commit.

### Tarea 5: descargas de red (NVD feeds + fallback online + GitHub), respetando el interruptor

**Ficheros:** `dedalo/cve.py` (`actualizar_base`, `consultar_online`), `dedalo/exploits.py` (`buscar_github`), tests con un `http.server` local en `tests/`.

**Produce:**
- `actualizar_base(con, destino, sin_internet: bool, log=print) -> None`: si `sin_internet`, no hace nada; si no, descarga los feeds de la NVD (acotados a los últimos 10 años), los pasa por `guardar_cves`, y marca `config.nvd_actualizada`. Incremental si ya hay datos.
- `consultar_online(cpe: str, sin_internet: bool) -> list[dict]`: `[]` si `sin_internet`; si no, consulta la API de la NVD por cpe y devuelve las CVE en el mismo formato que `guardar_cves`.
- `buscar_github(cve_id: str, sin_internet: bool, token: str | None = None) -> list[str]`: `[]` si `sin_internet`; si no, busca repos PoC por el id de CVE (enlaces); degrada a `[]` si falla o se agota el límite, nunca rompe.

**Pasos (TDD):**
- [ ] Test que falla: con `sin_internet=True`, las tres funciones no tocan la red (parchear/servidor local que registre llamadas) y devuelven vacío/no-op.
- [ ] Test que falla: `actualizar_base` contra un servidor local que sirve un feed de prueba puebla la base; `consultar_online` y `buscar_github` parsean la respuesta de prueba.
- [ ] Ejecutar: fallan. Implementar (URLs de feeds/endpoints fijadas como constantes, patrón `gowitness`). Tests → `OK`. Commit.

### Tarea 6: cruce de un servicio y orden determinista

**Ficheros:** crear `dedalo/vulnerabilidades.py`; tests en `tests/test_vulnerabilidades.py`.

**Consume:** Tareas 2-5.

**Produce:**
- `cruzar_servicio(con, cpes: list[str], kev, edb, sin_internet, buscar_github=...) -> dict`: para cada cpe, `cves_de` local; si local vacío para ese cpe, `consultar_online`. Por cada CVE, `exploit_de` y, si procede, `buscar_github` (PoC sin verificar). Devuelve `{"estado": "ok"|"sin_datos", "vulns": [{cve, severidad, enlace, exploit_nivel, enlaces_exploit, origen_cpe, sin_version}]}`. `sin_datos` cuando no hay base local y no se pudo consultar (interruptor o fallo).
- `orden(vulns: list[dict]) -> int`: clave de prioridad del servicio: exploit confirmado > CVE crítica > CVE > PoC sin verificar > nada.

**Pasos (TDD):**
- [ ] Test que falla: un servicio con una CVE crítica y exploit confirmado sale con `exploit_nivel="confirmado"` y mayor prioridad que uno con solo PoC de GitHub.
- [ ] Test que falla: sin base local y `sin_internet=True` → `estado="sin_datos"` (no `"ok"` con `vulns=[]`).
- [ ] Ejecutar: fallan. Implementar. Tests → `OK`. Commit.

### Tarea 7: ejecución `vuln` en el portal (cola, alcance en vivo, persistencia)

**Ficheros:** `dedalo/auditoria.py` (arranque/estado/persistencia del tipo `vuln`, patrón de `begin_version`/`finish_version`/`version_status`; tabla `vulnerabilidad` en la migración 6), `dedalo/web.py` (`_cruzar_vulns`, encolado y endpoint, patrón de `_detect`), tests en `tests/test_web.py` y `tests/test_auditoria.py`.

**Produce:** una ejecución tipo `vuln` sobre una importación que, por cada servicio **en alcance** (recomprobado en vivo con `_AlcanceVivo` antes de salir a internet), reúne sus CPE (de Nmap y de `deteccion` con confianza ≥ umbral), llama a `vulnerabilidades.cruzar_servicio` y guarda el resultado en `vulnerabilidad`. Un servicio excluido no se cruza y su CPE no sale. `sin_datos` se guarda distinto de «sin vulns».

**Pasos (TDD):**
- [ ] Test que falla: un servicio fuera de alcance en vivo no provoca ninguna salida a internet (parchear `consultar_online`/`buscar_github` y afirmar que no se llamó) y no se cruza.
- [ ] Test que falla: tras la ejecución, `vulnerabilidad` tiene las filas del servicio en alcance con su nivel de exploit; un servicio sin base marca `sin_datos`.
- [ ] Ejecutar: fallan. Implementar (migración 6 ya creó la tabla en la Tarea 2; aquí se usa). Tests → `OK`. Commit.

### Tarea 8: priorización IA, exportaciones, portal y docs

**Ficheros:** `dedalo/prioridad.py` (añadir las vulns al prompt de la IA, patrón del fingerprint), `dedalo/inventory.py` (CSV/JSON con columnas de vulns), `dedalo/report.py` (índice de capturas), `dedalo/static/` (sección de vulnerabilidades + `python design/check-contrast.py` si se tocan colores), `README.md`, `docs/CONTRATOS.md` §0.3/§0.4, `docs/MODELO_DATOS.md`. Tests en `tests/test_inventory.py`, `tests/test_web.py`.

**Produce:** las vulnerabilidades (CVE, severidad, nivel de exploit, enlaces) en el CSV/JSON del inventario y en el índice de capturas; el orden determinista visible; la señal pasada a la IA que prioriza; la sección en el portal; docs al día (incluida la regla de alcance §0.3 y el tipo `vuln` en §0.4 y MODELO_DATOS).

**Pasos (TDD):**
- [ ] Test que falla: el CSV/JSON del inventario de un activo con vulns incluye sus columnas (CVE, severidad, exploit, enlace); sin vulns, vacío; `sin_datos` se distingue de «sin vulns».
- [ ] Test que falla: `prioridad.build_prompt` (o equivalente) incluye las vulns del servicio cuando las hay.
- [ ] Ejecutar: fallan. Implementar. Docs al día.
- [ ] `python -m unittest discover -s tests` → `OK`; si se tocó captura/API, `python -m tests.integration_local` → `OK`. Commit.
