# Integrar el descubrimiento DNS en el portal · diseño

- Fecha: 2026-10-14
- Estado: **aprobado** (decisiones de Doro, 2026-10-14); pendiente de plan de implementación
- Relacionado: tarea `integrar-dns`, hito `hito-v1`
- Origen: investigación de diseño de un subagente; decisiones cerradas con Doro
- Contrato: `docs/CONTRATOS.md` §0.1, §0.3 (alcance), §0.4 (tipos de ejecución); modelo `docs/MODELO_DATOS.md`

## 1. Objetivo

Que el portal lance sobre el alcance de una ficha el descubrimiento DNS que ya vive en `dedalo/descubrimiento.py`, con un botón, y muestre el resultado en una pestaña nueva. Todo lo que **conecta** (modo `servidores`) recomprueba el alcance justo antes de cada consulta. Hoy `descubrimiento.py` existe y está probado (~14 tests), pero **no está cableado** ni en la consola ni en el portal. Adelanta parte del bloque 2 del anteproyecto, que `docs/CONTRATOS.md §0.1` tiene en «queda para después».

## 2. Qué hay hoy (verificado en el código)

- **`dedalo/descubrimiento.py`:** `MODES = ("nombres", "servidores")`, `MAX_ADDRESSES = 65_536`.
  - `expand(networks, limit)` → direcciones sueltas, en orden, sin duplicados; aborta si supera el límite.
  - `reverse_name(ip)` → `(nombre, error)`, PTR con `socket.gethostbyaddr`: habla **solo con el resolvedor del sistema**, no con el objetivo.
  - `dns_server(ip, domain, timeout, port)` → `(responde, detalle, error)`: **conecta** por UDP 53.
  - `sweep(addresses, mode, domain="", *, scope=None, timeout, delay, workers, stop, progress)` → filas `{"ip","encontrado","nombre","detalle","error"}`. **Recomprueba `scope.status(ip)` dentro del hilo, justo antes de cada consulta**; lo que no está en alcance se devuelve con el motivo y sin consultar. El modo `servidores` exige `scope` (`ValueError` si `None`) y valida el dominio antes de abrir sockets. `scope` es «cualquier objeto con `status(ip)`»; el test `test_scope_is_checked_at_query_time_not_when_planning` ya demuestra un envoltorio **vivo** cuyo `status()` cambia a mitad del barrido y se respeta.
- **Base de datos:** la migración 2 ya admite `tipo = 'descubrimiento'`. La situación de alcance de un activo **no se guarda**.
- **Patrón a imitar (captura y análisis):** un tipo de ejecución con `origen_id` → la importación; una sola cola `self.pending` drenada por un `_worker` (rama por tipo); estados con `begin_*`/`set_state`/`stop_*` y cierre de interrumpidas al arrancar; alcance de la ficha (`auditoria.scope`) recomprobado antes de conectar; pestaña en `dedalo/static/` + rutas en `dispatch`; resultados en la base ligados a la ejecución y, por `origen_id`, a la importación.

## 3. Decisiones (cerradas con Doro, 2026-10-14)

1. **Solo desde el portal.** Una sola vía de conexión auditada; el alcance vive en la ficha. El módulo queda listo para un subcomando de consola más adelante, sin rediseño.
2. **Por la misma cola de una-en-una** (`self.pending` / `_worker`) que capturas y análisis. El modo `servidores` conecta y debe serializarse con las capturas; reutiliza apagado ordenado, `stop` y progreso.
3. **Resultados como observaciones, sin migración.** El descubrimiento es otra ejecución que «vio» el activo: los nombres (`nombres`) caen en `observacion_activo.nombres` (creando el activo si no existía), y un servidor DNS (`servidores`) es un `servicio(udp,53)` observado, con `observacion` (`nombre='domain'`, detalle = rcode/nº de respuestas). El borrado en cascada ya limpia lo que solo vio esta ejecución. Las filas crudas «fuera de alcance / no consultada» son estado efímero (coherente con que el alcance no se persiste): se ven mientras corre y en el registro, no se guardan. **No hace falta ninguna migración.**
4. **Alcance en vivo, con caché por `scope_changes`.** El portal pasa a `sweep` un envoltorio de alcance cuyo `status(ip)` relee el alcance vigente de la ficha, releyendo solo cuando cambia el contador `store.scope_changes` que el portal ya incrementa en cada edición. Así una exclusión añadida a mitad de un barrido largo (hasta 65k IP) se respeta al momento, y es barato. Es la lectura literal de CONTRATOS §0.3.2.
5. **Dominio de sondeo configurable al arrancar.** El dominio que usa el modo `servidores` para sondear se fija con una opción del portal al arrancar (p. ej. `--dns-dominio`, con un dominio de sondeo estándar por defecto), no se escribe en cada barrido. La ejecución anota en sus `opciones` el dominio usado. La pestaña, por tanto, no lleva campo de dominio: solo el selector de modo y los botones.

**Garantías de alcance (obligatorias, en todas las piezas):**
- El portal **siempre** pasa un `scope`; `servidores` lanza `ValueError` si fuese `None`.
- **Antes de encolar**, si la ficha no tiene ninguna regla `incluir`, se rechaza con «Define el alcance de la ficha» (como `start()` rechaza con `total == 0`). Con `Scope` sin `incluir`, todo queda `OUT` y `servidores` no consultaría nada de todos modos: la verificación es una red de seguridad explícita.
- `addresses = expand(scope.include, MAX_ADDRESSES)`; un alcance demasiado grande se rechaza con el mensaje de `expand`.
- El dominio se valida antes de abrir sockets (ya lo hace `sweep`).
- El modo `nombres` no conecta con los objetivos (habla con el resolvedor del sistema), pero mantiene el filtro de alcance para no revelar ni registrar nada fuera de la ficha.

## 4. Cómo encaja (propuesta firme)

Un botón **«Descubrir»** en una pestaña nueva **«Descubrimiento»** de una importación crea una ejecución `descubrimiento` con `origen_id` en esa importación, la encola en la misma cola, y el `_worker` la ejecuta con `descubrimiento.sweep(...)`:
- `addresses = descubrimiento.expand(scope.include)` (rangos `incluir` de la ficha, acotado por `MAX_ADDRESSES`).
- `scope` = envoltorio vivo-cacheado (Decisión 4).
- `mode` = `nombres` | `servidores`; para `servidores`, `domain` = el dominio configurado al arrancar.
- `stop` / `progress` = igual que el análisis.

Estados idénticos al análisis: `preparada`→`en_cola`→`en_curso`→`completa` | `cancelada` | `deteniendo`→`interrumpida` | `error`.

Funciones espejo de las de análisis:
- En `auditoria.py`: `start_discovery`, `begin_discovery`, `discovery_status`, `stop_discovery`, `finish_discovery` (vuelca filas a observaciones en una transacción), y `close_interrupted_analyses` ampliada para cerrar también `descubrimiento`.
- En `web.py`: `discover(job_id, payload)`, `stop_discovery(job_id)`, `_run_discovery`, `_discover`, rama `"descubrimiento"` en `_worker`, estado y resultados en `detail`, rutas `/api/jobs/{id}/descubrir` y `/detener-descubrimiento` en `dispatch`.
- En `static/`: pestaña «Descubrimiento» con selector de modo y botones lanzar/detener, progreso, `renderDiscovery()` (todo texto encontrado pasa por `escapeHtml`).

## 5. Migración

**Ninguna.** El tipo `descubrimiento` existe desde la migración 2 y los resultados se guardan en las tablas de observación ya existentes (Decisión 3). Las migraciones publicadas quedan intactas (incluida la 4, que añade el bloque de credenciales).

## 6. Invariantes que respeta

- **Solo librería estándar** (`descubrimiento.py` ya lo cumple; el cableado no añade dependencias).
- **Alcance** recomprobado justo antes de cada consulta; la exclusión gana; sin `incluir`, no se lanza nada.
- **Migraciones** inmutables; esta función no añade ninguna.
- **Portal local** en `127.0.0.1` con `Origin` y `X-Dedalo-Token` (las rutas nuevas pasan por el mismo `dispatch`).

## 7. Esbozo de reparto de tareas (títulos; los pasos TDD van en el plan)

1. **auditoría: ciclo de vida del descubrimiento** — `start/begin/finish/stop/discovery_status` y ampliar el cierre de interrumpidas, espejo de las de análisis.
2. **Volcado de resultados a observaciones** — de las filas de `sweep` a `observacion_activo.nombres` / `servicio(udp,53)` + `observacion`, en una transacción, todo o nada.
3. **PortalStore: encolado y ejecución** — `discover`/`stop_discovery`/`_run_discovery`/`_discover`, rama `"descubrimiento"` en `_worker`, estado y resultados en `detail`; la opción `--dns-dominio` en `cli.py`/`serve_portal`.
4. **Alcance y guardas** — envoltorio de alcance vivo-cacheado (§3.4), rechazo sin `incluir`, `expand` acotado, validación de modo/dominio; tests de que no se consulta fuera de alcance y de que sin `incluir` no se lanza.
5. **Rutas del portal** — `/api/jobs/{id}/descubrir` y `/detener-descubrimiento` en `dispatch`, con sus tests (token + mismo origen).
6. **Pestaña «Descubrimiento»** — `data-tab`, selector de modo, botones lanzar/detener, progreso, `renderDiscovery()`; tokens de `DESIGN.md` y `python design/check-contrast.py`.
7. **Contrato y documentación** — mover el descubrimiento de «futuros» a incluido en `docs/CONTRATOS.md` (§0.1 y la tabla de §0.4 como tipo que conecta solo en alcance), `docs/MODELO_DATOS.md` (que el descubrimiento escribe observaciones) y README.
8. **Pruebas sin red** — unitarias de auditoría y PortalStore con un `sweep` falso, de `dispatch` y de la recomprobación de alcance; `python -m unittest discover -s tests` en `OK` sin red ni navegador.

## 8. Nota de secuencia

El bloque de credenciales (rama `claude/credenciales-por-defecto`) toca los mismos ficheros (`web.py`, `auditoria.py`, `static/`, docs). Para no chocar, el DNS se **implementa después** de que credenciales se fusione en main; esta rama parte de main y se pondrá al día antes de empezar.
