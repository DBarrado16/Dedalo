# Dédalo · Producto y versión con IA desde la captura — diseño

- Fecha: 2026-10-19
- Estado: borrador de diseño (brainstorming con Doro); pendiente de su ok antes de planificar
- Relacionado: tarea `version-ia-captura`; se apoya en el motor de priorización [[motor-priorizacion-ia]] (hecho) y mejora el fingerprint que usan las credenciales por defecto [[credenciales-por-defecto]] y el [[catalogo-credenciales-compartido]]
- Contrato: `docs/CONTRATOS.md` §0.4 (tipos de ejecución; hay que ampliarlo), modelo `docs/MODELO_DATOS.md`

## Objetivo y porqué

Hoy, lo que Dédalo cree que es cada servicio (su **producto y versión**, su «fingerprint») sale **solo de Nmap**. Con eso decide la prioridad y, sobre todo, **qué credenciales de fábrica se le prueban**. Nmap se queda corto con paneles web, routers y firmware: ve «nginx» o «un puerto 443», no «panel de MikroTik RouterOS 6.49.7».

En cada captura ya tenemos delante mucha más información y **no la estamos usando**: gowitness guarda el HTML del front, las cabeceras de respuesta y hasta una detección de tecnologías. La idea es aprovechar eso para afinar el producto y la versión de cada servicio, y de rebote mejorar qué credenciales se le prueban.

## Lo que ya hay (comprobado en el código, 2026-10-19)

- **gowitness ya captura y guarda todo lo necesario** en su base (`gowitness.sqlite3`, dentro de la carpeta de cada ejecución): tabla `results` con el **HTML** de la primera respuesta (`html`), `title`, `response_code`, `final_url`, `content_length`, `protocol`; tabla `headers` (clave/valor por resultado); tabla `technologies` (detección estilo Wappalyzer: en una prueba local salió `WordPress:6.4.2`, `PHP:7.4.33`, `jQuery:3.5.1`, `MySQL`). También `tls`, `cookies`, `network_logs`. **No hay que pedirle flags nuevos** (el HTML se guarda por defecto).
- **Dédalo tira casi todo.** `gowitness.read_results()` solo lee `url, final_url, response_code, title, filename`; la tabla `captura` guarda solo eso más estado y error. Ni cabeceras, ni HTML, ni tecnologías entran en la base de Dédalo ni se usan.
- **El fingerprint que mueve las credenciales sale de Nmap.** `credenciales._casa()` compara `producto`/`version` del servicio de Nmap (más el `http-title`) con el catálogo; no mira nada de la captura.
- **Hay un motor de IA ya montado y probado** (`dedalo/modelo.py` + `dedalo/prioridad.py`): Ollama en local por HTTP, solo loopback, sin proxy ni redirecciones, nunca modelos `-cloud`; respuesta en JSON con esquema fijo (`format`), temperatura 0, el `generate` se inyecta para poder testear con un modelo falso, y los metadatos del cliente viajan como **bloque de datos acotado, no como instrucciones**. Este es el patrón a reutilizar.

## Qué se decidió (con Doro)

1. **Automático y por detrás.** En cuanto termina una captura, Dédalo estima producto y versión **sin que Doro lance nada aparte** y **sin frenar la galería**: las imágenes se ven ya; la versión se va rellenando sola después.
2. **Se guarda y alimenta las credenciales (las dos cosas).** El resultado se ve en la galería/inventario y además entra en el fingerprint que decide qué credenciales por defecto se prueban.
3. **gowitness primero, la IA solo completa y afina.** Se aprovecha tal cual la detección de tecnologías de gowitness; la IA entra únicamente a reconocer y afinar lo que gowitness no identifica (routers, paneles raros, firmware). Si la IA está apagada o falla, queda al menos lo de gowitness.
4. **Cuando Nmap y la captura discrepan, se guardan las dos lecturas y se prueban las credenciales de ambas.** Más cobertura; no se elige una «ganadora».
5. **Motor: Ollama local por defecto; Claude por API como opción.** La opción de API se activa a conciencia, con aviso de que esos datos salen del equipo, y la clave de API en variable de entorno, nunca en la base ni en el repo. La detección por IA viene **apagada de serie** (como está hoy): Doro la enciende en el ajuste cuando quiere; un interruptor la apaga del todo.
6. **El HTML del cliente es contenido hostil.** Va al prompt del modelo como **dato acotado, nunca como instrucciones** (igual que los metadatos de Nmap en el motor de priorización); la respuesta se **valida** contra un esquema y lo que no encaja queda **sin versión**.
7. **No conecta de más.** La detección lee solo lo que la captura **ya guardó** en disco; no hace ninguna petición nueva a los objetivos. Las únicas salidas de red son al modelo: Ollama en loopback o, si se elige, la API de Claude.

## Cómo encaja (propuesta)

### Flujo
- Al **terminar una ejecución `captura`**, si la detección está activada, Dédalo arranca **por detrás** un paso de detección de versión sobre los servicios recién capturados de esa importación, reutilizando el andamiaje del análisis (misma cola, progreso «n de N», se puede detener, estados del §0.4). La captura ya está `completa` y visible antes de que esto empiece.
- El paso **lee de `gowitness.sqlite3`** (HTML, cabeceras, tecnologías) lo que gowitness guardó para cada URL. **No conecta con ningún objetivo.**
- Solo corre sobre **servicios capturados con éxito** (hay HTML/cabeceras que mirar); un `sin_captura` o un servicio no web se queda con el fingerprint de Nmap.
- Como el análisis, una detección nueva sobre la misma importación **solo sustituye a la anterior cuando termina bien**; si falla o se interrumpe, sigue valiendo la última completa.
- **gowitness primero:** sus `technologies` se recogen tal cual como lecturas del servicio.
- **La IA completa:** por cada servicio, se le pasa al modelo un **extracto acotado** —cabeceras relevantes (Server, X-Powered-By, etc.), `title`, metas tipo `generator`, y un **trozo recortado** del HTML, no entero— dentro de un bloque de datos. Devuelve producto + versión + confianza en JSON; `parse_result` lo valida; lo que no encaja o no supera un umbral de confianza queda sin versión.
- El resultado se **guarda** (ver datos) y queda disponible para la galería/inventario y para el emparejamiento de credenciales.

### Datos (regla del proyecto: migración nueva y numerada)
- Hace falta **guardar las detecciones** por servicio, admitiendo **varias por servicio** (varias tecnologías de gowitness + la lectura de la IA) y su **origen** (`nmap` ya lo tenemos aparte; aquí `gowitness` e `ia`), con `producto`, `version` y, para la IA, confianza/motivo. Esto es una **tabla nueva** ligada al servicio y a la ejecución que la produjo, con su **migración numerada** en `dedalo/db.py` (las ya publicadas quedan intactas).
- El HTML completo y las cabeceras siguen en `gowitness.sqlite3` (evidencia en disco); en la base de Dédalo se guarda **lo derivado** (las detecciones), no el HTML crudo, para no inflar la base.
- El esquema exacto de la tabla (nombre, columnas, índices) lo cierra el plan; la intención es: `(servicio_id, ejecucion_id, origen, producto, version, confianza, detalle)`.

### Fingerprint y credenciales
- El fingerprint de un servicio pasa a ser la **unión** de lo de Nmap y lo detectado desde la captura (gowitness + IA). El emparejamiento de credenciales (`credenciales._casa`/`objetivos`) considera **todas las lecturas**: si alguna casa con una entrada del catálogo, esa credencial se prueba (sigue mandando el recálculo de alcance en vivo y los topes del tipo `credenciales`).
- La prueba de credenciales **sigue siendo a propósito** (botón + confirmación): esto mejora *qué* se ofrece probar, no lanza pruebas solo.

### Motor de IA
- Reutiliza `dedalo/modelo.py`. Para **Ollama** no cambia nada del contrato de red (loopback, sin proxy, sin cloud).
- Para **Claude API** se añade un motor alternativo detrás de la misma interfaz `generate(prompt, ...) -> texto`: HTTP a la API de Anthropic con la clave desde variable de entorno, solo librería estándar (`urllib`), seleccionable y **apagado por defecto**. El selector de motor en el portal es análogo al desplegable de modelos de Ollama que ya tiene la priorización.

### Interfaz
- En la **galería/inventario**, mostrar junto a cada servicio el producto/versión detectado y de **qué origen** viene (Nmap / gowitness / IA), para fiarse de un vistazo. Es un dato añadido a vistas que ya existen, no una pantalla nueva.
- Un **ajuste** para activar/desactivar la detección y elegir motor (Ollama local / Claude API), con el aviso correspondiente al elegir API.

## No-goals / anti-goals

- **No** se elige una lectura «ganadora» cuando Nmap y la captura discrepan: se guardan las dos.
- **No** se mete la IA en el camino crítico de la captura: nunca retrasa ni bloquea que una imagen aparezca en la galería.
- **No** se guarda el HTML crudo en la base de Dédalo (sigue en `gowitness.sqlite3` como evidencia); solo lo derivado.
- **No** se prueban credenciales de forma automática: esto solo afina el fingerprint; la prueba sigue pidiendo botón y confirmación.
- **No** sale la clave de API a la base ni al repo; y con Ollama local nada del cliente sale del equipo.
- **Anti-goal:** que el HTML de una web de cliente logre **inyectar instrucciones** en el modelo y falsee el fingerprint. Se trata siempre como dato acotado y la salida se valida.
- **No** se toca el funcionamiento de la priorización ni de las credenciales más allá de alimentarlas con el fingerprint ampliado.

## Restricciones

- Solo librería estándar; portal local en `127.0.0.1` con `Origin` y `X-Dedalo-Token` en lo que muta.
- **Contrato = código:** ampliar `docs/CONTRATOS.md` §0.4 con el tipo de ejecución nuevo (qué hace, si conecta con objetivos —**no**—, qué escribe) y con la salida de datos a la API de Claude como opción explícita y avisada; hoy §0.4 asume que al modelo solo se habla por Ollama loopback.
- **Migración nueva y numerada** en `dedalo/db.py`; las publicadas, intactas.
- Patrón de IA: metadatos/HTML como dato, no instrucciones; respuesta validada contra esquema; `generate` inyectable para tests.
- TDD con un **modelo falso**, sin red ni navegador. Si toca capturas/gowitness/API del portal, pasar también las de integración.
- Datos reales (`portal_datos/`, capturas, `*.sqlite3` de ejecuciones) no se abren ni se pasan a subagentes; para probar, `ejemplos/` y `tests/`.
- `/simplify` → `/code-review`; toca entrada de usuario, red, ficheros y una dependencia externa nueva (API de Claude): aplicar las de Trail of Bits que correspondan (differential-review, insecure-defaults, sharp-edges, static-analysis, supply-chain-risk-auditor).
- README, `docs/CONTRATOS.md` y `docs/MODELO_DATOS.md` al día.
- Evaluar modelos locales para esta tarea (parte del trabajo, según la nota).

## Lo que queda al constructor (decisiones menores, mías)

- Esquema exacto de la tabla de detecciones (nombre, columnas, índices) y su migración.
- Qué cabeceras y cuántos KB de HTML entran en el extracto para la IA, y el umbral de confianza por debajo del cual se descarta.
- Formato del prompt y del esquema JSON de la respuesta (producto, versión, confianza, motivo), calcado del estilo de `prioridad.py`.
- Cómo se dispara el paso tras la captura (crear la ejecución al terminar, reusar la cola/progreso del análisis) y el nombre del tipo de ejecución.
- Interfaz del motor Claude API (endpoint, modelo por defecto, nombre de la variable de entorno, manejo de errores/timeout) tras la misma firma `generate`.
- Dónde y cómo se muestran las lecturas y su origen en la galería/inventario.

## Preguntas abiertas (a cerrar en el plan)

- ¿Un **tipo de ejecución nuevo** (p. ej. `version`/`fingerprint`) encolado tras la captura, o un paso dentro de la propia `captura`? Propuesta: tipo nuevo, por coherencia con el modelo de ejecuciones y §0.4. [a confirmar en el plan]
- La detección por IA viene **apagada de serie** y Doro la enciende en el ajuste (decidido con Doro, 2026-10-19).
- Modelo de Claude por defecto cuando se elige esa opción. [menor]
