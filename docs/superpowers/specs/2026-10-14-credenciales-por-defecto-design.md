# Dédalo · Credenciales por defecto (bloque 6) — diseño

- Fecha: 2026-10-14
- Estado: aprobado en brainstorming (Doro); pendiente de plan de implementación
- Relacionado: tarea `credenciales-por-defecto`, hito `hito-prcc-final`, motor de IA `motor-priorizacion-ia`
- Contrato: `docs/CONTRATOS.md` §0.1, §0.3 (alcance), §0.4 (tipos de ejecución); modelo `docs/MODELO_DATOS.md`

## Objetivo

Para cada activo de una importación, Dédalo propone las **credenciales por defecto** (contraseñas de fábrica) que le tocan según el aparato que parece ser, y —cuando el operador lo pide a propósito— las **prueba** contra los servicios en alcance, con cuidado de no bloquear cuentas, y enseña dónde se entró. Es el bloque 6 del anteproyecto, adelantado para la entrega final de PRCC (29-nov).

## Qué entra en la demo (29-nov)

El subsistema completo: catálogo curado **más** prueba activa, lanzada desde el portal, contra tres tipos de servicio con solo librería estándar:

- **HTTP Basic/Digest** (la ventana de usuario/clave del navegador) — `urllib`.
- **HTTP por formulario** (login con POST a un formulario) — `urllib`, guiado por una «receta» por panel. Es la parte «mejor esfuerzo»: cada panel es distinto.
- **FTP** — `ftplib`.

Fuera de la demo (y de esta tarea): SSH, RDP, SMB, bases de datos y Telnet (`telnetlib` se eliminó en Python 3.13); no son viables solo con la estándar en este plazo.

## Decisiones de diseño acordadas

1. **Dato curado, no IA en caliente.** Las credenciales salen de un catálogo curado y versionado que viaja con la herramienta, no de una IA que las invente en cada escaneo. La IA solo ayuda **offline** a construir el catálogo, con revisión manual. En ejecución no interviene ninguna IA.
2. **Enfoque A** (de los tres barajados): la fuente de verdad del catálogo es un **fichero en el repo** que al arrancar se **vuelca a SQLite**; git da los diffs revisables y la licencia auditable, y SQLite da la consulta rápida y la copia en el NAS.
3. **Prueba dirigida, no a lo bruto.** A cada servicio solo se le prueban las credenciales que pegan con lo que parece ser (fabricante/producto/versión del fingerprint y el rol que ya deduce la IA). Si no se reconoce el aparato, no se prueba nada.
4. **Permiso explícito del operador.** La prueba nunca es automática: se lanza con un botón y una confirmación. Como se conecta de verdad (a diferencia del análisis de IA, que solo lee), la confirmación es obligatoria.
5. **Alcance y límites.** Solo servicios en alcance, comprobado justo antes de conectar; tope de intentos por servicio y pausa entre intentos; se para un servicio que empieza a rechazar.

## Sección 1 — El catálogo

**Fuente de verdad:** `dedalo/datos/credenciales.json`, versionado en git. Cabecera con la versión del catálogo, el origen y la licencia; y una lista de entradas. Cada entrada empareja un tipo de equipo con sus credenciales:

- `fabricante`, `producto` (texto que debe aparecer en el producto/título del servicio), `version` (patrón opcional; vacío = cualquiera), `servicio` (`http-basic` | `http-form` | `ftp`).
- `credenciales`: lista de `{usuario, clave}`.
- `receta` (solo `http-form`): cómo se entra y cómo se sabe —`ruta`, campos del formulario, y señal de éxito/fallo (redirección, código, o un texto que aparece cuando falla).
- `fuente`, `licencia`.

**En SQLite (migración 4, nueva):** tabla `credencial_catalogo`, una fila por credencial, con índice por `servicio`/`producto`. Al abrir la base, Dédalo calcula la huella SHA-256 del fichero; si cambió respecto a la guardada, vacía la tabla y la recarga desde el fichero en una transacción. La migración define la tabla **una vez**; los datos se refrescan desde el fichero, **sin tocar migraciones ya publicadas**.

**Curar el catálogo** (importar de recopilaciones públicas con IA offline y revisión manual) es un paso aparte, posterior. Para la demo se siembra a mano un conjunto pequeño que cubra el laboratorio y un par de fabricantes comunes.

## Sección 2 — Emparejamiento

Por cada servicio de cada activo, Dédalo mira su fingerprint (producto, versión y título web que trae el inventario) y el rol que le puso la IA (tabla `prioridad`), y selecciona del catálogo **solo** las entradas cuyo `servicio` encaja con el servicio observado y cuyo `producto`/`version` casan con el fingerprint. Si nada casa, ese servicio no se prueba.

- Menos intentos → no bloquea cuentas; determinista → traza reproducible.
- Ampliable: un puñado de credenciales «universales» para los no reconocidos queda como opción futura, fuera de la demo.

## Sección 3 — Prueba activa

- **Botón + confirmación.** Nada ocurre solo. Un botón «Probar credenciales» y una confirmación («va a intentar entrar en los servicios en alcance de esta importación, ¿seguro?») antes de empezar.
- **Alcance justo antes.** Antes de conectar a cada servicio se recomprueba el alcance; la exclusión gana. Sin reglas `incluir`, no se lanza.
- **Conexión directa, sin proxy del sistema** (como el cliente del modelo): el tráfico va a la red auditada, no a través de un proxy.
- **Probadores (librería estándar):**
  - `http-basic`: `urllib` con la credencial en la cabecera `Authorization`; éxito = la petición deja de pedir login (no 401).
  - `http-form`: `urllib` hace el POST según la receta; éxito según la señal de la receta (redirección/código/ausencia del texto de fallo).
  - `ftp`: `ftplib.FTP`, intento de `login(usuario, clave)`; éxito = sin error.
- **Límites (por defecto, ajustables):** tope de intentos por servicio; pausa entre intentos; se abandona un servicio tras N rechazos seguidos; una cosa cada vez (bajo y lento).
- **Resultado:** por servicio probado, se guarda el estado (`entrada` / `fallo` / `error`) y, si se entró, la credencial que funcionó. Es el hallazgo de la auditoría.

## Sección 4 — Portal (UI) · **PROVISIONAL**

> Doro: la pestaña y su manejo quedan como propuesta; se afinan tras probar el portal a fondo.

- Pestaña nueva **«Credenciales»** en una importación, junto a «Priorización», con el botón «Probar credenciales».
- Va por la **misma cola** que capturas y análisis: una cosa a la vez, el portal sigue respondiendo.
- Se ve avanzar («Probando 3 de 12 servicios»), se puede **parar** a media y **cancelar** si está en cola — igual que el análisis.
- Resultados en lista por equipo/servicio, los «entró» resaltados y arriba.
- Por dentro, una ejecución tipo `credenciales` ligada a la importación, con el mismo ciclo de vida que `analisis`: una por importación, volver a probar sustituye la anterior (solo al terminar bien), un activo excluido después deja de salir, y una ejecución a medias al cerrar el portal queda `interrumpida`.

## Sección 5 — Seguridad, errores y pruebas

**Seguridad:**
- Solo con botón + confirmación; solo en alcance, comprobado justo antes; topes y pausas para no bloquear cuentas; solo credenciales del catálogo curado (nunca IA en caliente).
- La credencial encontrada es **dato sensible**: se guarda en la base local (que ya contiene datos de clientes y se queda en el equipo y en el NAS), se muestra en el portal y **no sale a ningún sitio**. Mismo trato que el resto de `portal_datos`.
- Pasa por `/simplify` → `/code-review` y las revisiones de Trail of Bits que apliquen (toca red, entrada de usuario, ficheros y datos externos): differential-review, sharp-edges, insecure-defaults y, por las listas importadas, supply-chain-risk-auditor.

**Errores:**
- Servicio caído o lento → `error`, sigue con el siguiente.
- Receta que no cuadra o panel raro → `fallo`/`error`, sin tumbar la ejecución.
- Fallo al escribir en la base → no tumba el hilo de la cola (como el análisis).
- Parada o cierre a media → `interrumpida`, con lo ya probado conservado.

**Pruebas (TDD, sin red ni aparatos reales):**
- Servicios de mentira en loopback (un HTTP con Basic, uno con formulario y un FTP falso), al estilo del `FakeOllama` ya usado.
- Casos: con la credencial buena entra y con la mala no; se recomprueba el alcance antes de conectar (y un activo excluido no se toca); se respetan topes y pausas; el resultado se guarda bien; volver a probar sustituye; una ejecución a medias queda interrumpida; el catálogo se carga y se refresca por huella.

## Modelo de datos (migración 4)

- Reconstruye `ejecucion` para admitir el tipo `credenciales` en su CHECK (igual que la migración 3 añadió `analisis`).
- `credencial_catalogo` (catálogo volcado del fichero; se refresca por huella, no por migración).
- `credencial_resultado` (id, `ejecucion_id` FK cascade, `activo_id` FK cascade, puerto, protocolo, `servicio` del catálogo, estado `entrada|fallo|error`, usuario, clave, detalle, orden), con índice por activo.
- Una tabla pequeña para la huella del catálogo cargado (p. ej. `config(clave, valor)`), para saber cuándo recargar.

## Contrato (cambios en docs/CONTRATOS.md)

- §0.4: `credenciales` pasa de «tipo futuro» a tipo real, con su fila (qué hace, que **sí** conecta y con qué límites, qué escribe) y sus estados.
- §0.1: el bloque 6 pasa a implementado.
- `docs/MODELO_DATOS.md`: las tablas nuevas y la migración 4.

## Fuera de alcance (YAGNI)

- SSH, RDP, SMB, bases de datos, Telnet.
- Credenciales «universales» a lo bruto para aparatos no reconocidos.
- IA generando credenciales en ejecución.
- Exportar los resultados a CSV (posible después; ya quedan en la base).

## Preguntas abiertas (a cerrar en el plan o al sembrar)

- **Licencia** de las recopilaciones públicas a importar (DefaultCreds-cheat-sheet, SecLists): revisar antes de incluir nada; para la demo, sembrar a mano un conjunto propio o de origen claramente permisivo.
- **Siembra de la demo:** qué entradas mínimas (el panel del laboratorio `10.30.1.21` y un par de fabricantes), y añadir a `ejemplos/laboratorio.xml` un FTP y un servicio con Basic para poder enseñar los tres probadores.
- **Valores por defecto** de los límites (intentos por servicio, pausa).

## Criterios de terminado

- Catálogo como fichero versionado en el repo, volcado a SQLite por huella; origen y licencia documentados.
- Prueba activa que se activa a propósito (botón + confirmación), respeta el alcance (comprobado justo antes), con topes y pausas, y queda registrada.
- Los tres probadores (http-basic, http-form, ftp) con servicios simulados; `python -m unittest discover -s tests` en OK, sin red real.
- `/simplify` → `/code-review` + Trail of Bits que apliquen.
- README, `docs/CONTRATOS.md` §0.1/§0.4 y `docs/MODELO_DATOS.md` al día.
