# Cruce de vulnerabilidades por CPE · diseño

## Intención y porqué
El inventario de Dédalo ya guarda el CPE de cada servicio (`cpe:/a:openbsd:openssh:8.2`), pero solo lo muestra. El auditor tiene que ir por su cuenta a buscar qué vulnerabilidades tiene cada cosa, y los servicios menos vistosos (FTP, SSH) se quedan atrás. La idea de Doro (2026-10-19): cruzar ese CPE con una fuente de CVE y, por cada CVE, decir si hay **exploit conocido**, para **priorizar a qué atacar primero** y que **salga en el informe**.

Encaja con lo recién hecho (detección de producto/versión con IA): primero sabes *qué es* un servicio, ahora sabes *qué le pasa*.

## Objetivos
- Por cada servicio con CPE, mostrar las CVE que le tocan.
- Por cada CVE, marcar si tiene exploit conocido y dar el enlace (no ejecutar, no descargar: solo señalar).
- Un orden propio y determinista del inventario: exploit > CVE crítica > CVE > nada. Funciona **sin IA**.
- Alimentar además al motor de priorización por IA que ya existe, como una señal más.
- Salir en el informe/exportación.
- Local-first: base de CVE en local; internet solo cuando en local no hay.

## No objetivos
- No ejecutar ni descargar exploits. Solo enlaces.
- No lanzar Nmap (eso es [[lanzar-nmap-portal]]); se parte del CPE que ya está en el inventario.
- No una base de CVE exhaustiva de todos los años: acotada a los últimos ~10.
- No puntuar/valorar el riesgo con criterio propio más allá del orden determinista citado; el matiz fino lo da la IA.

## Anti-objetivos (haría fracasar la tarea aunque «funcione»)
- Mandar datos del cliente a un tercero sin que sea una salida acotada y apagable (rompería el contrato de privacidad, §0.3/§0.4).
- Una alucinación o un dato inventado presentado como CVE real: aquí los datos vienen de fuentes, nunca de un modelo.
- Que la base de CVE engorde el repo o la instalación sin control.

## Decisiones tomadas (con Doro, 2026-10-21)
1. **Fuente de CVE:** base local de la **NVD** (feeds oficiales), acotada a los **últimos 10 años** (configurable). Si para un CPE no hay nada en local, **consulta la NVD online** en ese momento.
2. **Sobre qué se cruza (Doro):** el **cpe de Nmap** y, además, el producto/versión de la tabla `deteccion` (gowitness o IA) **cuando la confianza es alta**, construyendo un cpe a partir de producto/versión. Así se cubren los servicios web, que casi nunca traen cpe de Nmap. Cada vulnerabilidad lleva marcado **de qué origen salió el cpe** (Nmap / gowitness / IA). Una versión de baja confianza no genera CVE mostradas como reales (anti-objetivo).
3. **Exploit conocido en dos niveles (Doro):**
   - **Confirmado:** la CVE está en **CISA KEV** o en **Exploit-DB** (fuentes curadas, en local). Pesa en el orden de ataque.
   - **PoC sin verificar:** aparece en la **búsqueda en vivo en GitHub** por id de CVE. Se muestra con enlace y aviso de «sin verificar», pero **no** sube al nivel de los confirmados. Nunca ejecuta ni descarga el exploit.
4. **Salidas a internet** (NVD online como fallback, GitHub en vivo, y la actualización de la base): **automáticas** por defecto. Un **interruptor para apagarlas del todo** (entorno aislado), **desactivado de fábrica** (internet permitido por defecto). Es **global** y se puede fijar por **variable de entorno o flag antes del primer arranque** (como `--arrancar-ollama`/`DEDALO_MODELO`), para que un entorno aislado no se conecte en ese primer arranque. Con él activado, Dédalo no sale a internet ni para actualizar ni para consultar: usa lo que tenga en local.
5. **Mantenimiento de la base:** automático. Al arrancar el portal, en segundo plano (como Ollama), la primera vez descarga la base; luego solo las novedades (feeds incrementales de la NVD). Respeta el interruptor. El portal dice si la base está al día o desfasada.
6. **Qué dispara el cruce y caducidad:** una **ejecución con su tipo propio** que pasa por la cola y los estados de CONTRATOS §0.4 (como la detección de versión). «**No había base todavía / internet apagado**» se guarda **distinto** de «**sin vulnerabilidades**», para que un servicio sin datos no se lea como limpio; ese resultado se puede rehacer cuando la base esté lista.
7. **Persistencia:** el resultado del cruce se guarda en la base, con su **migración numerada nueva**, para no reconsultar y para las exportaciones.
8. **Priorización:** las dos cosas. Un orden determinista propio (**exploit confirmado > CVE crítica > CVE > PoC sin verificar > nada**) siempre visible, y además las CVE/exploits se le pasan a la IA que ya prioriza como contexto.
9. **Dónde se ve (Doro):** en las **exportaciones que ya existen** — el CSV/JSON del inventario (`dedalo/inventory.py`) y el índice HTML de capturas (`dedalo/report.py`) —, más la sección de vulnerabilidades en el inventario del portal, siguiendo DESIGN.md. **No** se crea un informe de hallazgos nuevo (sería una pieza aparte, fuera de esta tarea).
10. **Alcance:** el cruce solo toca activos **en alcance**, recomprobado **en vivo** antes de cualquier salida a internet. El cpe de un activo excluido o fuera de alcance **nunca** sale a un tercero (la exclusión siempre gana). Línea nueva en CONTRATOS §0.3, con su test.
11. **Privacidad:** lo que sale a internet es el cpe (producto+versión, a la NVD) y el id de CVE (a GitHub). No sale IP, nombre de cliente ni nada que identifique la auditoría. Decisión de Doro: un cpe genérico no señala al cliente.
12. **Control del ruido (CPE→CVE da muchos resultados):** el emparejamiento casa por **versión dentro del rango afectado** que declara la NVD, no por producto; una CVE cuyo rango no incluye la versión del servicio **no** sale. Si el cpe **no trae versión**, se marca «todas las del producto, sin filtrar por versión» y **no** sube la prioridad. En la vista, orden por severidad y por exploit confirmado, con el resto colapsado. Acotar a 10 años (decisión 1) también recorta. Así «salen muchos» se vuelve manejable y lo dudoso queda avisado, no mezclado con lo real.

## Restricciones (del proyecto)
- Solo librería estándar, sin pip: la descarga de feeds y las consultas HTTP se hacen con `urllib` (patrón de `probador`/`modelo`), el parseo con `json`/`gzip` de la stdlib.
- El binario/fuentes externos (feeds NVD, KEV, Exploit-DB) se traen por HTTPS; las URL y, donde exista, la verificación de integridad, fijadas en el código (patrón de `gowitness.py`).
- Migración nueva y numerada en `dedalo/db.py`; las publicadas no se tocan.
- Portal local de un usuario: 127.0.0.1, `Origin` y `X-Dedalo-Token`.
- CRLF en Windows: editar con la herramienta de edición.
- Contrato = código: CONTRATOS.md §0.3/§0.4 y MODELO_DATOS.md al día en el mismo cambio.
- Un servicio puede tener **varios CPE** (el inventario guarda `cpe` como lista): el cruce los contempla todos.

## Lo que queda al builder (plan e implementación)
- Cómo se almacena la base local de la NVD (tabla(s) nuevas vs. fichero local indexado), y el formato de descarga (feeds JSON comprimidos de la NVD; elegir el endpoint estable vigente).
- El emparejamiento CPE→CVE: la NVD expresa la aplicabilidad con rangos de versión (nodos CPE match); hay que resolver «esta versión cae en el rango afectado», no solo igualdad de cadena.
- Cuándo y cómo corre la actualización automática sin frenar el arranque (en segundo plano, como Ollama), y cómo se le dice al operador que está al día o desfasada.
- La búsqueda en vivo en GitHub: endpoint, si necesita token, límites de uso y qué hacer al agotarlos (degradar, no romper).
- La forma exacta de la sección en el inventario y en el informe (DESIGN.md; `python design/check-contrast.py` si se tocan colores).
- Dónde viven las URL/fuentes y su actualización (como VERSION/RELEASES de gowitness).
- Tests (TDD) con las fuentes **simuladas** (sin red real en los tests unitarios); integración aparte si procede.
- Revisión: /simplify → /code-review + Trail of Bits que apliquen (toca red, entrada externa y dependencia de datos de terceros: differential-review, insecure-defaults, sharp-edges, supply-chain-risk-auditor).

## Preguntas abiertas para Doro (a resolver antes o durante el plan)
- Ninguna de fondo pendiente; los puntos de «lo que queda al builder» son decisiones técnicas que tomará el plan. Si el builder-check saca algo que cambie lo que se construye, se traerá aquí.
