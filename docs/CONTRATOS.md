# Contratos de Dedalo (bloque 0)

Qué hace la primera versión, qué puede tocar cada módulo y qué estados usan. Si el código contradice este documento, se corrige uno de los dos; no se deja la diferencia.

## 0.1 Primera versión

**Incluye**

- Auditorías: un cliente o proyecto con nombre, alcance y todas sus ejecuciones.
- Importación de Nmap (XML, grepable y normal) a un inventario persistente de activos, servicios y observaciones.
- Capturas web con gowitness, cada una ligada al servicio y la ejecución que la produjo.
- Exportación: inventario CSV/JSON, índice de capturas y ZIP por subred.
- Migración del historial anterior de `portal_datos/` a una auditoría «Importadas».
- Instalación automática de gowitness verificada por SHA-256.
- Priorización con IA (bloque 5, adelantado el 2026-10-14): un modelo local (Ollama) ordena los hosts en alcance de una importación por prioridad, con su rol probable, el motivo y un siguiente paso sugerido. Solo lee la base; no conecta con ningún objetivo y no ejecuta nada.
- Credenciales por defecto (bloque 6, adelantado el 2026-10-14): a petición del operador, prueba contra los servicios en alcance las contraseñas de fábrica que les tocan según su fingerprint, a partir de un catálogo curado que viaja con la herramienta; conecta con límites y enseña dónde se entró.
- Descubrimiento DNS (parte del bloque 2): desde el portal, sobre las IP en alcance de una importación, pregunta por sus nombres (DNS inverso, sin conectar con los objetivos) o por los servidores DNS que responden (UDP 53, conecta). Un botón «Detectar mis redes» propone como alcance las subredes del propio equipo.

**Queda para después:** el escaneo con Nmap desde el portal (bloque 3) y el resto del descubrimiento de red (bloque 2) más allá del DNS.

**No se hará:** uso multiusuario, publicar el portal en red, explotar vulnerabilidades ni iniciar sesión en los servicios capturados.

La consola (`capturar`, `ver`) se mantiene como está; las auditorías son del portal.

## 0.2 Sistema de demostración

- **Entorno real:** el equipo Windows del auditor, conectado a la red de laboratorio o del cliente.
- **Sin red:** `ejemplos/inventario.xml` para el inventario y `python -m tests.integration_local` para capturas contra webs locales.
- Primera versión probada en Windows. Linux, en particular Kali, queda pendiente de una prueba real.

## 0.3 Alcance

Cada auditoría tiene una lista de reglas:

| Tipo | Ejemplo | Significado |
| --- | --- | --- |
| `incluir` | `10.10.0.0/16` | Red autorizada. También sirve para agrupar como hoy hacen los rangos. |
| `excluir` | `10.10.5.20/32`, motivo «impresora» | Nunca se contacta, aunque esté dentro de un rango incluido. |

Una IP queda en una de estas situaciones:

- **En alcance:** está en alguna regla `incluir` y en ninguna `excluir`.
- **Excluida:** está en alguna regla `excluir`. La exclusión siempre gana.
- **Fuera de alcance:** no está en ninguna regla `incluir`.

**Reglas que deben cumplir todos los módulos**

1. Importar nunca filtra. Todo lo que trae el Nmap se guarda, marcado con su situación, para no perder información.
2. **Solo se contacta lo que está en alcance.** Las capturas, el descubrimiento DNS, las credenciales y el favicon que trae la detección de versión —y en el futuro los escaneos— comprueban el alcance justo antes de conectar, no solo al planificar.
3. Una auditoría sin reglas `incluir` no tiene nada en alcance: se puede importar y consultar, pero no lanzar conexiones. El portal pide definir el alcance.
4. Cambiar el alcance no borra datos; solo cambia qué se puede contactar a partir de ese momento.
5. La captura que prueba el otro esquema (http/https) cuando falla el primero solo usa IP:puerto que ya son objetivo y ya pasaron el filtro de alcance: las URL candidatas se derivan de la lista de objetivos, nunca de lo que diga el log, y solo cambian el esquema.
6. El favicon que trae la detección de versión solo se descarga del **mismo IP:puerto** del servicio capturado, ya en alcance y recomprobado en vivo justo antes de conectar: un `href` de favicon que apunte a otro host (un CDN, por ejemplo) no se descarga.
7. El cruce de vulnerabilidades (`vuln`) solo reúne el CPE y consulta fuentes públicas de los servicios de IP en alcance, y recomprueba el alcance **en vivo** para cada servicio justo antes de reunir su CPE y de cruzarlo, que es donde hay salida a internet (NVD en línea, GitHub). El CPE de un host excluido, aunque se excluya a mitad del cruce, no sale; ese servicio no se cruza ni se guarda. No conecta con el activo: lo que sale a internet es un CPE (producto y versión) o un id de CVE, nunca su IP. Las vulnerabilidades ya guardadas de un host que se excluye después dejan de verse y de exportarse: sus columnas `vuln_*` quedan en blanco (los resultados se leen contra el alcance vigente). Su fila de captura en el índice permanece como hasta ahora; la exclusión solo impide nuevas conexiones.

> **Cambio respecto a hoy:** ahora mismo las IP que no están en ningún rango se capturan igualmente, agrupadas en `fuera_de_rango`. Con este contrato dejan de capturarse. Las ejecuciones migradas conservan sus capturas antiguas.

## 0.4 Etapas, estados y resultados

Cada cosa que se hace es una **ejecución** de un tipo. Estos son los tipos:

| Tipo | Qué hace | ¿Conecta con objetivos? | Qué escribe |
| --- | --- | --- | --- |
| `importacion` | Lee archivos Nmap | No | Activos, servicios, observaciones y el Nmap original como evidencia |
| `captura` | Hace capturas de los servicios web en alcance de una importación | Sí, HTTP/HTTPS | Un resultado por URL y las imágenes como evidencia |
| `analisis` | Pide a un modelo local, host por host, el rol y la prioridad de los hosts en alcance con algún puerto abierto de una importación | No: solo habla con Ollama en este equipo (loopback, sin proxy ni redirecciones) y con modelos descargados, nunca los «-cloud» | Una prioridad por activo (rol, nivel, motivo y siguiente paso sugerido) |
| `credenciales` | Prueba las contraseñas de fábrica que le tocan a cada servicio en alcance de una importación, según su fingerprint, solo cuando el operador lo pide y confirma | Sí, a los servicios en alcance (HTTP Basic/Digest, login por formulario, FTP), con conexión directa, tope de intentos por servicio y pausa | Por servicio probado: si entró (con qué usuario/clave), no entró o error |
| `descubrimiento` | Sobre las IP en alcance de una importación, pregunta por sus nombres (DNS inverso) o por los servidores DNS que responden | El modo `nombres` no (habla con el resolvedor del sistema); el modo `servidores` sí, a cada IP en alcance por UDP 53 | Observaciones: los nombres en el activo y cada servidor DNS como servicio `udp/53` |
| `version` | Tras una captura, estima el producto y la versión de cada servicio web capturado a partir de lo que gowitness ya guardó (cabeceras, tecnologías, TLS, HTML) y del favicon del propio objetivo cruzado con un catálogo local | Solo para el favicon: al mismo IP:puerto del servicio, ya en alcance y recomprobado en vivo; además habla con el modelo (Ollama en loopback, o la API de Claude si se elige a conciencia) | Una o varias lecturas por servicio en `deteccion` (origen `gowitness` o `ia`, con producto, versión y confianza) |
| `vuln` | Cruza cada servicio en alcance de una importación, por sus CPE (los de Nmap y los de la detección de alta confianza, umbral 80), con las CVE conocidas y busca su nivel de exploit: `confirmado` (CISA KEV o Exploit-DB) o `sin_verificar` (PoC en GitHub). Solo enlaza, nunca descarga ni ejecuta un exploit | No con los activos. Sale a internet solo con datos del producto: NVD (base local primero; API en línea de respaldo), CISA KEV, Exploit-DB y GitHub, y todo se apaga con el interruptor global `--sin-internet` / `DEDALO_SIN_INTERNET`, off de fábrica, fijado antes del primer arranque. Alcance recomprobado en vivo por servicio (0.3.7) | Por servicio cruzado, una fila por CVE (CVE, severidad `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` como la da la NVD, nivel de exploit, enlaces, el CPE de origen y su fuente, `nmap` o `deteccion`) o, si no hay ninguna, una fila centinela con `cve_id` vacío que lleva su estado: `ok` (se miró y está limpio) o `sin_datos` (no se pudo mirar). Un servicio sin filas no se cruzó |

Al modelo solo le llegan metadatos (IP, nombres, puerto, servicio, producto, versión, detalle y título web y, si hay cruce, las vulnerabilidades de cada servicio), como datos y no como instrucciones; su respuesta se valida contra un esquema fijo y lo que no encaja queda `sin_analisis`. Un análisis nuevo de la misma importación solo sustituye al anterior cuando termina bien; si falla, se cancela o se interrumpe, sigue valiendo el último completo. Para ofrecer en el portal los modelos descargados, el portal pregunta a ese mismo Ollama por su lista (`/api/tags`), con las mismas reglas; el modelo que llega del navegador se comprueba antes de usarlo (forma de nombre de Ollama y nunca de la nube). Con `--arrancar-ollama` (lo usa `iniciar_portal.cmd`), si ese Ollama no responde y está instalado, Dédalo lo arranca en este equipo (`ollama serve`, sin shell, en la dirección de `--ollama`) con `OLLAMA_NO_CLOUD=1`; no conecta con nada más.

La detección de versión (`version`) sigue las mismas reglas: el HTML (y sus señales de versión), las cabeceras, el título y el TLS de la captura, más la pista del favicon si se identificó, van al modelo como datos acotados, nunca como instrucciones, y la respuesta se valida (producto, versión y confianza); lo que no encaja o no supera el umbral queda sin versión. Viene **apagada de serie** y se activa en el portal, eligiendo motor: Ollama en local (como el análisis) o la **API de Claude**. Con Claude, y solo entonces, esos datos de la captura salen del equipo hacia la nube de Anthropic; es una decisión explícita del operador, avisada en el portal, con la clave en la variable de entorno `ANTHROPIC_API_KEY` (nunca en la base ni en el repo). Para traer el favicon, la detección **sí conecta**, pero solo con el propio objetivo: recomprueba el alcance en vivo justo antes (regla 0.3.6) y un fallo de red, de alcance o de catálogo no detiene el resto de la detección.

El cruce de vulnerabilidades (`vuln`) va por la misma cola, con el mismo ciclo de vida que el análisis (uno por importación; volver a cruzar sustituye al anterior solo al terminar bien; las vulnerabilidades de un activo excluido después dejan de salir de los resultados, del inventario y de las exportaciones (en el índice de capturas su fila permanece, con las columnas `vuln_*` en blanco); a medias al cerrar el portal queda `interrumpida`). Sin reglas `incluir`, no se lanza. Fuentes: la base local de la NVD (se actualiza sola al arrancar el portal y al empezar cada cruce, salvo que se actualizara hace menos de un día) con la API en línea como respaldo, y los ficheros de CISA KEV y Exploit-DB descargados con tope de tamaño, validación y escritura atómica. `sin_datos` significa que ningún CPE tuvo respuesta fiable (sin CPE, o sin base local completa y sin consulta en línea) y nunca se presenta como «sin vulnerabilidades»; con `--sin-internet` no se abre ninguna conexión y todo lo que no esté ya en local sale `sin_datos`. El orden de urgencia es determinista (`vulnerabilidades.orden`): 0 exploit confirmado, 1 CVE crítica, 2 alguna CVE, 3 solo PoC sin verificar, 4 nada. Los resultados llegan al CSV y JSON del inventario, al índice de capturas descargado del portal y, como dato acotado (CVE con forma válida, severidad conocida, nivel de exploit; las 10 más urgentes), al modelo que prioriza.

Las credenciales que prueba salen de un catálogo curado y versionado que viaja con la herramienta (`dedalo/datos/credenciales.json`, volcado a la base al arrancar), nunca de una IA en caliente. Solo se prueban las que pegan con lo que parece ser cada servicio (fabricante, producto, versión); si no se reconoce, no se prueba nada. La prueba se activa a propósito (botón y confirmación en el portal), recomprueba el alcance justo antes de cada conexión y respeta un tope de intentos por servicio para no bloquear cuentas. La contraseña encontrada es dato sensible: se guarda en la base local y no sale del equipo. Un análisis nuevo solo sustituye al anterior cuando termina bien. El catálogo se puede **ampliar desde el portal** (botón «Añadir al catálogo» en cualquier servicio), con la regla de **solo credenciales de fábrica**, nunca un secreto de un cliente; el fichero es compartible por el repo (`--catalogo` apunta al del equipo).

El descubrimiento va por la misma cola, con el mismo ciclo de vida que el análisis (uno por importación; volver a descubrir sustituye al anterior solo al terminar bien; un activo excluido después deja de salir; a medias al cerrar el portal queda `interrumpida`). Recomprueba el alcance **en vivo** antes de cada consulta, así que una exclusión a mitad de un barrido gana; sin reglas `incluir`, no se lanza. Sus hallazgos se guardan como observaciones, sin tablas ni migración nuevas. El dominio que usa el modo `servidores` para sondear se fija al arrancar (`--dns-dominio`). El botón «Detectar mis redes» solo mira las interfaces del propio equipo (lee `ipconfig`/`ip addr`) y propone sus subredes como alcance; no conecta con nada y el operador revisa lo propuesto.

Tipos futuros: `escaneo` (conecta, solo en alcance).

**Estados de una ejecución**

```text
preparada → en_cola → en_curso → completa
                   ↘ cancelada   ↘ deteniendo → interrumpida
                                 ↘ parcial | error | interrumpida
```

| Estado | Significado |
| --- | --- |
| `preparada` | Creada y revisable; todavía no ha hecho nada contra la red. |
| `en_cola` | Esperando a que termine la ejecución activa. Se ejecutan de una en una. |
| `en_curso` | Trabajando. |
| `deteniendo` | Se pidió parar; termina la subred actual (en un análisis, el host en curso). |
| `completa` | Terminó y todo salió bien. |
| `parcial` | Terminó, pero algún objetivo no tiene resultado. El resto es utilizable. |
| `error` | No pudo terminar; el motivo se guarda. |
| `cancelada` | Se canceló antes de empezar. |
| `interrumpida` | Se detuvo a mitad, a petición o porque se cerró el portal. No se relanza sola. |

Una importación pasa directamente de `preparada` a `completa`, o a `error` si el archivo no es válido.

**Resultado de cada URL en una captura:** `pendiente`, `capturada` o `sin_captura`, más el motivo del fallo cuando no hay imagen.
