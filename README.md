<p align="center"><img src="design/logo.webp" alt="Logo de Dedalo: un laberinto en rombo entre dos alas rojas" width="200"></p>

# Dedalo

Portal local para subir resultados de nmap, lanzar capturas con gowitness y consultar las imágenes por rango del cliente y subred. Por defecto: **80/TCP abierto → HTTP**, **443/TCP abierto → HTTPS**. También conserva sus comandos de consola.

La pestaña **Activos** conserva el inventario de hosts y puertos TCP/UDP abiertos de los archivos importados, incluidos servicios sin web como SSH, SMB, LDAP y DNS. Se puede consultar y exportar antes de lanzar capturas.

El selector de la esquina superior derecha alterna entre modo claro y oscuro. Recuerda la elección en este navegador; si no hay una preferencia guardada, sigue el tema del sistema. El paquete y los comandos de consola son ahora `dedalo`.

La interfaz utiliza la paleta de SilentForce: negro, gris y rojo, con adaptación al modo claro. El diseño prioriza las capturas, con IP y puerto encima de cada imagen y agrupación por subred. Las decisiones visuales y la aplicación de `avoid-ai-design` están documentadas en `DESIGN.md` y `design/AUDIT.md`.

Acepta XML (`-oX`), grepable (`-oG`) y salida normal (`-oN`), detectados por el contenido. No ejecuta nmap ni expande los CIDR a nuevas IP: los rangos sirven para clasificar las IP de los ficheros. El navegador sí sigue redirecciones y carga los recursos de cada página.

## Requisitos

- Python 3.12 o superior. Solo usa la librería estándar; no hay paquetes que instalar con pip.
- [gowitness v3](https://github.com/sensepost/gowitness), probado con **3.2.0**. Colocar el ejecutable en `bin/gowitness.exe` (Windows), `bin/gowitness` (Linux), en el PATH o indicar `--gowitness`.
- Chrome, Chromium o Edge. Se detectan automáticamente o se indican con `--chrome`. Si no se encuentra ninguno, gowitness puede descargar su navegador.
- Opcional, para la priorización con IA: [Ollama](https://ollama.com) en el mismo equipo, con un modelo descargado. El resto del portal funciona sin él.

El ejecutable de gowitness no se incluye en el repositorio. `python -m dedalo instalar` descarga el binario oficial para Windows, Linux o macOS (Intel o ARM), comprueba su SHA-256 contra la huella fijada en `dedalo/gowitness.py` y lo coloca en `bin/`. El portal lo hace automáticamente al arrancar si no encuentra gowitness **o si el que encuentra es de otra versión** (lo típico en WSL/Kali, donde el gowitness del sistema no conoce los flags que usa Dédalo): comprueba la versión y descarga solo el binario fijado, sin pasos a mano. Solo se salta esta comprobación si se indicó `--gowitness` (ahí mandas tú). Si la descarga falla, el portal arranca igualmente y muestra el aviso. Los comandos `capturar` y `ver` no descargan nada por su cuenta.

Ejecutar los comandos desde la carpeta del proyecto. En Kali usar `python3` en lugar de `python`. Si Windows no reconoce `python`, usar `py -3.12` o la ruta del intérprete, por ejemplo:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m dedalo --help
```

## Instalación desde cero

No hace falta entorno virtual ni `pip install`: Dedalo solo usa la librería estándar de Python. gowitness no es un paquete de Python, sino un ejecutable independiente que Dedalo lanza como proceso externo. Nmap todavía no es necesario, porque el portal lee archivos de Nmap ya generados.

### Windows

1. Instala **Python 3.12 o superior** desde [python.org/downloads](https://www.python.org/downloads/). En el instalador, marca **Add python.exe to PATH**. Abre una terminal nueva y comprueba la versión con `python --version`.
2. Asegúrate de tener **Chrome o Edge**. Edge viene con Windows.
3. Clona el repositorio o copia su carpeta sin `portal_datos/`, `pruebas_locales/` ni `salida/`, que contienen datos de ejecuciones.
4. **gowitness se instala solo.** La primera vez que se abre el portal, si no lo encuentra, descarga el binario oficial 3.2.0 para tu sistema desde GitHub (unos 50 MB), comprueba su huella SHA-256 y lo guarda en `bin\`. También se puede hacer antes, desde la carpeta del proyecto:

   ```powershell
   python -m dedalo instalar
   ```

   Si no hay acceso a internet, descarga a mano `gowitness-3.2.0-windows-amd64.exe` desde las [versiones oficiales](https://github.com/sensepost/gowitness/releases/tag/3.2.0), renómbralo a `gowitness.exe` y déjalo en `bin\`. Con el binario ya colocado, `python -m dedalo instalar` comprueba si coincide con el oficial.

5. Desde la carpeta del proyecto, ejecuta las pruebas. Deben terminar en `OK`. No usan gowitness ni la red:

   ```powershell
   python -m unittest discover -s tests
   ```

6. Haz doble clic en `iniciar_portal.cmd`. Para una primera prueba sin conectar con ninguna red, sube `ejemplos/inventario.xml` y revisa la pestaña **Activos** sin iniciar capturas.
7. Opcional: comprueba capturas reales con gowitness y el navegador contra dos webs locales que levanta la propia prueba:

   ```powershell
   python -m tests.integration_local
   ```

### Kali / Linux

Los mismos pasos con estas diferencias: usa `python3` (`python3 -m dedalo instalar` descarga el binario de Linux y le da permiso de ejecución), instala Chromium con `sudo apt install chromium` y arranca el portal con `python3 -m dedalo web --abrir`. En Linux todavía no se ha hecho una prueba real completa.

## Operar desde la web

En Windows puedes hacer doble clic en **`iniciar_portal.cmd`**. Abre el navegador y mantiene el servidor en una terminal; déjala abierta mientras trabajas. No requiere instalar paquetes con pip ni Node. Si tienes [Ollama](https://ollama.com) instalado y no está en marcha, el lanzador lo arranca en segundo plano para la priorización con IA (con el comando, `--arrancar-ollama`); sigue en marcha al cerrar el portal.

También puedes iniciarlo con:

```powershell
python -m dedalo web --abrir
```

El portal está en [http://127.0.0.1:8787](http://127.0.0.1:8787). Desde ahí:

1. En **Cliente**, elige la ficha del cliente o pulsa **Nueva ficha**: nombre, **rangos autorizados** (un CIDR o IP por línea, o desde un .txt) y, si hace falta, **exclusiones** con su motivo tras `#` (por ejemplo `172.31.253.241  # A10 producción`). Los rangos se escriben una sola vez y los usan todas las capturas de ese cliente. La lista de ejecuciones muestra solo las del cliente elegido.
2. Pulsa **Nueva captura**, pon nombre a la ejecución y arrastra o selecciona uno o varios nmap (XML, grepable o normal). El formulario muestra el alcance de la ficha.
3. **Solo se capturan las IP en alcance**: dentro de un rango autorizado y no excluidas. El resto se importa y aparece en Activos con la etiqueta «Fuera de alcance» o «Excluida», pero Dedalo no se conecta a ellas. Una ficha sin rangos autorizados no puede lanzar capturas. Si editas la ficha, las ejecuciones aún no lanzadas se recalculan; las ya lanzadas no cambian.
4. Si hace falta, ajusta puertos adicionales, concurrencia, timeout, espera, formato, página completa o el motor del navegador (ver «Motor del navegador y reintento»).
5. Pulsa **Revisar objetivos**: se muestra el reparto por rango y subred, y cuántos objetivos web quedan fuera de alcance o excluidos, sin hacer conexiones a los objetivos.
6. Pulsa **Iniciar captura**. Los trabajos se encolan y se ejecutan de uno en uno.
7. Consulta las imágenes y filtra por rango, subred, estado o texto. Puedes ampliar y descargar imágenes, descargar CSV/JSON o consultar el registro sin salir del portal. **Descargar capturas** en la cabecera de cada subred descarga un ZIP con todas sus capturas, aunque haya filtros activos. Cada imagen se llama `IP_PUERTO_ESQUEMA` (por ejemplo `10.10.5.1_443_https.jpeg`) y el `indice.csv` del ZIP recoge su URL, URL final, código HTTP y título. **Copiar para OneNote** copia al portapapeles todas las capturas de la subred como `IP:puerto` en negrita con su imagen debajo; pégalas en una página de OneNote con Ctrl+V. Las imágenes van incluidas en lo copiado, así que no hace falta que el portal siga abierto al pegar.
8. En **Activos**, busca por IP, nombre, puerto, servicio o producto y filtra por rango, subred o servicio. **Ocultar hosts sin puertos abiertos** viene marcado: un Nmap lanzado con `-Pn` da por activas todas las IP del rango aunque no respondan, y así solo quedan las que tienen algún puerto abierto. Entre paréntesis se indica cuántas se ocultan.

Junto a las pestañas Activos, Capturas y Objetivos web hay dos botones que descargan un `.txt` con `IP:puerto`, uno por línea (IPv6 como `[IP]:puerto`), listo para otras herramientas:

- **Exportar hosts**: todos los puertos abiertos TCP y UDP. En Activos aplica todos los filtros; en las demás pestañas, solo rango y subred.
- **Exportar hosts (web)**: solo los objetivos web de la ejecución (80/443 y los puertos añadidos en las opciones), con los filtros de la pestaña; en Capturas, por ejemplo, **Resultado → Sin captura** exporta solo los que fallaron. **Inventario CSV** y **Inventario JSON** descargan el inventario completo de la ejecución, independientemente de los filtros. Los enlaces de captura permiten abrir la imagen del servicio cuando está disponible.

El portal recibe archivos y **lanza las capturas**, no ejecuta un nuevo escaneo nmap. Las conexiones salen del equipo donde corre el servidor. Cerrar la pestaña no detiene las capturas.

**Detener tras esta subred** conserva las capturas y evita iniciar nuevos grupos. No mata a la fuerza el navegador de la subred activa; el tiempo de espera depende de sus objetivos y timeout. Un trabajo todavía en cola se cancela inmediatamente.

El historial y las cargas se conservan en `portal_datos/`. Al cerrar el servidor con Ctrl+C se solicita la parada y se espera a la subred activa. Si el servidor se cerró inesperadamente, al volver a abrirlo cada trabajo activo toma el estado final del motor si llegó a terminar y, si no, queda interrumpido; no se relanzan automáticamente. Si el motor siguiera en marcha, se le pide parar y termina la subred en curso.

Para eliminar una ejecución, selecciónala en el historial y pulsa **Borrar ejecución**. El portal pide confirmación y elimina permanentemente esa ejecución, sus capturas, copias de los Nmap subidos, índices y registros. Los archivos originales de tu equipo no se modifican. Si está en cola o capturando, primero cancélala o detenla y espera a que termine; entonces podrás borrarla. Si la base no se puede escribir en ese momento, no se borra nada y puedes reintentarlo. Si lo que falla es quitar la carpeta (por ejemplo, porque otro programa tiene abierta una captura), la ejecución sale del historial, la terminal lo avisa y el portal termina de borrarla la próxima vez que arranque.

```powershell
# Cambiar puerto y carpeta de almacenamiento
python -m dedalo web --puerto 8788 --datos portal_datos_cliente

# Indicar los ejecutables del equipo que hace las capturas
python -m dedalo web --chrome "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --gowitness bin/gowitness.exe
```

El portal admite hasta 20 archivos por carga (10 MB por archivo y 24 MB en total en la interfaz), con un máximo de 100.000 objetivos por ejecución. Muestra los resultados por páginas de 60 objetivos. Los ajustes de ejecutables se realizan al arrancar el servidor, no desde los archivos subidos.

Interruptor de internet: por defecto las funciones que consultan fuentes públicas pueden salir a internet. Para que el portal no abra ninguna conexión a internet y trabaje solo con datos locales, arráncalo con `--sin-internet` o con la variable de entorno `DEDALO_SIN_INTERNET=1` (valen `1`, `true`, `sí`/`si`; vacío o `0` lo dejan apagado). El flag manda sobre la variable. Se fija antes del primer arranque, igual que `--modelo`.

Si el puerto ya lo usa otro portal, el nuevo no arranca y lo indica: ciérralo o usa `--puerto`. En Windows el portal reserva el puerto en exclusiva para que dos portales no puedan quedar escuchando a la vez.

Es un portal local de un usuario: escucha exclusivamente en loopback y verifica el origen de las peticiones. No incluye autenticación multiusuario ni publicación en red. El navegador usa la misma galería del portal para todas las subredes; no hace falta arrancar visores separados de gowitness.

```text
portal_datos/
  dedalo.sqlite3           # base de auditorías, activos, servicios y evidencias
  ID_DE_EJECUCION/
    entradas/nmap-00.txt
    rangos.txt
    proceso.log
    resultado/             # mismos índices, bases y capturas que la consola
```

El estado, las opciones y los resultados de cada ejecución están en `dedalo.sqlite3`. Las carpetas de versiones anteriores traen además un `trabajo.json`: al arrancar, el portal las pasa a la base una sola vez, con sus capturas, sin modificar la carpeta (salvo que la ejecución estuviera activa al cerrarse: entonces añade el fichero `parar`, para que su motor, si siguiera vivo, no conecte con más subredes). Si alguna no se puede migrar (por ejemplo, porque faltan sus Nmap en `entradas/` o el `id` de su `trabajo.json` no coincide con el de la carpeta), lo avisa en la terminal y en el portal, con su nombre, el código de su carpeta y el motivo, porque no aparece en el historial; la conserva y lo reintenta en cada arranque. Una imagen de una captura antigua que ya no esté en disco no impide migrarla: esa URL queda sin captura y el resto se conserva. Los objetivos de cada ejecución se calculan la primera vez que se abre, no al arrancar, para que el portal abra enseguida aunque el historial sea grande. Si una ejecución ya guardada no se puede leer (al arrancar, o al abrirla si lo que falla es el cálculo de sus objetivos), aparece igualmente en el historial, sin objetivos y, si no se había lanzado, con estado «Error» y el motivo; el resto del portal funciona con normalidad.

Los resultados anteriores de consola siguen accesibles con `ver`; no se importan automáticamente en el historial web.

## Inventario de activos y servicios

Cada Nmap subido se registra en la base `portal_datos/dedalo.sqlite3` (modelo en `docs/MODELO_DATOS.md`): una ejecución de importación, cada IP como activo, cada puerto como servicio, lo que describe ese Nmap como observación y el archivo original como evidencia con su SHA-256. Una misma IP aparece una sola vez aunque la traigan varias subidas, y cada subida conserva su propia descripción. Mientras el portal no permita elegir auditoría, todo se guarda en la auditoría «Importadas».

Los hosts sin puertos web y los hosts activos sin puertos abiertos también se conservan. Las ejecuciones anteriores a la base se importan automáticamente la primera vez que se consulta su inventario, usando sus copias guardadas de Nmap; si faltan esas entradas se muestra el error y siguen disponibles las capturas. Los `inventario.json` que hubieran quedado de versiones anteriores ya no se usan. Borrar una ejecución también elimina sus datos de la base y los activos que solo ella había visto.

Al iniciar una captura, la base registra una ejecución de captura ligada a la importación, con cada URL en alcance y su servicio. Al terminar guarda el resultado de cada URL (código HTTP, título, URL final o motivo del fallo) y cada imagen y registro como evidencia con su SHA-256. Las subredes a las que no llegó una captura detenida quedan como pendientes. Las capturas anteriores a este cambio siguen visibles en el portal, pero todavía no están en la base.

Se incluyen únicamente puertos con estado `open`, diferenciando TCP y UDP aunque compartan número. `closed`, `filtered` y `open|filtered` no se cuentan como servicios abiertos. Solo los servicios TCP seleccionados se envían al motor de capturas.

XML conserva producto, versión, información adicional, CPE y el identificador y texto `output` de los scripts NSE de host o puerto. Dedalo muestra esos datos en **Datos Nmap**, sin ejecutar scripts nuevos ni interpretar sus resultados como instrucciones. Los formatos normal y grepable conservan el texto de producto/versión disponible, sin intentar separar campos que no están estructurados. En el formato normal se descarta la columna `REASON` que añaden `-v` o `--reason` (por ejemplo `syn-ack ttl 64`). Los archivos originales se guardan para conservar la información completa del escaneo.

Si varios archivos describen la misma IP y puerto/protocolo, se unen sus puertos y prevalece la última descripción de ese servicio en el orden de carga. Para conservar todos los metadatos estructurados de un servicio, carga su XML en último lugar. Las distintas ejecuciones mantienen inventarios independientes.

El inventario admite hasta 100.000 activos o servicios por ejecución. Las tablas muestran inicialmente 60 filas y permiten cargar más. El CSV incluye una fila por servicio y una fila vacía de servicio para los hosts sin puertos abiertos; los resultados de scripts se conservan en el JSON. El CSV neutraliza campos que una hoja de cálculo podría interpretar como fórmulas.

Puedes subir `ejemplos/inventario.xml` para revisar cuatro activos de documentación con servicios HTTP/HTTPS, SSH, LDAP, SMB, Kerberos y DNS, incluyendo TCP, UDP e IPv6. Basta con revisar la importación; no es necesario iniciar capturas contra esas direcciones de ejemplo.

## Priorización con IA

La pestaña **Priorización** de una ejecución ordena sus hosts en alcance con algún puerto abierto por prioridad con un modelo local de [Ollama](https://ollama.com). Cada host sale con su rol probable (por ejemplo, «controlador de dominio»), un nivel (alta, media o baja), el motivo y un siguiente paso sugerido. Es una opinión asesora: Dédalo solo lee el inventario de la base, no conecta con ningún equipo y no ejecuta lo que sugiera el modelo.

Pulsa **Analizar con IA**. El análisis va por la misma cola que las capturas, así que el portal sigue respondiendo; puede tardar alrededor de medio minuto por host con un modelo de 8B. Volver a analizar sustituye el resultado anterior solo cuando el nuevo termina bien: mientras tanto, o si falla o se interrumpe, se sigue viendo el último análisis completo con un aviso encima.

- El modelo se elige en la propia pestaña: el desplegable **Modelo** lista los que tienes descargados en Ollama (con su tamaño) y recuerda en ese navegador el último que usaste. Quedan fuera los de la nube y los que no generan texto. Si Ollama no responde o no tiene modelos, la pestaña lo dice y no deja analizar.
- El que se propone de entrada es, por orden: el último elegido, el de `--modelo NOMBRE`, el de la variable de entorno `DEDALO_MODELO` y, si no hay ninguno, `llama3.2:3b` (pequeño, para equipos modestos). Si ese no está descargado, se propone el primero de la lista. Con `DEDALO_MODELO` el doble clic en `iniciar_portal.cmd` usa tu modelo sin tocar el lanzador; en Windows se pone una vez con `setx DEDALO_MODELO fsec-analyst:latest` (vale para las terminales que abras después). `--ollama URL` si Ollama no está en `http://127.0.0.1:11434`.
- Al modelo solo le llegan metadatos de cada host (IP, nombres, puerto, servicio, producto, versión, detalle y título web), uno por pregunta, nunca credenciales ni volcados. Lo que dice el equipo analizado se le pasa como datos, no como instrucciones.
- La respuesta se pide en JSON con un esquema fijo y temperatura 0, así que la misma red da el mismo resultado. Si la respuesta de un host no encaja, ese host queda **Sin análisis** con el motivo; si el modelo no responde (Ollama apagado, modelo sin descargar o demasiado lento), el análisis acaba en error y lo explica.
- Mientras analiza, la pestaña y el botón muestran cuántos hosts lleva («Analizando 3 de 12…»). **Detener tras este host** para el análisis cuando el modelo termina la pregunta en curso, y queda como interrumpido; uno que aún espera en la cola se cancela al momento con **Cancelar análisis**. En los dos casos se descarta lo de ese intento y se sigue viendo el último análisis completo. Si ya iba por el último host, no queda nada que parar: termina y se queda el resultado nuevo.
- Si se cierra el portal a mitad, el análisis para tras el host en curso y queda como interrumpido.
- Solo «Analizar con IA» necesita Ollama arrancado y un modelo descargado; importar, el inventario y las capturas funcionan sin él. El doble clic en `iniciar_portal.cmd` (o `--arrancar-ollama`) arranca Ollama si está instalado y no responde, y lo hace con `OLLAMA_NO_CLOUD=1`: ese Ollama no sirve modelos de la nube, ni siquiera con otro nombre. Si Ollama ya estaba en marcha, se usa tal cual.
- Si después excluyes un host de la ficha, deja de aparecer en la priorización: la exclusión siempre gana.
- Ollama tiene que estar en este equipo: `--ollama` solo acepta `127.0.0.1`, `::1` o `localhost`, y la conexión no pasa por el proxy del sistema ni sigue redirecciones, para que los datos del cliente no salgan del equipo.
- Por lo mismo, `--modelo` rechaza los modelos en la nube de Ollama (etiqueta `cloud` o `…-cloud`, como `gpt-oss:120b-cloud`): Ollama los sirve desde el mismo servidor local, pero manda la pregunta a sus servidores. Para cerrar también esa puerta en el propio Ollama, arráncalo con `OLLAMA_NO_CLOUD=1`.

`ejemplos/laboratorio.xml` es un laboratorio inventado para probarlo: un controlador de dominio, un panel web de administración, un servidor de ficheros y un puesto de usuario en `10.30.0.0/16`. Crea una ficha con ese rango, sube el archivo y pulsa **Analizar con IA**.

## Detección de producto y versión

Tras cada captura, Dédalo puede estimar el **producto y la versión** de cada servicio web a partir de lo que gowitness ya guardó —las **cabeceras de respuesta**, las **tecnologías** que detecta, el **certificado TLS**, un extracto del **HTML** del front con sus señales de versión— y, además, trae el **favicon del propio objetivo, en alcance**, para cruzarlo con un catálogo local ampliable. Mejora el fingerprint que se ve en el inventario y, de rebote, qué credenciales por defecto se le prueban a cada servicio.

- **Apagada de serie.** Se enciende en la pestaña **Priorización**, con «Detectar producto y versión tras cada captura». Cuando está activa, al terminar una captura la detección se lanza **por detrás**, sin frenar la galería: las imágenes se ven al momento y la versión se va rellenando sola.
- **gowitness primero, la IA solo afina.** Las tecnologías que gowitness reconoce se muestran tal cual; la IA entra únicamente a completar y afinar lo que no reconoce (routers, paneles, firmware). Cada lectura se etiqueta con su origen (**gowitness** o **IA**, con su confianza). Si la IA falla o está apagada, queda al menos lo de gowitness.
- **El favicon, solo del propio objetivo.** La detección conecta, pero únicamente para traer el favicon del mismo IP:puerto que el servicio capturado: el alcance se recomprueba **en vivo** justo antes, y un `href` de favicon que apunte a otro host (un CDN, por ejemplo) no se descarga. Si se identifica contra el catálogo local (`dedalo/favicones.py`, `dedalo/datos/favicons.json`), esa pista también afina el fingerprint. Un fallo de red o de alcance al traer el favicon no detiene la detección: sigue con el resto de datos.
- **Motor elegible.** Por defecto, **Ollama en local** (mismas reglas que la priorización: solo loopback, sin modelos de la nube). Como opción, la **API de Claude**: al elegirla, el portal avisa de que el HTML y las cabeceras de la captura **salen del equipo** hacia la nube de Anthropic; la clave va en la variable de entorno `ANTHROPIC_API_KEY`, nunca en la base ni en el repo.
- **Contenido no confiable.** El TLS, el HTML y las cabeceras van al modelo como datos acotados, nunca como instrucciones; la respuesta se valida y lo que no encaja o tiene poca confianza queda sin versión.
- Cuando Nmap y la captura discrepan, se guardan **las dos lecturas** y, al probar credenciales, se prueban las que pegan con cualquiera de ellas.

## Credenciales por defecto

La pestaña **Credenciales** de una ejecución prueba, contra los servicios en alcance, las contraseñas de fábrica que le tocan a cada equipo según lo que parece ser (su fabricante, producto y versión). Es una acción que se lanza a propósito: pulsa **Probar credenciales** y confirma. A diferencia del análisis con IA, **esto sí se conecta** a los servicios.

- Las contraseñas salen de un **catálogo curado y versionado** que viaja con la herramienta (`dedalo/datos/credenciales.json`), no de una IA que las invente. Se vuelca a la base al arrancar. Para ampliarlo, edita el fichero (su origen y licencia van en cada entrada); el portal lo recarga cuando cambia.
- A cada servicio solo se le prueban las credenciales que **pegan con su fingerprint**; si no se reconoce el aparato, no se le prueba nada.
- Prueba tres tipos de servicio, solo con librería estándar: **HTTP Basic/Digest**, **login por formulario** (con una «receta» por panel) y **FTP**. En HTTPS no verifica el certificado (los aparatos suelen llevar uno autofirmado).
- Comprueba el **alcance justo antes** de cada conexión (la exclusión gana), con un **tope de intentos por servicio y una pausa** para no bloquear cuentas. Se puede ver el progreso, pararla y cancelarla, como el análisis.
- Lo ves por servicio: **entró** (con qué usuario/clave, resaltado), no entró o error. La contraseña encontrada es dato sensible: se guarda en la base local y **no sale del equipo**.
- Volver a probar sustituye el resultado anterior solo cuando el nuevo termina bien.
- **Ampliar el catálogo desde el portal:** en cualquier servicio del inventario, el botón «Añadir al catálogo» mete una entrada nueva (producto y versión ya puestos; tú pones usuario, clave y de dónde salió). El catálogo es **compartido por el repo** (que pasará a privado en una organización), para que el equipo beba de él sin repetir la research; **solo credenciales de fábrica**, nunca un secreto real de un cliente (el portal pide confirmarlo). Con `--catalogo` se apunta a un fichero de catálogo compartido.

Para probarlo de verdad necesitas servicios reales en las IP en alcance (un laboratorio con un panel web y un FTP, por ejemplo); el `ejemplos/laboratorio.xml` sirve para ver qué credenciales se le propondrían a cada servicio, pero esas IP no responden solas.

## Descubrimiento de red

La pestaña **Descubrimiento** de una ejecución pregunta, sobre las IP en alcance de la ficha, en uno de dos modos (como `nslookup`):

- **Nombres (DNS inverso):** le pide a cada IP su nombre al resolvedor del sistema. **No conecta** con los objetivos.
- **Servidores DNS:** le pregunta a cada IP, por **UDP 53**, por un dominio de sondeo, para ver cuáles responden como servidor DNS. **Esto sí conecta**, así que solo toca IP en alcance (recomprobado en vivo antes de cada consulta). El dominio de sondeo se fija al arrancar con `--dns-dominio` (por defecto `example.com`).

Lo encontrado se guarda como observaciones de esa ejecución: los nombres en el activo, y cada servidor DNS como un servicio `udp/53`. Va por la misma cola que las capturas y el análisis, con su progreso, y se puede parar.

Para no teclear la subred a mano, el botón **Detectar mis redes** —en el formulario de la ficha y en esta pestaña— lee las interfaces de **tu propio equipo** (`ipconfig` en Windows, `ip addr` en Linux) y propone sus subredes como alcance. Solo mira las interfaces locales, no conecta con nada, y tú revisas lo que propone antes de guardarlo.

## Uso desde consola

Crear `rangos.txt` con un CIDR por línea:

```text
# Rangos del cliente
10.10.0.0/17
172.16.20.0/22
```

Comprobar primero el reparto, sin conexiones ni archivos de salida:

```powershell
python -m dedalo capturar escaneo.xml -r rangos.txt --simular
```

Capturar y abrir el visor:

```powershell
python -m dedalo capturar escaneo.xml -r rangos.txt -o salida/cliente-01
python -m dedalo ver salida/cliente-01
```

Abrir [http://127.0.0.1:7171](http://127.0.0.1:7171) y consultar la galería de gowitness. Cada resultado muestra su URL con la IP. El servidor permanece en la terminal hasta pulsar Ctrl+C.

En el modo de consola, la selección se hace al lanzar `ver` y se usa la galería nativa de gowitness. En el portal `web`, la selección se hace con los filtros de la página.

## Captura

Se pueden mezclar formatos y combinar varios escaneos sin duplicar objetivos:

```powershell
python -m dedalo capturar parte1.xml parte2.gnmap parte3.nmap -r rangos.txt -o salida/cliente-02
```

Si la misma IP aparece en varios archivos, se unen sus puertos abiertos; no se interpreta como un histórico de aperturas y cierres. Se captura por IP, aunque nmap incluya nombres DNS.

| Opción | Función |
| --- | --- |
| `-r, --rangos` | Archivo de rangos. Opcional; sin él todas las IP van a `fuera_de_rango`. |
| `--solo-rangos` | Captura solo las IP dentro de `--rangos`; sin rangos no captura nada. El portal lo usa siempre. |
| `--excluir ARCHIVO` | IP o CIDR (uno por línea) que nunca se capturan, aunque estén en un rango. |
| `-o, --salida` | Carpeta nueva o vacía. Si se omite: `salida/FECHA-HORA-MICROSEGUNDOS`. |
| `--simular` / `--dry-run` | Muestra IP, URL y agrupación sin ejecutar gowitness. |
| `--puertos "8080=http,8443=https"` | Añade puertos al mapa de 80/443; si se repite un puerto, sustituye su esquema. |
| `--por-servicio` / `--by-service` | Incluye otros puertos que nmap identifique como HTTP/TLS. |
| `-t, --hilos 6` | Concurrencia dentro de cada subred; las subredes se procesan en orden. |
| `--timeout 60` | Límite por página, segundos. |
| `--delay 10` | Espera antes de la captura, segundos (10 por defecto). Para contenido lento, prueba 20–30. |
| `--formato jpeg` | `jpeg` o `png`. |
| `--pagina-completa` | Solicita captura de página completa a gowitness. |
| `--driver gorod` | Motor con el que gowitness maneja el navegador: `gorod` (por defecto) o `chromedp`. |
| `--sin-reintento` | No prueba el otro esquema (http/https) ni reintenta con el otro motor las páginas que cargan pero no dan imagen. |
| `--sin-barra-url` | No quema la barra con la URL en las capturas (por defecto sí se quema). |
| `--chrome RUTA` | Navegador que debe utilizar. |
| `--gowitness RUTA` | Ejecutable de gowitness v3. |

**Barra de URL (para informes).** Por defecto cada captura lleva quemada una **barra de direcciones** estilo navegador con su URL, para pegarla suelta en un informe y que se vea de qué objetivo es. La compone Chrome a partir de la imagen ya capturada (una pasada más por captura) y, con la barra activa, el formato de la imagen pasa a **PNG**. Se apaga con `--sin-barra-url` o con la casilla «Barra de URL en las capturas» del portal.

Ejemplo en Windows:

```powershell
python -m dedalo capturar escaneo.xml -r rangos.txt -o salida/cliente-03 --puertos "8080=http,8443=https" --formato png --hilos 4 --timeout 30 --chrome "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
```

Ejemplo en Kali:

```bash
python3 -m dedalo capturar escaneo.gnmap -r rangos.txt -o salida/cliente-04 --chrome /usr/bin/chromium
```

En consola, sin `--solo-rangos`, los rangos solo agrupan: una IP que no pertenezca a ninguno se conserva en `fuera_de_rango` y se captura. El portal, en cambio, aplica siempre el alcance de la ficha del cliente. Un /17 se organiza en sus /24, creando únicamente las subredes con objetivos. Si se solapan rangos, gana el más específico. Un /25 o /26 se conserva sin ampliarlo a /24. Para IPv6 se agrupa por /64; sus nombres de carpeta sustituyen `:` por `_`.

## Archivos de salida

```text
salida/cliente-01/
  ejecucion.json
  indice.csv
  10.10.0.0_17/
    10.10.5.0_24/
      urls.txt
      gowitness.sqlite3
      gowitness.log
      sin_captura.txt
      capturas/
    10.10.6.0_24/
      ...
  fuera_de_rango/
    192.168.1.0_24/
      ...
  .vistas/
    FECHA-HORA-ID/
      gowitness.sqlite3
      merge.log
      capturas/
```

- `indice.csv`: una fila por objetivo, con rango, subred, IP, puerto, URL original, estado, código HTTP, título, URL final, ruta relativa de captura y error. Se guarda en UTF-8 con BOM; se neutralizan textos que Excel podría tratar como fórmulas.
- `ejecucion.json`: objetivos, opciones, estado y resultados por subred. Necesario para `ver`. Se actualiza al terminar cada grupo.
- `urls.txt`: URLs enviadas a gowitness, con **puertos siempre explícitos**, incluidos 80 y 443. Esto impide que el lector de gowitness añada puertos por defecto.
- `sin_captura.txt`: URLs sin imagen válida. Un fichero vacío significa que ese grupo se capturó completo.
- `gowitness.log`: errores de conexión, tiempos agotados y mensajes del proceso.
- Solo se cuentan como capturadas las filas correctas de la base que además tengan un fichero de imagen existente y no vacío.

Una respuesta HTTP 401, 403, 404 o 500 puede tener captura y se conserva con su código. Un puerto que estaba abierto cuando se hizo nmap puede haber dejado de responder.

## Visor por subred, rango o completo

```powershell
# Ver qué grupos hay, sin arrancar el servidor
python -m dedalo ver salida/cliente-01 --listar

# Una subred concreta
python -m dedalo ver salida/cliente-01 10.10.5.0/24

# Un rango del cliente
python -m dedalo ver salida/cliente-01 10.10.0.0/17

# IP fuera de los rangos indicados
python -m dedalo ver salida/cliente-01 fuera_de_rango

# Todo junto
python -m dedalo ver salida/cliente-01

# Solo preparar la vista y obtener su carpeta
python -m dedalo ver salida/cliente-01 --preparar

# Otro puerto local
python -m dedalo ver salida/cliente-01 --puerto 7172
```

Los selectores deben corresponder a un rango o subred listado en la ejecución. Si solo hay una base con capturas, se utiliza directamente. Si hay varias, se combinan con `gowitness report merge`, conservando los originales; las imágenes se enlazan físicamente o se copian cuando el sistema de archivos no permite enlaces.

Cada vista combinada crea una carpeta nueva en `.vistas/` para no modificar una base abierta por otro visor. Estas carpetas se pueden borrar cuando sus visores estén cerrados: se regeneran con `ver`. Las bases pueden ocupar espacio aunque las imágenes compartan disco mediante enlaces.

Por defecto el visor solo escucha en `127.0.0.1`. `--host` permite cambiarlo. No se añade una capa de autenticación al visor de gowitness, así que con una dirección que no sea de loopback `ver` avisa en la terminal de que cualquiera que llegue a ella ve las capturas.

## Ejecuciones repetidas e interrupciones

Nunca se reutiliza una salida no vacía. Para repetir una captura, indicar otra carpeta o dejar que se cree una con fecha.

Si falla gowitness en una subred se registra el error y se continúa con las restantes. Ctrl+C conserva lo completado, marca la ejecución interrumpida y deja los objetivos no intentados como pendientes en el CSV. No hay reanudación automática; usar otra salida para una nueva ejecución.

| Código de salida | Significado |
| --- | --- |
| 0 | Operación correcta; captura completa, o no había objetivos. |
| 1 | Error de archivo, configuración, base o proceso gowitness. |
| 2 | Argumentos de consola incorrectos. |
| 3 | Captura terminada con alguna URL sin imagen. El resto de resultados es utilizable. |
| 130 | Captura interrumpida con Ctrl+C. |

## Pruebas

Pruebas automáticas sin conexiones ni navegador:

```powershell
python -m unittest discover -s tests -v
```

Ejemplo incluido que se puede simular:

```powershell
python -m dedalo capturar ejemplos/escaneo.xml ejemplos/escaneo.gnmap ejemplos/escaneo.nmap -r ejemplos/rangos.txt --simular
```

Prueba real de principio a fin:

```powershell
python -m tests.integration_local
```

Necesita gowitness y navegador instalado. Arranca dos webs locales en `127.0.0.1` y `127.0.1.1`, intenta usar 80/443 y usa puertos libres si no puede. Verifica HTTP, redirección, HTTPS autofirmado, un puerto cerrado, URLs exactas, CSV, bases por subred, combinaciones de rango/todo y respuesta del servidor web. Cierra los servicios al terminar y conserva resultados en `pruebas_locales/FECHA-HORA/resultado`.

El certificado y la clave de `tests/fixtures/` son exclusivamente material público de prueba local; no se instalan en el almacén de certificados.

Con el portal arrancado, también hay una prueba de principio a fin de su API:

```powershell
python -m tests.integration_web
```

Sube nmap y rangos de prueba, inicia el trabajo y verifica capturas HTTP/HTTPS, progreso, fallo de conexión, imágenes, CSV, JSON y registro. Conserva la ejecución en el historial del portal. `--portal http://127.0.0.1:8788` permite usar otro puerto. `--manual` deja los dos servidores locales y archivos preparados para probar los botones de la interfaz; Ctrl+C cierra esos servidores de prueba.

Antes de abrir con esta versión un `portal_datos/` de versiones anteriores, se puede ensayar su migración sobre una copia temporal, con el portal cerrado:

```powershell
python -m tests.ensayo_migracion RUTA\portal_datos
```

Solo imprime recuentos y comprobaciones por ejecución (estado, nombre, archivos, capturas, evidencias y carpeta intacta), sin nombres, IP ni URL, y borra la copia al terminar.

Para medir cuánto tarda el portal en arrancar, en refrescar el historial y en abrir una ejecución, con un historial sintético en una carpeta temporal (por defecto, 200 ejecuciones de un /24 y 4 de un /20; sin red ni navegador):

```powershell
python -m tests.medir_portal
```

## Detalles y límites

- Para acceder por VPN, inicia `iniciar_portal.cmd` desde Windows con la VPN conectada. Un portal arrancado desde un entorno con red restringida hereda esa restricción aunque puedas entrar en él por localhost. `ERR_NETWORK_ACCESS_DENIED` indica una denegación de red al navegador de captura.
- Las tarjetas muestran el error específico del motor, también en ejecuciones antiguas. Un error `ERR_INVALID_AUTH_CREDENTIALS` indica autenticación HTTP requerida; el perfil temporal no comparte las credenciales de tu navegador.
- Selección automática en Windows: Chrome instalado, Chromium headless de una instalación existente de Playwright y, por último, Edge. `--chrome` tiene prioridad. Chromium headless resolvió un bloqueo de Edge al generar capturas de un panel ORION; no se instala ni se descarga ningún navegador adicional mediante esta detección.

- **Motor del navegador y reintento.** gowitness maneja el navegador con uno de sus dos motores internos, `gorod` o `chromedp`; no hay que instalar nada. Dedalo usa `gorod` por defecto: con `chromedp` y una espera de 3 s o más, scanme.nmap.org respondía 200 con título pero la captura acababa en `context deadline exceeded`, y con `gorod` se capturaba en unos 5 s. Si una página carga pero se queda sin imagen (`could not grab screenshot`), al terminar su subred se reintenta una vez con el otro motor, en la misma base y con su propio registro `gowitness-reintento.log`. Los errores de conexión no se reintentan. Si el reintento también falla, la tarjeta lo indica. Antes del reintento hay una pasada de esquema: si una URL falla con un error típico de esquema equivocado (`ERR_EMPTY_RESPONSE`, `ERR_INVALID_HTTP_RESPONSE`, `ERR_CONNECTION_RESET`, `ERR_CONNECTION_CLOSED`, `ERR_SSL_PROTOCOL_ERROR` o `ERR_SSL_VERSION_OR_CIPHER_MISMATCH`), se prueba una vez el otro esquema (http↔https) en el mismo IP:puerto y se queda el que responde; el puerto estándar pasa a explícito (`http://ip/` prueba `https://ip:80/`). Solo usa IP:puerto que ya son objetivo y están en alcance, deja `urls-esquema.txt` y `gowitness-esquema.log` en la carpeta de la subred y se desactiva con el mismo interruptor del reintento. Si responde el otro esquema, el informe lleva esa URL; si ninguno, el error empieza por «Ni http ni https respondieron». En el portal ambos ajustes están en **Opciones de captura**.
- Probado en Windows con gowitness 3.2.0, Chrome y Edge. El código contempla Linux, pero no se ha ejecutado aquí una prueba real en Kali.
- Las URI de SQLite que recibe gowitness son relativas a su carpeta, evitando el conflicto de `C:\...` con el formato URI.
- En Windows, al lanzar Edge, se omite `__COMPAT_LAYER` solo en el entorno del proceso hijo. La capa heredada puede hacer que Edge se relance y rompa su conexión de automatización. No se modifica el entorno del equipo.
- El navegador usa el perfil temporal de gowitness, sin reutilizar las sesiones personales.
- Las capturas HTTPS con certificado autofirmado funcionan con la versión probada. No se resuelven pantallas de login ni se añaden nombres de virtual host/SNI: se accede a la IP solicitada.
- El portal permite cargar nmap y cambiar de subred desde el navegador. Sigue necesitando que su servidor local esté iniciado (con doble clic en el lanzador o con `web`).
- Si cambias de versión de gowitness, actualiza `VERSION` y las huellas de `RELEASES` en `dedalo/gowitness.py` y repite la prueba de integración: los parámetros, el esquema de base y el comportamiento del navegador son dependencias externas.
