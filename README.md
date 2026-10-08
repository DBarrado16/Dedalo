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

El ejecutable de gowitness no se incluye en el repositorio. `python -m dedalo instalar` descarga el binario oficial para Windows, Linux o macOS (Intel o ARM), comprueba su SHA-256 contra la huella fijada en `dedalo/gowitness.py` y lo coloca en `bin/`. El portal lo hace automáticamente al arrancar si no encuentra gowitness y no se indicó `--gowitness`; si la descarga falla, arranca igualmente y muestra el aviso. Los comandos `capturar` y `ver` no descargan nada por su cuenta.

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

En Windows puedes hacer doble clic en **`iniciar_portal.cmd`**. Abre el navegador y mantiene el servidor en una terminal; déjala abierta mientras trabajas. No requiere instalar paquetes con pip ni Node.

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

Para eliminar una ejecución, selecciónala en el historial y pulsa **Borrar ejecución**. El portal pide confirmación y elimina permanentemente esa ejecución, sus capturas, copias de los Nmap subidos, índices y registros. Los archivos originales de tu equipo no se modifican. Si está en cola o capturando, primero cancélala o detenla y espera a que termine; entonces podrás borrarla.

```powershell
# Cambiar puerto y carpeta de almacenamiento
python -m dedalo web --puerto 8788 --datos portal_datos_cliente

# Indicar los ejecutables del equipo que hace las capturas
python -m dedalo web --chrome "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --gowitness bin/gowitness.exe
```

El portal admite hasta 20 archivos por carga (10 MB por archivo y 24 MB en total en la interfaz), con un máximo de 100.000 objetivos por ejecución. Muestra los resultados por páginas de 60 objetivos. Los ajustes de ejecutables se realizan al arrancar el servidor, no desde los archivos subidos.

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

El estado, las opciones y los resultados de cada ejecución están en `dedalo.sqlite3`. Las carpetas de versiones anteriores traen además un `trabajo.json`: al arrancar, el portal las pasa a la base una sola vez, con sus capturas, sin modificar la carpeta (salvo que la ejecución estuviera activa al cerrarse: entonces añade el fichero `parar`, para que su motor, si siguiera vivo, no conecte con más subredes). Si alguna no se puede migrar (por ejemplo, porque faltan sus Nmap en `entradas/` o el `id` de su `trabajo.json` no coincide con el de la carpeta), lo avisa en la terminal y en el portal, con su nombre, el código de su carpeta y el motivo, porque no aparece en el historial; la conserva y lo reintenta en cada arranque. Una imagen de una captura antigua que ya no esté en disco no impide migrarla: esa URL queda sin captura y el resto se conserva. Si una ejecución ya guardada no se puede leer al arrancar, aparece igualmente en el historial, sin objetivos y, si no se había lanzado, con estado «Error» y el motivo; el resto del portal arranca con normalidad.

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
| `--sin-reintento` | No reintenta con el otro motor las páginas que cargan pero no dan imagen. |
| `--chrome RUTA` | Navegador que debe utilizar. |
| `--gowitness RUTA` | Ejecutable de gowitness v3. |

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

Por defecto el visor solo escucha en `127.0.0.1`. `--host` permite cambiarlo. No se añade una capa de autenticación al visor de gowitness.

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

## Detalles y límites

- Para acceder por VPN, inicia `iniciar_portal.cmd` desde Windows con la VPN conectada. Un portal arrancado desde un entorno con red restringida hereda esa restricción aunque puedas entrar en él por localhost. `ERR_NETWORK_ACCESS_DENIED` indica una denegación de red al navegador de captura.
- Las tarjetas muestran el error específico del motor, también en ejecuciones antiguas. Un error `ERR_INVALID_AUTH_CREDENTIALS` indica autenticación HTTP requerida; el perfil temporal no comparte las credenciales de tu navegador.
- Selección automática en Windows: Chrome instalado, Chromium headless de una instalación existente de Playwright y, por último, Edge. `--chrome` tiene prioridad. Chromium headless resolvió un bloqueo de Edge al generar capturas de un panel ORION; no se instala ni se descarga ningún navegador adicional mediante esta detección.

- **Motor del navegador y reintento.** gowitness maneja el navegador con uno de sus dos motores internos, `gorod` o `chromedp`; no hay que instalar nada. Dedalo usa `gorod` por defecto: con `chromedp` y una espera de 3 s o más, scanme.nmap.org respondía 200 con título pero la captura acababa en `context deadline exceeded`, y con `gorod` se capturaba en unos 5 s. Si una página carga pero se queda sin imagen (`could not grab screenshot`), al terminar su subred se reintenta una vez con el otro motor, en la misma base y con su propio registro `gowitness-reintento.log`. Los errores de conexión no se reintentan. Si el reintento también falla, la tarjeta lo indica. En el portal ambos ajustes están en **Opciones de captura**.
- Probado en Windows con gowitness 3.2.0, Chrome y Edge. El código contempla Linux, pero no se ha ejecutado aquí una prueba real en Kali.
- Las URI de SQLite que recibe gowitness son relativas a su carpeta, evitando el conflicto de `C:\...` con el formato URI.
- En Windows, al lanzar Edge, se omite `__COMPAT_LAYER` solo en el entorno del proceso hijo. La capa heredada puede hacer que Edge se relance y rompa su conexión de automatización. No se modifica el entorno del equipo.
- El navegador usa el perfil temporal de gowitness, sin reutilizar las sesiones personales.
- Las capturas HTTPS con certificado autofirmado funcionan con la versión probada. No se resuelven pantallas de login ni se añaden nombres de virtual host/SNI: se accede a la IP solicitada.
- El portal permite cargar nmap y cambiar de subred desde el navegador. Sigue necesitando que su servidor local esté iniciado (con doble clic en el lanzador o con `web`).
- Si cambias de versión de gowitness, actualiza `VERSION` y las huellas de `RELEASES` en `dedalo/gowitness.py` y repite la prueba de integración: los parámetros, el esquema de base y el comportamiento del navegador son dependencias externas.
