# Lanzar Nmap desde el portal (bloque 3) · diseño

Fecha: 2026-11-04. Origen: tarea `lanzar-nmap-portal` del Brain (idea de Doro, 2026-10-16 y 2026-10-19). Diseño propuesto por el agente y aprobado por Doro en la sesión del 2026-11-04. Lo marcado como **(decisión del agente)** no lo decidió Doro expresamente; lo aceptó al aprobar el conjunto.

## Por qué

Hoy el operador lanza Nmap a mano y sube el fichero al portal. Doro quiere lanzarlo desde Dédalo, sobre el alcance de la ficha, y poder encadenar **varios presets del tirón**, porque a veces los Nmap salen raros por VPN y un preset distinto ayuda. Con `-sV` el CPE alimenta el cruce de vulnerabilidades.

## Objetivos

1. Un botón **«Escanear con Nmap»** en la ficha del cliente, junto a la subida de archivos de Nmap.
2. Se escanea solo lo que está **en alcance** de la ficha, con el alcance comprobado en vivo durante todo el escaneo (`docs/CONTRATOS.md` §0.3). La exclusión siempre gana.
3. El resultado entra en la ficha como **una importación más**, por el mismo camino que un fichero subido: inventario, capturas, IA y cruce de CVE funcionan igual.
4. Tres presets fijos; se pueden marcar varios y se lanzan seguidos sobre el mismo alcance, y todo se junta en **una sola importación** (como subir varios ficheros, que `parser.merge` ya une). **(decisión del agente)**
5. Casilla opcional **«Capturar las webs al terminar»**: al acabar el escaneo, se lanza la captura de esa importación como si el operador pulsara el botón.
6. Rangos grandes (un /16 o un /19 son casos reales de Doro) se escanean enteros, troceados en /24 que se lanzan uno detrás de otro, con progreso «trozo N de M».

## No objetivos (esta versión)

- IPv6: solo se escanea IPv4. Las reglas `incluir` IPv6 de la ficha se ignoran al escanear y el diálogo lo dice.
- UDP.
- Scripts NSE (`-sC`, `--script`): ninguno. Algunos tocan otros hosts (broadcast, `newtargets`) y saltarían el alcance. **(decisión del agente)**
- Que una IA elija o ajuste opciones de Nmap. Como mucho, más adelante, que sugiera un preset.
- Opciones de Nmap escritas por el usuario.
- Instalar o descargar Nmap.
- Un barrido previo de «qué IP están vivas» antes de los presets (Doro lo descartó: «me sirve así»).

## Anti-objetivos (fracaso aunque funcione)

- Que Nmap reciba un paquete hacia una IP excluida o fuera de alcance que Dédalo le haya dado, o que una exclusión hecha a mitad de escaneo no corte el trozo en curso.
- Que texto que viene del navegador (nombre, rangos, lo que sea) llegue a la línea de comandos de Nmap.
- Una dependencia de pip.
- Que un escaneo a medias deje la ficha con una importación rota o deje una importación de la que no se sabe cómo se hizo.

## Presets (fijos, en el código)

Todos usan escaneo por conexión (`-sT`): funciona sin privilegios de administrador (el portal corre como usuario) y pasa por cualquier adaptador VPN. Ninguno usa `-O` (necesita privilegios). **(decisión del agente)**

| Preset | Para qué | Opciones propias |
| --- | --- | --- |
| `rapido` · Rápido | Lo normal | `-sT --top-ports 1000 -sV --version-light -T4 -PE -PS21,22,23,25,80,135,139,443,445,3389,8080,8443 --max-retries 2 --host-timeout 15m` |
| `completo` · Completo | Todos los puertos TCP | `-sT -p- -sV -T4 -PE -PS21,22,23,25,80,135,139,443,445,3389,8080,8443 --max-retries 2 --host-timeout 60m` |
| `vpn` · Red difícil / VPN | Cuando el ping está bloqueado o el Nmap sale raro | `-sT -Pn --top-ports 1000 -sV -T3 --max-retries 4 --host-timeout 20m` |

Comunes a todos, siempre: `-n` (sin DNS inverso: eso es el descubrimiento DNS), `-oX <fichero del trozo>`, `-iL <objetivos del trozo>`, `--excludefile <exclusiones del trozo>`. Los valores exactos de cada preset son **(decisión del agente)**; si un valor no funciona con Nmap real, se corrige en la implementación y se dice.

Por qué existe `vpn`: sin privilegios, el descubrimiento de Nmap solo prueba conexiones a unos puertos; por VPN el ping suele estar bloqueado y Nmap da por caídos equipos vivos. `-Pn` se salta el descubrimiento y escanea todas las IP. En un rango grande eso es lento (prueba los puertos también en las IP vacías): el diálogo lo avisa.

## Alcance (la parte delicada)

Nmap conecta por su cuenta, así que Dédalo no puede vigilar cada paquete como hace el proxy con las capturas. La regla:

1. **Sin reglas `incluir` no se lanza** (`Conflict`, como el descubrimiento).
2. **Objetivos:** las reglas `incluir` IPv4 de la ficha, menos las `excluir`. Se trocean en bloques /24 alineados (un rango menor de /24 es un trozo; un /16 son 256 trozos). Los trozos se escanean de uno en uno, en orden. **(decisión del agente)**
3. **Antes de cada trozo** se relee el alcance vivo (el mismo mecanismo que la captura y el descubrimiento: el portal mantiene `alcance-vivo.json` en la carpeta de la ejecución y lo reescribe al cambiar la ficha). Se calculan las IP en alcance del trozo; si no queda ninguna, el trozo se salta. A Nmap se le pasa la lista del trozo en un fichero (`-iL`), escrita por Dédalo a partir de `ipaddress` (nunca texto del usuario), y las excluidas que caen en el trozo en `--excludefile`. Si el alcance no se puede leer, no se lanza el trozo y el escaneo termina en `error` sin contactar con nadie.
4. **Durante el trozo**, Dédalo vigila el alcance vivo (cada segundo, por fecha y tamaño del fichero, como `AlcanceVivo`). Si una IP del trozo en curso deja de estar en alcance (se excluye o se quita su rango), **para Nmap** (terminar el proceso; matarlo si no sale en 5 s), descarta la salida de ese intento y **relanza el trozo** con el alcance nuevo. **(decisión del agente)**
5. Límite que queda, documentado en CONTRATOS §0.3: entre el cambio de la ficha y la parada de Nmap pasa como mucho el intervalo de vigilancia (≈1 s) más lo que tarde en salir el proceso.
6. Un escaneo como máximo de **65.536 IP en alcance** (un /16) por lanzamiento; si hay más, error claro antes de lanzar («divide el alcance o elige rangos»). **(decisión del agente)**

## Qué ve el operador

- **Botón** «Escanear con Nmap» en la ficha, junto a «Seleccionar archivos de Nmap». Deshabilitado con explicación si la ficha no tiene alcance o si no se encuentra Nmap (con el texto de cómo instalarlo y de la opción `--nmap`).
- **Diálogo:**
  - Rangos: por defecto todas las reglas `incluir` IPv4 de la ficha, con casillas para escanear solo algunas. Solo se puede elegir entre las reglas de la ficha, no escribir rangos nuevos.
  - Presets: casillas `Rápido` (marcado por defecto), `Completo`, `Red difícil / VPN`, con una línea de qué hace cada uno.
  - Casilla «Capturar las webs al terminar» (desmarcada por defecto). **(decisión del agente)**
  - Antes de lanzar, un resumen: cuántas IP en alcance recibirán paquetes, cuántos trozos, presets y una **estimación de tiempo** (heurística por preset e IP; orden de magnitud, no promesa). Si se combina `vpn` o `completo` con más de 1.024 IP, un aviso visible de que puede tardar horas. Botón de confirmar.
- **Mientras corre:** el escaneo sale en el historial de la ficha como un trabajo más, con su estado y el progreso (preset actual, trozo N de M) y un botón **Detener**.
- **Al terminar:** aparece la importación nueva (nombre «Escaneo Nmap · <presets> · <fecha>»), con el inventario como cualquier otra. Desde el escaneo se llega a su importación.

## Ciclo de vida

- Tipo de ejecución nuevo **`escaneo`** (ya anunciado en CONTRATOS §0.4 como tipo futuro), en la misma cola que el resto: de uno en uno. Mientras escanea no corre otra cosa de la cola; es coherente con el contrato y evita dos cosas tocando la red del cliente a la vez. **(decisión del agente)**
- Estados: los de siempre. `preparada` no se usa: se crea `en_cola` al confirmar.
- **Detener:** para Nmap enseguida (no espera al fin del trozo, que en `completo` puede ser largo), descarta el trozo en curso e **importa lo ya terminado** como resultado `parcial`. Sin ningún trozo terminado: `cancelada`/`interrumpida` sin importación.
- **Fin normal:** todos los trozos de todos los presets terminados → se importa todo → `completa`. Si algún trozo falló (Nmap salió con error) y otros no → se importa lo bueno → `parcial`, con el error de cada trozo en el registro.
- **Alcance ilegible a mitad:** no se lanza el trozo siguiente; se importa lo ya terminado y el escaneo queda `parcial`, con el motivo en su error. Sin nada terminado, `error`. **(decisión del agente)**
- **Portal cerrado a mitad:** el portal para Nmap al cerrarse (no puede sobrevivir al portal: no vería las exclusiones que se hicieran al reabrir) y el escaneo queda `interrumpida`, como el resto de tipos. Al reabrir, si tiene trozos terminados que no se importaron, se importan entonces y queda `parcial`. **(decisión del agente)**
- **«Capturar al terminar»:** si el escaneo acaba `completa` o `parcial` y produjo importación, se encola su captura con las opciones de captura por defecto.

## Importación resultante

- Por el **mismo camino** que hoy sigue un fichero subido (`parser.parse_*`, `parser.merge`, `auditoria.import_nmap`), en la misma ficha. Los XML de cada trozo y preset son sus ficheros Nmap de evidencia, con su SHA-256.
- **Hosts fantasma de `-Pn`:** con `-Pn`, Nmap da por `up` todas las IP («user-set»), aunque no conteste ninguna. Antes de unir, el escaneo descarta los hosts cuyo estado viene solo de `-Pn` (razón `user-set`) y no tienen ningún puerto abierto: Nmap no supo nada de ellos, así que no es información que se pierda. Sin esto, un /16 con `vpn` metería 65.536 activos vacíos en la ficha. Solo en el escaneo; la subida de ficheros no cambia. **(decisión del agente)**
- **Hosts que responden en todos los puertos (decidido por Doro):** un cortafuegos o *tarpit* detrás de VPN puede dar «abierto» en todos los puertos, y con `completo` dos hosts así superan el límite del inventario (100.000 servicios) y harían fallar la importación entera. Un host con **más de 1.000 puertos abiertos** en el resultado unido se importa **sin sus puertos**, con una observación «responde en todos los puertos (N abiertos)». Los XML completos quedan como evidencia. Si aun así se superan los límites, el escaneo termina en `error` con un mensaje claro y los XML quedan en su carpeta.
- **Vínculo escaneo ↔ importación:** va en las `opciones` de cada ejecución (el id de la otra), **no** en `origen_id`, cuya clave ajena borra en cascada. Borrar el escaneo deja la importación (son los datos que importan) y borrar la importación deja el escaneo con «importación borrada». **(decisión del agente)**
- Además, en la carpeta del escaneo y como evidencia: un `escaneo.json` con la versión de Nmap, la ruta del binario y, por trozo y preset, la línea de comandos exacta, inicio, fin, código de salida y si se relanzó por un cambio de alcance; y la salida estándar y de error de Nmap de cada trozo.

## El binario

- No se instala ni se descarga: Nmap en Windows necesita Npcap (instalación de administrador) y su licencia complica redistribuirlo. **(decisión del agente)**
- Búsqueda, en este orden: la opción `--nmap` del portal (y de la consola si se añade), `C:\Program Files (x86)\Nmap\nmap.exe`, `C:\Program Files\Nmap\nmap.exe`, el PATH (sin contar la carpeta actual, como ya hacen `find_gowitness` y `find_ollama`), `/usr/bin/nmap`.
- Al encontrarlo se comprueba con `nmap --version` que responde y se guarda su versión. Sin huella fija: es el Nmap que instaló el operador.
- Se lanza **sin shell**, con la lista de argumentos construida por Dédalo, y con la **carpeta de trabajo = la carpeta del escaneo** (Nmap busca ficheros de datos en la carpeta actual; ahí solo hay ficheros de Dédalo).

## Base de datos

- Migración nueva y numerada en `dedalo/db.py`: `escaneo` en el `CHECK` de `ejecucion.tipo` (reconstruyendo la tabla como las migraciones anteriores). Las opciones del escaneo (rangos elegidos, presets, capturar al terminar) van en `opciones`, como el resto de tipos. Nada más si no hace falta.

## Pruebas

- Unidad (sin red ni Nmap real), con un **Nmap falso** (script que lee `-iL`/`--excludefile`, escribe un XML y registra sus argumentos):
  - lo excluido y lo fuera de alcance nunca aparece en el `-iL`; lo excluido del trozo va al `--excludefile`;
  - sin `incluir` no se lanza; más de 65.536 IP, error antes de lanzar; IPv6 se ignora;
  - troceo: /19 → 32 trozos, /16 → 256, /26 → 1;
  - la línea de comandos solo contiene los argumentos fijos del preset y rutas de Dédalo, aunque el nombre o las opciones del navegador traigan texto hostil;
  - una exclusión hecha a mitad de un trozo para Nmap y relanza el trozo sin esa IP;
  - Detener importa lo terminado como `parcial`; cerrar a mitad y reabrir importa lo terminado;
  - varios presets → una sola importación con todos los XML como evidencia;
  - con `vpn`, los hosts `user-set` sin puertos abiertos no llegan a la importación;
  - un host con más de 1.000 puertos abiertos entra sin puertos y con su observación;
  - borrar el escaneo no borra su importación, y al revés;
  - cerrar el portal para el proceso de Nmap;
  - «capturar al terminar» encola la captura;
  - sin Nmap: el botón explica cómo instalarlo y la API responde con error claro;
  - la carpeta de trabajo de Nmap es la del escaneo y no se usa shell.
- Integración: contra servicios locales en `127.0.0.1` con el Nmap real. **En el PC de Doro (KmelloFumon) no hay Nmap instalado**: hace falta instalarlo (con Npcap) o probarlo en Kali. Si no se puede, se dice y la prueba queda pendiente.

## Documentación

- `docs/CONTRATOS.md`: §0.1 (el bloque 3 pasa a «Incluye»), §0.3 regla 2 (cómo comprueba el alcance el escaneo y su límite), §0.4 (fila del tipo `escaneo`).
- `docs/MODELO_DATOS.md`: el tipo nuevo y la migración.
- `README.md`: cómo instalar Nmap, `--nmap`, los presets.
- `docs/SEGURIDAD.md`: si la revisión encuentra algo.

## Lo que queda al constructor

- Cómo se estructura el código (módulo nuevo `dedalo/escaneo.py` parece lo natural, junto a `descubrimiento.py`).
- La heurística exacta de la estimación de tiempo.
- El diseño visual del diálogo y del progreso, siguiendo `DESIGN.md`.
- Cómo se vigila el alcance durante el trozo, siempre que cumpla el punto 4 de «Alcance».
