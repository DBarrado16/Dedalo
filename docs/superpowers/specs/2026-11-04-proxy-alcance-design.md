# Proxy de alcance para el navegador de la captura (H1) · diseño

Fecha: 2026-11-04. Origen: hallazgo H1 de `docs/SEGURIDAD.md`. Decidido con Doro en la sesión del 2026-11-04.

## Por qué

Dédalo comprueba el alcance de las URL que le da a gowitness, pero el navegador hace luego lo que diga la página: sigue redirecciones y carga recursos (imágenes, scripts, CSS) sin pasar por esa comprobación. Una web en alcance puede hacer que el navegador conecte con una IP interna fuera de alcance o excluida (una impresora frágil, una red que no está en el contrato). Esa conexión sale del equipo del auditor y, ante el cliente, la ha hecho el auditor. Es el límite que hoy recoge `docs/CONTRATOS.md` §0.3, regla 2.

Además, Doro quiere **verlo**: junto a cada web capturada, qué intentó tocar que no estaba en alcance.

## Objetivos

1. Ninguna conexión del navegador de la captura llega a una IP **excluida** ni a una IP **interna** fuera de alcance.
2. Las capturas se ven como hoy: lo que esté en alcance y lo que la web cargue de **internet público** pasa sin tocar.
3. En el portal, junto a cada web, un aviso con lo que se le cortó: destino (nombre si lo había, IP:puerto) y si estaba **excluido** o **fuera de alcance**.
4. Lo cortado queda en la base y sale al exportar.

## No objetivos

- No se enseña lo que la web carga de internet público (decisión de Doro: solo lo que se corta).
- No se filtra el tráfico de otros módulos (credenciales, favicon, DNS, vulnerabilidades): ya comprueban el alcance ellos mismos.
- No se cambia cómo se elige el navegador ni el motor (gorod/chromedp).

## Anti-objetivos (sería un fracaso aunque funcione)

- Que las capturas en alcance cambien: más errores, otros mensajes, la pasada de esquema http/https disparándose donde antes no, o capturas de una página de error del proxy.
- Que el proxy, al fallar o al no poder leer el alcance, deje pasar algo interno: falla en cerrado.
- Una dependencia de pip: todo con la librería estándar.

## Regla de paso (decidida con Doro)

Para cada conexión que pida el navegador, justo antes de conectar y con el alcance vigente:

| Destino (IP ya resuelta) | Qué pasa |
|---|---|
| Excluida | Se corta. La exclusión siempre gana, aunque sea pública. |
| En alcance | Pasa. |
| Pública (`ipaddress.is_global`) y no excluida | Pasa (internet público). |
| Cualquier otra (privada, enlace local, CGNAT, reservada…) fuera de alcance | Se corta. |

- **Alcance vigente.** Con `--alcance-vivo` (siempre desde el portal), el de ese fichero, releído en cada conexión (vale un `stat` y releer si cambió). Si no se puede leer, se corta **todo**, también lo público, como hoy en `in_live_scope` (falla en cerrado).
- **Alcance ilegible.** Antes de fallar en cerrado se reintenta la lectura brevemente (unos pocos intentos en ~200 ms): en Windows, leer justo mientras el portal sustituye el fichero puede dar `PermissionError` un instante. Si sigue sin leerse, se corta con el motivo propio `alcance_ilegible`, que el portal no presenta como «la web intentó contactar», sino como «no se pudo comprobar el alcance» (decisión del agente).
- **Consola sin portal.** El `Scope(["0.0.0.0/0", "::/0"], excluidos)` que `cli.plan` usa con `--excluir` sin `--solo-rangos` sirve para planificar, no para el proxy: no puede volverlo más permisivo. En consola cuenta como «en alcance» el conjunto de IP de los objetivos planificados, más los rangos de `--rangos` si hay `--solo-rangos`, menos lo excluido (decisión del agente).
- **Nombres.** Si el destino es un nombre, el proxy lo resuelve con el resolvedor del sistema (`getaddrinfo`), aplica la regla a cada dirección y conecta **a la IP que comprobó**, no vuelve a resolver. Si alguna dirección del nombre se cortaría, se usa solo una que pase; si ninguna pasa, se corta (decisión del agente).
- IPv6 mapeada se juzga como su IPv4, igual que `Scope`.

## Cómo funciona

- **Proxy local.** Un módulo nuevo (por ejemplo `dedalo/proxy.py`) con un servidor TCP en `127.0.0.1`, puerto elegido por el sistema, que vive lo que dura el proceso `capturar` (lo arranca y lo para `cli.capture`). gowitness lo recibe con `--chrome-proxy http://127.0.0.1:PUERTO` en cada `scan_subnet` (comprobado: gowitness 3.2.0 tiene ese flag y Chrome/Edge lo respetan con los dos motores; ver «Comprobado»).
- **Lo que atiende.**
  - `CONNECT host:puerto` (HTTPS, WebSocket seguro): decide, conecta y hace de túnel de bytes. El TLS va de punta a punta; el proxy no lo abre.
  - Peticiones HTTP con URL absoluta (`GET http://host:puerto/ruta`): decide, conecta, reenvía la petición en forma de origen (`GET /ruta`) y hace de túnel de bytes. Chrome reutiliza una conexión al proxy para hosts distintos, así que cada conexión HTTP del cliente lleva una sola petición: el proxy fuerza `Connection: close` hacia el servidor y cierra con el cliente al acabar.
- **Respuestas del proxy** (elegidas para no cambiar lo que ve hoy gowitness; ver anti-objetivos):
  - Cortado: `403` sin cuerpo. Chrome lo da como `ERR_TUNNEL_CONNECTION_FAILED` (CONNECT) o `ERR_HTTP_RESPONSE_CODE_FAILURE` (HTTP), sin imagen.
  - No se pudo conectar (rechazada, sin respuesta): `502` sin cuerpo, con el mismo efecto. Nunca cerrar sin responder: Chrome lo daría como `ERR_EMPTY_RESPONSE`, que está en `SCHEME_ERRORS` y dispararía la pasada de esquema en un puerto cerrado.
- **Registro del proxy.** Un fichero JSON Lines **por pasada** de gowitness (normal, esquema, reintento), en la carpeta de su subred junto a sus logs, con una línea por conexión **cortada**: `destino` tal como lo pidió el navegador, `ip`, `puerto`, `motivo` (`excluida` | `fuera_de_alcance` | `alcance_ilegible`). No se anota lo que pasa. El proxy es uno para todo el proceso; la pasada se distingue porque `cli` le indica a qué fichero escribe antes de lanzar cada una (las pasadas van en serie).

## Qué se ve en cada web

- **Atribución por página.** gowitness 3.2.0 guarda en su base, por resultado, la tabla `network_logs` con cada petición de la página (URL, IP remota, código, error), **también las que el proxy cortó** (comprobado). Al leer los resultados de la subred, cada petición de `network_logs` cuyo `host:puerto` aparezca como cortado en `proxy.jsonl` se atribuye a esa web.
- **Web que no llegó a cargar.** Si una redirección de la propia página se corta, gowitness no guarda resultado ni `network_logs` (comprobado: solo un `ERRO failed to witness target` en el log), y con varios hilos no hay forma fiable de saber qué página pidió ese corte. No se adivina: el error de esa URL queda como hoy, y los cortes de la pasada que no se atribuyen a ninguna página se enseñan **a nivel de subred**: «En esta subred se cortaron conexiones a: …» (decisión del agente). Atribuirlos por página exigiría seguir la cadena de redirecciones y queda fuera.
- **Manifiesto.** Cada resultado del manifiesto lleva una lista `bloqueos` (`destino`, `ip`, `puerto`, `motivo`), vacía si nada se cortó; cada grupo (subred), una lista `bloqueos_sin_pagina` con los no atribuidos.
- **Base.** Migración nueva (la 8, tras la 7 de la PR #15) con una tabla `captura_bloqueo` (`captura_id` con borrado en cascada, `destino`, `ip`, `puerto`, `motivo`), que `record_captures` rellena de forma repetible (la reconciliación al arrancar vuelve a volcar). Los cortes sin página de cada subred se leen del manifiesto y no van a la base (decisión del agente). Se documenta en `docs/MODELO_DATOS.md`.
- **Portal.** En el detalle de cada captura, junto a la web, un aviso: «Esta web intentó contactar con 10.20.0.5:443 (excluida) y se cortó», uno por destino. En la lista de capturas, una marca visible en las que tengan alguno. Diseño según `DESIGN.md` y las skills de interfaz del proyecto.
- **Exportar.** Una columna nueva en `indice.csv` con los destinos cortados de cada web, en todos los sitios donde se escribe (`report._write_rows`, que usan el portal y el ZIP por subred).
- **Errores de los objetivos.** Los mensajes de error de las URL objetivo no cambian respecto a hoy (anti-objetivo). Tras el proxy, un puerto cerrado o caído llega a Chrome como fallo del túnel; el proxy anota sus fallos de conexión (`rechazada`, `sin_respuesta`) y, al leer los errores, el código de esa URL se vuelve a escribir como el que daría Chrome sin proxy (decisión del agente, al planificar).

## Límites que quedan (se escriben en CONTRATOS §0.3)

- Chrome no manda por el proxy lo que va al propio equipo (`localhost`, `127.0.0.0/8`, `::1`), y gowitness no deja pasar `--proxy-bypass-list`. Solo afecta al equipo del auditor.
- Una página con JavaScript hecho a propósito podría mandar UDP por WebRTC sin pasar por el proxy (no se puede pasar `--force-webrtc-ip-handling-policy` a través de gowitness).
- La resolución de nombres la hace el resolvedor del sistema, como hoy hace el navegador.
- El propio navegador (Edge sobre todo) hace peticiones de fondo a internet (telemetría, SmartScreen); pasan por ser públicas y no se atribuyen a ninguna web.

## Comprobado (2026-11-04, KmelloFumon, solo local)

Experimento con una web en `127.0.0.1` y un proxy local que responde `403` a todo, gowitness 3.2.0 con chromedp y Edge:

- Las peticiones a nombres e IP no locales (`http://bloqueado.test:8080/x.png`, `https://cdn-bloqueado.test/a.css`, `http://10.99.99.99:81/s.js`) llegaron al proxy; ninguna salió directa.
- `network_logs` de la web guardó las tres, con `ERR_TUNNEL_CONNECTION_FAILED` / `ERR_ABORTED` o el `403`.
- Una redirección a `http://redir-bloqueado.test/` dejó el objetivo sin resultado, con `ERR_HTTP_RESPONSE_CODE_FAILURE` en el log.
- Edge mandó tráfico propio al proxy (`edge.microsoft.com`, `www.bing.com`, SmartScreen).

## Pruebas

- Unidad, sin red: la regla de paso (excluida pública, en alcance, pública, privada fuera, IPv6 mapeada, nombre con varias direcciones, alcance ilegible), el análisis de `CONNECT` y de peticiones HTTP absolutas, la atribución desde `network_logs` y `proxy.jsonl`, y la migración.
- Un test por cada conexión nueva que demuestre que lo excluido no se contacta (regla del proyecto).
- Integración (`tests/integration_local.py`): una web de prueba que carga un recurso y redirige a un destino fuera de alcance; se comprueba que el destino no recibe nada, que el aviso sale en el manifiesto y que los casos de hoy (puerto cerrado, esquema equivocado) siguen dando el mismo resultado. Como Chrome no manda `127.0.0.1` al proxy, los destinos «fuera de alcance» de la prueba son nombres o IP no locales que el proxy corta antes de conectar, sin salir del equipo. `integration_web` debe seguir en OK.

## Depende de

Las PR #12 a #15 fusionadas en `main` (la migración 7 está en la #15). La rama de la implementación sale del `main` resultante.

## Decide el constructor

Nombres de módulos, funciones y ficheros; hilos o `selectors` para el proxy; topes y tiempos de espera (por debajo del `-T` de gowitness); el texto exacto de los avisos; cómo cachear el alcance vivo entre conexiones sin dejar de releerlo si cambia.
