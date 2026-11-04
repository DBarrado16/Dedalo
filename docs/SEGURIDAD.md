# Revisión de seguridad · 2026-11-04

Revisión de todo el código de `main` (7c6399f), en solo lectura, más los arreglos de la rama `claude/revision-seguridad`. Hizo la revisión un subagente y la verificó el agente principal, que comprobó H1, H2 y H4 contra el código y ejecutando. No se abrió ningún dato real: solo `dedalo/`, `tests/`, `docs/` y `ejemplos/`, y para probar, carpetas temporales con datos sintéticos.

**Herramientas.** Semgrep y CodeQL no están instalados en el equipo de la revisión, y las skills de Trail of Bits no pudieron ejecutar su pipeline. Sus categorías se repasaron a mano: valores inseguros por defecto, interfaces propensas a errores y cadena de suministro.

## Resumen

La parte web aguanta bien:
- Comprueba `Host` (frena el DNS rebinding), `Origin` y `Sec-Fetch-Site`.
- Los POST exigen token y `Content-Type` JSON, con un tope de tamaño.
- Hay CSP estricta y `nosniff`.
- Las rutas de ficheros quedan contenidas, incluso frente a enlaces simbólicos.
- El SQL va parametrizado y el CSV neutraliza las fórmulas.
- Credenciales, favicon, DNS y cruce de vulnerabilidades recomprueban el alcance en vivo.

El punto débil estaba en la regla central del alcance, y solo en la **captura** (H1 y H2, los dos arreglados).

## Hallazgos

| Id | Severidad | Qué | Estado |
|---|---|---|---|
| H1 | Alta | El navegador de gowitness sigue redirecciones (HTTP, meta, JS) y carga los recursos de la página sin comprobar el alcance: una web en alcance puede hacerle pedir algo fuera de alcance o excluido. | **Arreglado.** El navegador de gowitness sale por un proxy local de alcance (`dedalo/proxy.py`, librería estándar, con `--chrome-proxy` de gowitness 3.2.0) que decide cada conexión justo antes de conectar: corta lo excluido y lo interno fuera de alcance, deja pasar lo que está en alcance e internet público, y si no puede leer el alcance corta todo. Lo cortado se ve junto a cada web en el portal, en la base y en el índice CSV. Quedan, escritos en CONTRATOS §0.3, regla 2: lo que va al propio equipo (loopback) no pasa por el proxy; una página hecha a propósito podría mandar UDP por WebRTC; los nombres los resuelve el resolvedor del sistema, y el tráfico de fondo del navegador a internet pasa por ser público. |
| H2 | Alta | Una captura fijaba su alcance al lanzarse: una exclusión hecha con ella en cola o en curso no se aplicaba (regla 0.3.4). | **Arreglado.** El portal escribe `alcance-vivo.json` al arrancar el motor y en cada cambio de la ficha. `capturar` lo relee antes de cada subred, de la pasada de esquema y del reintento, y si no puede leerlo no contacta con nadie. |
| H3 | Media en un equipo compartido, baja si es de un solo usuario | Las GET no piden token y `/api/bootstrap` lo entrega a quien llegue a `127.0.0.1:puerto`: cualquier proceso o usuario local puede leer el inventario y las credenciales encontradas, y manejar el portal. | **Aceptado (Doro, 2026-11-04).** Se mantiene la decisión de diseño «portal local de un usuario, sin autenticación» (ADR 2026-09-28): el portal corre en un equipo de una sola persona. Si eso cambia, la alternativa es un secreto de un solo uso en la URL que abre el portal, que fija una cookie `HttpOnly; SameSite=Strict` exigida en todo `/api/*`. |
| H4 | Baja | Una IPv6 «IPv4-mapped» (`::ffff:10.0.0.5`) no casaba con una exclusión IPv4. | **Arreglado.** `Scope` juzga esas direcciones, y las reglas escritas así, como su IPv4. |
| H5 | Baja | Qué credenciales de fábrica se prueban depende de texto que controla el objetivo: el título HTTP de Nmap y la lectura de la IA, que admite inyección de prompt desde el HTML. | **Aceptado (Doro, 2026-11-04).** Se queda como está: el título y la lectura de la IA amplían qué se prueba, y lo que se prueba sigue limitado al catálogo y al alcance. |
| H6 | Baja | En Windows, `gowitness` (si se buscaba en el PATH) e `ipconfig` podían ejecutarse desde la carpeta actual. | **Arreglado.** Se ignora un `gowitness` de la carpeta actual, igual que ya se hacía con Ollama, e `ipconfig` se lanza con su ruta completa de `System32`. |
| H7 | Baja/Media | Sin Chrome ni Edge instalados, gowitness descarga un Chromium sin huella fijada. | **Arreglado.** Se exige un navegador instalado (Chrome, Chromium o Edge, o el de `--chrome`); sin ninguno, la captura no arranca y el portal lo indica. gowitness ya no descarga el suyo. |
| I3 | Informativa | La `ruta` de una receta de formulario no se validaba. Con `@otro/` o `:81@…` podría cambiar el host de la URL, aunque en las pruebas nunca llegó a conectar fuera. | **Arreglado.** Se exige `/` al principio y que la URL siga apuntando al mismo IP:puerto, tanto al conectar como al añadir una entrada al catálogo. |

### Informativas sin cambio
- **XML de Nmap.** Con Python 3.14 y expat 2.8, el *billion laughs* y las entidades externas se rechazan. Con los topes de 10 MB por fichero, el riesgo es bajo. Como defensa ante un expat antiguo, se podría rechazar `<!ENTITY` (Nmap no lo emite).
- **Qué sale del equipo.**
  - A la API de la NVD va el CPE de Nmap, y a GitHub, ids de CVE.
  - Los feeds se descargan al arrancar salvo con `--sin-internet`.
  - Claude viene apagado de serie. Si se activa, además del HTML y las cabeceras también salen el título, el certificado TLS (puede llevar nombres internos) y las tecnologías.
  - `ANTHROPIC_API_KEY` la heredan los procesos hijos: conviene quitarla de su entorno.
- **Descargas.** El opener común sigue redirecciones, incluso de https a http. Las fuentes son fijas y el TLS se verifica.
- **Interfaz.** Algunos datos numéricos o del propio servidor se interpolan sin escapar (`app.js`). La CSP lo mitiga; conviene escaparlos por coherencia.

## Revisado y correcto
`allowed()` y el token, cabeceras de seguridad, ficheros servidos (`report.inside`, `screenshot_path`), borrados (sin seguir enlaces ni junctions), procesos externos sin shell, descarga de gowitness con SHA-256 fijado, topes y escritura atómica de los feeds, Ollama solo en loopback y sin proxy, salida de la IA validada contra un esquema, valores por defecto (escucha en 127.0.0.1, detección de versión apagada, `DEDALO_SIN_INTERNET` falla en cerrado, sin `incluir` no hay nada en alcance).

## No revisado
- El código de gowitness y go-rod (flags del navegador, descarga de Chromium).
- `auditoria.py`, `db.py`, `prioridad.py` y `vulnerabilidades.py`, revisados solo en parte.
