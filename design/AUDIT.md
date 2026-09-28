# Auditoría de diseño de Dedalo

Skill aplicada: [avoid-ai-design 0.4.0](https://github.com/funboy322/avoid-ai-design/blob/main/SKILL.md), copia local en `design/avoid-ai-design`. Perfil: dashboard. Alcance: HTML, CSS y JS del portal; temas claro/oscuro y diálogos. Sin nuevas dependencias de ejecución.

## Punto de partida

Scanner: 1 P0, 6 P1 y 2 P2; véase `audit-before.json`.

| Nivel / ID | Ubicación inicial | Evidencia y decisión |
| --- | --- | --- |
| P0 / T1 | style.css, línea 1 | Código: Inter declarado como primera familia sin cargarse. Sustituido por tipografía local elegida por función. |
| P1 / CP3 | index.html, línea 73; app.js, línea 232 | Código: flechas añadidas a «Revisar objetivos». Eliminadas. |
| P1 / SD6 | index.html, líneas 26, 52, 56 | Código: marcadores 01/02 en campos paralelos. Se eliminan y se conserva el texto informativo. |
| P1 / K3 | style.css, línea 1 | Código: desenfoque del fondo del diálogo. Sustituido por una superposición sólida semitransparente. |
| P1 / K7 | index.html | Falso positivo: el foco estaba en el CSS enlazado. Se conserva, se verifica y se documenta una excepción específica. |
| P1 / C9 | style.css, línea 1 | El scanner mezclaba el token oscuro y el fondo claro. También había textos pequeños muy tenues en la interfaz. Nueva comprobación separada por temas en contrast.json. |
| P2 / SD4d | HTML y JS | Código: separadores de punto medio por defecto. Sustituidos por etiquetas y agrupación visual. Los nombres aportados por el usuario no se modifican. |
| P1 / K2 | Resumen, estado, galería | Render: cuatro contadores en cajas equivalentes y otro panel grande antes de las imágenes. Se sustituye por franja de datos y barra de acciones sin caja. |
| P1 / SD4 | Encabezados y formulario | Render: etiquetas decorativas y marca repetida encima de un título. Se retiran. |
| P2 / S1 | Vista de capturas | Render: los bloques previos a la galería tienen tanto peso como las imágenes. Se reduce el espacio de controles y se destacan las subredes y sus capturas. |

## Dirección elegida

Ejecución, subred, IP y captura determinan el orden visual. La alternativa de una tabla dominante se descartó porque el usuario necesita reconocer webs visualmente. También se descartó replicar una terminal: los logs ya tienen su propia vista.

La primera propuesta cromática utilizaba gris y azul. El usuario pidió la paleta de SilentForce durante el trabajo: se adopta negro/gris/rojo real de su CSS, con adaptación clara. Esta elección explícita prevalece sobre el detector SD2; se añade una excepción documentada, no se elimina la regla del scanner.

## Resultado

- Resumen compacto; cabeceras por subred y fichas con IP/puerto encima de la captura.
- Contraste verificado en 60 pares, por tema y uso. Enlaces rojos más claros en oscuro para superar 4.5:1.
- Se conserva el tema persistente, el historial, los filtros, las descargas, la cola y las opciones del motor.
- Revisadas las vistas de galería y tabla, el formulario, el detalle de imagen, búsqueda y persistencia de tema. Revisión visual a ancho original, 1440 px y 390 px; sin desbordamiento horizontal de la página en móvil.
- Las 30 pruebas Python pasan y el JS pasa la comprobación sintáctica.
- Scanner final sin hallazgos, con dos excepciones explícitas: K7 (foco externo comprobado) y SD2 (paleta solicitada por el usuario). No se usa el scanner como sustituto de la revisión visual.

## Juicio final

Los cambios sirven a una tarea concreta: comparar servicios por subred. La tipografía, el orden y el espacio favorecen las IP y las imágenes. Claro, oscuro, tabla y diálogos comparten tokens; el negro/rojo responde a una referencia expresa del usuario. La silueta deja de depender de tarjetas de indicadores y pasa a depender de grupos de servicios reales.
