# Dedalo

## Función y jerarquía

Herramienta local para revisar capturas web obtenidas a partir de Nmap. La unidad de trabajo es una ejecución; dentro de ella, una subred y sus IP/puertos. La imagen de la web es el contenido principal. La marca Dedalo se acompaña del logo elegido por el usuario: un laberinto en rombo entre dos alas rojas, con fondo transparente. El original, de 1254 px, está en `design/logo.webp` y es el que muestra el README. El portal usa `dedalo/static/logo.png`, una copia de 128 px y 21 KB sacada de ese original con el decodificador de imágenes de Windows (cualquier editor que exporte PNG con transparencia sirve para regenerarla). La sirve el propio portal (sin recursos externos), mide 48 px en la columna lateral y es también el icono de la pestaña. Sus degradados y relieve se apartan del diseño plano del resto de la interfaz: es una elección expresa del usuario, como la paleta.

El historial permanece en una columna lateral en escritorio y una fila desplazable en móvil. El encabezado identifica la ejecución. Los recuentos son una franja compacta, seguidos por las acciones, las vistas y los filtros. Cada subred abre un grupo de capturas. IP y protocolo aparecen encima de la imagen; título, URL y estado HTTP debajo. Una imagen sin título no se presenta como pendiente.

## Paleta de SilentForce

Paleta pedida expresamente por el usuario, extraída de https://silentforce.io/style.css el 25/09/2026. No se copia su estructura de página comercial. Los estados conservan un texto descriptivo además del color.

| Rol | Claro | Oscuro |
| --- | --- | --- |
| Fondo | #f0f0f0 | #0a0a0a |
| Superficie | #ffffff | #141414 |
| Agrupación | #e5e5e5 | #1a1a1a |
| Texto | #141414 | #f0f0f0 |
| Texto secundario | #555555 | #b0b0b0 |
| Acción de marca | #b22d37 | #e63946 |
| Enlace | #b22d37 | #ff4d5a |
| Selección | #f8e3e5 | #35191c |

El rojo claro de la marca sirve como enlace en oscuro para mantener el contraste. Los botones oscuros usan texto casi negro sobre rojo; los claros, blanco sobre rojo oscuro. Éxito, atención y error tienen tokens independientes, reservados para estados reales. El contraste se verifica con `python design/check-contrast.py`: 4.5:1 para texto normal y 3:1 para iconos y foco.

## Tipografía

- Tahoma para controles y lectura: disponible en el Windows de uso, formas compactas y claras. Verdana como alternativa.
- Bahnschrift local para título y recuentos, con Tahoma como alternativa. Fuente comprobada en `C:/Windows/Fonts/bahnschrift.ttf`; no se descargan fuentes externas.
- Consolas exclusivamente para IP, CIDR, URLs, código y registros, con Liberation Mono como alternativa.
- Texto de interfaz 12–14 px; IP 17 px; títulos 27–30 px. Sin etiquetas decorativas en mayúsculas espaciadas.

## Componentes y estados

- Bordes de 3–4 px de radio en controles e imágenes; 8 px en diálogos. Sin sombras de tarjetas ni fondos borrosos.
- Las capturas no se envuelven en otra tarjeta: imagen y ficha comparten alineación.
- Los errores de captura ocupan el espacio de la imagen y explican el motivo.
- Foco visible de 2 px. Los controles de archivos tienen foco en el contenedor. Los diálogos conservan cierre por Escape y restauración del foco.
- Los temas se guardan en `dedalo-theme`; se recupera la preferencia anterior de `prometheus-theme` si todavía no existe una válida. Sin elección previa, se respeta el sistema. La paleta no altera las imágenes capturadas.
- Rejilla de capturas adaptable. A 760 px o menos, historial horizontal y filtros en dos columnas; búsqueda y estado ocupan la fila completa. Las tablas tienen desplazamiento propio.
- Transiciones de estado cortas, sin zoom de imágenes ni animaciones decorativas; se respeta movimiento reducido.

## Validación y mantenimiento

La implementación está en `dedalo/static/`. API, rutas, archivos históricos y ejecución del motor mantienen su contrato. El registro de aplicación de la skill está en `design/AUDIT.md`. Mantener estos tokens también en las vistas Objetivos, Registro y los dos diálogos.
