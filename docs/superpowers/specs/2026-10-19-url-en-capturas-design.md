# Dédalo · URL quemada en las capturas, como un navegador — diseño

- Fecha: 2026-10-19
- Estado: borrador de diseño (brainstorming + spike aprobado por Doro); pendiente de su ok antes de planificar
- Relacionado: tarea `url-en-capturas` (1ª de las mejoras del 2026-10-16, orden 4)
- Contrato: `docs/CONTRATOS.md` (capturas), `dedalo/gowitness.py`, `DESIGN.md`

## Objetivo y porqué

Las capturas de gowitness salen **sin la URL** (Chrome headless no dibuja la barra de direcciones). Para los **informes**, Doro quiere que cada imagen lleve su URL **quemada dentro** —como si fuera una captura de su navegador normal— para poder pegarla suelta y que se vea de qué objetivo es, sin depender del texto que la rodea en el portal.

Validado con un spike: una **barra estilo Chrome/Brave de Windows** (← → ⟳, candado + URL, menú ⋮) encima de la captura, en una **imagen plana**. Aprobado el aspecto.

## Qué se decidió (con Doro)

1. **Quemada en la imagen**, no un overlay del portal: el fichero descargado/exportado tiene que llevar la URL dentro.
2. **Solo librería estándar** (regla del proyecto): nada de Pillow/pip. Se compone con **Chrome**, que ya usamos.
3. **Barra estilo navegador de Windows** (Chromium): flechas ← → ⟳, candado + URL, menú ⋮. Nada de los puntos de Mac.

## Cómo (enfoque: recomponer con Chrome, dos pasadas)

Por qué dos pasadas y no un iframe: meter la **página real** en un `<iframe>` se rompe en cuanto el objetivo manda `X-Frame-Options`/CSP (panales de admin, lo normal). Embeber la **imagen ya capturada** nunca falla. Así que:

1. gowitness captura el objetivo como ahora → imagen en `SHOTS_DIR` (gowitness guarda el mapeo URL→fichero en su SQLite, que Dédalo ya lee).
2. Por cada imagen, Dédalo:
   - lee el **ancho y alto reales** de la imagen de su cabecera (stdlib: IHDR de PNG / marcadores SOFn de JPEG; sin librerías),
   - escribe un HTML envoltorio: la **barra** (HTML/CSS, con la URL real del objetivo) + la imagen embebida como `data:` URI,
   - lo fotografía con **Chrome headless** (`--headless=new --screenshot=… --window-size=ancho,barra+alto --hide-scrollbars`) → **PNG plano** con la URL quemada,
   - guarda esa imagen como la captura de ese objetivo.
3. El resto de Dédalo (galería, ampliar, descargar, ZIP, «Copiar para OneNote») sirve esa imagen tal cual.

La URL que va en la barra es la que Dédalo ya conoce del objetivo (esquema + ip:puerto + ruta).

## Decisiones de la opción (mis calls, menores)

- **Interruptor:** opción de captura **«Barra de URL en las capturas»**, **activada por defecto** (el objetivo es el informe). Apagada → se guarda la captura pelada como hoy. Va en las opciones de captura del portal y como flag del comando `capturar` de consola.
- **Formato:** la imagen compuesta es **PNG** (Chrome `--screenshot` solo saca PNG). La captura de ese objetivo pasa a PNG; la galería/descarga/ZIP la sirven igual (ya manejan jpeg y png).
- **Chrome:** se reutiliza el que ya detecta Dédalo (`gowitness.find_chrome` / `--chrome`). Cuesta **una pasada de Chrome más por objetivo capturado**; solo se hace sobre los que tienen imagen.
- **Barra:** tokens de color propios (sin romper `DESIGN.md`); clara, neutra, como la del spike.

## No-goals / anti-goals

- No es un overlay solo en el portal (tiene que ir en el fichero).
- No se mete Pillow ni ninguna dependencia de pip.
- No se toca gowitness ni su forma de capturar; esto es un paso **posterior**.
- No se compone nada para objetivos **sin imagen** (fallidos): se quedan como están.
- No se busca una réplica pixel-perfecta del navegador; basta con que lea «captura de navegador con su URL».

## Restricciones

- Solo librería estándar; portal local `127.0.0.1` + `Origin`/`X-Dedalo-Token`.
- Alcance intacto: esto no conecta con nada nuevo, solo recompone imágenes ya capturadas.
- TDD sin red ni navegador real (Chrome y la composición se simulan en los tests; una integración aparte, con Chrome, como las que ya hay).
- `/simplify` → `/code-review` + Trail of Bits que apliquen (lanza un binario externo con rutas: sharp-edges, insecure-defaults).

## Lo que queda al constructor

- Dónde exactamente se engancha el paso de composición en el flujo de captura (tras `scan_subnet`, recorriendo el mapeo URL→imagen que Dédalo ya lee) y cómo sustituye/guarda la imagen compuesta.
- El parseo de dimensiones de PNG/JPEG a mano (stdlib).
- La plantilla HTML/CSS exacta de la barra (a partir del spike).

## Riesgos a vigilar (para el plan)

- **Capturas de página completa** (muy altas): el `--window-size` de Chrome tiene que abarcar todo el alto; comprobar que no se recorta y, si hay tope, acotarlo.
- **Edge/Brave como Chrome:** mismo Chromium, debería ir; probar en la integración.
- **Coste:** una pasada de Chrome por objetivo; si molesta, el interruptor lo apaga.

## Preguntas abiertas (a cerrar en el plan)

- ¿La barra lleva **solo la URL**, o también el **título de la página** o el **código de estado** (200, 302…)? El spike va solo con la URL; se puede añadir. [menor, a gusto de Doro]
- ¿Interruptor por **captura** (opciones) o también por **ficha** (recordado)? Propuesta: por captura, por defecto activado. [menor]
