# Dédalo · Catálogo de credenciales compartido por el equipo — diseño

- Fecha: 2026-10-16
- Estado: borrador de diseño (brainstorming con Doro); pendiente de su ok antes de planificar
- Relacionado: tarea `catalogo-credenciales-compartido`, se apoya en [[credenciales-por-defecto]] (bloque 6, hecho)
- Contrato: `docs/CONTRATOS.md` §0.4 (tipo `credenciales`), modelo `docs/MODELO_DATOS.md`

## Objetivo y porqué

Dédalo acabará siendo una herramienta **de equipo**. Hoy, cuando alguien necesita las credenciales de fábrica de un aparato (ve un panel, mira la versión, busca el manual en internet y saca las claves), ese trabajo se queda **en su cabeza o suelto en OneNote**, y el siguiente que ve el mismo panel lo repite. La idea es que el catálogo de credenciales por defecto sea la **memoria compartida del equipo**: se investiga **una vez**, se captura, y todos lo reutilizan.

Lo importante no es crear la tabla (ya existe: `credencial_catalogo`, bloque 6), sino **(1)** que el catálogo se **comparta** y **(2)** que **añadir** sea fácil desde el portal.

## Qué se decidió (con Doro)

1. **La tabla se queda como está.** Mismo esquema `credencial_catalogo` (fabricante, producto, versión, servicio ∈ {http-basic, http-form, ftp}, usuario, clave, receta, fuente, licencia), **sin columnas nuevas ni migración**. La fuente de verdad sigue siendo `dedalo/datos/credenciales.json`, volcado a la tabla por huella SHA-256.
2. **Compartido = por el repo.** El fichero del catálogo vive en un **repo privado dentro de una organización**; el equipo se baja la última versión por git. No se monta ningún servicio central ahora.
3. **Trazabilidad.** El «de dónde salió» va en `fuente` (manual, enlace). El «quién lo metió y cuándo» lo da el **git** (autor y fecha del commit), que es lo propio de un repo. Por eso no hacen falta columnas de autor/fecha.
4. **Añadir, fácil desde el portal.** Un botón **«Añadir al catálogo»** en la pestaña de Credenciales, por servicio, con **producto y versión ya rellenos** (Dédalo los sabe del inventario); el operador pone usuario, clave y `fuente`. El portal escribe una entrada nueva en `credenciales.json` y el catálogo se recarga.
5. **Gobernanza (regla dura).** Al catálogo compartido solo van **credenciales de fábrica** (conocimiento de producto). Un **secreto real de un cliente nunca** entra ahí; se queda en su `portal_datos`. El botón de añadir avisa de esto antes de guardar.
6. **Al instante / central = futuro.** Lo ideal (nube/servidor, que aparezca al momento para todos) queda para más adelante; el acceso al catálogo se mantiene detrás de `catalogo.py` para poder apuntar a una fuente central el día de mañana **sin rehacerlo**.

## Cómo encaja (propuesta)

- **Botón «Añadir al catálogo»** disponible en **cualquier servicio del inventario** (esté probado o no; decisión de Doro, 2026-10-16), para poder capturar lo que se investiga a mano aunque no se haya lanzado una prueba. Abre un formulario con `fabricante`/`producto`/`version`/`servicio` **rellenos** desde el servicio del inventario; el operador completa `usuario`, `clave`, `fuente` y (solo `http-form`) la `receta` con valores por defecto. Un aviso recuerda que esto **se comparte con el equipo** y que no se metan secretos de cliente.
- **Guardado:** una ruta del portal (POST, con token + mismo origen) valida la entrada y la **añade a `credenciales.json`**; si una entrada con el mismo `(fabricante, producto, version, servicio)` ya existe, **añade la credencial** a su lista en vez de duplicar. Al cambiar el fichero, `catalogo.cargar` recarga por huella.
- **Dónde vive el fichero:** para el caso de equipo, Dédalo debe poder **apuntar al catálogo del repo compartido** (hoy `catalogo.RUTA` es fijo dentro del paquete). Se añade una forma de indicar la ruta del catálogo (config/flag al arrancar), con el fichero del repo como valor por defecto.
- **Trust visible (opcional):** mostrar la `fuente` del catálogo junto a la credencial propuesta/entrada, para fiarse de un vistazo.

## No-goals / anti-goals

- **No** se monta un servicio central/en vivo ahora (es el objetivo futuro).
- **No** entran secretos reales de cliente en el catálogo compartido (anti-goal: filtrar una contraseña real de un cliente a un repo del equipo).
- **No** es esto la IA que saca credenciales de internet (esa es la tarea `credenciales-ia-api`, aparte y más delicada).
- **No** se automatiza el commit/push al repo de la organización: compartir el cambio sigue siendo un paso de git normal del equipo.
- **No** se añaden columnas ni migración al catálogo.

## Restricciones

- Solo librería estándar; portal local en `127.0.0.1` con `Origin` y `X-Dedalo-Token` en lo que muta.
- Migraciones ya publicadas, intactas; esta tarea no añade ninguna.
- Servicios admitidos: los tres que Dédalo sabe probar (`http-basic`, `http-form`, `ftp`); capturar servicios no probables (SSH, etc.) queda para más adelante.
- TDD, sin red; `/simplify` → `/code-review` + Trail of Bits (toca entrada de usuario y ficheros).
- README, `docs/CONTRATOS.md` y `docs/MODELO_DATOS.md` al día (añadir de dónde sale el catálogo y cómo se amplía desde el portal).

## Lo que queda al constructor (mis decisiones, menores)

- Forma exacta del formulario y dónde cuelga el botón (por servicio en Credenciales); valores por defecto de la `receta` de `http-form`.
- Validación de la entrada antes de escribir el JSON (servicio válido, usuario/clave no vacíos, JSON de receta correcto).
- Añadir-o-fusionar por `(fabricante, producto, version, servicio)`.
- El mecanismo para apuntar a la ruta del catálogo compartido (flag/env), con el fichero del repo por defecto.

## Preguntas abiertas (a cerrar en el plan)

- ¿Mostrar la `fuente` en el portal junto a la credencial, o dejarlo solo en el catálogo? [menor]
- Dónde cuelga el botón: en **cualquier servicio del inventario**, esté probado o no (decidido con Doro, 2026-10-16).
