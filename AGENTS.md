# Dédalo · guía para agentes

Portal local que importa resultados de Nmap a un inventario por auditoría y hace capturas web con gowitness, solo de lo que está en **alcance**. Python ≥ 3.12; paquete y comando `dedalo` (`python -m dedalo`).

## Antes de tocar
- **Red o alcance** (capturas, DNS, cualquier conexión): `docs/CONTRATOS.md` §0.3.
- **Base de datos** (`dedalo/db.py`, `dedalo/auditoria.py`, lo que se guarda): `docs/MODELO_DATOS.md`.
- **Interfaz** (`dedalo/static/`): `DESIGN.md`.
- **Comandos y límites conocidos** (motor del navegador, Windows, Kali, VPN): `README.md`.

## Reglas del proyecto
- **Alcance.** Solo se conecta con IP en alcance, comprobado justo antes de conectar, no solo al planificar. Importar guarda todo, marcado con su situación; la exclusión siempre gana. El código nuevo que conecte pasa por esa comprobación y llega con un test que lo demuestra.
- **Librería estándar.** Sin paquetes de pip: lo que en otro proyecto sería una dependencia se escribe a mano (por ejemplo, la consulta DNS de `dedalo/descubrimiento.py`).
- **Migraciones.** Un cambio de esquema es una migración nueva y numerada en `dedalo/db.py`. Las ya publicadas quedan como están: las bases de los usuarios ya las aplicaron.
- **Portal local de un usuario.** Escucha en `127.0.0.1` y verifica `Origin` y la cabecera `X-Dedalo-Token`; sin cuentas ni publicación en red.
- **gowitness verificado.** Binario externo lanzado sin shell, con `VERSION` y las huellas SHA-256 de `RELEASES` fijadas en `dedalo/gowitness.py`. Cambiar de versión es actualizar ambas y repetir `python -m tests.integration_local`.
- **Contrato = código.** Si el código contradice `docs/CONTRATOS.md`, se corrige uno de los dos en el mismo cambio.

## Datos reales
Para probar, usa `ejemplos/` y `tests/`. `portal_datos/`, `salida/`, `pruebas_locales/`, `RESUMEN.md`, las bases `*.sqlite3` y las capturas guardan resultados de ejecuciones, también de redes reales de clientes: no se abren, copian ni suben, ni se pasan a un subagente.

## Pruebas
- `python -m unittest discover -s tests` termina en `OK`, sin red ni navegador. Las líneas `Error del portal: …` son salida esperada.
- Si tocas capturas, gowitness o la API del portal, pasa también las de integración (README, «Pruebas»; necesitan gowitness y navegador).

## Cómo trabajamos
- Doro decide qué se hace. El agente principal escribe el plan, reparte el trabajo entre subagentes y revisa su salida antes de darla por buena.
- Al delegar, copia en el prompt del subagente las reglas que afectan a su tarea (alcance, datos reales): los subagentes Explore y Plan no cargan este fichero.
- Cada cambio va en una rama y llega a `main` tras la revisión de Doro.
- Skills de Claude Code (si falta alguna, avisa en vez de improvisar):
  - Feature: brainstorming → writing-plans → test-driven-development → subagentes en worktrees → requesting-code-review (superpowers).
  - Bug: systematic-debugging; el arreglo ataca la causa raíz y llega con un test que la reproduce.
  - Código terminado: `/simplify` → `/code-review`; si toca entrada de usuario, red, ficheros o dependencias, también las de Trail of Bits que apliquen (differential-review, insecure-defaults, sharp-edges, static-analysis, supply-chain-risk-auditor).
  - Interfaz: frontend-design → avoid-ai-design → webapp-testing, y `python design/check-contrast.py` tras tocar colores.
  - Siempre: karpathy-guidelines.

## Trampas
- En Windows el checkout es CRLF: edita con la herramienta de edición o en binario; `sed -i` lo pasa a LF y ensucia el diff.
- `design/audit-before.json` conserva el nombre antiguo `nmapshot` por ser una instantánea histórica, y `dedalo/static/app.js` lee `prometheus-theme` para migrar el tema elegido en la etapa anterior. Los dos se quedan así.

## Fuera del repo
La ficha, las decisiones y el roadmap del proyecto viven en el Brain de Doro. Si existe `CLAUDE.local.md`, ahí está dónde y qué actualizar al terminar cada tarea; si no, al terminar resume a Doro qué ha cambiado para que lo registre.
