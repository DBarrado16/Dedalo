# Autonomía HTTP/HTTPS en la captura · plan

> **Para agentes:** ejecutar con superpowers:subagent-driven-development, tarea a tarea, en TDD.

**Objetivo:** si una URL falla con un error típico de esquema equivocado, la captura prueba una vez el otro esquema en el mismo IP:puerto y se queda con el que responde.

**Arquitectura:** una pasada nueva, la «de esquema», entre la primera pasada y el reintento con el otro motor, siguiendo el mismo patrón (fichero de URL y log propios). El informe busca la captura con el esquema original y, si no la hay, con el otro.

**Diseño aprobado por Doro (chat del 2026-10-20):** el otro esquema solo se prueba si falla el primero; nunca los dos siempre.

## Restricciones globales
- Solo librería estándar. Comentarios y textos en español. El checkout es CRLF: editar con la herramienta de edición, nunca con `sed -i`.
- Alcance (docs/CONTRATOS.md §0.3): la pasada de esquema solo usa IP:puerto que ya son objetivo (ya filtrados por alcance en `cli.plan`). Las URL candidatas se derivan de la lista de objetivos, nunca del log.
- Sin opción nueva: la pasada se desactiva con el mismo interruptor del reintento (`--sin-reintento` / «reintentar» en el portal).
- No abrir `portal_datos/`, `salida/`, `pruebas_locales/`, `RESUMEN.md`, `*.sqlite3` ni capturas. Probar solo con `tests/` y `ejemplos/`.
- `python -m unittest discover -s tests` termina en `OK`.

## Review Focus
1. Puertos estándar: `http://10.0.0.1/` debe pasar a `https://10.0.0.1:80/`, no a `https://10.0.0.1/` (que sería el 443, otro puerto).
2. IPv6: `http://[fe80::1]:8080/` debe pasar a `https://[fe80::1]:8080/`.
3. Un error en el log para una URL que no es objetivo nunca genera candidata (alcance).
4. `ERR_CONNECTION_REFUSED`, `ERR_CONNECTION_TIMED_OUT`, `ERR_ADDRESS_UNREACHABLE` y `ERR_NETWORK_ACCESS_DENIED` no disparan la pasada.
5. Una URL que la pasada de esquema captura pero se queda sin imagen entra en el reintento con el otro motor.

---

### Tarea 1: helpers en gowitness.py y fila del informe

**Ficheros:** `dedalo/gowitness.py`, `dedalo/report.py:69-97`, tests en `tests/test_dedalo.py` (junto a los de `read_errors` y `retry_candidates`).

**Produce:**
- Constantes `SCHEME_URLS = "urls-esquema.txt"`, `SCHEME_LOG = "gowitness-esquema.log"` y `SCHEME_ERRORS = ("ERR_EMPTY_RESPONSE", "ERR_INVALID_HTTP_RESPONSE", "ERR_CONNECTION_RESET", "ERR_CONNECTION_CLOSED", "ERR_SSL_PROTOCOL_ERROR", "ERR_SSL_VERSION_OR_CIPHER_MISMATCH")`.
- `other_scheme(url: str) -> str`: cambia http↔https conservando host y puerto, y escribe el puerto explícito si era el estándar del esquema original (Review Focus 1 y 2).
- `scheme_candidates(directory: Path, urls: list[str]) -> list[str]`: para cada URL de `urls` sin fila en la base cuyo error en `LOG_NAME` es `failed to witness target` y contiene alguno de `SCHEME_ERRORS`, devuelve `other_scheme(url)`, en el orden de `urls`.
- `retry_candidates` lee los fallos `GRAB_FAILED` de `LOG_NAME` y de `SCHEME_LOG`.
- `read_errors` lee también `SCHEME_LOG`, con el prefijo «Ni http ni https respondieron: ». El orden es `LOG_NAME`, `SCHEME_LOG`, `RETRY_LOG`.
- `report.collect_group`: si no hay resultado para `target["url"]`, busca `other_scheme(target["url"])`. Si lo encuentra, la fila lleva `"url"` = esa URL y estado `capturada`. Si no, el error es `errors.get(otra) or errors.get(original) or ...`. `sin_captura.txt` sigue listando la URL original.

**Pasos (TDD):**
- [ ] Tests que fallan:
  - `test_other_scheme`: `http://10.0.0.1/`→`https://10.0.0.1:80/`, `https://10.0.0.1/`→`http://10.0.0.1:443/`, `http://10.0.0.1:8443/`→`https://10.0.0.1:8443/`, `http://[fe80::1]:8080/`→`https://[fe80::1]:8080/`.
  - `test_scheme_candidates`: un log con `ERR_EMPTY_RESPONSE` en `http://10.0.0.1:8443/` y `ERR_SSL_PROTOCOL_ERROR` en `https://10.0.0.2:8080/` (las dos son objetivo), `ERR_CONNECTION_REFUSED` en `http://10.0.0.3:80/` y `ERR_EMPTY_RESPONSE` en `http://10.9.9.9:8443/` (no es objetivo) devuelve exactamente `["https://10.0.0.1:8443/", "http://10.0.0.2:8080/"]`.
  - `test_collect_group_usa_el_otro_esquema`: el objetivo `http://10.0.0.1:8443/` y la base con fila `https://10.0.0.1:8443/` dan una fila `capturada` con esa URL.
  - `test_collect_group_ni_http_ni_https`: un error en los dos logs da una fila cuyo `error` empieza por «Ni http ni https respondieron: ».
  - `test_retry_incluye_pasada_de_esquema`: un `could not grab screenshot` en `SCHEME_LOG` para la URL alternativa la devuelve `retry_candidates(directory, urls + alternativas)`.
- [ ] Ejecutar: fallan.
- [ ] Implementar.
- [ ] `python -m unittest discover -s tests` → `OK`.
- [ ] Commit.

### Tarea 2: pasada de esquema en `cli.capture` y docs

**Ficheros:** `dedalo/cli.py:197-212`, `README.md`, `docs/CONTRATOS.md` §0.3 y, si algún texto del portal describe «reintentar», `dedalo/static/`. Tests en `tests/test_dedalo.py`, junto al test de captura que parchea `scan_subnet` (cerca de la línea 149).

**Consume:** lo que produce la Tarea 1.

**Comportamiento:** tras la primera pasada, si `opts["retry"]` está activo y no hay parada, se llama a `alternativas = gowitness.scheme_candidates(directory, urls)`. Si hay alguna, se imprime `  N sin respuesta; se prueban con el otro esquema (http/https)...` y se ejecuta `scan_subnet(binary, directory, alternativas, opts, gowitness.SCHEME_URLS, gowitness.SCHEME_LOG)`; si falla (`OSError`, `CalledProcessError`), se avisa por stderr y se sigue, igual que el reintento. Después, `retry_candidates(directory, urls + alternativas)`.

**Pasos (TDD):**
- [ ] Tests que fallan:
  - `test_capture_prueba_el_otro_esquema`: con `scan_subnet` simulado, la primera llamada escribe en el log un `ERR_EMPTY_RESPONSE` para un objetivo `http://…:8443/`. La segunda llamada recibe `["https://…:8443/"]` con `SCHEME_URLS` y `SCHEME_LOG`.
  - `test_capture_sin_reintento_no_prueba_esquema`: con `sin_reintento`, `scan_subnet` se llama una sola vez.
- [ ] Ejecutar: fallan.
- [ ] Implementar.
- [ ] Docs: en README, la captura prueba el otro esquema si falla el primero, cuándo y qué ficheros deja; en CONTRATOS §0.3, que la pasada solo usa IP:puerto de objetivos ya en alcance.
- [ ] `python -m unittest discover -s tests` → `OK`.
- [ ] Commit.
