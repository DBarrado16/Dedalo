# Catálogo de credenciales compartido — plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Que el equipo haga crecer el catálogo de credenciales de fábrica desde el portal: un botón «Añadir al catálogo» en cada servicio del inventario escribe una entrada nueva en `dedalo/datos/credenciales.json`, que se recarga al momento; el fichero se comparte por el repo (privado en una organización, más adelante).

**Architecture:** Sin tabla ni migración nuevas: se sigue usando `credencial_catalogo` y el volcado por huella de `catalogo.py`. Se añade `catalogo.agregar(ruta, entrada)` que mete/fusiona una entrada en el JSON y lo reescribe de forma atómica; el portal expone una ruta `POST /api/catalogo` que valida, escribe y recarga. La ruta del catálogo es configurable (`--catalogo`) para poder apuntar al repo compartido; por defecto, el fichero del propio repo.

**Tech Stack:** Python ≥ 3.12, solo librería estándar (`json`, `pathlib`, `os`, `sqlite3`). Frontend en `dedalo/static/` (HTML/CSS/JS a mano).

**Spec:** `docs/superpowers/specs/2026-10-16-catalogo-credenciales-compartido-design.md`

## Global Constraints

- Python ≥ 3.12; **solo librería estándar**, sin pip.
- **Sin migración ni columnas nuevas:** la tabla `credencial_catalogo` se queda como está; la fuente de verdad es `credenciales.json`.
- `servicio` ∈ {`http-basic`, `http-form`, `ftp`} (lo que Dédalo sabe probar); `receta` solo en `http-form`.
- **Solo credenciales de fábrica** en el catálogo compartido; un secreto real de cliente **nunca** entra (anti-goal). El portal avisa antes de guardar.
- Escribir el catálogo es **atómico** (fichero temporal + reemplazo) y **preserva la estructura** del JSON (`version`, `nota`, `entradas`), con `indent=2`, `ensure_ascii=False` (diffs de git limpios).
- Portal local en `127.0.0.1` con `Origin` y `X-Dedalo-Token` en lo que muta.
- CRLF en Windows: editar con la herramienta de edición, nunca `sed -i`.
- `python -m unittest discover -s tests` en OK, sin red ni navegador. **Los tests nunca escriben en el `credenciales.json` real**: usan un catálogo temporal.
- Commits terminan con `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

## Review Focus

- **Escritura atómica/estructura:** un guardado a medias o con datos raros no debe corromper `credenciales.json`; la estructura (`version`, `nota`, `entradas`) se conserva. → test en Task 1.
- **Duplicados:** añadir una credencial que ya está no debe duplicar entrada ni fila. → test en Task 1.
- **Entrada inválida:** servicio fuera de los tres, usuario/clave vacíos, o receta mal formada → se rechaza y **no se escribe**. → test en Task 1 y Task 2.
- **Aislamiento en tests:** el portal escribe en la ruta **configurada**, nunca en el `credenciales.json` del paquete. → test en Task 2 usa una copia temporal.
- **Recarga:** tras añadir, la credencial nueva queda **usable** (vuelta a volcar a la tabla). → test en Task 2.

---

### Task 1: `catalogo.agregar` — meter/fusionar una entrada en el JSON, atómico

**Files:**
- Modify: `dedalo/catalogo.py`
- Test: `tests/test_catalogo.py`

**Interfaces:**
- Produces:
  - `agregar(ruta: Path, entrada: dict) -> None` — valida `entrada` y la añade a `credenciales.json`. Si ya existe una entrada con el mismo `(fabricante, producto, version, servicio)`, **añade las credenciales** `{usuario, clave}` que falten a su lista; si no, crea una entrada nueva. Reescribe el fichero de forma atómica (temporal en el mismo directorio + `os.replace`), con `indent=2`, `ensure_ascii=False`. Lanza `ValueError` si `entrada` no es válida (producto vacío, `servicio` fuera de `SERVICIOS`, sin credenciales con `usuario`/`clave` de texto, o `receta` presente sin ser un dict).

- [ ] **Step 1: Write the failing tests** en `tests/test_catalogo.py` (usa un catálogo temporal con `tempfile`; `entrada_ftp = {"fabricante":"ACME","producto":"vsftpd","version":"","servicio":"ftp","credenciales":[{"usuario":"ftp","clave":"ftp"}],"fuente":"manual"}`):

```python
def test_agregar_crea_una_entrada_nueva(self):
    catalogo.agregar(self.ruta, self.entrada_ftp)
    datos = json.loads(self.ruta.read_text("utf-8"))
    self.assertEqual(datos["entradas"][-1]["producto"], "vsftpd")
    self.assertEqual(datos["entradas"][-1]["credenciales"], [{"usuario": "ftp", "clave": "ftp"}])

def test_agregar_fusiona_en_la_entrada_existente_sin_duplicar(self):
    catalogo.agregar(self.ruta, self.entrada_ftp)
    catalogo.agregar(self.ruta, {**self.entrada_ftp, "credenciales": [{"usuario": "ftp", "clave": "ftp"}, {"usuario": "admin", "clave": "admin"}]})
    entradas = [e for e in json.loads(self.ruta.read_text("utf-8"))["entradas"] if e["producto"] == "vsftpd"]
    self.assertEqual(len(entradas), 1)
    self.assertEqual(entradas[0]["credenciales"], [{"usuario": "ftp", "clave": "ftp"}, {"usuario": "admin", "clave": "admin"}])

def test_agregar_conserva_la_estructura_del_fichero(self):
    original = json.loads(self.ruta.read_text("utf-8"))
    catalogo.agregar(self.ruta, self.entrada_ftp)
    datos = json.loads(self.ruta.read_text("utf-8"))
    self.assertEqual(datos["version"], original["version"])  # version/nota intactas
    self.assertEqual(len(datos["entradas"]), len(original["entradas"]) + 1)

def test_agregar_rechaza_lo_invalido_y_no_escribe(self):
    antes = self.ruta.read_text("utf-8")
    for mala in ({**self.entrada_ftp, "servicio": "ssh"}, {**self.entrada_ftp, "producto": ""},
                 {**self.entrada_ftp, "credenciales": [{"usuario": "x"}]}):
        with self.assertRaises(ValueError):
            catalogo.agregar(self.ruta, mala)
    self.assertEqual(self.ruta.read_text("utf-8"), antes)  # el fichero no cambió
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m unittest tests.test_catalogo -v`
Expected: FAIL (`agregar` no existe).

- [ ] **Step 3: Implement `agregar(ruta: Path, entrada: dict) -> None` in `dedalo/catalogo.py`**

Valida con una función interna que reutilice `SERVICIOS` (y la misma comprobación de `usuario`/`clave` de texto que `_filas`). Lee el JSON, fusiona por `(fabricante, producto, version, servicio)` añadiendo solo las credenciales que no estén ya, y reescribe con fichero temporal en el mismo directorio + `os.replace`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_catalogo -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add dedalo/catalogo.py tests/test_catalogo.py
git commit -m "Add catalogo.agregar: append or merge a catalog entry atomically

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Portal — ruta `POST /api/catalogo`, ruta del catálogo configurable

**Files:**
- Modify: `dedalo/web.py`, `dedalo/cli.py`
- Test: `tests/test_web.py`

**Interfaces:**
- Consumes: `catalogo.agregar` (Task 1), `catalogo.cargar`, `catalogo.RUTA`.
- Produces:
  - `PortalStore.__init__(..., catalogo=catalogo.RUTA)` guarda `self.catalogo_ruta`; `_load` usa `catalogo.cargar(con, self.catalogo_ruta)`.
  - `PortalStore.add_credential(payload: dict) -> dict` — arma la `entrada` desde `payload` (`fabricante`, `producto`, `version`, `servicio`, `receta` opcional, `fuente`, y `credenciales=[{usuario, clave}]`), llama `catalogo.agregar(self.catalogo_ruta, entrada)`, recarga con `catalogo.cargar`, y devuelve `{"anadida": True}`. `ValueError` → 400.
  - Ruta `POST /api/catalogo` (token + mismo origen) → `self.json(store.add_credential(payload))`.
  - `cli.py`: `--catalogo` (ruta al fichero del catálogo; por defecto el del repo). `serve_portal` pasa `catalogo=args.catalogo or catalogo.RUTA`.

- [ ] **Step 1: Write the failing tests** en `tests/test_web.py` (el test apunta el store a un catálogo temporal copiado de la semilla, para no tocar el real; usa `self.store.catalogo_ruta = tmp` y `shutil.copy`):

```python
def catalogo_temporal(self):
    tmp = Path(self.temp.name) / "credenciales.json"
    shutil.copy(web.catalogo.RUTA, tmp)
    self.store.catalogo_ruta = tmp
    return tmp

def test_catalogo_needs_the_token_and_same_origin(self):
    self.create()
    for headers in ({"X-Dedalo-Token": "wrong"}, {"Origin": "https://example.org"}):
        self.assertEqual(self.request("/api/catalogo", {"producto": "x", "servicio": "ftp",
            "credenciales": [{"usuario": "a", "clave": "b"}]}, headers)[0], 403)

def test_catalogo_adds_a_factory_credential_and_reloads(self):
    tmp = self.catalogo_temporal()
    body = {"fabricante": "ACME", "producto": "RouterOS", "version": "", "servicio": "ftp",
            "fuente": "manual del fabricante", "credenciales": [{"usuario": "admin", "clave": "admin"}]}
    self.assertEqual(self.request("/api/catalogo", body)[0], 200)
    self.assertIn("RouterOS", tmp.read_text("utf-8"))  # escrito en el fichero
    with closing(self.store.database()) as con:
        self.assertTrue(any(e["producto"] == "RouterOS" for e in web.catalogo.entradas(con)))  # recargado

def test_catalogo_rejects_an_invalid_entry(self):
    self.catalogo_temporal()
    self.assertEqual(self.request("/api/catalogo", {"producto": "x", "servicio": "ssh",
        "credenciales": [{"usuario": "a", "clave": "b"}]})[0], 400)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m unittest tests.test_web -v -k catalogo`
Expected: FAIL (ni ruta ni método existen).

- [ ] **Step 3: Implement** en `dedalo/web.py` y `dedalo/cli.py` según el bloque Interfaces. En `cli.py`, junto a `--dns-dominio`, añadir `portal.add_argument("--catalogo", type=Path, help="Fichero del catálogo de credenciales compartido; por defecto el del repo")`; `serve_portal` pasa `catalogo=args.catalogo or catalogo.RUTA`. Ajustar el `argparse.Namespace` a mano de `test_second_portal_cannot_share_the_port` para incluir `catalogo=None`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_web -v -k catalogo`
Expected: PASS.

- [ ] **Step 5: Run the whole suite and commit**

Run: `python -m unittest discover -s tests`
Expected: OK.

```bash
git add dedalo/web.py dedalo/cli.py tests/test_web.py
git commit -m "Add POST /api/catalogo to grow the catalog from the portal

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Botón «Añadir al catálogo» y su formulario

**Files:**
- Modify: `dedalo/static/index.html`, `dedalo/static/app.js`, `dedalo/static/style.css`
- Test: `tests/test_web.py` (cableado de la página)

**Interfaces:**
- Consumes: `POST /api/catalogo` (Task 2); el inventario (`inventory.activos[].servicios[]` con `producto`, `version`, `servicio`, `tunel`).

- [ ] **Step 1: Write the failing test** en `tests/test_web.py`:

```python
def test_page_has_the_add_to_catalog_dialog(self):
    page, script = self.request("/")[1], self.request("/app.js")[1]
    for needle in (b'id="catalog-dialog"', b'id="catalog-form"', b'data-add-catalog', b'id="catalog-factory"'):
        self.assertIn(needle, page) if needle != b'data-add-catalog' else self.assertIn(needle, script)
    self.assertIn(b'request("/api/catalogo"', script)
    self.assertIn("de fábrica".encode(), page)  # el aviso de gobernanza
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_web -v -k add_to_catalog`
Expected: FAIL.

- [ ] **Step 3: Implement.**
  - `index.html`: un `<dialog id="catalog-dialog">` con `<form id="catalog-form">` y campos `fabricante`, `producto`, `version`, un `<select>` de `servicio` (http-basic/http-form/ftp), `usuario`, `clave`, `fuente`, los campos de `receta` (ruta, campo_usuario, campo_clave, señal) **ocultos salvo http-form**, y una casilla **obligatoria** `id="catalog-factory"` con el texto de que es una credencial **de fábrica**, no un secreto de cliente. Calcar la forma del `#audit-dialog`.
  - `app.js`: en `renderInventory`, en los servicios aptos (web → http-basic/http-form; `servicio=="ftp"` → ftp) añadir un botón `data-add-catalog` que lleve `producto`/`version`/tipo adivinado; un manejador abre el diálogo con esos campos **rellenos**; al enviar, reúne el formulario y llama `await request("/api/catalogo", cuerpo)`, avisa del resultado y recarga el inventario. La casilla de fábrica debe estar marcada para poder enviar.
  - `style.css`: reutilizar las clases de formulario/diálogo existentes (sin colores nuevos).

- [ ] **Step 4: Run tests and the contrast check**

Run: `python -m unittest tests.test_web -v -k add_to_catalog`
Expected: PASS.
Run: `python design/check-contrast.py`
Expected: sin fallos.

- [ ] **Step 5: Commit**

```bash
git add dedalo/static/index.html dedalo/static/app.js dedalo/static/style.css tests/test_web.py
git commit -m "Add the Añadir al catálogo button and form

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Documentación

**Files:**
- Modify: `docs/CONTRATOS.md`, `docs/MODELO_DATOS.md`, `README.md`

**Interfaces:**
- Consumes: todo lo anterior.

- [ ] **Step 1: Documentación.**
  - `README.md` (sección «Credenciales por defecto»): que el catálogo se puede **ampliar desde el portal** (botón «Añadir al catálogo»), que es **compartido por el repo** (privado en una organización, más adelante), la regla de **solo fábrica** (secretos de cliente no), y el `--catalogo` para apuntar a un fichero compartido.
  - `docs/MODELO_DATOS.md`: una línea en lo del catálogo, diciendo que ahora también crece desde el portal (escribe en `credenciales.json`, se recarga por huella); sigue sin migración.
  - `docs/CONTRATOS.md`: si procede, una nota en §0.4 de que el catálogo es editable desde el portal con la regla de solo-fábrica.

- [ ] **Step 2: Run the whole suite and commit**

Run: `python -m unittest discover -s tests`
Expected: OK.

```bash
git add docs/CONTRATOS.md docs/MODELO_DATOS.md README.md
git commit -m "Document growing the shared credential catalog from the portal

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Cierre

- `/simplify` → `/code-review` + Trail of Bits que aplican por tocar entrada de usuario y ficheros: `differential-review`, `sharp-edges`.
- Prueba real: Doro añade una credencial de fábrica desde el portal y comprueba que queda en `credenciales.json` y que se propone en el servicio.
- Al terminar: ficha, nota `catalogo-credenciales-compartido` y `04-IA/registro.md` del Brain al día; lista a Doro para su «ok»; recordar `git push nas`.
