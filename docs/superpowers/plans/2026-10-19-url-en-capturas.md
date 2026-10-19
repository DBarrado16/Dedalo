# URL quemada en las capturas — plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Que cada captura lleve su URL quemada dentro, en una barra estilo navegador de Windows, para pegarla suelta en informes.

**Architecture:** Tras capturar con gowitness, por cada imagen se compone un HTML (barra con la URL + la imagen embebida) y se re-fotografía con **Chrome headless** (`--screenshot`) a un PNG plano que **sustituye** a la captura en su mismo fichero. Para que el nombre y el formato cuadren sin tocar la base de gowitness, con la barra activa **se fuerza el formato a PNG**. Solo librería estándar: el tamaño de la imagen se lee de la cabecera PNG (IHDR), y Chrome es el que ya detecta Dédalo.

**Tech Stack:** Python ≥ 3.12 (stdlib: `subprocess`, `struct`, `base64`, `html`, `pathlib`, `tempfile`). Chrome/Chromium/Edge (ya detectado). Frontend en `dedalo/static/`.

**Spec:** `docs/superpowers/specs/2026-10-19-url-en-capturas-design.md`

## Global Constraints

- Python ≥ 3.12; **solo librería estándar**, sin pip (nada de Pillow).
- No conecta con nada nuevo: solo recompone imágenes **ya capturadas**.
- Chrome se reutiliza (`gowitness.find_chrome` / `--chrome`); una pasada de Chrome más por imagen.
- Con la barra activa, el formato de captura es **PNG** (la imagen compuesta es PNG).
- Portal local `127.0.0.1` con `Origin`/`X-Dedalo-Token`; migraciones intactas (esta tarea no añade ninguna).
- CRLF en Windows: editar con la herramienta de edición, nunca `sed -i`.
- `python -m unittest discover -s tests` en OK, sin red ni navegador (Chrome se simula; la prueba con Chrome real va en integración).
- Commits terminan con `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

## Review Focus

- **Chrome falla al componer:** la imagen **original se conserva** y la captura no se rompe; se avisa. → test en Task 1.
- **URL con caracteres especiales de HTML** (`<`, `"`, `&`): van escapados en la barra, sin romperla ni inyectar. → test en Task 1.
- **Página completa (imágenes muy altas):** el `--window-size` abarca todo el alto leído de la cabecera. → test de dimensiones en Task 1; comprobación real en integración.
- **Barra apagada:** las capturas quedan como hoy (sin componer, sin forzar PNG). → test en Task 2.
- **Objetivo sin imagen** (captura fallida): se salta, no se compone nada. → test en Task 2.

---

### Task 1: `barra.py` — leer tamaño PNG y componer la barra con Chrome

**Files:**
- Create: `dedalo/barra.py`
- Test: `tests/test_barra.py`

**Interfaces:**
- Produces:
  - `dimensiones_png(ruta: Path) -> tuple[int, int]` — ancho y alto leídos del IHDR; `ValueError` si no es PNG.
  - `componer(imagen: Path, url: str, chrome: str, ejecutar=subprocess.run) -> None` — lee el tamaño de `imagen`, escribe un envoltorio HTML (barra estilo Chromium con `html.escape(url)` + la imagen como `data:` URI), lo fotografía con Chrome (`--headless=new --disable-gpu --hide-scrollbars --screenshot=<png> --window-size=<ancho>,<alto+ALTO_BARRA>`) y **sustituye** `imagen` por el PNG compuesto. Si Chrome falla (`CalledProcessError`/`OSError`), deja `imagen` intacta y lanza `ValueError`. `ejecutar` se inyecta para los tests.
  - `ALTO_BARRA: int` (altura de la barra en px).

- [ ] **Step 1: Write the failing tests** en `tests/test_barra.py`:

```python
import base64, struct, subprocess, zlib, unittest
from pathlib import Path
import tempfile
from dedalo import barra

def png(w, h):  # PNG mínimo válido (una fila), con IHDR correcto
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    def chunk(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    datos = zlib.compress(b"\x00" + b"\x00\x00\x00" * w)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", datos) + chunk(b"IEND", b"")

class BarraTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp()); self.img = self.dir / "shot.png"
        self.img.write_bytes(png(400, 300))

    def test_dimensiones_png_lee_ancho_y_alto(self):
        self.assertEqual(barra.dimensiones_png(self.img), (400, 300))

    def test_componer_llama_a_chrome_con_el_tamano_y_escapa_la_url(self):
        visto = {}
        def falso(cmd, **kw):
            visto["cmd"] = cmd
            wrapper = Path(cmd[-1].replace("file:///", "").replace("file://", ""))
            visto["html"] = wrapper.read_text("utf-8")
            Path(next(a.split("=", 1)[1] for a in cmd if a.startswith("--screenshot="))).write_bytes(png(400, 352))
            return subprocess.CompletedProcess(cmd, 0)
        barra.componer(self.img, 'https://10.0.0.1/a?x="y"&z=<1>', "chrome.exe", ejecutar=falso)
        self.assertIn(f"--window-size=400,{300 + barra.ALTO_BARRA}", " ".join(visto["cmd"]))
        self.assertIn("&amp;", visto["html"]); self.assertIn("&lt;1&gt;", visto["html"])  # URL escapada
        self.assertNotIn('<1>', visto["html"])
        self.assertEqual(barra.dimensiones_png(self.img), (400, 352))  # imagen sustituida por la compuesta

    def test_componer_conserva_la_imagen_si_chrome_falla(self):
        antes = self.img.read_bytes()
        def falla(cmd, **kw): raise subprocess.CalledProcessError(1, cmd)
        with self.assertRaises(ValueError):
            barra.componer(self.img, "https://10.0.0.1/", "chrome.exe", ejecutar=falla)
        self.assertEqual(self.img.read_bytes(), antes)  # intacta
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m unittest tests.test_barra -v`
Expected: FAIL (`No module named 'dedalo.barra'`).

- [ ] **Step 3: Write `dedalo/barra.py`.** `dimensiones_png`: comprueba la firma PNG y saca `struct.unpack(">II", datos[16:24])`. `componer`: escribe el envoltorio en un fichero temporal del mismo directorio (barra HTML/CSS del spike + `<img src="data:image/png;base64,…">`), llama `ejecutar([chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--screenshot={salida}", f"--window-size={w},{h+ALTO_BARRA}", wrapper.as_uri()], check=True, capture_output=True)`, y si va bien `os.replace(salida, imagen)`; si lanza, borra los temporales, deja `imagen` y relanza como `ValueError`. La plantilla de la barra es la del spike (flechas ← → ⟳, candado + URL, menú ⋮), con `html.escape(url)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_barra -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add dedalo/barra.py tests/test_barra.py
git commit -m "Compose a browser-style URL bar onto a capture with headless Chrome

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Engancharlo en el comando `capturar` (forzar PNG + componer por imagen)

**Files:**
- Modify: `dedalo/cli.py`
- Test: `tests/test_dedalo.py` (o donde se prueba `capture`; si no hay, `tests/test_cli_captura.py`)

**Interfaces:**
- Consumes: `barra.componer` (Task 1), `gowitness.read_results`, `gowitness.screenshot_path`, `gowitness.find_chrome`.
- Produces: la opción `--sin-barra-url` en el parser de `capturar` (por defecto la barra está **activa**); con la barra activa, `opts["format"]` pasa a `"png"`; tras `scan_subnet` (+ reintento) de cada subred, por cada resultado **con imagen** se llama `barra.componer(screenshot_path(directory, fila["filename"]), fila["final_url"] or url, chrome)`; los fallos de composición se avisan y no rompen la captura.

- [ ] **Step 1: Write the failing test** (parchea `gowitness.scan_subnet` y `barra.componer`; usa un nmap mínimo con un puerto web, como en los tests de captura existentes):

```python
def test_captura_con_barra_fuerza_png_y_compone_cada_imagen(self):
    # … preparar un nmap con un host:puerto web y una salida temporal …
    compuestas = []
    def scan(binary, directory, urls, opts, *a, **k):
        # simula gowitness: deja una base con una fila con imagen
        _escribe_db_y_png(directory, urls, formato=opts["format"])
    with patch("dedalo.cli.gowitness.scan_subnet", side_effect=scan), \
         patch("dedalo.cli.barra.componer", side_effect=lambda img, url, chrome, **k: compuestas.append((img.name, url))):
        cli.main(["capturar", nmap, "-o", str(salida)])   # barra activa por defecto
    self.assertTrue(compuestas)                            # se compuso cada imagen
    self.assertTrue(all(nombre.endswith(".png") for nombre, _ in compuestas))  # PNG forzado

def test_captura_sin_barra_no_compone_ni_fuerza_png(self):
    with patch("dedalo.cli.gowitness.scan_subnet", side_effect=scan_jpeg), \
         patch("dedalo.cli.barra.componer") as componer:
        cli.main(["capturar", nmap, "-o", str(salida), "--sin-barra-url", "--formato", "jpeg"])
    componer.assert_not_called()

def test_un_objetivo_sin_imagen_no_se_compone(self):
    # scan deja una fila SIN filename -> componer no se llama para ese
    ...
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_dedalo -v -k barra`
Expected: FAIL (opción y bucle no existen).

- [ ] **Step 3: Implement** en `dedalo/cli.py`: añadir `capture.add_argument("--sin-barra-url", action="store_true", help="No quemar la barra con la URL en las capturas")`; en `capture()`, `url_bar = not args.sin_barra_url`; si `url_bar`, `opts["format"] = "png"`; tras el bloque de `scan_subnet`+reintento de cada subred, si `url_bar` y hay `chrome`, recorrer `gowitness.read_results(directory / gowitness.DB_NAME)` y, por cada fila con `filename`, llamar `barra.componer(...)` dentro de un `try/except ValueError` que avise por stderr y siga. Importar `barra`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_dedalo -v -k barra`
Expected: PASS.

- [ ] **Step 5: Run the whole suite and commit**

Run: `python -m unittest discover -s tests`
Expected: OK.

```bash
git add dedalo/cli.py tests/
git commit -m "Burn the URL bar into captures from the capturar command

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Interruptor en el portal (opción + casilla)

**Files:**
- Modify: `dedalo/web.py`, `dedalo/auditoria.py` (defaults de `portal_options`/`options_from` si ahí viven), `dedalo/static/index.html`, `dedalo/static/app.js`
- Test: `tests/test_web.py`

**Interfaces:**
- Consumes: la opción `--sin-barra-url` del comando (Task 2).
- Produces: la opción de captura `barra_url` (por defecto `True`) en las opciones del portal; el `_worker` añade `--sin-barra-url` al comando cuando `barra_url` es falso; una casilla **«Barra de URL en las capturas»** (marcada por defecto) en las opciones de captura de la interfaz, que viaja en `opciones`.

- [ ] **Step 1: Write the failing test** en `tests/test_web.py`:

```python
def test_capture_without_url_bar_passes_the_flag(self):
    job = json.loads(self.request("/api/jobs", payload() | {"auditoria": self.audit["id"], "opciones": {"barra_url": False}})[1])
    recibido = {}
    def run(command, **kw):
        recibido["cmd"] = command
        return subprocess.CompletedProcess(command, 0)
    with patch("dedalo.web.subprocess.run", side_effect=run), patch("dedalo.web.ensure_gowitness"):
        self.store.start(job["id"])  # … o encolar y dejar correr el worker …
    self.assertIn("--sin-barra-url", recibido["cmd"])

def test_capture_with_url_bar_on_by_default_does_not_pass_the_flag(self):
    # opciones por defecto -> barra_url True -> sin --sin-barra-url
    ...

def test_page_has_the_url_bar_option(self):
    page = self.request("/")[1]
    self.assertIn(b'id="opt-url-bar"', page)
    self.assertIn("Barra de URL".encode(), page)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_web -v -k url_bar`
Expected: FAIL.

- [ ] **Step 3: Implement.** Añadir `barra_url` (por defecto `True`) a los valores por defecto de las opciones de captura (`options_from` / `portal_options`, donde estén `pagina_completa`, `reintentar`, etc.); en el `_worker`, `if not options.get("barra_url", True): command.append("--sin-barra-url")`; en `index.html`, una casilla `id="opt-url-bar"` **marcada** junto a las otras opciones de captura; en `app.js`, incluir `barra_url: $("opt-url-bar").checked` donde se arman las `opciones` de la captura.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_web -v -k url_bar`
Expected: PASS. Y `python design/check-contrast.py` sin fallos.

- [ ] **Step 5: Run the whole suite and commit**

Run: `python -m unittest discover -s tests`
Expected: OK.

```bash
git add dedalo/web.py dedalo/auditoria.py dedalo/static/index.html dedalo/static/app.js tests/test_web.py
git commit -m "Add the URL-bar capture option in the portal

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Documentación

**Files:**
- Modify: `README.md`, `docs/CONTRATOS.md` (si procede)

**Interfaces:**
- Consumes: todo lo anterior.

- [ ] **Step 1: Documentación.** README (sección de captura): que las capturas llevan por defecto una **barra con la URL quemada** (estilo navegador), que se apaga con `--sin-barra-url` o la casilla, que con la barra el formato es **PNG**, y que la compone Chrome (una pasada más por imagen). `docs/CONTRATOS.md`: una nota si describe el formato/estados de la captura.

- [ ] **Step 2: Run the whole suite and commit**

Run: `python -m unittest discover -s tests`
Expected: OK.

```bash
git add README.md docs/CONTRATOS.md
git commit -m "Document the URL bar burned into captures

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Cierre

- `/simplify` → `/code-review` + Trail of Bits que apliquen (sharp-edges, insecure-defaults; lanza un binario externo con rutas).
- **Integración con Chrome real**: una captura de laboratorio con la barra activa y comprobar a ojo la imagen compuesta (normal y página completa). Prueba real de Doro para los informes.
- Al terminar: ficha, nota `url-en-capturas` y `04-IA/registro.md` del Brain al día; lista a Doro para su «ok»; recordar `git push nas`/`nas-vpn`.
