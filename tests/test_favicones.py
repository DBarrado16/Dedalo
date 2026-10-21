from contextlib import contextmanager, redirect_stderr
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path

from dedalo import favicones


def _handler(cuerpo: bytes, content_type: str):
    """Un servidor mínimo que contesta siempre lo mismo, como Panel en tests/test_probador.py."""
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(cuerpo)))
            self.end_headers()
            self.wfile.write(cuerpo)

        def log_message(self, *a):
            pass
    return Handler


@contextmanager
def sirviendo(handler):
    servidor = HTTPServer(("127.0.0.1", 0), handler)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True); hilo.start()
    try:
        yield servidor.server_address[1]
    finally:
        servidor.shutdown(); servidor.server_close(); hilo.join()


class Mmh3ShodanTests(unittest.TestCase):
    def test_la_cadena_vacia_ancla_el_algoritmo(self):
        # mmh3.hash(b"", seed=0) (con signo) es 0, el vector conocido del algoritmo; el base64 de
        # b"" también es b"", así que mmh3_shodan(b"") debe dar lo mismo.
        self.assertEqual(favicones.mmh3_shodan(b""), 0)

    def test_valor_conocido_sobre_un_favicon_de_prueba(self):
        # Calculado con esta misma implementación durante el desarrollo (ver informe de la tarea).
        self.assertEqual(favicones.mmh3_shodan(b"\x89PNG\r\n\x1a\n favicon de prueba"), 805670246)


class Sha256HexTests(unittest.TestCase):
    def test_huella_sha256_conocida(self):
        import hashlib
        contenido = b"favicon de prueba"
        self.assertEqual(favicones.sha256_hex(contenido), hashlib.sha256(contenido).hexdigest())


class CargarTests(unittest.TestCase):
    def test_indexa_por_mmh3_y_sha256_e_ignora_entradas_sin_producto(self):
        con_tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        json.dump({"entradas": [
            {"mmh3": 123, "sha256": "abc", "producto": "RouterOS"},
            {"mmh3": 456, "producto": "FortiGate"},
            {"sha256": "sin-producto-no-vale"},  # sin producto: se ignora
        ]}, con_tmp)
        con_tmp.close()
        try:
            catalogo = favicones.cargar(Path(con_tmp.name))
        finally:
            Path(con_tmp.name).unlink()
        self.assertEqual(catalogo["mmh3"][123]["producto"], "RouterOS")
        self.assertEqual(catalogo["mmh3"][456]["producto"], "FortiGate")
        self.assertEqual(catalogo["sha256"]["abc"]["producto"], "RouterOS")
        self.assertNotIn("sin-producto-no-vale", catalogo["sha256"])
        self.assertEqual(len(catalogo["mmh3"]), 2)


    def test_un_json_invalido_o_ilegible_devuelve_el_catalogo_vacio_y_avisa(self):
        with tempfile.TemporaryDirectory() as carpeta:
            roto = Path(carpeta) / "roto.json"
            roto.write_text('{"entradas": [', encoding="utf-8")
            ausente = Path(carpeta) / "no-existe.json"
            for ruta in (roto, ausente):
                with self.subTest(ruta=ruta.name), redirect_stderr(io.StringIO()) as aviso:
                    self.assertEqual(favicones.cargar(ruta), {"mmh3": {}, "sha256": {}})
                self.assertIn("Error del portal:", aviso.getvalue())


class IdentificarTests(unittest.TestCase):
    def setUp(self):
        self.contenido = b"favicon de ejemplo para identificar"
        self.catalogo = {
            "mmh3": {favicones.mmh3_shodan(self.contenido): {"producto": "Por mmh3"}},
            "sha256": {favicones.sha256_hex(b"otro contenido"): {"producto": "Por sha256"}},
        }

    def test_encuentra_por_mmh3(self):
        self.assertEqual(favicones.identificar(self.contenido, self.catalogo)["producto"], "Por mmh3")

    def test_encuentra_por_sha256_si_el_mmh3_no_case(self):
        catalogo = {"mmh3": {}, "sha256": {favicones.sha256_hex(self.contenido): {"producto": "Por sha256"}}}
        self.assertEqual(favicones.identificar(self.contenido, catalogo)["producto"], "Por sha256")

    def test_devuelve_none_si_no_hay_coincidencia(self):
        self.assertIsNone(favicones.identificar(b"contenido desconocido", {"mmh3": {}, "sha256": {}}))


class UrlFaviconTests(unittest.TestCase):
    def test_usa_el_href_del_link_icon_resuelto_contra_la_base(self):
        self.assertEqual(
            favicones.url_favicon("https://10.0.0.1:8443/", '<link rel="icon" href="/x.png">'),
            "https://10.0.0.1:8443/x.png")

    def test_sin_link_usa_favicon_ico(self):
        self.assertEqual(favicones.url_favicon("https://10.0.0.1:8443/", "<html></html>"),
                         "https://10.0.0.1:8443/favicon.ico")

    def test_href_a_otro_host_queda_fuera_de_alcance(self):
        self.assertIsNone(favicones.url_favicon(
            "https://10.0.0.1:8443/", '<link rel="icon" href="https://cdn.otro.com/f.ico">'))


class DescargarTests(unittest.TestCase):
    def test_trae_los_bytes_de_una_imagen_pequena(self):
        with sirviendo(_handler(b"imagen-de-prueba", "image/x-icon")) as puerto:
            self.assertEqual(favicones.descargar(f"http://127.0.0.1:{puerto}/favicon.ico"), b"imagen-de-prueba")

    def test_none_si_el_cuerpo_supera_el_tope(self):
        with sirviendo(_handler(b"x" * 1000, "image/x-icon")) as puerto:
            self.assertIsNone(favicones.descargar(f"http://127.0.0.1:{puerto}/favicon.ico", tope=10))

    def test_none_si_el_content_type_no_es_imagen(self):
        with sirviendo(_handler(b"<html></html>", "text/html")) as puerto:
            self.assertIsNone(favicones.descargar(f"http://127.0.0.1:{puerto}/favicon.ico"))

    def test_none_si_falla_la_conexion(self):
        servidor = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        puerto = servidor.server_address[1]
        servidor.server_close()  # cierra sin escuchar: conectar ahí falla rápido, sin esperar el timeout
        self.assertIsNone(favicones.descargar(f"http://127.0.0.1:{puerto}/x", timeout=1))


if __name__ == "__main__":
    unittest.main()
