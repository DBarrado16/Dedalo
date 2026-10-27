import http.server
import json
import threading
import unittest
from contextlib import contextmanager

from dedalo import modelo


@contextmanager
def fake_api(status=200, body=None, capturado=None):
    """Un servidor local que imita /v1/messages: guarda las cabeceras y responde lo indicado."""
    cuerpo = body if body is not None else {"content": [{"type": "text", "text": '{"producto":"X"}'}]}

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            largo = int(self.headers.get("Content-Length", 0))
            self.rfile.read(largo)
            if capturado is not None:
                capturado["x-api-key"] = self.headers.get("x-api-key")
                capturado["version"] = self.headers.get("anthropic-version")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(cuerpo).encode("utf-8"))

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/v1/messages"
    finally:
        srv.shutdown()


class GenerateClaudeTests(unittest.TestCase):
    def test_manda_la_clave_y_devuelve_el_texto(self):
        visto = {}
        with fake_api(body={"content": [{"type": "text", "text": '{"producto":"RouterOS"}'}]}, capturado=visto) as url:
            texto = modelo.generate_claude("hola", "claude-sonnet-5-5", api_key="secreta", url=url)
        self.assertEqual(texto, '{"producto":"RouterOS"}')
        self.assertEqual(visto["x-api-key"], "secreta")
        self.assertTrue(visto["version"])  # manda anthropic-version

    def test_sin_clave_falla_citandola(self):
        import os
        previo = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            with self.assertRaisesRegex(ValueError, "ANTHROPIC_API_KEY"):
                modelo.generate_claude("hola", "claude-sonnet-5-5", url="http://127.0.0.1:1/v1/messages")
        finally:
            if previo is not None:
                os.environ["ANTHROPIC_API_KEY"] = previo

    def test_un_error_http_se_convierte_en_valueerror(self):
        with fake_api(status=500, body={"error": "boom"}) as url:
            with self.assertRaises(ValueError):
                modelo.generate_claude("hola", "claude-sonnet-5-5", api_key="k", url=url)


if __name__ == "__main__":
    unittest.main()
