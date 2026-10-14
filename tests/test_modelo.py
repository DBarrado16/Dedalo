from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
import threading
import unittest
import urllib.error
from unittest.mock import patch

from dedalo import modelo


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def answering(body):
    return patch.object(modelo._OPENER, "open", return_value=FakeResponse(body))


class FakeOllama(BaseHTTPRequestHandler):
    """Ollama mínimo en 127.0.0.1 que contesta «ok» a cualquier pregunta."""

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        body = json.dumps({"response": "ok"}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class ModelTests(unittest.TestCase):
    def test_asks_the_local_model_for_one_whole_answer(self):
        with answering(json.dumps({"response": "hola"}).encode()) as opened:
            self.assertEqual(modelo.generate("¿qué es?", "llama3.2:3b", "http://127.0.0.1:11434/"), "hola")
        request = opened.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:11434/api/generate")
        # JSON obligado y sin razonamiento en voz alta: con un modelo de razonamiento, 35 s en vez de 142 s por host.
        # Temperatura 0: la misma pregunta da la misma respuesta, como pide una traza de auditoría.
        self.assertEqual(json.loads(request.data), {"model": "llama3.2:3b", "prompt": "¿qué es?", "stream": False,
                                                    "format": "json", "think": False, "options": {"temperature": 0}})

    def test_a_schema_constrains_the_answer(self):
        schema = {"type": "object", "properties": {"nivel": {"type": "string", "enum": ["alta"]}}, "required": ["nivel"]}
        with answering(json.dumps({"response": "{}"}).encode()) as opened:
            modelo.generate("p", "m", schema=schema)
        self.assertEqual(json.loads(opened.call_args.args[0].data)["format"], schema)

    def test_the_model_is_reached_directly_even_with_a_system_proxy(self):
        server = HTTPServer(("127.0.0.1", 0), FakeOllama)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        closed_proxy = "http://127.0.0.1:1"  # si se usara el proxy, la conexión fallaría
        clean = {key: value for key, value in os.environ.items() if key.lower() not in ("no_proxy", "http_proxy", "all_proxy")}
        try:
            with patch.dict(os.environ, clean | {"HTTP_PROXY": closed_proxy, "http_proxy": closed_proxy}, clear=True):
                self.assertEqual(modelo.generate("p", "m", f"http://127.0.0.1:{server.server_address[1]}"), "ok")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_only_a_model_on_this_machine_is_used(self):
        for host in ("http://10.0.0.5:11434", "http://ollama.example:11434", "file:///etc/passwd"):
            with self.subTest(host=host), answering(b"{}") as opened:
                with self.assertRaisesRegex(ValueError, "este equipo"):
                    modelo.generate("p", "m", host)
                opened.assert_not_called()
        for host in ("http://localhost:11434", "http://[::1]:11434", "http://127.0.0.1:11434"):
            with self.subTest(host=host), answering(json.dumps({"response": "ok"}).encode()):
                self.assertEqual(modelo.generate("p", "m", host), "ok")

    def test_explains_when_the_model_is_unreachable(self):
        with patch.object(modelo._OPENER, "open", side_effect=urllib.error.URLError("refused")):
            with self.assertRaisesRegex(ValueError, "Ollama"):
                modelo.generate("p", "llama3.2:3b")

    def test_a_slow_model_says_it_took_too_long(self):
        with patch.object(modelo._OPENER, "open", side_effect=TimeoutError("timed out")):
            with self.assertRaisesRegex(ValueError, "tardó más de 120 s.*--modelo"):
                modelo.generate("p", "fsec-analyst:latest")

    def test_an_answer_without_text_is_an_error(self):
        for body in (b"no es json", json.dumps({"error": "model not found"}).encode()):
            with self.subTest(body=body), answering(body):
                with self.assertRaises(ValueError):
                    modelo.generate("p", "llama3.2:3b")
