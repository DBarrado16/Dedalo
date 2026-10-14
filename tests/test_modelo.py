import io
import json
import unittest
import urllib.error
from unittest.mock import patch

from dedalo import modelo


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class ModelTests(unittest.TestCase):
    def test_asks_the_local_model_for_one_whole_answer(self):
        body = json.dumps({"response": "hola"}).encode()
        with patch("dedalo.modelo.urllib.request.urlopen", return_value=FakeResponse(body)) as urlopen:
            self.assertEqual(modelo.generate("¿qué es?", "llama3.2:3b", "http://127.0.0.1:11434/"), "hola")
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:11434/api/generate")
        # JSON obligado y sin razonamiento en voz alta: con un modelo de razonamiento, 35 s en vez de 142 s por host.
        # Temperatura 0: la misma pregunta da la misma respuesta, como pide una traza de auditoría.
        self.assertEqual(json.loads(request.data), {"model": "llama3.2:3b", "prompt": "¿qué es?", "stream": False,
                                                    "format": "json", "think": False, "options": {"temperature": 0}})

    def test_a_schema_constrains_the_answer(self):
        schema = {"type": "object", "properties": {"nivel": {"type": "string", "enum": ["alta"]}}, "required": ["nivel"]}
        body = json.dumps({"response": "{}"}).encode()
        with patch("dedalo.modelo.urllib.request.urlopen", return_value=FakeResponse(body)) as urlopen:
            modelo.generate("p", "m", schema=schema)
        self.assertEqual(json.loads(urlopen.call_args.args[0].data)["format"], schema)

    def test_explains_when_the_model_is_unreachable(self):
        with patch("dedalo.modelo.urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            with self.assertRaisesRegex(ValueError, "Ollama"):
                modelo.generate("p", "llama3.2:3b")

    def test_a_slow_model_says_it_took_too_long(self):
        with patch("dedalo.modelo.urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            with self.assertRaisesRegex(ValueError, "tardó más de 120 s.*--modelo"):
                modelo.generate("p", "fsec-analyst:latest")

    def test_an_answer_without_text_is_an_error(self):
        for body in (b"no es json", json.dumps({"error": "model not found"}).encode()):
            with self.subTest(body=body), patch("dedalo.modelo.urllib.request.urlopen", return_value=FakeResponse(body)):
                with self.assertRaises(ValueError):
                    modelo.generate("p", "llama3.2:3b")
