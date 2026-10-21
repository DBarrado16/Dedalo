import json
import tempfile
import unittest
from pathlib import Path

from dedalo import favicones


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


if __name__ == "__main__":
    unittest.main()
