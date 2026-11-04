"""Lectura por trozos de los feeds de la NVD (_leer_feed), sin red."""

import gzip
import json
from pathlib import Path
import tempfile
import tracemalloc
import unittest
from unittest import mock

from dedalo import cve
from tests.test_red_externa import cve_nvd


class LeerFeedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def escribir(self, cuerpo: bytes, comprimido=True) -> Path:
        ruta = Path(self.temp.name) / "feed.json.gz"
        ruta.write_bytes(gzip.compress(cuerpo) if comprimido else cuerpo)
        return ruta

    def test_trozos_que_cortan_entradas_numeros_y_texto_dan_lo_mismo(self):
        entradas = [cve_nvd(f"CVE-2026-{n:04d}") for n in range(40)] + [cve_nvd("CVE-2026-9999", estado="Rejected")]
        # La clave no tiene por qué ir al final, y los demás campos se saltan.
        cuerpo = b"\xef\xbb\xbf" + json.dumps({"resultsPerPage": 12345, "format": "NVD_CVE", "vulnerabilities": entradas,
                                              "totalResults": 41, "extra": {"a": [1, "b]}"]}}, ensure_ascii=False,
                                             indent=1).encode("utf-8")
        esperado = [cve.item_desde_nvd(e) for e in entradas[:40]]
        for comprimido in (True, False):
            for trozo in (1, 7, 1 << 20):
                with self.subTest(comprimido=comprimido, trozo=trozo), mock.patch.object(cve, "TROZO_FEED", trozo):
                    self.assertEqual(cve._leer_feed(self.escribir(cuerpo, comprimido)), esperado)

    def test_un_feed_vacio_o_sin_vulnerabilidades(self):
        self.assertEqual(cve._leer_feed(self.escribir(b'{"vulnerabilities": [ ]}')), [])
        for cuerpo in (b"{}", b'{"otra": []}', b'{"vulnerabilities": {}}', b"[]", b'{"vulnerabilities": [{}',
                       b'{"vulnerabilities": []} basura', b"", b'{"vulnerabilities": [] "x": 1}'):
            with self.subTest(cuerpo=cuerpo), self.assertRaises(ValueError):
                cve._leer_feed(self.escribir(cuerpo))

    def test_respeta_el_tope_descomprimido(self):
        with mock.patch.object(cve, "MAX_DESCOMPRIMIDO", 100), self.assertRaisesRegex(ValueError, "mayor de lo esperado"):
            cve._leer_feed(self.escribir(json.dumps({"vulnerabilities": [cve_nvd()] * 5}).encode()))

    def test_la_memoria_no_crece_con_el_tamano_del_feed(self):
        # Un feed de unos 8 MB: cargado entero, el pico pasaba con mucho del tamaño del texto.
        entradas = [cve_nvd(f"CVE-2026-{n:05d}", descripciones=[{"lang": "en", "value": "x" * 1500}]) for n in range(5000)]
        ruta = self.escribir(json.dumps({"vulnerabilities": entradas}).encode())
        tamano = len(gzip.decompress(ruta.read_bytes()))
        del entradas
        tracemalloc.start()
        try:
            items = cve._leer_feed(ruta)
            conservado, pico = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(len(items), 5000)
        # Por encima de los items que se devuelven, solo unos trozos: ni el texto entero ni su árbol JSON.
        self.assertLess(pico - conservado, tamano // 2, (pico, conservado, tamano))


if __name__ == "__main__":
    unittest.main()
