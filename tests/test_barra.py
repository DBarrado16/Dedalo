import struct
import subprocess
import tempfile
import unittest
from urllib.parse import urlsplit
from urllib.request import url2pathname
import zlib
from pathlib import Path

from dedalo import barra


def png(w, h):
    """PNG mínimo válido con el IHDR correcto (contenido irrelevante)."""
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)

    def chunk(tipo, datos):
        return struct.pack(">I", len(datos)) + tipo + datos + struct.pack(">I", zlib.crc32(tipo + datos) & 0xffffffff)

    idat = zlib.compress(b"\x00" + b"\x00\x00\x00" * w)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


class BarraTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.img = self.dir / "shot.png"
        self.img.write_bytes(png(400, 300))

    def test_dimensiones_png_lee_ancho_y_alto(self):
        self.assertEqual(barra.dimensiones_png(self.img), (400, 300))

    def test_componer_llama_a_chrome_con_el_tamano_y_escapa_la_url(self):
        visto = {}

        def falso(cmd, **kw):
            visto["cmd"] = cmd
            wrapper = Path(url2pathname(urlsplit(cmd[-1]).path))  # file:// -> ruta, también en Windows
            visto["html"] = wrapper.read_text("utf-8")
            salida = next(a.split("=", 1)[1] for a in cmd if a.startswith("--screenshot="))
            Path(salida).write_bytes(png(400, 352))
            return subprocess.CompletedProcess(cmd, 0)

        barra.componer(self.img, 'https://10.0.0.1/a?x="y"&z=<1>', "chrome.exe", ejecutar=falso)
        self.assertIn(f"--window-size=400,{300 + barra.ALTO_BARRA}", " ".join(visto["cmd"]))
        self.assertIn("&amp;", visto["html"])
        self.assertIn("&lt;1&gt;", visto["html"])          # URL escapada
        self.assertNotIn("<1>", visto["html"])
        self.assertEqual(barra.dimensiones_png(self.img), (400, 352))  # imagen sustituida por la compuesta

    def test_componer_conserva_la_imagen_si_chrome_falla(self):
        antes = self.img.read_bytes()

        def falla(cmd, **kw):
            raise subprocess.CalledProcessError(1, cmd)

        with self.assertRaises(ValueError):
            barra.componer(self.img, "https://10.0.0.1/", "chrome.exe", ejecutar=falla)
        self.assertEqual(self.img.read_bytes(), antes)     # intacta


if __name__ == "__main__":
    unittest.main()
