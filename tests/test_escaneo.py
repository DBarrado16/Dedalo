import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from dedalo import escaneo

# Cambiar os.name a "posix" en Windows rompe pathlib: se sustituye solo el os del módulo.
POSIX = SimpleNamespace(name="posix", environ=os.environ)


class EncontrarNmapTests(unittest.TestCase):
    def test_usa_el_explicito_si_existe(self):
        with tempfile.TemporaryDirectory() as temp:
            falso = Path(temp) / "nmap"
            falso.write_text("")
            self.assertEqual(escaneo.find_nmap(str(falso)), str(falso.resolve()))

    def test_explicito_inexistente_falla(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                escaneo.find_nmap(str(Path(temp) / "no-existe"))

    def test_sin_ninguno_explica(self):
        with patch.object(escaneo.shutil, "which", lambda nombre: None), \
                patch.object(escaneo, "os", POSIX), \
                patch.object(escaneo.Path, "is_file", lambda self: False):
            with self.assertRaisesRegex(ValueError, "No se encuentra Nmap"):
                escaneo.find_nmap(None)

    def test_ignora_el_de_la_carpeta_actual(self):
        with tempfile.TemporaryDirectory() as temp:
            falso = Path(temp) / "nmap"
            falso.write_text("")
            with patch.object(escaneo.shutil, "which", lambda nombre: str(falso)), \
                    patch.object(escaneo, "os", POSIX), \
                    patch.object(escaneo.Path, "cwd", classmethod(lambda cls: Path(temp))), \
                    patch.object(escaneo.Path, "is_file", lambda self: False):
                with self.assertRaisesRegex(ValueError, "No se encuentra Nmap"):
                    escaneo.find_nmap(None)

    def test_usa_el_del_path(self):
        with tempfile.TemporaryDirectory() as temp:
            falso = Path(temp) / "nmap"
            falso.write_text("")
            with patch.object(escaneo.shutil, "which", lambda nombre: str(falso)), \
                    patch.object(escaneo, "os", POSIX):
                self.assertEqual(escaneo.find_nmap(None), str(falso.resolve()))

    def test_windows_prueba_program_files(self):
        with tempfile.TemporaryDirectory() as temp:
            nmap = Path(temp) / "Nmap" / "nmap.exe"
            nmap.parent.mkdir()
            nmap.write_text("")
            windows = SimpleNamespace(name="nt", environ={"ProgramFiles": temp})
            with patch.object(escaneo, "os", windows), \
                    patch.object(escaneo.shutil, "which", lambda nombre: None):
                self.assertEqual(escaneo.find_nmap(None), str(nmap.resolve()))


class VersionNmapTests(unittest.TestCase):
    def test_extrae_la_version(self):
        salida = subprocess.CompletedProcess([], 0, stdout="Nmap version 7.95 ( https://nmap.org )\n", stderr="")
        with patch.object(escaneo.subprocess, "run", return_value=salida) as ejecutar:
            self.assertEqual(escaneo.nmap_version("nmap"), "7.95")
        self.assertEqual(ejecutar.call_args.args[0], ["nmap", "--version"])
        self.assertNotIn("shell", ejecutar.call_args.kwargs)

    def test_sin_respuesta_es_none(self):
        with patch.object(escaneo.subprocess, "run", side_effect=OSError):
            self.assertIsNone(escaneo.nmap_version("nmap"))
        salida = subprocess.CompletedProcess([], 0, stdout="otra cosa", stderr="")
        with patch.object(escaneo.subprocess, "run", return_value=salida):
            self.assertIsNone(escaneo.nmap_version("nmap"))


if __name__ == "__main__":
    unittest.main()
