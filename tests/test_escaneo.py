import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from dedalo import escaneo, targets

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


class PresetsTests(unittest.TestCase):
    def test_son_los_tres(self):
        self.assertEqual(set(escaneo.PRESETS), {"rapido", "completo", "vpn"})
        self.assertIn("-sT", escaneo.PRESETS["vpn"]["args"])
        self.assertIn("-Pn", escaneo.PRESETS["vpn"]["args"])
        self.assertEqual(escaneo.COMUNES, ["-n"])

    def test_ninguno_lleva_privilegios_ni_ficheros(self):
        for preset in escaneo.PRESETS.values():
            self.assertTrue(preset["etiqueta"])
            for prohibido in ("-O", "-oX", "-iL", "--excludefile"):
                self.assertNotIn(prohibido, preset["args"])


class TrocearTests(unittest.TestCase):
    def test_un_16_da_256(self):
        self.assertEqual(len(escaneo.trocear(["10.0.0.0/16"])), 256)

    def test_un_26_da_1_trozo(self):
        trozos = escaneo.trocear(["10.0.0.0/26"])
        self.assertEqual(len(trozos), 1)
        self.assertEqual(trozos[0].prefixlen, 26)

    def test_ignora_ipv6(self):
        self.assertEqual(escaneo.trocear(["2001:db8::/32", "10.0.0.0/24"]), [ipaddress.ip_network("10.0.0.0/24")])

    def test_sin_solapar_y_en_orden(self):
        trozos = escaneo.trocear(["10.0.1.0/24", "10.0.0.0/23", "10.0.1.128/25"])
        self.assertEqual([str(t) for t in trozos], ["10.0.0.0/24", "10.0.1.0/24"])


class ObjetivosDelTrozoTests(unittest.TestCase):
    def test_respeta_el_alcance(self):
        scope = targets.Scope(["10.0.0.0/24"], ["10.0.0.5/32"])
        dentro, excluidas = escaneo.objetivos_del_trozo(ipaddress.ip_network("10.0.0.0/24"), scope)
        self.assertNotIn("10.0.0.5", dentro)
        self.assertIn("10.0.0.5", excluidas)
        self.assertIn("10.0.0.1", dentro)

    def test_las_de_fuera_no_van_en_ninguna(self):
        scope = targets.Scope(["10.0.0.0/25"])
        dentro, excluidas = escaneo.objetivos_del_trozo(ipaddress.ip_network("10.0.0.0/24"), scope)
        self.assertNotIn("10.0.0.200", dentro)
        self.assertNotIn("10.0.0.200", excluidas)
        self.assertEqual(excluidas, [])


FAKE = Path(__file__).with_name("fake_nmap.py").resolve()


def nmap_falso(carpeta: Path) -> str:
    """Un ejecutable «nmap» que lanza fake_nmap.py (Popen sin shell no ejecuta un .py suelto)."""
    if os.name == "nt":
        envoltorio = carpeta / "nmap.cmd"
        envoltorio.write_text(f'@"{sys.executable}" "{FAKE}" %*\n')
    else:
        envoltorio = carpeta / "nmap"
        envoltorio.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE}" "$@"\n')
        envoltorio.chmod(0o755)
    return str(envoltorio)


class EscanearTrozoTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        base = Path(temp.name)
        (base / "bin").mkdir()
        self.nmap = nmap_falso(base / "bin")
        self.carpeta = base / "trozo"
        self.carpeta.mkdir()

    def args(self):
        return json.loads((self.carpeta / "args.json").read_text())

    def test_no_pasa_excluidas_a_nmap(self):
        r = escaneo.escanear_trozo(self.nmap, "rapido", ["10.0.0.1", "10.0.0.2"], ["10.0.0.9"], self.carpeta)
        self.assertNotIn("10.0.0.9", (self.carpeta / "objetivos.txt").read_text())
        self.assertIn("--excludefile", self.args())
        self.assertIn("10.0.0.9", (self.carpeta / "excluir.txt").read_text())
        self.assertEqual(r["codigo"], 0)
        self.assertFalse(r["relanzado"])
        self.assertTrue((self.carpeta / "salida.xml").is_file())

    def test_sin_excluidas_no_pone_excludefile(self):
        escaneo.escanear_trozo(self.nmap, "rapido", ["10.0.0.1"], [], self.carpeta)
        self.assertNotIn("--excludefile", self.args())

    def test_argumentos_los_pone_el_codigo(self):
        r = escaneo.escanear_trozo(self.nmap, "vpn", ["10.0.0.1"], [], self.carpeta)
        esperado = [*escaneo.COMUNES, *escaneo.PRESETS["vpn"]["args"], "-oX", "salida.xml", "-iL", "objetivos.txt"]
        self.assertEqual(self.args(), esperado)
        self.assertEqual(r["comando"], [self.nmap, *esperado])

    def test_no_usa_shell(self):
        visto = {}
        original = subprocess.Popen

        def espia(args, **kw):
            visto.update(kw)
            visto["args"] = args
            return original(args, **kw)

        with patch.object(escaneo.subprocess, "Popen", espia):
            escaneo.escanear_trozo(self.nmap, "rapido", ["10.0.0.1"], [], self.carpeta)
        self.assertIs(visto.get("shell", False), False)
        self.assertEqual(str(visto.get("cwd")), str(self.carpeta))
        self.assertIsInstance(visto["args"], list)

    def test_parar_mata_el_proceso_y_marca_relanzado(self):
        with patch.dict(os.environ, {"FAKE_NMAP_ESPERA": "10"}):
            r = escaneo.escanear_trozo(self.nmap, "rapido", ["10.0.0.1"], [], self.carpeta, parar=lambda: True)
        self.assertTrue(r["relanzado"])
        self.assertFalse((self.carpeta / "salida.xml").exists())


if __name__ == "__main__":
    unittest.main()
