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

from dedalo import escaneo, parser, targets

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
        r = escaneo.escanear_trozo(self.nmap, "rapido", ["10.0.0.1", "10.0.0.2"], ["10.0.0.9"], self.carpeta, parar=lambda: False)
        self.assertNotIn("10.0.0.9", (self.carpeta / "objetivos.txt").read_text())
        self.assertIn("--excludefile", self.args())
        self.assertIn("10.0.0.9", (self.carpeta / "excluir.txt").read_text())
        self.assertEqual(r["codigo"], 0)
        self.assertFalse(r["relanzado"])
        self.assertTrue((self.carpeta / "salida.xml").is_file())

    def test_sin_excluidas_no_pone_excludefile(self):
        escaneo.escanear_trozo(self.nmap, "rapido", ["10.0.0.1"], [], self.carpeta, parar=lambda: False)
        self.assertNotIn("--excludefile", self.args())

    def test_argumentos_los_pone_el_codigo(self):
        r = escaneo.escanear_trozo(self.nmap, "vpn", ["10.0.0.1"], [], self.carpeta, parar=lambda: False)
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
            escaneo.escanear_trozo(self.nmap, "rapido", ["10.0.0.1"], [], self.carpeta, parar=lambda: False)
        self.assertIs(visto.get("shell", False), False)
        self.assertEqual(str(visto.get("cwd")), str(self.carpeta))
        self.assertIsInstance(visto["args"], list)

    def test_guarda_stdout_y_stderr_del_trozo(self):
        escaneo.escanear_trozo(self.nmap, "rapido", ["10.0.0.1"], [], self.carpeta, parar=lambda: False)
        self.assertIn("fake nmap", (self.carpeta / "nmap.out").read_text())
        self.assertTrue((self.carpeta / "nmap.err").is_file())

    def test_preset_desconocido_revienta(self):
        with self.assertRaises(ValueError):
            escaneo.escanear_trozo(self.nmap, "fantasma", ["10.0.0.1"], [], self.carpeta, parar=lambda: False)

    def test_parar_mata_el_proceso_y_marca_relanzado(self):
        with patch.dict(os.environ, {"FAKE_NMAP_ESPERA": "10"}):
            r = escaneo.escanear_trozo(self.nmap, "rapido", ["10.0.0.1"], [], self.carpeta, parar=lambda: True)
        self.assertTrue(r["relanzado"])
        self.assertFalse((self.carpeta / "salida.xml").exists())


class LimpiarHostsTests(unittest.TestCase):
    def test_quita_hosts_sin_puertos(self):
        h = [parser.Host(ip="10.0.0.1"), parser.Host(ip="10.0.0.2", ports={80: parser.Port(80)})]
        self.assertEqual([x.ip for x in escaneo.limpiar_hosts(h)], ["10.0.0.2"])

    def test_conserva_host_con_solo_udp(self):
        h = [parser.Host(ip="10.0.0.4", udp_ports={53: parser.Port(53)})]
        self.assertEqual([x.ip for x in escaneo.limpiar_hosts(h)], ["10.0.0.4"])

    def test_puertos_sondeados_es_el_mayor_de_los_presets(self):
        self.assertEqual(escaneo.puertos_sondeados(["rapido"]), 1000)
        self.assertEqual(escaneo.puertos_sondeados(["vpn"]), 1000)
        self.assertEqual(escaneo.puertos_sondeados(["rapido", "completo"]), 65535)

    def test_vacia_host_que_responde_a_todo_con_top_1000(self):
        # Con rapido/vpn (--top-ports 1000) un host abierto en los 1000 responde a todo.
        h = parser.Host(ip="10.0.0.3", ports={n: parser.Port(n) for n in range(1, 1001)})
        out = escaneo.limpiar_hosts([h], puertos_sondeados=1000)[0]
        self.assertEqual(out.ports, {})
        self.assertIn({"id": "dedalo-todos-los-puertos",
                       "output": "responde en todos los puertos (1000 abiertos)"}, out.scripts)

    def test_host_normal_conserva_sus_puertos(self):
        h = parser.Host(ip="10.0.0.5", ports={n: parser.Port(n) for n in range(1, 51)})
        out = escaneo.limpiar_hosts([h], puertos_sondeados=1000)[0]
        self.assertEqual(len(out.ports), 50)
        self.assertEqual(out.scripts, [])

    def test_sin_puertos_sondeados_no_marca_a_nadie(self):
        h = parser.Host(ip="10.0.0.6", ports={n: parser.Port(n) for n in range(1, 2000)})
        out = escaneo.limpiar_hosts([h])[0]
        self.assertEqual(len(out.ports), 1999)
        self.assertEqual(out.scripts, [])


if __name__ == "__main__":
    unittest.main()



class EstimarTests(unittest.TestCase):
    def test_devuelve_texto_y_crece_con_las_ip(self):
        self.assertIsInstance(escaneo.estimar(["rapido"], 256), str)
        self.assertNotEqual(escaneo.estimar(["rapido"], 256), escaneo.estimar(["rapido"], 65536))

    def test_completo_tarda_mas_que_rapido(self):
        self.assertGreater(escaneo.segundos_estimados(["completo"], 256), escaneo.segundos_estimados(["rapido"], 256))

    def test_presets_suman(self):
        self.assertAlmostEqual(escaneo.segundos_estimados(["rapido", "vpn"], 100),
                               escaneo.segundos_estimados(["rapido"], 100) + escaneo.segundos_estimados(["vpn"], 100))

    def test_sin_ip_no_hay_nada_que_escanear(self):
        self.assertIn("nada", escaneo.estimar(["rapido"], 0))

    def test_unidades_legibles(self):
        self.assertIn("min", escaneo.estimar(["rapido"], 256))
        self.assertIn("h", escaneo.estimar(["completo"], 256))
        self.assertIn("días", escaneo.estimar(["completo"], 65536))

    def test_preset_desconocido_falla(self):
        with self.assertRaises(ValueError):
            escaneo.estimar(["inexistente"], 10)
