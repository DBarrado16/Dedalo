"""Reglas de alcance (docs/CONTRATOS.md 0.3) que no dependen de ningún otro módulo."""

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from dedalo import gowitness, probador, redes, targets


class AlcanceTests(unittest.TestCase):
    def test_una_ipv4_escrita_como_ipv6_mapeada_no_esquiva_la_exclusion(self):
        # ::ffff:10.0.0.5 es el mismo equipo que 10.0.0.5: la exclusión gana, se escriba como se escriba.
        alcance = targets.Scope(["::/0", "10.0.0.0/24"], ["10.0.0.5/32"])
        self.assertEqual(alcance.status("::ffff:10.0.0.5"), targets.Scope.EXCLUDED)
        alcance = targets.Scope(["10.0.0.0/24"], ["::ffff:10.0.0.5/128"])
        self.assertEqual(alcance.status("10.0.0.5"), targets.Scope.EXCLUDED)
        # Y una regla IPv6 amplia no mete en alcance una IPv4 que no se incluyó.
        self.assertEqual(targets.Scope(["::/0"]).status("::ffff:10.0.0.6"), targets.Scope.OUT)
        self.assertEqual(targets.Scope(["10.0.0.0/24"]).status("::ffff:10.0.0.6"), targets.Scope.IN)


class SalidasEndurecidasTests(unittest.TestCase):
    def test_la_ruta_de_una_receta_no_puede_cambiar_el_host(self):
        objetivo = {"https": False, "puerto": 80}
        self.assertEqual(probador._url("10.0.0.5", objetivo, "/login"), "http://10.0.0.5:80/login")
        for ruta in ("@evil.example/", ":81@evil.example/", "//evil.example/", "x.evil/", ""):
            with self.subTest(ruta=ruta), self.assertRaises(ValueError):
                probador._url("10.0.0.5", objetivo, ruta)

    def test_un_gowitness_en_la_carpeta_actual_no_se_ejecuta(self):
        with tempfile.TemporaryDirectory() as carpeta:
            plantado = Path(carpeta) / "gowitness.exe"
            plantado.write_bytes(b"")
            anterior = os.getcwd()
            os.chdir(carpeta)
            try:
                with mock.patch.object(gowitness, "local_binary", return_value=Path(carpeta) / "no" / "existe"), \
                        mock.patch.object(gowitness.shutil, "which", return_value=str(plantado)), \
                        self.assertRaises(ValueError):
                    gowitness.find_gowitness(None)
            finally:
                os.chdir(anterior)

    @unittest.skipUnless(sys.platform.startswith("win"), "ipconfig solo en Windows")
    def test_ipconfig_se_lanza_con_su_ruta_completa(self):
        with mock.patch.object(redes.subprocess, "run") as run:
            redes._ejecutar()
        self.assertTrue(run.call_args[0][0][0].lower().endswith("\\system32\\ipconfig.exe"), run.call_args)


if __name__ == "__main__":
    unittest.main()
