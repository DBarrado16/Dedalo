import contextlib
import hashlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from dedalo import cli, gowitness, web

CONTENT = b"binario-de-prueba"
RELEASE = ("gowitness-prueba", hashlib.sha256(CONTENT).hexdigest())


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.target = Path(self.temp.name) / "bin" / "gowitness"

    def tearDown(self):
        self.temp.cleanup()

    def install(self, content=CONTENT, error=None):
        response = patch("dedalo.gowitness.urllib.request.urlopen",
                         side_effect=error, return_value=io.BytesIO(content))
        with patch("dedalo.gowitness.release_for_this_system", return_value=RELEASE), response as opener:
            try:
                return gowitness.install_gowitness(self.target, log=lambda text: None)
            finally:
                self.url = opener.call_args[0][0]

    def test_installs_only_verified_official_binary(self):
        self.assertEqual(self.install(), str(self.target))
        self.assertEqual(self.target.read_bytes(), CONTENT)
        self.assertEqual(self.url, f"https://github.com/sensepost/gowitness/releases/download/{gowitness.VERSION}/gowitness-prueba")
        self.assertEqual(list(self.target.parent.iterdir()), [self.target])

    def test_rejects_wrong_hash_and_leaves_nothing(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.install(b"binario-alterado")
        self.assertEqual(list(self.target.parent.iterdir()), [])

    def test_network_error_explains_manual_install(self):
        with self.assertRaisesRegex(ValueError, "a mano"):
            self.install(error=urllib.error.URLError("sin red"))
        self.assertFalse(self.target.exists())

    def test_release_matches_system_and_architecture(self):
        cases = {("Windows", "AMD64"): "windows-amd64.exe", ("Linux", "x86_64"): "linux-amd64",
                 ("Linux", "aarch64"): "linux-arm64", ("Linux", "armv7l"): "linux-arm", ("Darwin", "arm64"): "darwin-arm64"}
        for (system, machine), suffix in cases.items():
            with self.subTest(system=system, machine=machine), patch("platform.system", return_value=system), patch("platform.machine", return_value=machine):
                self.assertTrue(gowitness.release_for_this_system()[0].endswith(suffix))
        with patch("platform.system", return_value="FreeBSD"), patch("platform.machine", return_value="amd64"):
            with self.assertRaisesRegex(ValueError, "a mano"):
                gowitness.release_for_this_system()

    def test_portal_downloads_only_when_missing_and_starts_on_failure(self):
        with patch("dedalo.web.gowitness.install_gowitness") as install:
            web.ensure_gowitness("C:/ruta/indicada/gowitness.exe")
            with patch("dedalo.web.gowitness.find_gowitness", return_value="existente"), \
                 patch("dedalo.web.gowitness.installed_version", return_value=gowitness.VERSION):
                web.ensure_gowitness(None)
            install.assert_not_called()
        output = io.StringIO()
        with patch("dedalo.web.gowitness.find_gowitness", side_effect=ValueError("falta")), \
             patch("dedalo.web.gowitness.install_gowitness", side_effect=ValueError("sin red")), \
             contextlib.redirect_stdout(output):
            web.ensure_gowitness(None)
        self.assertIn("Aviso: sin red", output.getvalue())

    def test_installed_version_parses_gowitness_output(self):
        salida = subprocess.CompletedProcess([], 0, stdout="gowitness\nVersion: v3.2.0 (abc)\n", stderr="")
        with patch("dedalo.gowitness.subprocess.run", return_value=salida):
            self.assertEqual(gowitness.installed_version("cualquiera"), "3.2.0")
        with patch("dedalo.gowitness.subprocess.run", side_effect=OSError("no existe")):
            self.assertIsNone(gowitness.installed_version("cualquiera"))

    def test_portal_redownloads_a_gowitness_of_the_wrong_version(self):
        # En WSL/Kali hay un gowitness del PATH de otra versión: la app debe bajar sola el fijado.
        with patch("dedalo.web.gowitness.find_gowitness", return_value="viejo"), \
             patch("dedalo.web.gowitness.installed_version", return_value="2.1.0"), \
             patch("dedalo.web.gowitness.install_gowitness") as install, \
             contextlib.redirect_stdout(io.StringIO()):
            web.ensure_gowitness(None)
        install.assert_called_once()

    def test_cli_reports_existing_binary_without_downloading(self):
        self.target.parent.mkdir()
        self.target.write_bytes(CONTENT)
        output = io.StringIO()
        with patch("dedalo.cli.gowitness.local_binary", return_value=self.target), \
             patch("dedalo.cli.gowitness.release_for_this_system", return_value=RELEASE), \
             patch("dedalo.cli.gowitness.install_gowitness") as install, contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(["instalar"]), 0)
        install.assert_not_called()
        self.assertIn("coincide con", output.getvalue())
        self.assertNotIn("NO coincide", output.getvalue())
