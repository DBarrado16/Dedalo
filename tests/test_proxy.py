"""Regla de paso del proxy de alcance y sus fuentes de alcance."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from dedalo import proxy, targets


class ReglaDePasoTests(unittest.TestCase):
    def test_regla_de_paso(self):
        s = targets.Scope(["10.10.0.0/16", "8.8.8.0/24"], ["10.10.5.20/32", "1.1.1.1/32"])
        self.assertEqual(proxy.decidir("10.10.5.20", s), proxy.EXCLUIDA)
        self.assertEqual(proxy.decidir("1.1.1.1", s), proxy.EXCLUIDA)      # pública pero excluida
        self.assertIsNone(proxy.decidir("10.10.1.1", s))                      # en alcance
        self.assertIsNone(proxy.decidir("8.8.4.4", s))                        # pública
        self.assertEqual(proxy.decidir("192.168.1.1", s), proxy.FUERA)
        self.assertEqual(proxy.decidir("100.64.0.1", s), proxy.FUERA)        # CGNAT no es global
        self.assertEqual(proxy.decidir("::ffff:10.10.5.20", s), proxy.EXCLUIDA)
        self.assertEqual(proxy.decidir("8.8.4.4", None), proxy.ILEGIBLE)

    def test_ipv6_mapeada_se_juzga_como_su_ipv4(self):
        s = targets.Scope(["10.10.0.0/16"], [])
        self.assertIsNone(proxy.decidir("::ffff:10.10.1.1", s))
        self.assertEqual(proxy.decidir("::ffff:192.168.1.1", s), proxy.FUERA)
        self.assertIsNone(proxy.decidir("::ffff:8.8.4.4", s))

    def test_nombre_con_una_ip_excluida_usa_otra(self):
        s = targets.Scope(["10.10.0.0/16"], ["10.10.5.20/32"])
        self.assertEqual(proxy.elegir_ip(["10.10.5.20", "10.10.5.21"], s), ("10.10.5.21", None))
        self.assertEqual(proxy.elegir_ip(["10.10.5.20"], s), (None, proxy.EXCLUIDA))

    def test_elegir_ip_sin_direcciones_ni_alcance(self):
        s = targets.Scope(["10.10.0.0/16"], [])
        self.assertEqual(proxy.elegir_ip([], s), (None, None))
        self.assertEqual(proxy.elegir_ip(["10.10.1.1"], None), (None, proxy.ILEGIBLE))

    def test_consola_con_excluir_no_abre_lo_interno(self):
        s = proxy.alcance_de_consola(["10.0.0.5"], [], False, ["10.0.0.9/32"])
        self.assertIsNone(proxy.decidir("10.0.0.5", s))
        self.assertEqual(proxy.decidir("10.0.0.6", s), proxy.FUERA)

    def test_consola_con_rangos_solo_si_solo_rangos(self):
        sin = proxy.alcance_de_consola(["10.0.0.5"], ["10.1.0.0/16"], False, [])
        con = proxy.alcance_de_consola(["10.0.0.5"], ["10.1.0.0/16"], True, [])
        self.assertEqual(proxy.decidir("10.1.2.3", sin), proxy.FUERA)
        self.assertIsNone(proxy.decidir("10.1.2.3", con))

    def test_consola_acepta_objetivos_ipv6(self):
        s = proxy.alcance_de_consola(["fd00::5"], [], False, [])
        self.assertIsNone(proxy.decidir("fd00::5", s))
        self.assertEqual(proxy.decidir("fd00::6", s), proxy.FUERA)

    def test_alcance_fijo_devuelve_el_mismo(self):
        s = targets.Scope(["10.0.0.0/8"], [])
        self.assertIs(proxy.AlcanceFijo(s).actual(), s)


class AlcanceVivoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ruta = Path(self.tmp.name) / "alcance.json"

    def escribir(self, incluir, excluir=()):
        self.ruta.write_text(json.dumps({"incluir": list(incluir), "excluir": list(excluir)}), encoding="utf-8")

    def test_alcance_vivo_lee_el_fichero(self):
        self.escribir(["10.0.0.0/8"], ["10.0.0.9/32"])
        vivo = proxy.AlcanceVivo(self.ruta)
        self.assertIsNone(proxy.decidir("10.0.0.1", vivo.actual()))
        self.assertEqual(proxy.decidir("10.0.0.9", vivo.actual()), proxy.EXCLUIDA)

    def test_alcance_vivo_relee_si_cambia(self):
        self.escribir(["10.0.0.0/8"])
        vivo = proxy.AlcanceVivo(str(self.ruta))
        self.assertIsNone(proxy.decidir("10.0.0.1", vivo.actual()))
        self.escribir(["10.0.0.0/8"], ["10.0.0.1/32"])  # cambia el tamaño
        self.assertEqual(proxy.decidir("10.0.0.1", vivo.actual()), proxy.EXCLUIDA)

    def test_alcance_vivo_no_relee_si_no_cambia(self):
        self.escribir(["10.0.0.0/8"])
        vivo = proxy.AlcanceVivo(self.ruta)
        primero = vivo.actual()
        with mock.patch.object(Path, "read_text", side_effect=AssertionError("no debía releer")):
            self.assertIs(vivo.actual(), primero)

    def test_alcance_vivo_ilegible_corta_todo(self):
        self.escribir(["10.0.0.0/8"])
        vivo = proxy.AlcanceVivo(self.ruta)
        self.assertIsNotNone(vivo.actual())
        self.ruta.unlink()
        self.assertIsNone(vivo.actual())
        self.assertEqual(proxy.decidir("8.8.4.4", vivo.actual()), proxy.ILEGIBLE)

    def test_alcance_vivo_con_json_roto_corta_todo(self):
        self.ruta.write_text("{\"incluir\": [", encoding="utf-8")
        with mock.patch.object(proxy.time, "sleep"):
            self.assertIsNone(proxy.AlcanceVivo(self.ruta).actual())

    def test_alcance_vivo_con_contenido_invalido_corta_todo(self):
        self.ruta.write_text(json.dumps({"incluir": ["no-es-una-red"], "excluir": []}), encoding="utf-8")
        with mock.patch.object(proxy.time, "sleep"):
            self.assertIsNone(proxy.AlcanceVivo(self.ruta).actual())

    def test_alcance_vivo_reintenta_un_fallo_momentaneo(self):
        self.escribir(["10.0.0.0/8"])
        original = Path.read_text
        llamadas = []

        def falla_una_vez(ruta, *args, **kwargs):
            llamadas.append(1)
            if len(llamadas) == 1:
                raise PermissionError("el fichero se está reemplazando")
            return original(ruta, *args, **kwargs)

        with mock.patch.object(Path, "read_text", falla_una_vez):
            actual = proxy.AlcanceVivo(self.ruta).actual()
        self.assertIsNotNone(actual)
        self.assertGreaterEqual(len(llamadas), 2)


if __name__ == "__main__":
    unittest.main()
