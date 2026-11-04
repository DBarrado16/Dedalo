"""Carpetas base demasiado largas para Windows sin rutas largas (MAX_PATH)."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dedalo import cli, report
from tests.test_dedalo import ROOT


class RutasLargasTests(unittest.TestCase):
    def test_una_carpeta_que_deja_las_capturas_por_encima_de_260_se_rechaza_con_su_motivo(self):
        larga = Path("C:/" + "x" * (260 - report.HOLGURA_DATOS))
        with patch.object(report, "rutas_largas_activadas", return_value=False):
            with self.assertRaisesRegex(ValueError, "demasiado larga"):
                report.comprobar_longitud(larga, report.HOLGURA_DATOS)
            report.comprobar_longitud(Path("C:/datos"), report.HOLGURA_DATOS)
        with patch.object(report, "rutas_largas_activadas", return_value=True):
            report.comprobar_longitud(larga, report.HOLGURA_DATOS)  # con rutas largas, no hay límite

    def test_capturar_no_crea_nada_en_una_salida_demasiado_larga(self):
        with tempfile.TemporaryDirectory() as temporal:
            salida = Path(temporal) / ("y" * 200)
            with patch.object(report, "rutas_largas_activadas", return_value=False):
                codigo = cli.main(["capturar", str(ROOT / "ejemplos" / "escaneo.xml"), "-o", str(salida)])
            self.assertEqual(codigo, 1)
            self.assertFalse(salida.exists())

    def test_la_holgura_del_portal_cubre_la_de_cada_ejecucion(self):
        # El portal captura en <datos>/<id de 32>/resultado: su holgura no puede quedarse corta.
        self.assertGreaterEqual(report.HOLGURA_DATOS, 32 + 1 + len("resultado") + 1 + report.HOLGURA_SALIDA)


if __name__ == "__main__":
    unittest.main()
