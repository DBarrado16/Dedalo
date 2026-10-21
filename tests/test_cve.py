import sqlite3
import tempfile
import unittest

from dedalo import cve, db


def regla(producto, vendor="apache", v_ini=None, v_ini_incl=1, v_fin=None, v_fin_incl=0, parte="a"):
    return {"parte": parte, "vendor": vendor, "producto": producto,
            "v_ini": v_ini, "v_ini_incl": v_ini_incl, "v_fin": v_fin, "v_fin_incl": v_fin_incl}


def item(cve_id, cpes, severidad="ALTA", cvss=7.5, resumen="", publicada="2026-01-01T00:00:00Z"):
    return {"id": cve_id, "publicada": publicada, "severidad": severidad, "cvss": cvss,
            "resumen": resumen or cve_id, "cpes": cpes}


class CompararVersionesTests(unittest.TestCase):
    def test_orden_numerico_por_componentes(self):
        self.assertEqual(cve.comparar_versiones("2.4.9", "2.4.10"), -1)
        self.assertEqual(cve.comparar_versiones("2.4.10", "2.4.9"), 1)
        self.assertEqual(cve.comparar_versiones("10.0", "9.9.9"), 1)

    def test_iguales_y_ceros_a_la_derecha(self):
        self.assertEqual(cve.comparar_versiones("1.0", "1.0.0"), 0)
        self.assertEqual(cve.comparar_versiones("1.0.0", "1.0"), 0)
        self.assertEqual(cve.comparar_versiones("2.4.59", "2.4.59"), 0)

    def test_componentes_no_numericos_son_lexicograficos(self):
        self.assertEqual(cve.comparar_versiones("1.0.a", "1.0.b"), -1)
        self.assertEqual(cve.comparar_versiones("1.0.b", "1.0.a"), 1)
        self.assertEqual(cve.comparar_versiones("1.0a", "1.0a"), 0)

    def test_version_mas_larga_con_resto_no_nulo_es_mayor(self):
        self.assertEqual(cve.comparar_versiones("1.0", "1.0.1"), -1)
        self.assertEqual(cve.comparar_versiones("1.0.1", "1.0"), 1)


class CvesDeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.con = db.connect(self.temp.name)
        cve.guardar_cves(self.con, [
            item("CVE-2026-0001", [regla("http_server", v_ini="2.4.0", v_fin="2.4.58", v_fin_incl=1)]),   # <= 2.4.58
            item("CVE-2026-0002", [regla("http_server", v_ini="2.4.0", v_fin="2.4.60")]),                 # 2.4.0 <= v < 2.4.60
            item("CVE-2026-0003", [regla("http_server", v_fin="2.4.59")], cvss=9.8),                      # < 2.4.59 (borde)
            item("CVE-2026-0004", [regla("http_server", v_ini="2.4.59", v_fin="2.4.59", v_fin_incl=1)]),  # exactamente 2.4.59
            item("CVE-2026-0005", [regla("http_server")]),                                                # sin rango: todas
            item("CVE-2026-0006", [regla("http_server", v_ini="2.4.59", v_ini_incl=0, v_fin="2.5.0")]),   # > 2.4.59 (borde)
            item("CVE-2026-0007", [regla("nginx", vendor="f5", v_fin="1.25.0")]),
            item("CVE-2026-0008", [regla("http_server", vendor="otro", v_fin="9.9")]),
        ])

    def tearDown(self):
        self.con.close()
        self.temp.cleanup()

    def ids(self, filas):
        return sorted(f["id"] for f in filas)

    def test_casa_por_producto_y_rango(self):
        filas = cve.cves_de(self.con, "cpe:/a:apache:http_server:2.4.59")
        self.assertEqual(self.ids(filas), ["CVE-2026-0002", "CVE-2026-0004", "CVE-2026-0005"])

    def test_los_bordes_excluidos_no_casan(self):
        ids = self.ids(cve.cves_de(self.con, "cpe:/a:apache:http_server:2.4.59"))
        self.assertNotIn("CVE-2026-0001", ids)   # <= 2.4.58
        self.assertNotIn("CVE-2026-0003", ids)   # versionEndExcluding = 2.4.59
        self.assertNotIn("CVE-2026-0006", ids)   # versionStartExcluding = 2.4.59

    def test_los_bordes_incluidos_casan(self):
        self.assertEqual(self.ids(cve.cves_de(self.con, "cpe:/a:apache:http_server:2.4.58")),
                         ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0005"])

    def test_con_version_la_marca_es_falsa(self):
        filas = cve.cves_de(self.con, "cpe:/a:apache:http_server:2.4.59")
        self.assertTrue(all(f["sin_version"] is False for f in filas))

    def test_cpe_sin_version_marca_sin_version(self):
        filas = cve.cves_de(self.con, "cpe:/a:apache:http_server")
        self.assertEqual(self.ids(filas), ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003",
                                           "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006"])
        self.assertTrue(all(f["sin_version"] is True for f in filas))

    def test_version_comodin_cuenta_como_sin_version(self):
        for cpe in ("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*"):
            with self.subTest(cpe=cpe):
                filas = cve.cves_de(self.con, cpe)
                self.assertTrue(filas and all(f["sin_version"] for f in filas))

    def test_formato_cpe_23(self):
        filas = cve.cves_de(self.con, "cpe:2.3:a:apache:http_server:2.4.59:*:*:*:*:*:*:*")
        self.assertEqual(self.ids(filas), ["CVE-2026-0002", "CVE-2026-0004", "CVE-2026-0005"])

    def test_vendor_del_cpe_filtra_y_sin_vendor_no(self):
        # El vendor «otro» no casa con apache...
        self.assertNotIn("CVE-2026-0008", self.ids(cve.cves_de(self.con, "cpe:/a:apache:http_server:2.4.59")))
        # ...y un cpe sin vendor casa solo por producto.
        self.assertIn("CVE-2026-0008", self.ids(cve.cves_de(self.con, "cpe:/a::http_server:2.4.59")))

    def test_mayusculas_no_importan(self):
        filas = cve.cves_de(self.con, "cpe:/a:Apache:HTTP_Server:2.4.59")
        self.assertEqual(len(filas), 3)

    def test_producto_desconocido_o_cpe_invalido_devuelve_vacio(self):
        self.assertEqual(cve.cves_de(self.con, "cpe:/a:apache:desconocido:1.0"), [])
        for cpe in ("", "no es un cpe", "cpe:/a", "cpe:/a:apache"):
            with self.subTest(cpe=cpe):
                self.assertEqual(cve.cves_de(self.con, cpe), [])

    def test_cada_cve_sale_una_vez_aunque_casen_varias_reglas(self):
        cve.guardar_cves(self.con, [item("CVE-2026-0009", [regla("http_server", v_fin="3.0"),
                                                           regla("http_server", v_ini="2.0", v_fin="2.9")])])
        filas = [f for f in cve.cves_de(self.con, "cpe:/a:apache:http_server:2.4.59") if f["id"] == "CVE-2026-0009"]
        self.assertEqual(len(filas), 1)

    def test_fila_con_los_datos_de_la_cve_y_orden_por_gravedad(self):
        filas = cve.cves_de(self.con, "cpe:/a:apache:http_server:2.4.50")
        self.assertEqual(filas[0]["id"], "CVE-2026-0003")   # cvss 9.8 primero
        self.assertEqual(set(filas[0]), {"id", "publicada", "severidad", "cvss", "resumen", "sin_version"})
        self.assertEqual((filas[0]["severidad"], filas[0]["cvss"]), ("ALTA", 9.8))


class GuardarCvesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.con = db.connect(self.temp.name)

    def tearDown(self):
        self.con.close()
        self.temp.cleanup()

    def cuenta(self, tabla):
        return self.con.execute(f"SELECT COUNT(*) FROM {tabla}").fetchone()[0]

    def test_es_idempotente(self):
        datos = [item("CVE-2026-0001", [regla("http_server", v_fin="2.4.59")])]
        cve.guardar_cves(self.con, datos)
        cve.guardar_cves(self.con, datos)
        self.assertEqual((self.cuenta("cve"), self.cuenta("cve_cpe")), (1, 1))

    def test_actualiza_la_cve_y_sustituye_sus_reglas(self):
        cve.guardar_cves(self.con, [item("CVE-2026-0001", [regla("http_server", v_fin="2.4.59")], cvss=5.0)])
        cve.guardar_cves(self.con, [item("CVE-2026-0001", [regla("http_server", v_fin="2.4.50")], cvss=9.0, severidad="CRITICA")])
        fila = self.con.execute("SELECT severidad, cvss FROM cve WHERE id = 'CVE-2026-0001'").fetchone()
        self.assertEqual(tuple(fila), ("CRITICA", 9.0))
        reglas = self.con.execute("SELECT v_fin FROM cve_cpe WHERE cve_id = 'CVE-2026-0001'").fetchall()
        self.assertEqual([r[0] for r in reglas], ["2.4.50"])
        self.assertEqual(cve.cves_de(self.con, "cpe:/a:apache:http_server:2.4.55"), [])

    def test_ignora_entradas_mal_formadas(self):
        buenas = item("CVE-2026-0001", [regla("http_server", v_fin="2.4.59")])
        cve.guardar_cves(self.con, [
            "texto", None, 5, {}, {"id": ""}, {"id": 7},
            {"id": "CVE-2026-0002", "cpes": "no es una lista"},
            buenas,
            item("CVE-2026-0003", ["no es un dict", {"vendor": "x"}, {"producto": ""}, regla("http_server", v_fin="1.0")]),
        ])
        self.assertEqual(sorted(r[0] for r in self.con.execute("SELECT id FROM cve")),
                         ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"])
        # CVE-0003 conserva solo su regla válida; CVE-0002 se guarda sin reglas.
        self.assertEqual(self.cuenta("cve_cpe"), 2)

    def test_campos_opcionales_toman_valores_por_defecto(self):
        cve.guardar_cves(self.con, [{"id": "CVE-2026-0001", "cpes": [{"producto": "nginx"}]}])
        fila = self.con.execute("SELECT publicada, severidad, cvss, resumen FROM cve").fetchone()
        self.assertEqual(tuple(fila), ("", "", None, ""))
        regla_ = self.con.execute("SELECT parte, vendor, producto, v_ini, v_fin FROM cve_cpe").fetchone()
        self.assertEqual(tuple(regla_), ("", "", "nginx", None, None))
        self.assertEqual(len(cve.cves_de(self.con, "cpe:/a:f5:nginx:1.0")), 1)

    def test_todo_o_nada_si_la_escritura_falla(self):
        cve.guardar_cves(self.con, [item("CVE-2026-0001", [regla("http_server", v_fin="2.4.59")])])
        self.con.execute("CREATE TRIGGER falla BEFORE INSERT ON cve_cpe WHEN NEW.producto = 'falla' "
                         "BEGIN SELECT RAISE(ABORT, 'escritura rechazada'); END")
        with self.assertRaises(sqlite3.DatabaseError):
            cve.guardar_cves(self.con, [item("CVE-2026-0003", [regla("nginx")]),
                                        item("CVE-2026-0002", [regla("falla")])])
        self.assertEqual([r[0] for r in self.con.execute("SELECT id FROM cve")], ["CVE-2026-0001"])


if __name__ == "__main__":
    unittest.main()
