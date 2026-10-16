import json
from pathlib import Path
import tempfile
import unittest

from dedalo import catalogo, db


class CatalogoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.con = db.connect(self.root)

    def tearDown(self):
        self.con.close()
        self.temp.cleanup()

    def fichero(self, entradas):
        ruta = self.root / "credenciales.json"
        ruta.write_text(json.dumps({"version": "test", "entradas": entradas}, ensure_ascii=False), encoding="utf-8")
        return ruta

    def test_loads_entries_and_decodes_the_recipe(self):
        ruta = self.fichero([
            {"fabricante": "Cisco", "producto": "RV340", "servicio": "http-form",
             "credenciales": [{"usuario": "cisco", "clave": "cisco"}],
             "receta": {"ruta": "/login", "campo_usuario": "user", "campo_clave": "pwd"}},
            {"producto": "vsftpd", "servicio": "ftp", "credenciales": [{"usuario": "anonymous", "clave": ""}]},
        ])
        self.assertEqual(catalogo.cargar(self.con, ruta), 2)
        filas = catalogo.entradas(self.con)
        self.assertEqual({f["producto"] for f in filas}, {"RV340", "vsftpd"})
        cisco = next(f for f in filas if f["producto"] == "RV340")
        self.assertEqual(cisco["receta"]["campo_usuario"], "user")

    def test_reload_only_happens_when_the_file_changes(self):
        ruta = self.fichero([{"producto": "A", "servicio": "ftp", "credenciales": [{"usuario": "a", "clave": "b"}]}])
        self.assertEqual(catalogo.cargar(self.con, ruta), 1)
        self.assertEqual(catalogo.cargar(self.con, ruta), 0)  # misma huella: no recarga
        self.fichero([{"producto": "B", "servicio": "ftp", "credenciales": [{"usuario": "c", "clave": "d"}]}])
        self.assertEqual(catalogo.cargar(self.con, ruta), 1)
        self.assertEqual([f["producto"] for f in catalogo.entradas(self.con)], ["B"])

    def test_a_bad_entry_is_skipped_not_fatal(self):
        ruta = self.fichero([
            {"servicio": "ftp", "credenciales": [{"usuario": "a", "clave": "b"}]},  # sin producto: se ignora
            {"producto": "X", "servicio": "telnet", "credenciales": [{"usuario": "a", "clave": "b"}]},  # servicio no válido
            {"producto": "Y", "servicio": "ftp", "credenciales": [{"usuario": "a", "clave": "b"}]},  # válida
        ])
        self.assertEqual(catalogo.cargar(self.con, ruta), 1)
        self.assertEqual([f["producto"] for f in catalogo.entradas(self.con)], ["Y"])

    def test_the_shipped_catalog_loads(self):
        self.assertGreater(catalogo.cargar(self.con, catalogo.RUTA), 0)

    def test_agregar_crea_una_entrada_nueva(self):
        ruta = self.fichero([{"producto": "A", "servicio": "ftp", "credenciales": [{"usuario": "a", "clave": "b"}]}])
        catalogo.agregar(ruta, {"fabricante": "ACME", "producto": "vsftpd", "version": "", "servicio": "ftp",
                                "credenciales": [{"usuario": "ftp", "clave": "ftp"}], "fuente": "manual"})
        datos = json.loads(ruta.read_text("utf-8"))
        self.assertEqual(datos["entradas"][-1]["producto"], "vsftpd")
        self.assertEqual(datos["entradas"][-1]["credenciales"], [{"usuario": "ftp", "clave": "ftp"}])

    def test_agregar_fusiona_en_la_entrada_existente_sin_duplicar(self):
        ruta = self.fichero([{"fabricante": "ACME", "producto": "vsftpd", "version": "", "servicio": "ftp",
                              "credenciales": [{"usuario": "ftp", "clave": "ftp"}]}])
        catalogo.agregar(ruta, {"fabricante": "ACME", "producto": "vsftpd", "version": "", "servicio": "ftp",
                                "credenciales": [{"usuario": "ftp", "clave": "ftp"}, {"usuario": "admin", "clave": "admin"}]})
        entradas = [e for e in json.loads(ruta.read_text("utf-8"))["entradas"] if e["producto"] == "vsftpd"]
        self.assertEqual(len(entradas), 1)
        self.assertEqual(entradas[0]["credenciales"], [{"usuario": "ftp", "clave": "ftp"}, {"usuario": "admin", "clave": "admin"}])

    def test_agregar_conserva_la_estructura_del_fichero(self):
        ruta = self.fichero([{"producto": "A", "servicio": "ftp", "credenciales": [{"usuario": "a", "clave": "b"}]}])
        catalogo.agregar(ruta, {"producto": "B", "servicio": "ftp", "credenciales": [{"usuario": "c", "clave": "d"}]})
        datos = json.loads(ruta.read_text("utf-8"))
        self.assertEqual(datos["version"], "test")                 # version intacta
        self.assertEqual(len(datos["entradas"]), 2)

    def test_agregar_rechaza_lo_invalido_y_no_escribe(self):
        ruta = self.fichero([{"producto": "A", "servicio": "ftp", "credenciales": [{"usuario": "a", "clave": "b"}]}])
        antes = ruta.read_text("utf-8")
        base = {"producto": "Z", "servicio": "ftp", "credenciales": [{"usuario": "x", "clave": "y"}]}
        for mala in ({**base, "servicio": "ssh"}, {**base, "producto": ""}, {**base, "credenciales": [{"usuario": "x"}]}):
            with self.assertRaises(ValueError):
                catalogo.agregar(ruta, mala)
        self.assertEqual(ruta.read_text("utf-8"), antes)           # el fichero no cambió
