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
