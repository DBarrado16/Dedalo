import tempfile
import unittest

from dedalo import auditoria, db


def lectura(servicio_id, origen, producto, version="", confianza=None):
    return {"servicio_id": servicio_id, "origen": origen, "producto": producto,
            "version": version, "confianza": confianza, "detalle": ""}


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.con = db.connect(self.temp.name)
        with self.con:
            self.con.execute("INSERT INTO auditoria (id, nombre, creada) VALUES ('a1', 'C', 't')")
            self.con.execute("INSERT INTO alcance (auditoria_id, tipo, cidr) VALUES ('a1', 'incluir', '10.10.5.3/32')")
            self.con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, nombre, estado, creada) "
                             "VALUES ('imp', 'a1', 'importacion', 'N', 'completa', 't')")
            asset = self.con.execute("INSERT INTO activo (auditoria_id, ip) VALUES ('a1', '10.10.5.3')").lastrowid
            self.svc = self.con.execute("INSERT INTO servicio (activo_id, protocolo, puerto) VALUES (?, 'tcp', 443)",
                                        (asset,)).lastrowid
            self.con.execute("INSERT INTO observacion (ejecucion_id, servicio_id, nombre) VALUES ('imp', ?, 'https')",
                             (self.svc,))
            self.con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, origen_id, nombre, estado, creada) "
                             "VALUES ('cap', 'a1', 'captura', 'imp', 'N', 'completa', 't')")
            self.con.execute("INSERT INTO captura (ejecucion_id, servicio_id, url, estado) "
                             "VALUES ('cap', ?, 'https://10.10.5.3/', 'capturada')", (self.svc,))
            self.con.execute("INSERT INTO captura (ejecucion_id, servicio_id, url, estado) "
                             "VALUES ('cap', ?, 'https://10.10.5.3/otra', 'sin_captura')", (self.svc,))

    def tearDown(self):
        self.con.close()
        self.temp.cleanup()

    def test_captured_services_solo_las_capturadas(self):
        self.assertEqual(auditoria.captured_services(self.con, "cap"),
                         [{"servicio_id": self.svc, "url": "https://10.10.5.3/"}])

    def test_ciclo_start_begin_finish_y_detections(self):
        vid = auditoria.start_version(self.con, "imp", {})
        self.assertEqual(auditoria.version_status(self.con, "imp")["estado"], "en_cola")
        self.assertTrue(auditoria.begin_version(self.con, vid))
        auditoria.finish_version(self.con, vid, [lectura(self.svc, "gowitness", "nginx", "1.18"),
                                                 lectura(self.svc, "ia", "RouterOS", "6.49.7", 90)])
        self.assertEqual(auditoria.version_status(self.con, "imp")["estado"], "completa")
        det = auditoria.detections(self.con, "imp")
        self.assertEqual({(l["origen"], l["producto"]) for l in det[self.svc]},
                         {("gowitness", "nginx"), ("ia", "RouterOS")})

    def test_una_version_completa_sustituye_a_la_anterior(self):
        v1 = auditoria.start_version(self.con, "imp", {})
        auditoria.begin_version(self.con, v1)
        auditoria.finish_version(self.con, v1, [lectura(self.svc, "ia", "Viejo", "", 80)])
        v2 = auditoria.start_version(self.con, "imp", {})
        auditoria.begin_version(self.con, v2)
        auditoria.finish_version(self.con, v2, [lectura(self.svc, "ia", "Nuevo", "", 80)])
        det = auditoria.detections(self.con, "imp")
        self.assertEqual([l["producto"] for l in det[self.svc]], ["Nuevo"])
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM ejecucion WHERE tipo = 'version'").fetchone()[0], 1)

    def test_una_version_que_falla_no_sustituye(self):
        v1 = auditoria.start_version(self.con, "imp", {})
        auditoria.begin_version(self.con, v1)
        auditoria.finish_version(self.con, v1, [lectura(self.svc, "ia", "Bueno", "", 80)])
        v2 = auditoria.start_version(self.con, "imp", {})
        auditoria.begin_version(self.con, v2)
        auditoria.set_state(self.con, v2, "error", "falló")
        det = auditoria.detections(self.con, "imp")
        self.assertEqual([l["producto"] for l in det[self.svc]], ["Bueno"])

    def test_fuera_de_alcance_no_sale(self):
        v = auditoria.start_version(self.con, "imp", {})
        auditoria.begin_version(self.con, v)
        auditoria.finish_version(self.con, v, [lectura(self.svc, "ia", "X", "", 80)])
        with self.con:
            self.con.execute("INSERT INTO alcance (auditoria_id, tipo, cidr) VALUES ('a1', 'excluir', '10.10.5.3/32')")
        self.assertEqual(auditoria.detections(self.con, "imp"), {})

    def test_stop_version_en_cola_cancela(self):
        auditoria.start_version(self.con, "imp", {})
        self.assertEqual(auditoria.stop_version(self.con, "imp"), "cancelada")

    def test_close_interrupted_cierra_la_version_a_medias(self):
        auditoria.start_version(self.con, "imp", {})
        auditoria.close_interrupted_analyses(self.con)
        self.assertEqual(auditoria.version_status(self.con, "imp")["estado"], "interrumpida")


if __name__ == "__main__":
    unittest.main()
