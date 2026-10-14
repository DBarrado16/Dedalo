from contextlib import closing
import hashlib
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from dedalo import auditoria, db, inventory, parser
from tests.test_dedalo import ROOT


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.con = db.connect(self.root)
        self.audit = auditoria.default_audit(self.con)

    def tearDown(self):
        self.con.close()
        self.temp.cleanup()

    def load(self, execution, source="inventario.xml", hosts=None):
        path = self.root / execution / source
        path.parent.mkdir(exist_ok=True)
        shutil.copy(ROOT / "ejemplos" / source, path)
        hosts = hosts if hosts is not None else parser.merge([parser.parse_file(path)])
        auditoria.import_nmap(self.con, self.audit, execution, "Nmap " + execution, hosts, [path], self.root)
        return hosts, path

    def count(self, table):
        return self.con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def test_round_trip_keeps_every_field_the_inventory_shows(self):
        hosts, _ = self.load("lunes")
        networks = ["192.0.2.0/24", "2001:db8::/48"]
        self.assertEqual(inventory.build(auditoria.observed_hosts(self.con, "lunes"), networks),
                         inventory.build(hosts, networks))

    def test_import_records_execution_and_original_as_evidence(self):
        _, path = self.load("lunes")
        execution = self.con.execute("SELECT * FROM ejecucion").fetchone()
        self.assertEqual((execution["tipo"], execution["estado"], execution["auditoria_id"]), ("importacion", "completa", self.audit))
        evidence = self.con.execute("SELECT * FROM evidencia").fetchone()
        self.assertEqual((evidence["tipo"], evidence["ruta"]), ("nmap", "lunes/inventario.xml"))
        self.assertEqual(evidence["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_repeated_assets_are_shared_but_observations_are_kept_apart(self):
        hosts, _ = self.load("lunes")
        changed = parser.merge([hosts])
        changed[0].ports[22].version = "9.7"
        self.load("jueves", hosts=changed)
        self.assertEqual((self.count("activo"), self.count("servicio")), (4, 9))
        self.assertEqual((self.count("observacion_activo"), self.count("observacion")), (8, 18))
        versions = [row[0] for row in self.con.execute(
            "SELECT o.version FROM observacion o JOIN servicio s ON s.id = o.servicio_id JOIN activo a ON a.id = s.activo_id "
            "WHERE a.ip = ? AND s.puerto = 22 ORDER BY o.ejecucion_id DESC", (hosts[0].ip,))]
        self.assertEqual(versions, ["9.6", "9.7"])  # lunes, jueves
        self.assertEqual(auditoria.observed_hosts(self.con, "lunes")[0].ports[22].version, "9.6")

    def test_delete_keeps_assets_seen_by_other_executions(self):
        hosts, _ = self.load("lunes")
        self.load("jueves", hosts=hosts[:1])
        auditoria.delete_execution(self.con, "lunes")
        self.assertEqual([row[0] for row in self.con.execute("SELECT ip FROM activo")], [hosts[0].ip])
        self.assertEqual(self.count("servicio"), len(hosts[0].ports) + len(hosts[0].udp_ports))
        self.assertEqual(self.count("evidencia"), 1)

    def test_failed_import_leaves_nothing(self):
        hosts, _ = self.load("lunes")
        with self.assertRaises(sqlite3.IntegrityError):
            self.load("lunes", hosts=hosts)  # misma ejecución dos veces
        self.assertEqual((self.count("ejecucion"), self.count("observacion")), (1, 9))

    def priority(self, ip, order, level="alta", role="Rol"):
        return {"ip": ip, "orden": order, "rol": role, "nivel": level, "motivo": "Por sus servicios.", "siguiente": "Revisar."}

    def load_in_scope(self, execution):
        """Importa el inventario de ejemplo en una ficha cuyo alcance cubre sus hosts."""
        self.audit = auditoria.create_audit(self.con, "Laboratorio", "192.0.2.0/24")
        return self.load(execution)

    def test_analysis_keeps_its_priorities_in_order(self):
        self.load_in_scope("lunes")
        self.assertEqual((auditoria.analysis_status(self.con, "lunes"), auditoria.priorities(self.con, "lunes")), (None, []))
        analysis = auditoria.start_analysis(self.con, "lunes", {"modelo": "llama3.2:3b"})
        row = self.con.execute("SELECT tipo, origen_id, estado, opciones FROM ejecucion WHERE id = ?", (analysis,)).fetchone()
        self.assertEqual(tuple(row[:3]), ("analisis", "lunes", "en_cola"))
        self.assertIn("llama3.2:3b", row["opciones"])
        self.assertEqual(auditoria.analysis_status(self.con, "lunes"), {"estado": "en_cola", "error": ""})
        auditoria.finish_analysis(self.con, analysis, [
            self.priority("192.0.2.20", 1, "baja", "Estación"), self.priority("192.0.2.10", 0, "alta", "Servidor"),
            self.priority("203.0.113.9", 2)])  # una IP que no es de la ficha no se guarda
        self.assertEqual([(p["ip"], p["rol"], p["nivel"]) for p in auditoria.priorities(self.con, "lunes")],
                         [("192.0.2.10", "Servidor", "alta"), ("192.0.2.20", "Estación", "baja")])
        self.assertEqual(set(auditoria.priorities(self.con, "lunes")[0]), {"ip", "rol", "nivel", "motivo", "siguiente"})

    def test_a_host_excluded_after_the_analysis_is_left_out(self):
        self.load_in_scope("lunes")
        analysis = auditoria.start_analysis(self.con, "lunes", {})
        auditoria.finish_analysis(self.con, analysis, [self.priority("192.0.2.10", 0), self.priority("192.0.2.20", 1)])
        auditoria.update_audit(self.con, self.audit, "Laboratorio", "192.0.2.0/24", "192.0.2.20")
        self.assertEqual([p["ip"] for p in auditoria.priorities(self.con, "lunes")], ["192.0.2.10"])  # la exclusión gana

    def analyses(self):
        return self.con.execute("SELECT COUNT(*) FROM ejecucion WHERE tipo = 'analisis'").fetchone()[0]

    def test_analysing_again_keeps_the_previous_result_until_the_new_one_completes(self):
        self.load_in_scope("lunes")
        first = auditoria.start_analysis(self.con, "lunes", {"modelo": "m"})
        auditoria.finish_analysis(self.con, first, [self.priority("192.0.2.10", 0, role="Antes")])
        second = auditoria.start_analysis(self.con, "lunes", {"modelo": "m"})
        self.assertEqual(auditoria.analysis_status(self.con, "lunes"), {"estado": "en_cola", "error": ""})
        self.assertEqual([p["rol"] for p in auditoria.priorities(self.con, "lunes")], ["Antes"])
        auditoria.finish_analysis(self.con, second, [self.priority("192.0.2.10", 0, role="Después")])
        self.assertEqual(auditoria.analysis_status(self.con, "lunes"), {"estado": "completa", "error": ""})
        self.assertEqual([p["rol"] for p in auditoria.priorities(self.con, "lunes")], ["Después"])
        self.assertEqual(self.analyses(), 1)

    def test_a_failed_reanalysis_keeps_the_previous_result(self):
        self.load_in_scope("lunes")
        first = auditoria.start_analysis(self.con, "lunes", {})
        auditoria.finish_analysis(self.con, first, [self.priority("192.0.2.10", 0, role="Antes")])
        failed = auditoria.start_analysis(self.con, "lunes", {})
        auditoria.set_state(self.con, failed, "error", "Ollama apagado")
        self.assertEqual(auditoria.analysis_status(self.con, "lunes"), {"estado": "error", "error": "Ollama apagado"})
        self.assertEqual([p["rol"] for p in auditoria.priorities(self.con, "lunes")], ["Antes"])
        auditoria.start_analysis(self.con, "lunes", {})  # el intento fallido ya no hace falta; el completo, sí
        self.assertEqual(self.analyses(), 2)
        self.assertEqual([p["rol"] for p in auditoria.priorities(self.con, "lunes")], ["Antes"])

    def test_only_imports_can_be_analysed(self):
        with self.assertRaises(FileNotFoundError):
            auditoria.start_analysis(self.con, "no-existe", {})

    def test_default_audit_is_created_once(self):
        self.assertEqual(auditoria.default_audit(self.con), self.audit)
        with closing(db.connect(self.root)) as other:
            self.assertEqual(auditoria.default_audit(other), self.audit)
        self.assertEqual(self.count("auditoria"), 1)
