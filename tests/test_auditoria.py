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

    def test_a_queued_analysis_is_cancelled_and_never_starts(self):
        self.load_in_scope("lunes")
        analysis = auditoria.start_analysis(self.con, "lunes", {})
        self.assertEqual(auditoria.stop_analysis(self.con, "lunes"), "cancelada")
        self.assertFalse(auditoria.begin_analysis(self.con, analysis))  # el hilo de la cola ya no lo empieza
        self.assertEqual(auditoria.analysis_status(self.con, "lunes")["estado"], "cancelada")

    def test_a_running_analysis_is_asked_to_stop_once(self):
        self.load_in_scope("lunes")
        self.assertIsNone(auditoria.stop_analysis(self.con, "lunes"))  # no hay ninguno
        analysis = auditoria.start_analysis(self.con, "lunes", {})
        self.assertTrue(auditoria.begin_analysis(self.con, analysis))
        self.assertEqual(auditoria.stop_analysis(self.con, "lunes"), "deteniendo")
        self.assertIsNone(auditoria.stop_analysis(self.con, "lunes"))  # ya se pidió
        auditoria.close_interrupted_analyses(self.con)  # si se cierra el portal mientras para
        self.assertEqual(auditoria.analysis_status(self.con, "lunes")["estado"], "interrumpida")

    def test_the_newest_attempt_wins_even_if_the_clock_went_back(self):
        self.load_in_scope("lunes")
        first = auditoria.start_analysis(self.con, "lunes", {}, created="2026-10-14T10:00:00+00:00")
        auditoria.finish_analysis(self.con, first, [self.priority("192.0.2.10", 0)])
        auditoria.start_analysis(self.con, "lunes", {}, created="2026-10-14T09:00:00+00:00")  # reloj atrasado
        self.assertEqual(auditoria.analysis_status(self.con, "lunes")["estado"], "en_cola")

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

    def credential_row(self, ip, order, estado="entrada", servicio="http-form"):
        return {"ip": ip, "orden": order, "puerto": 8443, "protocolo": "tcp", "servicio": servicio,
                "estado": estado, "usuario": "admin", "clave": "admin", "detalle": ""}

    def test_credential_test_keeps_results_and_replaces_only_on_complete(self):
        self.load_in_scope("lunes")
        self.assertEqual((auditoria.credential_status(self.con, "lunes"), auditoria.credential_results(self.con, "lunes")), (None, []))
        first = auditoria.start_credential_test(self.con, "lunes", {})
        self.assertTrue(auditoria.begin_credential_test(self.con, first))
        auditoria.finish_credential_test(self.con, first, [self.credential_row("192.0.2.10", 0)])
        self.assertEqual(auditoria.credential_status(self.con, "lunes"), {"estado": "completa", "error": ""})
        self.assertEqual([r["ip"] for r in auditoria.credential_results(self.con, "lunes")], ["192.0.2.10"])
        second = auditoria.start_credential_test(self.con, "lunes", {})  # vuelve a probar
        auditoria.set_state(self.con, second, "error", "sin respuesta")
        self.assertEqual(auditoria.credential_status(self.con, "lunes")["estado"], "error")
        self.assertEqual([r["ip"] for r in auditoria.credential_results(self.con, "lunes")], ["192.0.2.10"])  # el bueno sigue

    def test_a_host_excluded_after_the_credential_test_is_left_out(self):
        self.load_in_scope("lunes")
        test = auditoria.start_credential_test(self.con, "lunes", {})
        auditoria.finish_credential_test(self.con, test, [self.credential_row("192.0.2.10", 0), self.credential_row("192.0.2.20", 1)])
        auditoria.update_audit(self.con, self.audit, "Laboratorio", "192.0.2.0/24", "192.0.2.20")
        self.assertEqual([r["ip"] for r in auditoria.credential_results(self.con, "lunes")], ["192.0.2.10"])

    def test_stopping_and_closing_a_credential_test(self):
        self.load_in_scope("lunes")
        self.assertIsNone(auditoria.stop_credential_test(self.con, "lunes"))
        test = auditoria.start_credential_test(self.con, "lunes", {})
        self.assertEqual(auditoria.stop_credential_test(self.con, "lunes"), "cancelada")
        self.assertFalse(auditoria.begin_credential_test(self.con, test))
        other = auditoria.start_credential_test(self.con, "lunes", {})
        auditoria.begin_credential_test(self.con, other)
        self.assertEqual(auditoria.stop_credential_test(self.con, "lunes"), "deteniendo")
        auditoria.close_interrupted_analyses(self.con)
        self.assertEqual(auditoria.credential_status(self.con, "lunes")["estado"], "interrumpida")

    def discovery_row(self, ip, modo, encontrado=True, nombre="", detalle=""):
        return {"ip": ip, "modo": modo, "encontrado": encontrado, "nombre": nombre, "detalle": detalle, "error": ""}

    def test_discovery_names_become_asset_observations(self):
        self.load_in_scope("lunes")
        disc = auditoria.start_discovery(self.con, "lunes", {"modo": "nombres"})
        self.assertTrue(auditoria.begin_discovery(self.con, disc))
        auditoria.finish_discovery(self.con, disc, [self.discovery_row("192.0.2.10", "nombres", nombre="dc.local"),
                                                   self.discovery_row("203.0.113.9", "nombres", nombre="fuera")])
        self.assertEqual(auditoria.discovery_status(self.con, "lunes"), {"estado": "completa", "error": ""})
        res = auditoria.discovery_results(self.con, "lunes")  # 203.0.113.9 no está en 192.0.2.0/24: no sale
        self.assertEqual([(r["ip"], r["nombre"]) for r in res], [("192.0.2.10", "dc.local")])

    def test_discovery_servers_become_a_udp53_service(self):
        self.load_in_scope("lunes")
        disc = auditoria.start_discovery(self.con, "lunes", {"modo": "servidores"})
        auditoria.begin_discovery(self.con, disc)
        auditoria.finish_discovery(self.con, disc, [self.discovery_row("192.0.2.10", "servidores", detalle="correcta; 1 respuesta(s)")])
        fila = self.con.execute(
            "SELECT s.protocolo, s.puerto, o.nombre FROM observacion o JOIN servicio s ON s.id = o.servicio_id "
            "JOIN activo a ON a.id = s.activo_id WHERE a.ip = '192.0.2.10' AND s.puerto = 53").fetchone()
        self.assertEqual((fila["protocolo"], fila["puerto"], fila["nombre"]), ("udp", 53, "domain"))
        self.assertEqual([r["detalle"] for r in auditoria.discovery_results(self.con, "lunes")], ["correcta; 1 respuesta(s)"])

    def test_re_discovering_does_not_duplicate_assets_or_services(self):
        self.load_in_scope("lunes")
        for _ in range(2):
            disc = auditoria.start_discovery(self.con, "lunes", {"modo": "servidores"})
            auditoria.begin_discovery(self.con, disc)
            auditoria.finish_discovery(self.con, disc, [self.discovery_row("192.0.2.77", "servidores", detalle="correcta; 0 respuesta(s)")])
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM activo WHERE ip = '192.0.2.77'").fetchone()[0], 1)
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM servicio s JOIN activo a ON a.id=s.activo_id "
                                          "WHERE a.ip='192.0.2.77' AND s.puerto=53").fetchone()[0], 1)

    def test_only_found_discovery_rows_are_stored(self):
        self.load_in_scope("lunes")
        disc = auditoria.start_discovery(self.con, "lunes", {"modo": "nombres"})
        auditoria.begin_discovery(self.con, disc)
        auditoria.finish_discovery(self.con, disc, [self.discovery_row("192.0.2.10", "nombres", encontrado=False)])
        self.assertEqual(auditoria.discovery_results(self.con, "lunes"), [])  # lo no encontrado no se guarda

    # --- Ejecución `vuln` (cruce de vulnerabilidades por CPE) ---

    def service_id(self, ip, port, protocol="tcp"):
        return self.con.execute("SELECT s.id FROM servicio s JOIN activo a ON a.id = s.activo_id "
                                "WHERE a.ip = ? AND s.protocolo = ? AND s.puerto = ?", (ip, protocol, port)).fetchone()[0]

    def vuln_row(self, service, estado="ok", vulns=None):
        return {"servicio_id": service, "estado": estado, "vulns": vulns or []}

    def vuln_item(self, cve="CVE-2026-0001", nivel="confirmado", cpe="cpe:/a:openbsd:openssh:9.6", fuente="nmap"):
        return {"cve": cve, "severidad": "CRITICAL", "exploit_nivel": nivel,
                "enlaces_exploit": ["https://www.exploit-db.com/exploits/1"], "origen_cpe": cpe, "fuente_cpe": fuente}

    def test_vuln_services_gives_the_nmap_cpe_and_the_good_readings_of_each_observed_service(self):
        self.load_in_scope("lunes")
        ssh = self.service_id("192.0.2.10", 22)
        version = auditoria.start_version(self.con, "lunes", {})
        auditoria.begin_version(self.con, version)
        auditoria.finish_version(self.con, version, [
            {"servicio_id": ssh, "origen": "ia", "producto": "OpenSSH", "version": "9.6p1", "confianza": 90, "detalle": ""}])
        services = {(s["ip"], s["protocolo"], s["puerto"]): s for s in auditoria.vuln_services(self.con, "lunes")}
        self.assertEqual(services[("192.0.2.10", "tcp", 22)]["cpe"], ["cpe:/a:openbsd:openssh:9.6"])
        self.assertEqual(services[("192.0.2.10", "tcp", 22)]["lecturas"],
                         [{"producto": "OpenSSH", "version": "9.6p1", "confianza": 90}])
        self.assertEqual(services[("192.0.2.10", "tcp", 80)]["cpe"], [])
        self.assertIn(("192.0.2.20", "udp", 53), services)  # también los UDP observados

    def test_vuln_cycle_keeps_no_data_apart_from_no_vulnerabilities(self):
        self.load_in_scope("lunes")
        ssh, http, https = (self.service_id("192.0.2.10", p) for p in (22, 80, 443))
        vuln = auditoria.start_vuln(self.con, "lunes", {})
        self.assertEqual(auditoria.vuln_status(self.con, "lunes"), {"estado": "en_cola", "error": ""})
        self.assertTrue(auditoria.begin_vuln(self.con, vuln))
        auditoria.finish_vuln(self.con, vuln, [
            self.vuln_row(ssh, "ok", [self.vuln_item()]),
            self.vuln_row(http, "ok"),            # se miró y no hay CVE: limpio
            self.vuln_row(https, "sin_datos")])   # no se pudo mirar: NO es limpio
        self.assertEqual(auditoria.vuln_status(self.con, "lunes")["estado"], "completa")
        results = {(r["ip"], r["puerto"]): r for r in auditoria.vuln_results(self.con, "lunes")}
        self.assertEqual(results[("192.0.2.10", 80)]["estado"], "ok")
        self.assertEqual(results[("192.0.2.10", 80)]["vulns"], [])
        self.assertEqual(results[("192.0.2.10", 443)]["estado"], "sin_datos")
        self.assertEqual(results[("192.0.2.10", 443)]["vulns"], [])
        self.assertEqual(results[("192.0.2.10", 22)]["estado"], "ok")
        self.assertEqual(results[("192.0.2.10", 22)]["vulns"], [{
            "cve": "CVE-2026-0001", "severidad": "CRITICAL", "exploit_nivel": "confirmado",
            "enlaces_exploit": ["https://www.exploit-db.com/exploits/1"],
            "cpe": "cpe:/a:openbsd:openssh:9.6", "fuente_cpe": "nmap"}])

    def test_a_service_that_was_never_crossed_has_no_vuln_result(self):
        self.load_in_scope("lunes")
        ssh = self.service_id("192.0.2.10", 22)
        vuln = auditoria.start_vuln(self.con, "lunes", {})
        auditoria.begin_vuln(self.con, vuln)
        auditoria.finish_vuln(self.con, vuln, [self.vuln_row(ssh)])
        self.assertEqual([(r["ip"], r["puerto"]) for r in auditoria.vuln_results(self.con, "lunes")], [("192.0.2.10", 22)])

    def test_vuln_results_only_show_what_is_in_scope_now(self):
        self.load_in_scope("lunes")
        ssh = self.service_id("192.0.2.10", 22)
        vuln = auditoria.start_vuln(self.con, "lunes", {})
        auditoria.begin_vuln(self.con, vuln)
        auditoria.finish_vuln(self.con, vuln, [self.vuln_row(ssh, "ok", [self.vuln_item()])])
        auditoria.update_audit(self.con, self.audit, "Laboratorio", "192.0.2.0/24", "192.0.2.10")
        self.assertEqual(auditoria.vuln_results(self.con, "lunes"), [])

    def test_a_completed_vuln_run_replaces_the_previous_one_but_a_failed_one_does_not(self):
        self.load_in_scope("lunes")
        ssh = self.service_id("192.0.2.10", 22)
        first = auditoria.start_vuln(self.con, "lunes", {})
        auditoria.begin_vuln(self.con, first)
        auditoria.finish_vuln(self.con, first, [self.vuln_row(ssh, "ok", [self.vuln_item("CVE-2026-0001")])])
        failed = auditoria.start_vuln(self.con, "lunes", {})
        auditoria.begin_vuln(self.con, failed)
        auditoria.set_state(self.con, failed, "error", "x")
        self.assertEqual(auditoria.vuln_results(self.con, "lunes")[0]["vulns"][0]["cve"], "CVE-2026-0001")
        second = auditoria.start_vuln(self.con, "lunes", {})
        auditoria.begin_vuln(self.con, second)
        auditoria.finish_vuln(self.con, second, [self.vuln_row(ssh, "ok", [self.vuln_item("CVE-2026-0002")])])
        self.assertEqual([v["cve"] for r in auditoria.vuln_results(self.con, "lunes") for v in r["vulns"]], ["CVE-2026-0002"])
        self.assertEqual(self.count("vulnerabilidad"), 1)

    def test_finish_vuln_ignores_a_service_of_another_audit(self):
        self.load_in_scope("lunes")
        other = auditoria.create_audit(self.con, "Otra", "198.51.100.0/24")
        with self.con:
            asset = self.con.execute("INSERT INTO activo (auditoria_id, ip) VALUES (?, '198.51.100.9')", (other,)).lastrowid
            foreign = self.con.execute("INSERT INTO servicio (activo_id, protocolo, puerto) VALUES (?, 'tcp', 22)", (asset,)).lastrowid
        vuln = auditoria.start_vuln(self.con, "lunes", {})
        auditoria.begin_vuln(self.con, vuln)
        auditoria.finish_vuln(self.con, vuln, [self.vuln_row(foreign, "ok", [self.vuln_item()])])
        self.assertEqual(self.count("vulnerabilidad"), 0)

    def test_stop_vuln_cancels_a_queued_run_and_asks_a_running_one_to_stop(self):
        self.load_in_scope("lunes")
        self.assertIsNone(auditoria.stop_vuln(self.con, "lunes"))
        vuln = auditoria.start_vuln(self.con, "lunes", {})
        self.assertEqual(auditoria.stop_vuln(self.con, "lunes"), "cancelada")
        vuln = auditoria.start_vuln(self.con, "lunes", {})
        auditoria.begin_vuln(self.con, vuln)
        self.assertEqual(auditoria.stop_vuln(self.con, "lunes"), "deteniendo")

    def test_a_vuln_run_left_active_is_closed_as_interrupted_on_reopening(self):
        self.load_in_scope("lunes")
        auditoria.start_vuln(self.con, "lunes", {})
        auditoria.close_interrupted_analyses(self.con)
        self.assertEqual(auditoria.vuln_status(self.con, "lunes")["estado"], "interrumpida")
