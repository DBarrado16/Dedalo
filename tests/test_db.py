from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from dedalo import auditoria, db

LATEST = max(db.MIGRATIONS)
NEXT = LATEST + 1  # número para migraciones de prueba
TABLES = {"auditoria", "alcance", "ejecucion", "activo", "servicio", "observacion_activo",
          "observacion", "evidencia", "captura", "prioridad",
          "config", "credencial_catalogo", "credencial_resultado", "deteccion",
          "cve", "cve_cpe", "vulnerabilidad"}


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.con = db.connect(self.temp.name)

    def tearDown(self):
        self.con.close()
        self.temp.cleanup()

    def audit(self, con=None):
        con = con or self.con
        with con:
            con.execute("INSERT INTO auditoria (id, nombre, creada) VALUES ('a1', 'Cliente', '2026-09-28T00:00:00Z')")
            con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, nombre, estado, creada) "
                        "VALUES ('e1', 'a1', 'importacion', 'Nmap lunes', 'completa', '2026-09-28T00:00:00Z')")
            asset = con.execute("INSERT INTO activo (auditoria_id, ip) VALUES ('a1', '10.10.5.3')").lastrowid
            service = con.execute("INSERT INTO servicio (activo_id, protocolo, puerto) VALUES (?, 'tcp', 443)", (asset,)).lastrowid
            con.execute("INSERT INTO observacion (ejecucion_id, servicio_id, nombre, producto) VALUES ('e1', ?, 'https', 'nginx')", (service,))
        return asset, service

    def test_creates_schema_with_current_version(self):
        tables = {row[0] for row in self.con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        self.assertEqual(tables, TABLES)
        self.assertEqual(self.con.execute("PRAGMA user_version").fetchone()[0], max(db.MIGRATIONS))
        self.assertEqual(self.con.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertEqual(self.con.execute("PRAGMA journal_mode").fetchone()[0], "wal")

    def test_reopening_keeps_data_and_does_not_migrate_again(self):
        self.audit()
        self.con.close()
        self.con = db.connect(self.temp.name)
        self.assertEqual(self.con.execute("SELECT producto FROM observacion").fetchone()[0], "nginx")

    def test_rejects_invalid_values_and_broken_references(self):
        asset, _ = self.audit()
        invalid = [
            ("INSERT INTO alcance (auditoria_id, tipo, cidr) VALUES ('a1', 'quizas', '10.0.0.0/8')", ()),
            ("INSERT INTO servicio (activo_id, protocolo, puerto) VALUES (?, 'tcp', 70000)", (asset,)),
            ("INSERT INTO servicio (activo_id, protocolo, puerto) VALUES (?, 'sctp', 80)", (asset,)),
            ("INSERT INTO servicio (activo_id, protocolo, puerto) VALUES (?, 'tcp', 443)", (asset,)),
            ("INSERT INTO activo (auditoria_id, ip) VALUES ('a1', '10.10.5.3')", ()),
            ("INSERT INTO activo (auditoria_id, ip) VALUES ('no-existe', '10.10.5.4')", ()),
            ("UPDATE ejecucion SET estado = 'terminada'", ()),
        ]
        for sql, parameters in invalid:
            with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                with self.con:
                    self.con.execute(sql, parameters)

    def test_deleting_audit_removes_everything_it_owns(self):
        self.audit()
        with self.con:
            self.con.execute("DELETE FROM auditoria WHERE id = 'a1'")
        for table in TABLES:
            with self.subTest(table=table):
                self.assertEqual(self.con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0)

    def test_failed_migration_is_rolled_back(self):
        self.con.close()
        broken = {**db.MIGRATIONS, NEXT: "CREATE TABLE nueva (a TEXT); ESTO NO ES SQL;"}
        with patch.dict(db.MIGRATIONS, broken), self.assertRaises(sqlite3.Error):
            db.connect(self.temp.name)
        self.con = db.connect(self.temp.name)
        self.assertEqual(self.con.execute("PRAGMA user_version").fetchone()[0], LATEST)
        self.assertIsNone(self.con.execute("SELECT name FROM sqlite_master WHERE name = 'nueva'").fetchone())

    def test_rebuilding_a_parent_table_keeps_what_hangs_from_it(self):
        # Ampliar un CHECK obliga a reconstruir la tabla; el DROP no debe borrar en cascada.
        self.audit()
        self.con.close()
        rebuild = """
CREATE TABLE nueva_ejecucion (
  id TEXT PRIMARY KEY, auditoria_id TEXT NOT NULL REFERENCES auditoria(id) ON DELETE CASCADE,
  tipo TEXT NOT NULL CHECK (tipo IN ('importacion', 'captura', 'descubrimiento', 'prueba')), origen_id TEXT REFERENCES ejecucion(id),
  nombre TEXT NOT NULL, estado TEXT NOT NULL, opciones TEXT NOT NULL DEFAULT '{}', creada TEXT NOT NULL,
  iniciada TEXT, terminada TEXT, error TEXT NOT NULL DEFAULT '');
INSERT INTO nueva_ejecucion SELECT * FROM ejecucion;
DROP TABLE ejecucion;
ALTER TABLE nueva_ejecucion RENAME TO ejecucion;
"""
        with patch.dict(db.MIGRATIONS, {**db.MIGRATIONS, NEXT: rebuild}):
            self.con = db.connect(self.temp.name)
        self.assertEqual(self.con.execute("PRAGMA user_version").fetchone()[0], NEXT)
        self.assertEqual(self.con.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertEqual(self.con.execute("SELECT producto FROM observacion").fetchone()[0], "nginx")
        with self.con:
            self.con.execute("UPDATE ejecucion SET tipo = 'prueba'")
        # Las referencias siguen apuntando a la tabla reconstruida.
        with self.con:
            self.con.execute("DELETE FROM ejecucion")
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM observacion").fetchone()[0], 0)

    def test_migration_that_breaks_references_is_rolled_back(self):
        self.audit()
        self.con.close()
        with patch.dict(db.MIGRATIONS, {**db.MIGRATIONS, NEXT: "DELETE FROM activo;"}), \
                self.assertRaisesRegex(sqlite3.IntegrityError, "referencias rotas"):
            db.connect(self.temp.name)
        self.con = db.connect(self.temp.name)
        self.assertEqual(self.con.execute("PRAGMA user_version").fetchone()[0], LATEST)
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM activo").fetchone()[0], 1)
        self.assertEqual(self.con.execute("PRAGMA foreign_keys").fetchone()[0], 1)

    def test_version_one_database_is_upgraded_keeping_its_data(self):
        self.con.close()
        path = Path(self.temp.name) / db.FILENAME
        path.unlink()
        old = sqlite3.connect(path)
        old.executescript(f"BEGIN; {db.MIGRATIONS[1]} PRAGMA user_version = 1; COMMIT;")
        old.execute("PRAGMA foreign_keys = ON")
        self.audit(old)
        old.close()
        self.con = db.connect(self.temp.name)
        self.assertEqual(self.con.execute("PRAGMA user_version").fetchone()[0], LATEST)
        self.assertEqual(self.con.execute("SELECT producto FROM observacion").fetchone()[0], "nginx")
        self.assertEqual(tuple(self.con.execute("SELECT tipo, estado FROM ejecucion WHERE id = 'e1'").fetchone()),
                         ("importacion", "completa"))
        indexes = {row[0] for row in self.con.execute("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'ejecucion'")}
        self.assertLessEqual({"ejecucion_auditoria", "ejecucion_origen"}, indexes)

    def test_discovery_executions_and_deleting_an_import_removes_its_captures(self):
        _, service = self.audit()
        with self.con:
            self.con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, nombre, estado, creada) "
                             "VALUES ('d1', 'a1', 'descubrimiento', 'DNS', 'completa', '2026-09-29T00:00:00Z')")
            self.con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, origen_id, nombre, estado, creada) "
                             "VALUES ('c1', 'a1', 'captura', 'e1', 'Nmap lunes', 'completa', '2026-09-29T00:00:00Z')")
            self.con.execute("INSERT INTO captura (ejecucion_id, servicio_id, url, estado) "
                             "VALUES ('c1', ?, 'https://10.10.5.3/', 'pendiente')", (service,))
        with self.con:
            self.con.execute("DELETE FROM ejecucion WHERE id = 'e1'")
        self.assertEqual([r[0] for r in self.con.execute("SELECT id FROM ejecucion")], ["d1"])
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM captura").fetchone()[0], 0)

    def test_analysis_executions_keep_priorities_until_their_import_is_deleted(self):
        asset, _ = self.audit()
        self.assertGreaterEqual(LATEST, 3)
        with self.con:
            self.con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, origen_id, nombre, estado, creada) "
                             "VALUES ('p1', 'a1', 'analisis', 'e1', 'Nmap lunes', 'completa', '2026-10-14T00:00:00Z')")
            self.con.execute("INSERT INTO prioridad (ejecucion_id, activo_id, orden, rol, nivel, motivo, siguiente) "
                             "VALUES ('p1', ?, 0, 'Servidor web', 'alta', 'nginx en 443', 'revisar el panel')", (asset,))
        self.assertEqual(self.con.execute("SELECT nivel, siguiente FROM prioridad").fetchone()[:],
                         ("alta", "revisar el panel"))
        with self.assertRaises(sqlite3.IntegrityError), self.con:
            self.con.execute("INSERT INTO prioridad (ejecucion_id, activo_id, orden, nivel) VALUES ('p1', ?, 1, 'urgente')",
                             (asset,))
        with self.con:
            self.con.execute("DELETE FROM ejecucion WHERE id = 'e1'")
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM prioridad").fetchone()[0], 0)
        # Borrar un activo en cascada no recorre toda la tabla; UNIQUE ya indexa por ejecución.
        indexes = {row[0] for row in self.con.execute("SELECT name FROM sqlite_master WHERE type = 'index' "
                                                      "AND tbl_name = 'prioridad' AND sql IS NOT NULL")}
        self.assertEqual(indexes, {"prioridad_activo"})

    def test_migration_4_adds_credential_tables_and_type(self):
        con = self.con
        self.assertGreaterEqual(con.execute("PRAGMA user_version").fetchone()[0], 4)
        tablas = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertLessEqual({"credencial_catalogo", "credencial_resultado", "config"}, tablas)
        indices = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        self.assertLessEqual({"credencial_catalogo_servicio", "credencial_resultado_activo"}, indices)
        audit = auditoria.default_audit(con)
        con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, nombre, estado, creada) "
                    "VALUES ('c1', ?, 'credenciales', 'x', 'en_cola', ?)", (audit, auditoria.now()))
        with self.assertRaises(sqlite3.IntegrityError):
            con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, nombre, estado, creada) "
                        "VALUES ('c2', ?, 'inventado', 'x', 'en_cola', ?)", (audit, auditoria.now()))

    def test_migration_5_adds_detection_table_and_type(self):
        con = self.con
        self.assertGreaterEqual(con.execute("PRAGMA user_version").fetchone()[0], 5)
        tablas = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("deteccion", tablas)
        indices = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        self.assertIn("deteccion_servicio", indices)
        _, service = self.audit()
        with con:
            con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, origen_id, nombre, estado, creada) "
                        "VALUES ('v1', 'a1', 'version', 'e1', 'Nmap lunes', 'completa', '2026-10-19T00:00:00Z')")
            con.execute("INSERT INTO deteccion (ejecucion_id, servicio_id, origen, producto, version, confianza) "
                        "VALUES ('v1', ?, 'gowitness', 'nginx', '1.18', NULL)", (service,))
            con.execute("INSERT INTO deteccion (ejecucion_id, servicio_id, origen, producto, version, confianza) "
                        "VALUES ('v1', ?, 'ia', 'RouterOS', '6.49.7', 90)", (service,))
        self.assertEqual(con.execute("SELECT COUNT(*) FROM deteccion").fetchone()[0], 2)
        with self.assertRaises(sqlite3.IntegrityError), con:
            con.execute("INSERT INTO deteccion (ejecucion_id, servicio_id, origen, producto) "
                        "VALUES ('v1', ?, 'otro', 'x')", (service,))
        # Borrar la ejecución borra sus detecciones en cascada.
        with con:
            con.execute("DELETE FROM ejecucion WHERE id = 'v1'")
        self.assertEqual(con.execute("SELECT COUNT(*) FROM deteccion").fetchone()[0], 0)

    def test_migration_6_adds_cve_tables_and_vuln_type(self):
        con = self.con
        self.assertGreaterEqual(con.execute("PRAGMA user_version").fetchone()[0], 6)
        tablas = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertLessEqual({"cve", "cve_cpe", "vulnerabilidad"}, tablas)
        indices = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        self.assertLessEqual({"cve_cpe_producto", "vulnerabilidad_servicio"}, indices)
        _, service = self.audit()
        with con:
            con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, origen_id, nombre, estado, creada) "
                        "VALUES ('x1', 'a1', 'vuln', 'e1', 'Nmap lunes', 'completa', '2026-10-21T00:00:00Z')")
            con.execute("INSERT INTO cve (id, publicada, severidad, cvss, resumen) "
                        "VALUES ('CVE-2026-0001', '2026-01-01', 'ALTA', 7.5, 'x')")
            con.execute("INSERT INTO cve_cpe (cve_id, parte, vendor, producto, v_ini, v_ini_incl, v_fin, v_fin_incl) "
                        "VALUES ('CVE-2026-0001', 'a', 'nginx', 'nginx', NULL, 1, '1.25.0', 0)")
            con.execute("INSERT INTO vulnerabilidad (ejecucion_id, servicio_id, cve_id, severidad, exploit_nivel, "
                        "enlaces, origen_cpe, estado) VALUES ('x1', ?, 'CVE-2026-0001', 'ALTA', '', '[]', "
                        "'cpe:/a:nginx:nginx:1.18', 'nueva')", (service,))
        with self.assertRaises(sqlite3.IntegrityError), con:
            con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, nombre, estado, creada) "
                        "VALUES ('x2', 'a1', 'inventado', 'x', 'en_cola', '2026-10-21T00:00:00Z')")
        # Borrar la CVE se lleva sus reglas; borrar la ejecución, sus vulnerabilidades.
        with con:
            con.execute("DELETE FROM cve")
            con.execute("DELETE FROM ejecucion WHERE id = 'x1'")
        for tabla in ("cve_cpe", "vulnerabilidad"):
            self.assertEqual(con.execute(f"SELECT COUNT(*) FROM {tabla}").fetchone()[0], 0)

    def test_version_five_database_is_upgraded_keeping_its_data(self):
        self.con.close()
        path = Path(self.temp.name) / db.FILENAME
        path.unlink()
        old = sqlite3.connect(path)
        script = "".join(f"{db.MIGRATIONS[v]}\n" for v in range(1, 6))
        old.executescript(f"BEGIN; {script} PRAGMA user_version = 5; COMMIT;")
        old.execute("PRAGMA foreign_keys = ON")
        _, service = self.audit(old)
        old.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, origen_id, nombre, estado, creada) "
                    "VALUES ('v1', 'a1', 'version', 'e1', 'x', 'completa', '2026-10-21T00:00:00Z')")
        old.execute("INSERT INTO deteccion (ejecucion_id, servicio_id, origen, producto) VALUES ('v1', ?, 'ia', 'nginx')",
                    (service,))
        old.commit()
        old.close()
        self.con = db.connect(self.temp.name)
        self.assertEqual(self.con.execute("PRAGMA user_version").fetchone()[0], LATEST)
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM ejecucion").fetchone()[0], 2)
        self.assertEqual(self.con.execute("SELECT producto FROM deteccion").fetchone()[0], "nginx")
        self.assertEqual(self.con.execute("SELECT producto FROM observacion").fetchone()[0], "nginx")
        indexes = {row[0] for row in self.con.execute("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'ejecucion'")}
        self.assertLessEqual({"ejecucion_auditoria", "ejecucion_origen"}, indexes)

    def test_refuses_database_from_newer_version(self):
        self.con.execute("PRAGMA user_version = 99")
        self.con.close()
        with self.assertRaisesRegex(ValueError, "más nueva"):
            db.connect(self.temp.name)
        self.con = sqlite3.connect(":memory:")  # tearDown cierra algo válido
