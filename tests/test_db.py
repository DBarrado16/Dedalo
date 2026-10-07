from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from dedalo import db

LATEST = max(db.MIGRATIONS)
NEXT = LATEST + 1  # número para migraciones de prueba
TABLES = {"auditoria", "alcance", "ejecucion", "activo", "servicio", "observacion_activo",
          "observacion", "evidencia", "captura"}


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

    def test_refuses_database_from_newer_version(self):
        self.con.execute("PRAGMA user_version = 99")
        self.con.close()
        with self.assertRaisesRegex(ValueError, "más nueva"):
            db.connect(self.temp.name)
        self.con = sqlite3.connect(":memory:")  # tearDown cierra algo válido
