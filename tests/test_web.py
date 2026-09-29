import argparse
from contextlib import closing
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import threading
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import zipfile

from nmapshot import auditoria, cli, report, web
from nmapshot.web import PortalStore, PortalServer
from tests.test_nmapshot import ROOT, fake_database


def payload():
    return {"nombre": "Prueba de portal", "archivos": [{"nombre": "escaneo.xml", "contenido": (ROOT / "ejemplos/escaneo.xml").read_text()}],
            "opciones": {"timeout": 5, "delay": 0}}


class PortalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = PortalStore(self.temp.name)
        self.server = PortalServer(("127.0.0.1", 0), self.store)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:" + str(self.server.server_address[1])
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        # El ejemplo trae 10.10.5.10 (80, 443), 10.10.6.20 (80) y 192.168.1.8 (443), que queda fuera.
        self.audit = self.store.create_audit({"nombre": "Cliente de prueba", "incluir": "10.10.0.0/17"})

    def payload(self):
        return payload() | {"auditoria": self.audit["id"]}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.store.close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, route, data=None, headers=None):
        values = {"Content-Type": "application/json", "X-Nmapshot-Token": self.store.token}
        values.update(headers or {})
        request = urllib.request.Request(self.url + route, data=json.dumps(data).encode() if data is not None else None, headers=values)
        try:
            response = self.opener.open(request, timeout=5)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            content = response.read()
            return response.status, content

    def create(self):
        status, content = self.request("/api/jobs", self.payload())
        self.assertEqual(status, 201, content)
        return json.loads(content)

    def test_upload_preview_is_persistent_and_does_not_capture(self):
        with patch("nmapshot.web.subprocess.run") as run:
            job = self.create()
            self.assertEqual(job["total"], 3)
            self.assertEqual(job["subredes"], 2)
            self.assertEqual(job["fuera_alcance"], {"fuera": 1, "excluida": 0})
            self.assertEqual(job["auditoria"], self.audit["id"])
            self.assertEqual(job["estado"], "preparada")
            run.assert_not_called()
        meta = self.store.directory(job["id"]) / "trabajo.json"
        self.assertTrue(meta.is_file())
        self.assertFalse((meta.parent / "resultado").exists())
        status, content = self.request("/api/jobs")
        self.assertEqual(json.loads(content)[0]["id"], job["id"])

    def test_invalid_upload_and_options(self):
        data = self.payload()
        data["archivos"][0]["contenido"] = "no es nmap"
        self.assertEqual(self.request("/api/jobs", data)[0], 400)
        data = self.payload()
        data["opciones"]["hilos"] = 999
        self.assertEqual(self.request("/api/jobs", data)[0], 400)
        data = self.payload()
        data["auditoria"] = "a" * 32
        self.assertEqual(self.request("/api/jobs", data)[0], 400)
        self.assertFalse(self.store.jobs)
        for scope in ({"nombre": "X", "incluir": "10.0.0.0/80"}, {"nombre": "", "incluir": "10.0.0.0/8"},
                      {"nombre": "X", "incluir": "10.0.0.0/8", "excluir": "no-es-ip"}):
            with self.subTest(scope=scope):
                self.assertEqual(self.request("/api/audits", scope)[0], 400)
        self.assertEqual(len(json.loads(self.request("/api/audits")[1])), 1)

    def test_delete_removes_only_selected_job_and_persists_after_restart(self):
        job, other = self.create(), self.create()
        directory = self.store.directory(job["id"])
        captures = directory / "resultado" / "capturas"
        captures.mkdir(parents=True)
        (captures / "test.png").write_bytes(b"test-image")
        route = "/api/jobs/" + job["id"]
        self.assertEqual(self.request(route + "/delete", {})[0], 200)
        self.assertFalse(directory.exists())
        self.assertEqual(self.request(route)[0], 404)
        self.assertEqual(self.request(route + "/delete", {})[0], 404)
        self.assertTrue((self.store.directory(other["id"]) / "trabajo.json").is_file())
        self.store.close()
        self.store = PortalStore(self.temp.name)
        self.server.store = self.store
        self.assertEqual([item["id"] for item in self.store.list()], [other["id"]])
        self.assertEqual(self.request("/api/jobs/" + other["id"] + "/delete", {})[0], 200)
        self.assertEqual(json.loads(self.request("/api/jobs")[1]), [])

    def test_delete_rejects_active_jobs_and_requires_same_origin_token(self):
        job = self.create()
        route = "/api/jobs/" + job["id"] + "/delete"
        for headers in ({"X-Nmapshot-Token": "wrong"}, {"Origin": "https://example.org"}):
            self.assertEqual(self.request(route, {}, headers)[0], 403)
        self.assertEqual(self.request(route)[0], 404)
        for state in ("en_cola", "en_curso", "deteniendo"):
            with self.subTest(state=state):
                self.store.jobs[job["id"]]["estado"] = state
                self.assertEqual(self.request(route, {})[0], 409)
                self.assertTrue(self.store.directory(job["id"]).exists())
        self.store.jobs[job["id"]]["estado"] = "preparada"

    def test_delete_rejects_directory_alias_and_retains_job_on_disk_error(self):
        job, other = self.create(), self.create()
        route = "/api/jobs/" + job["id"] + "/delete"
        other_directory = self.store.directory(other["id"])
        with patch.object(self.store, "directory", return_value=other_directory), patch("nmapshot.web.shutil.rmtree") as remove:
            self.assertEqual(self.request(route, {})[0], 400)
            remove.assert_not_called()
        with patch("nmapshot.web.shutil.rmtree", side_effect=PermissionError("Archivo ocupado")):
            self.assertEqual(self.request(route, {})[0], 500)
        self.assertIn(job["id"], self.store.jobs)
        self.assertTrue(self.store.directory(job["id"]).exists())

    def test_csrf_origin_host_and_body_size(self):
        self.assertEqual(self.request("/api/jobs", self.payload(), {"X-Nmapshot-Token": "wrong"})[0], 403)
        self.assertEqual(self.request("/api/jobs", self.payload(), {"Origin": "https://example.org"})[0], 403)
        self.assertEqual(self.request("/api/jobs", headers={"Host": "example.org"})[0], 403)
        self.assertEqual(self.request("/api/jobs", self.payload(), {"Content-Length": str(40*1024*1024)})[0], 413)
        self.assertEqual(self.request("/api/jobs", self.payload(), {"Content-Type": "text/plain"})[0], 415)

    def test_images_and_downloads_are_scoped_to_job(self):
        job = self.create()
        meta = self.store.jobs[job["id"]]
        root = self.store.directory(job["id"]) / "resultado"
        group = meta["grupos"][0]
        directory = root / group["carpeta"]
        fake_database(directory, [group["objetivos"][0]["url"]])
        report.collect_group(root, group)
        manifest = {"version": 1, "grupos": [group]}
        report.write_index(root, manifest)
        status, content = self.request("/api/jobs/" + job["id"] + "/image/0/0")
        self.assertEqual(status, 200)
        self.assertEqual(content, b"test-image")
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/image/0/999")[0], 404)
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/download/csv")[0], 200)
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/download/../../trabajo.json")[0], 404)
        self.assertEqual(self.request("/api/jobs/" + "a"*32)[0], 404)
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/image/-1/0")[0], 404)

    def test_subnet_zip_contains_only_that_subnet_captures(self):
        job = self.create()
        meta = self.store.jobs[job["id"]]
        root = self.store.directory(job["id"]) / "resultado"
        group = meta["grupos"][0]
        target = group["objetivos"][0]
        fake_database(root / group["carpeta"], [target["url"]])
        report.collect_group(root, group)
        report.write_index(root, {"version": 1, "grupos": meta["grupos"]})
        route = "/api/jobs/" + job["id"] + "/download/captures/"
        status, content = self.request(route + "0")
        self.assertEqual(status, 200)
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            scheme = target["url"].split(":", 1)[0]
            image = f"{target['ip']}_{target['port']}_{scheme}.png"
            self.assertEqual(sorted(archive.namelist()), sorted([image, "indice.csv"]))
            self.assertEqual(archive.read(image), b"test-image")
            index = list(csv.DictReader(io.StringIO(archive.read("indice.csv").decode("utf-8-sig"))))
        self.assertEqual((index[0]["archivo"], index[0]["url"], index[0]["titulo"]), (image, target["url"], "'=test"))
        self.assertEqual(self.request(route + "1")[0], 404)
        self.assertEqual(self.request(route + "99")[0], 404)
        self.assertEqual(self.request(route + "-1")[0], 404)
        self.assertEqual(self.request(route + "x")[0], 400)

    def test_queue_start_once_and_cancel_queued_job(self):
        first, second, third = self.create(), self.create(), self.create()
        begun, release = threading.Event(), threading.Event()
        def run(*args, **kwargs):
            begun.set()
            release.wait(5)
            class Result:
                returncode = 130
            return Result()
        try:
            with patch("nmapshot.web.gowitness.find_gowitness", return_value="fake"), patch("nmapshot.web.gowitness.find_chrome", return_value="fake"), patch("nmapshot.web.subprocess.run", side_effect=run):
                self.assertEqual(self.request("/api/jobs/" + first["id"] + "/start", {})[0], 202)
                self.assertTrue(begun.wait(2))
                self.assertEqual(self.request("/api/jobs/" + first["id"] + "/start", {})[0], 409)
                self.assertEqual(self.request("/api/jobs/" + second["id"] + "/start", {})[0], 202)
                self.assertEqual(self.store.detail(second["id"])["estado"], "en_cola")
                self.assertEqual(self.request("/api/jobs/" + second["id"] + "/cancel", {})[0], 200)
                self.assertEqual(self.store.detail(second["id"])["estado"], "cancelada")
                self.assertEqual(self.request("/api/jobs/" + second["id"] + "/delete", {})[0], 200)
                self.assertEqual(self.request("/api/jobs/" + third["id"] + "/start", {})[0], 202)
                self.request("/api/jobs/" + first["id"] + "/cancel", {})
                self.assertTrue((self.store.directory(first["id"]) / "parar").exists())
                release.set()
                deadline = time.monotonic() + 3
                while self.store.detail(first["id"])["estado"] == "deteniendo" and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertEqual(self.store.detail(first["id"])["estado"], "interrumpida")
                while self.store.detail(third["id"])["estado"] in ("en_cola", "en_curso") and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertEqual(self.store.detail(third["id"])["estado"], "interrumpida")
                self.assertTrue(self.store.worker.is_alive())
        finally:
            release.set()

    def test_second_portal_cannot_claim_same_history(self):
        with self.assertRaisesRegex(ValueError, "Ya hay"):
            PortalStore(self.temp.name)

    def test_history_survives_portal_restart(self):
        job = self.create()
        self.store.close()
        self.store = PortalStore(self.temp.name)
        self.server.store = self.store
        detail = self.store.detail(job["id"])
        self.assertEqual(detail["estado"], "preparada")
        self.assertEqual(detail["total"], 3)
        self.assertEqual(detail["archivos"], ["escaneo.xml"])

    def test_inventory_is_available_before_capture_and_survives_restart(self):
        data = self.payload()
        data["archivos"] = [{"nombre": "inventario.xml", "contenido": (ROOT / "ejemplos/inventario.xml").read_text(encoding="utf-8")}]
        with patch("nmapshot.web.subprocess.run") as run:
            status, content = self.request("/api/jobs", data)
            self.assertEqual(status, 201)
            job = json.loads(content)
            route = "/api/jobs/" + job["id"]
            status, content = self.request(route + "/inventory")
            self.assertEqual(status, 200)
            inventory = json.loads(content)
            self.assertEqual((inventory["activos_total"], inventory["servicios_total"]), (4, 9))
            # Sus IP de documentación no están en la ficha: se ven, pero no se capturan.
            self.assertEqual((job["total"], job["fuera_alcance"]["fuera"]), (0, 2))
            self.assertEqual({a["alcance"] for a in inventory["activos"]}, {"fuera"})
            self.assertEqual(self.request(route + "/download/inventory-json")[0], 200)
            status, content = self.request(route + "/download/inventory-csv")
            self.assertEqual(status, 200)
            self.assertIn(b"OpenSSH,9.6", content)
            run.assert_not_called()
        self.store.close()
        self.store = PortalStore(self.temp.name)
        self.server.store = self.store
        self.assertEqual(json.loads(self.request(route + "/inventory")[1]), inventory)

    def test_legacy_inventory_is_imported_from_original_inputs(self):
        job = self.create()
        directory = self.store.directory(job["id"])
        with closing(self.store.database()) as con:
            auditoria.delete_execution(con, job["id"])  # como una ejecución anterior a la base
        original_meta = (directory / "trabajo.json").read_bytes()
        result = self.store.inventory(job["id"])
        self.assertEqual(result["servicios_total"], 7)
        self.assertEqual((directory / "trabajo.json").read_bytes(), original_meta)
        self.assertFalse((directory / "inventario.json").exists())
        with closing(self.store.database()) as con:
            row = con.execute("SELECT nombre, creada FROM ejecucion WHERE id = ?", (job["id"],)).fetchone()
        self.assertEqual((row["nombre"], row["creada"]), ("Prueba de portal", job["fecha"]))
        self.assertEqual(self.request("/api/jobs/" + "a"*32 + "/inventory")[0], 404)

    def test_upload_is_stored_in_database_and_delete_removes_it(self):
        job, other = self.create(), self.create()
        with closing(self.store.database()) as con:
            evidence = con.execute("SELECT ruta, sha256, bytes FROM evidencia WHERE ejecucion_id = ?", (job["id"],)).fetchall()
            self.assertEqual([row["ruta"] for row in evidence], [job["id"] + "/entradas/nmap-00.txt"])
            original = (self.store.directory(job["id"]) / "entradas/nmap-00.txt").read_bytes()
            self.assertEqual((evidence[0]["sha256"], evidence[0]["bytes"]), (hashlib.sha256(original).hexdigest(), len(original)))
            # Dos subidas del mismo Nmap: los activos no se duplican, las observaciones sí.
            self.assertEqual(con.execute("SELECT COUNT(*) FROM activo").fetchone()[0], 3)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM observacion").fetchone()[0], 14)
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/delete", {})[0], 200)
        with closing(self.store.database()) as con:
            self.assertFalse(auditoria.has_execution(con, job["id"]))
            self.assertEqual(con.execute("SELECT COUNT(*) FROM activo").fetchone()[0], 3)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM observacion").fetchone()[0], 7)
        self.assertEqual(self.request("/api/jobs/" + other["id"] + "/delete", {})[0], 200)
        with closing(self.store.database()) as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM activo").fetchone()[0], 0)

    def test_failed_import_leaves_no_job_behind(self):
        with patch("nmapshot.web.auditoria.import_nmap", side_effect=sqlite3.OperationalError("disco lleno")):
            self.assertEqual(self.request("/api/jobs", self.payload())[0], 500)
        self.assertFalse(self.store.jobs)
        self.assertEqual([p.name for p in Path(self.temp.name).iterdir() if p.is_dir()], [])

    def test_upload_with_only_non_web_services_retains_inventory(self):
        data = self.payload()
        data["archivos"][0]["contenido"] = "Nmap scan report for 192.0.2.1\n22/tcp open ssh OpenSSH 9.6\n53/udp open domain\n"
        status, content = self.request("/api/jobs", data)
        self.assertEqual(status, 201)
        job = json.loads(content)
        self.assertEqual(job["total"], 0)
        self.assertEqual(self.store.inventory(job["id"])["servicios_total"], 2)

    def test_static_page_uses_local_assets(self):
        status, content = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn(b"Nueva captura", content)
        self.assertEqual(self.request("/app.js")[0], 200)
        self.assertEqual(self.request("/style.css")[0], 200)


    def test_audit_scope_decides_what_is_captured_and_replans_prepared_jobs(self):
        job = self.create()
        directory = self.store.directory(job["id"])
        self.assertEqual((directory / "rangos.txt").read_text(), "10.10.0.0/17\n")
        route = "/api/audits/" + self.audit["id"]
        # Excluir 10.10.5.10 deja solo 10.10.6.20:80.
        status, content = self.request(route, {"nombre": "Cliente", "incluir": "10.10.0.0/17",
                                               "excluir": "10.10.5.10  # impresora"})
        self.assertEqual(status, 200, content)
        self.assertEqual(json.loads(content)["excluir"], [{"cidr": "10.10.5.10/32", "motivo": "impresora"}])
        detail = self.store.detail(job["id"])
        self.assertEqual((detail["total"], detail["fuera_alcance"]), (1, {"fuera": 1, "excluida": 2}))
        self.assertEqual((directory / "excluir.txt").read_text(), "10.10.5.10/32\n")
        inventory = {a["ip"]: a["alcance"] for a in self.store.inventory(job["id"])["activos"]}
        self.assertEqual(inventory, {"10.10.5.10": "excluida", "10.10.6.20": "en_alcance", "192.168.1.8": "fuera"})
        # Sin rangos incluidos no se puede lanzar nada.
        self.assertEqual(self.request(route, {"nombre": "Cliente", "incluir": ""})[0], 200)
        with patch("nmapshot.web.gowitness.find_gowitness", return_value="fake"), patch("nmapshot.web.gowitness.find_chrome", return_value="fake"):
            status, content = self.request("/api/jobs/" + job["id"] + "/start", {})
        self.assertEqual(status, 409)
        self.assertIn("alcance", json.loads(content)["error"])
        self.assertEqual(self.request("/api/audits/" + "b" * 32, {"nombre": "X", "incluir": ""})[0], 404)

    def test_capture_command_enforces_scope(self):
        job = self.create()
        started = threading.Event()
        def run(command, **kwargs):
            self.command = command
            started.set()
            class Result:
                returncode = 0
            return Result()
        with patch("nmapshot.web.gowitness.find_gowitness", return_value="fake"), patch("nmapshot.web.gowitness.find_chrome", return_value=None), \
             patch("nmapshot.web.subprocess.run", side_effect=run):
            self.assertEqual(self.request("/api/jobs/" + job["id"] + "/start", {})[0], 202)
            self.assertTrue(started.wait(3))
        directory = self.store.directory(job["id"])
        self.assertIn("--solo-rangos", self.command)
        self.assertEqual(self.command[self.command.index("--excluir") + 1], str(directory / "excluir.txt"))


class PortTests(unittest.TestCase):
    def test_second_portal_cannot_share_the_port(self):
        with tempfile.TemporaryDirectory() as first_data, tempfile.TemporaryDirectory() as second_data:
            store = PortalStore(first_data)
            server = PortalServer(("127.0.0.1", 0), store)
            try:
                args = argparse.Namespace(datos=second_data, gowitness="indicado", chrome=None,
                                          puerto=server.server_address[1], abrir=False)
                with self.assertRaisesRegex(ValueError, "ya está en uso"):
                    web.serve_portal(args)
            finally:
                server.server_close()
                store.close()
            # El portal que no pudo arrancar liberó su carpeta de datos.
            PortalStore(second_data).close()


class StopTests(unittest.TestCase):
    def test_cooperative_stop_leaves_pending_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "stop"
            output = Path(temporary) / "result"
            def scan(binary, directory, urls, opts):
                fake_database(directory, urls)
                marker.touch()
            from contextlib import redirect_stdout
            import io
            with patch("nmapshot.cli.gowitness.find_gowitness", return_value="fake"), patch("nmapshot.cli.gowitness.find_chrome", return_value="fake"), patch("nmapshot.cli.gowitness.scan_subnet", side_effect=scan), redirect_stdout(io.StringIO()):
                result = cli.main(["capturar", str(ROOT / "ejemplos/escaneo.xml"), "-o", str(output), "--stop-file", str(marker)])
            self.assertEqual(result, 130)
            manifest = report.load_manifest(output)
            self.assertEqual(manifest["estado"], "interrumpida")
            self.assertEqual(manifest["grupos"][0]["capturas"], 2)
            self.assertEqual(manifest["grupos"][1]["estado"], "pendiente")
