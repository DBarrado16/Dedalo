import json
import os
from pathlib import Path
import threading
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

from nmapshot import cli, report
from nmapshot.web import PortalStore, PortalServer
from tests.test_nmapshot import ROOT, fake_database


def payload():
    return {"nombre": "Prueba de portal", "archivos": [{"nombre": "escaneo.xml", "contenido": (ROOT / "ejemplos/escaneo.xml").read_text()}],
            "rangos": "10.10.0.0/17", "opciones": {"timeout": 5, "delay": 0}}


class PortalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = PortalStore(self.temp.name)
        self.server = PortalServer(("127.0.0.1", 0), self.store)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:" + str(self.server.server_address[1])
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

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
        status, content = self.request("/api/jobs", payload())
        self.assertEqual(status, 201, content)
        return json.loads(content)

    def test_upload_preview_is_persistent_and_does_not_capture(self):
        with patch("nmapshot.web.subprocess.run") as run:
            job = self.create()
            self.assertEqual(job["total"], 4)
            self.assertEqual(job["subredes"], 3)
            self.assertEqual(job["estado"], "preparada")
            run.assert_not_called()
        meta = self.store.directory(job["id"]) / "trabajo.json"
        self.assertTrue(meta.is_file())
        self.assertFalse((meta.parent / "resultado").exists())
        status, content = self.request("/api/jobs")
        self.assertEqual(json.loads(content)[0]["id"], job["id"])

    def test_invalid_upload_and_options(self):
        data = payload()
        data["archivos"][0]["contenido"] = "no es nmap"
        self.assertEqual(self.request("/api/jobs", data)[0], 400)
        data = payload()
        data["opciones"]["hilos"] = 999
        self.assertEqual(self.request("/api/jobs", data)[0], 400)
        data = payload()
        data["rangos"] = "10.0.0.0/80"
        self.assertEqual(self.request("/api/jobs", data)[0], 400)
        self.assertFalse(self.store.jobs)

    def test_csrf_origin_host_and_body_size(self):
        self.assertEqual(self.request("/api/jobs", payload(), {"X-Nmapshot-Token": "wrong"})[0], 403)
        self.assertEqual(self.request("/api/jobs", payload(), {"Origin": "https://example.org"})[0], 403)
        self.assertEqual(self.request("/api/jobs", headers={"Host": "example.org"})[0], 403)
        self.assertEqual(self.request("/api/jobs", payload(), {"Content-Length": str(40*1024*1024)})[0], 413)
        self.assertEqual(self.request("/api/jobs", payload(), {"Content-Type": "text/plain"})[0], 415)

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

    def test_queue_start_once_and_cancel_queued_job(self):
        first, second = self.create(), self.create()
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
                self.request("/api/jobs/" + first["id"] + "/cancel", {})
                self.assertTrue((self.store.directory(first["id"]) / "parar").exists())
                release.set()
                deadline = time.monotonic() + 3
                while self.store.detail(first["id"])["estado"] == "deteniendo" and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertEqual(self.store.detail(first["id"])["estado"], "interrumpida")
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
        self.assertEqual(detail["total"], 4)
        self.assertEqual(detail["archivos"], ["escaneo.xml"])

    def test_static_page_uses_local_assets(self):
        status, content = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn(b"Nueva captura", content)
        self.assertEqual(self.request("/app.js")[0], 200)
        self.assertEqual(self.request("/style.css")[0], 200)


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
