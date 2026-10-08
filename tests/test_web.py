import argparse
from contextlib import closing, redirect_stderr
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import threading
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import zipfile

from dedalo import auditoria, cli, report, web
from dedalo.web import PortalStore, PortalServer
from tests.test_dedalo import ROOT, fake_database


def first_image(results):
    """Primera captura guardada de un resultado: resultado/rango/subred/capturas/*.png."""
    return sorted(Path(results).glob("*/*/capturas/*.png"))[0]


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
        values = {"Content-Type": "application/json", "X-Dedalo-Token": self.store.token}
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
        with patch("dedalo.web.subprocess.run") as run:
            job = self.create()
            self.assertEqual(job["total"], 3)
            self.assertEqual(job["subredes"], 2)
            self.assertEqual(job["fuera_alcance"], {"fuera": 1, "excluida": 0})
            self.assertEqual(job["auditoria"], self.audit["id"])
            self.assertEqual(job["estado"], "preparada")
            run.assert_not_called()
        # El estado y las opciones están en la base, no en un trabajo.json.
        directory = self.store.directory(job["id"])
        self.assertFalse((directory / "trabajo.json").exists())
        self.assertFalse((directory / "resultado").exists())
        with closing(self.store.database()) as con:
            stored = auditoria.portal_options(con, job["id"])
        self.assertEqual((stored["archivos"], stored["captura"]["timeout"]), (["escaneo.xml"], 5))
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
        self.assertTrue((self.store.directory(other["id"]) / "entradas" / "nmap-00.txt").is_file())
        self.store.close()
        self.store = PortalStore(self.temp.name)
        self.server.store = self.store
        self.assertEqual([item["id"] for item in self.store.list()], [other["id"]])
        self.assertEqual(self.request("/api/jobs/" + other["id"] + "/delete", {})[0], 200)
        self.assertEqual(json.loads(self.request("/api/jobs")[1]), [])

    def test_delete_rejects_active_jobs_and_requires_same_origin_token(self):
        job = self.create()
        route = "/api/jobs/" + job["id"] + "/delete"
        for headers in ({"X-Dedalo-Token": "wrong"}, {"Origin": "https://example.org"}):
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
        with patch.object(self.store, "directory", return_value=other_directory), patch("dedalo.web.shutil.rmtree") as remove:
            self.assertEqual(self.request(route, {})[0], 400)
            remove.assert_not_called()
        with patch("dedalo.web.shutil.rmtree", side_effect=PermissionError("Archivo ocupado")):
            self.assertEqual(self.request(route, {})[0], 500)
        self.assertIn(job["id"], self.store.jobs)
        self.assertTrue(self.store.directory(job["id"]).exists())

    def test_csrf_origin_host_and_body_size(self):
        self.assertEqual(self.request("/api/jobs", self.payload(), {"X-Dedalo-Token": "wrong"})[0], 403)
        self.assertEqual(self.request("/api/jobs", self.payload(), {"Origin": "https://example.org"})[0], 403)
        self.assertEqual(self.request("/api/jobs", headers={"Host": "example.org"})[0], 403)
        self.assertEqual(self.request("/api/jobs", self.payload(), {"Content-Length": str(40*1024*1024)})[0], 413)
        self.assertEqual(self.request("/api/jobs", self.payload(), {"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.request("/api/jobs", self.payload(), {"Content-Length": "mucho"})[0], 400)

    def test_rejection_reaches_a_client_that_keeps_sending(self):
        # Un cliente que sigue subiendo tras el rechazo debe recibir la respuesta, no un
        # corte de conexión; y un Content-Length mayor que lo enviado no bloquea el hilo.
        port = self.server.server_address[1]
        for extra, status in (({"Content-Length": str(40 * 1024 * 1024)}, b" 413 "),
                              ({"Content-Length": "1000000", "X-Dedalo-Token": "wrong"}, b" 403 ")):
            headers = {"Host": f"127.0.0.1:{port}", "Content-Type": "application/json",
                       "X-Dedalo-Token": self.store.token} | extra
            with self.subTest(status=status), socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(b"POST /api/jobs HTTP/1.1\r\n" +
                               b"".join(f"{k}: {v}\r\n".encode() for k, v in headers.items()) + b"\r\n")
                sender = threading.Thread(target=lambda: self._send_quietly(client, b"x" * 512 * 1024))
                started = time.monotonic()
                sender.start()
                response = b""
                while chunk := client.recv(65536):
                    response += chunk
                sender.join(5)
                self.assertIn(status, response.split(b"\r\n", 1)[0])
                self.assertIn(b'"error"', response)
                self.assertLess(time.monotonic() - started, 4)

    @staticmethod
    def _send_quietly(client, data):
        try:
            client.sendall(data)
        except OSError:
            pass

    def test_client_that_hangs_up_mid_response_gets_no_second_reply_or_traceback(self):
        # Si el navegador corta mientras el portal escribe (al recargar, por ejemplo), no se
        # intenta un 500 por el mismo socket ni se llena la terminal de trazas.
        port = self.server.server_address[1]
        for error in (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            with self.subTest(error=error.__name__), \
                    patch.object(web.PortalHandler, "send_bytes", side_effect=error) as send, \
                    redirect_stderr(io.StringIO()) as stderr, \
                    socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(f"GET /api/audits HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
                self.assertEqual(client.recv(65536), b"")  # el portal cierra después de cualquier traza
                self.assertEqual([call.args[0] for call in send.call_args_list], [200])
                self.assertEqual(stderr.getvalue(), "")

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
            with patch("dedalo.web.gowitness.find_gowitness", return_value="fake"), patch("dedalo.web.gowitness.find_chrome", return_value="fake"), patch("dedalo.web.subprocess.run", side_effect=run):
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

    def run_engine(self, job_id, stop_after_first=False):
        """Arranca la captura con el motor real de la consola y un gowitness simulado.

        Con stop_after_first se pulsa «Detener» durante la primera subred."""
        def run(command, **kwargs):
            from contextlib import redirect_stdout
            def scan(binary, directory, urls, opts):
                fake_database(directory, urls)
                if stop_after_first:
                    Path(command[command.index("--stop-file") + 1]).touch()
            with patch("dedalo.cli.gowitness.scan_subnet", side_effect=scan), redirect_stdout(io.StringIO()):
                code = cli.main(command[4:])  # sin «python -u -m dedalo»
            class Result:
                returncode = code
            return Result()
        with patch("dedalo.web.gowitness.find_gowitness", return_value="fake"), \
                patch("dedalo.web.gowitness.find_chrome", return_value="fake"), \
                patch("dedalo.web.subprocess.run", side_effect=run):
            self.assertEqual(self.request("/api/jobs/" + job_id + "/start", {})[0], 202)
            deadline = time.monotonic() + 10
            while self.store.detail(job_id)["estado"] in ("en_cola", "en_curso") and time.monotonic() < deadline:
                time.sleep(.02)
        with closing(self.store.database()) as con:
            capture = auditoria.capture_of(con, job_id)
            deadline = time.monotonic() + 5
            while con.execute("SELECT estado FROM ejecucion WHERE id = ?", (capture,)).fetchone()[0] in ("en_cola", "en_curso") \
                    and time.monotonic() < deadline:
                time.sleep(.02)
        return capture

    def test_capture_is_recorded_in_the_database_with_its_evidence(self):
        job = self.create()
        capture = self.run_engine(job["id"])
        with closing(self.store.database()) as con:
            execution = con.execute("SELECT * FROM ejecucion WHERE id = ?", (capture,)).fetchone()
            self.assertEqual((execution["tipo"], execution["origen_id"], execution["estado"]), ("captura", job["id"], "completa"))
            self.assertTrue(execution["iniciada"] and execution["terminada"])
            self.assertEqual(json.loads(execution["opciones"])["timeout"], 5)
            rows = con.execute("SELECT c.url, c.estado, c.codigo_http, c.titulo, a.ip, s.puerto, e.ruta, e.sha256 FROM captura c "
                               "JOIN servicio s ON s.id = c.servicio_id JOIN activo a ON a.id = s.activo_id "
                               "JOIN evidencia e ON e.id = c.evidencia_id WHERE c.ejecucion_id = ? ORDER BY c.url", (capture,)).fetchall()
            # 192.168.1.8 queda fuera del alcance de la ficha: ni se captura ni se registra.
            self.assertEqual([(r["url"], r["estado"], r["codigo_http"], r["titulo"], r["ip"], r["puerto"]) for r in rows], [
                ("http://10.10.5.10/", "capturada", 200, "=test", "10.10.5.10", 80),
                ("http://10.10.6.20/", "capturada", 200, "=test", "10.10.6.20", 80),
                ("https://10.10.5.10/", "capturada", 200, "=test", "10.10.5.10", 443),
            ])
            for row in rows:
                image = Path(self.temp.name) / row["ruta"]
                self.assertEqual(row["sha256"], hashlib.sha256(image.read_bytes()).hexdigest())
            logs = [r[0] for r in con.execute("SELECT ruta FROM evidencia WHERE ejecucion_id = ? AND tipo = 'registro'", (capture,))]
            self.assertIn(job["id"] + "/proceso.log", logs)
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/delete", {})[0], 200)
        with closing(self.store.database()) as con:
            for table in ("ejecucion", "captura", "evidencia", "activo"):
                self.assertEqual(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0, table)

    def test_interrupted_capture_keeps_unreached_targets_pending(self):
        job = self.create()
        capture = self.run_engine(job["id"], stop_after_first=True)
        with closing(self.store.database()) as con:
            self.assertEqual(con.execute("SELECT estado FROM ejecucion WHERE id = ?", (capture,)).fetchone()[0], "interrumpida")
            rows = con.execute("SELECT url, estado, evidencia_id IS NOT NULL FROM captura WHERE ejecucion_id = ? ORDER BY url",
                               (capture,)).fetchall()
        self.assertEqual([tuple(r) for r in rows], [("http://10.10.5.10/", "capturada", 1),
                                                     ("http://10.10.6.20/", "pendiente", 0),
                                                     ("https://10.10.5.10/", "capturada", 1)])

    def test_cancelled_queued_capture_is_recorded_as_cancelled(self):
        first, second = self.create(), self.create()
        begun, release = threading.Event(), threading.Event()
        def run(*args, **kwargs):
            begun.set()
            release.wait(5)
            class Result:
                returncode = 130
            return Result()
        try:
            with patch("dedalo.web.gowitness.find_gowitness", return_value="fake"), \
                    patch("dedalo.web.gowitness.find_chrome", return_value="fake"), \
                    patch("dedalo.web.subprocess.run", side_effect=run):
                self.request("/api/jobs/" + first["id"] + "/start", {})
                self.assertTrue(begun.wait(2))
                self.request("/api/jobs/" + second["id"] + "/start", {})
                with closing(self.store.database()) as con:
                    ids = {job: auditoria.capture_of(con, job) for job in (first["id"], second["id"])}
                    state = lambda job: con.execute("SELECT estado, terminada FROM ejecucion WHERE id = ?", (ids[job],)).fetchone()
                    self.assertEqual(state(first["id"])["estado"], "en_curso")
                    self.assertEqual(tuple(state(second["id"])), ("en_cola", None))
                    self.assertEqual(con.execute("SELECT COUNT(*) FROM captura WHERE ejecucion_id = ? AND estado = 'pendiente'",
                                                 (ids[second["id"]],)).fetchone()[0], 3)
                    self.request("/api/jobs/" + second["id"] + "/cancel", {})
                    self.assertEqual(state(second["id"])["estado"], "cancelada")
                    self.assertTrue(state(second["id"])["terminada"])
                    self.request("/api/jobs/" + first["id"] + "/cancel", {})
                    self.assertEqual(state(first["id"])["estado"], "deteniendo")
        finally:
            release.set()

    def capture_finishing(self, job_id):
        """Lanza una captura cuyo motor acaba al instante y la retiene tras guardar su estado final.

        Es el hueco en que la base ya dice «completa» pero el portal aún no ha cerrado
        el trabajo en memoria. Devuelve el evento que la libera."""
        saved, release = threading.Event(), threading.Event()
        real_set_state = auditoria.set_state
        def set_state(con, execution_id, state, error=""):
            real_set_state(con, execution_id, state, error)
            if state in auditoria.FINAL:
                saved.set()
                release.wait(5)
        class Result:
            returncode = 0
        self.enterContext(patch("dedalo.web.gowitness.find_gowitness", return_value="fake"))
        self.enterContext(patch("dedalo.web.gowitness.find_chrome", return_value="fake"))
        self.enterContext(patch("dedalo.web.subprocess.run", return_value=Result()))
        self.enterContext(patch("dedalo.auditoria.set_state", side_effect=set_state))
        self.assertEqual(self.request("/api/jobs/" + job_id + "/start", {})[0], 202)
        self.assertTrue(saved.wait(5))
        return release

    def stored_capture(self, job_id):
        with closing(self.store.database()) as con:
            return con.execute("SELECT estado, terminada FROM ejecucion WHERE id = ?", (auditoria.capture_of(con, job_id),)).fetchone()

    def test_stop_after_the_final_state_was_saved_cannot_overwrite_it(self):
        job = self.create()
        release = self.capture_finishing(job["id"])
        try:
            self.assertEqual(self.stored_capture(job["id"])["estado"], "completa")
            status, content = self.request("/api/jobs/" + job["id"] + "/cancel", {})
        finally:
            release.set()
        deadline = time.monotonic() + 5
        while self.store.detail(job["id"])["estado"] in ("en_curso", "deteniendo") and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertEqual(self.store.detail(job["id"])["estado"], "completa")
        row = self.stored_capture(job["id"])
        self.assertEqual(row["estado"], "completa")
        self.assertTrue(row["terminada"])
        # El «Detener» tardío se rechaza como cualquier otro de un trabajo que no corre.
        self.assertEqual(status, 409, content)
        self.assertIn("terminó", json.loads(content)["error"])
        self.assertFalse((self.store.directory(job["id"]) / "parar").exists())

    def test_closing_the_portal_while_a_capture_is_being_saved_waits_for_it_without_error(self):
        job = self.create()
        release = self.capture_finishing(job["id"])
        looped, errors = threading.Event(), io.StringIO()
        real_put = self.store.pending.put
        def put(item):
            real_put(item)
            looped.set()
        closer = threading.Thread(target=self.store.close)
        try:
            with patch.object(self.store.pending, "put", side_effect=put), redirect_stderr(errors):
                closer.start()
                self.assertTrue(looped.wait(5))  # close() ya recorrió los trabajos activos
        finally:
            release.set()
        closer.join(5)
        self.assertFalse(closer.is_alive())
        self.assertNotIn("Error del portal", errors.getvalue())
        self.assertEqual(self.stored_capture(job["id"])["estado"], "completa")
        self.assertEqual(self.store.detail(job["id"])["estado"], "completa")

    def test_stop_whose_state_cannot_be_saved_still_stops_the_engine_and_says_so(self):
        job = self.create()
        begun, release = threading.Event(), threading.Event()
        def run(*args, **kwargs):
            begun.set()
            release.wait(5)
            class Result:
                returncode = 130
            return Result()
        real_set_state = auditoria.set_state
        def set_state(con, execution_id, state, error=""):
            if state == "deteniendo":
                raise sqlite3.OperationalError("database is locked")
            real_set_state(con, execution_id, state, error)
        errors = io.StringIO()
        try:
            with patch("dedalo.web.gowitness.find_gowitness", return_value="fake"), \
                    patch("dedalo.web.gowitness.find_chrome", return_value="fake"), \
                    patch("dedalo.web.subprocess.run", side_effect=run), \
                    patch("dedalo.auditoria.set_state", side_effect=set_state), redirect_stderr(errors):
                self.assertEqual(self.request("/api/jobs/" + job["id"] + "/start", {})[0], 202)
                self.assertTrue(begun.wait(5))
                status, content = self.request("/api/jobs/" + job["id"] + "/cancel", {})
                self.assertEqual(status, 409, content)
                message = json.loads(content)["error"]
                self.assertIn("parada está pedida", message)
                self.assertIn("no se pudo guardar", message)
                # El fichero de parada va antes que la base: el motor para aunque la base falle.
                self.assertTrue((self.store.directory(job["id"]) / "parar").is_file())
                # Lo que se ve y lo que está guardado siguen coincidiendo.
                self.assertEqual(self.store.detail(job["id"])["estado"], "en_curso")
                self.assertEqual(self.stored_capture(job["id"])["estado"], "en_curso")
                self.assertIn("database is locked", errors.getvalue())
                release.set()
                deadline = time.monotonic() + 5
                while self.store.detail(job["id"])["estado"] == "en_curso" and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertEqual(self.store.detail(job["id"])["estado"], "interrumpida")
        finally:
            release.set()
        self.assertEqual(self.stored_capture(job["id"])["estado"], "interrumpida")

    def reopen(self):
        self.store.close()
        self.store = PortalStore(self.temp.name)
        self.server.store = self.store

    def test_startup_says_how_many_old_runs_it_moves_to_the_database(self):
        # La migración puede tardar minutos: se avisa en la terminal, y solo si hay algo que migrar.
        from contextlib import redirect_stdout
        job = self.create()
        self.make_legacy(job["id"])
        output = io.StringIO()
        with redirect_stdout(output):
            self.reopen()
        self.assertIn("Pasando 1 ejecución anterior a la base de datos", output.getvalue())
        self.assertEqual(self.store.detail(job["id"])["estado"], "preparada")
        output = io.StringIO()
        with redirect_stdout(output):
            self.reopen()
        self.assertNotIn("Pasando", output.getvalue())

    def test_reopening_after_a_crash_closes_the_capture_in_the_database(self):
        # Una captura que no llegó a empezar y otra que el motor terminó sin que el portal lo anotase.
        unstarted, finished = self.create(), self.create()
        finished_capture = self.run_engine(finished["id"])
        with closing(self.store.database()) as con:
            unstarted_capture = auditoria.start_capture(con, unstarted["id"], {}, self.store.jobs[unstarted["id"]]["grupos"])
            with con:
                con.execute("UPDATE ejecucion SET estado = 'en_curso', terminada = NULL WHERE id IN (?, ?)",
                            (unstarted_capture, finished_capture))
                con.execute("UPDATE captura SET estado = 'pendiente', evidencia_id = NULL WHERE ejecucion_id = ?", (finished_capture,))
        self.reopen()
        self.assertEqual(self.store.detail(unstarted["id"])["estado"], "interrumpida")
        self.assertEqual(self.store.detail(finished["id"])["estado"], "completa")
        with closing(self.store.database()) as con:
            row = con.execute("SELECT estado, error, terminada FROM ejecucion WHERE id = ?", (unstarted_capture,)).fetchone()
            self.assertEqual(row["estado"], "interrumpida")
            self.assertIn("se cerró", row["error"])
            self.assertTrue(row["terminada"])
            states = [r[0] for r in con.execute("SELECT estado FROM captura WHERE ejecucion_id = ?", (finished_capture,))]
            self.assertEqual(states, ["capturada"] * 3)

    def test_reopening_after_a_crash_tells_a_leftover_engine_to_stop(self):
        # Si el portal murió sin cerrarse, su motor puede seguir conectando: se le pide parar.
        active = {state: self.create() for state in ("en_cola", "en_curso", "deteniendo")}
        untouched = self.create()
        with closing(self.store.database()) as con:
            for state, job in active.items():
                capture = auditoria.start_capture(con, job["id"], {}, self.store.jobs[job["id"]]["grupos"])
                with con:
                    con.execute("UPDATE ejecucion SET estado = ?, terminada = NULL WHERE id = ?", (state, capture))
        stop_file = lambda job: self.store.directory(job["id"]) / "parar"
        self.assertFalse(any(stop_file(job).exists() for job in [*active.values(), untouched]))
        self.reopen()
        for state, job in active.items():
            with self.subTest(state=state):
                self.assertEqual(self.store.detail(job["id"])["estado"], "interrumpida")
                self.assertTrue(stop_file(job).is_file())
        self.assertFalse(stop_file(untouched).exists())

    def test_reopening_still_closes_the_capture_if_the_stop_file_cannot_be_written(self):
        job = self.create()
        with closing(self.store.database()) as con:
            capture = auditoria.start_capture(con, job["id"], {}, self.store.jobs[job["id"]]["grupos"])
            with con:
                con.execute("UPDATE ejecucion SET estado = 'en_curso', terminada = NULL WHERE id = ?", (capture,))
        errors = io.StringIO()
        with patch("dedalo.web.Path.touch", side_effect=PermissionError("denegado")), redirect_stderr(errors):
            self.reopen()
        self.assertEqual(self.store.detail(job["id"])["estado"], "interrumpida")
        self.assertIn("denegado", errors.getvalue())

    def make_legacy(self, job_id):
        """Deja una ejecución como la guardaban las versiones anteriores: trabajo.json y nada en la base."""
        meta = self.store.jobs[job_id]
        path = self.store.directory(job_id) / "trabajo.json"
        path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        with closing(self.store.database()) as con:
            auditoria.delete_execution(con, job_id)
        return path.read_bytes()

    def test_old_captures_are_moved_to_the_database_once(self):
        prepared, captured = self.create(), self.create()
        self.run_engine(captured["id"])
        before = self.store.detail(captured["id"])
        originals = {job["id"]: self.make_legacy(job["id"]) for job in (prepared, captured)}
        self.reopen()
        for _ in range(2):  # al reabrir otra vez no se duplica nada
            with closing(self.store.database()) as con:
                self.assertEqual(con.execute("SELECT COUNT(*) FROM ejecucion WHERE tipo = 'importacion'").fetchone()[0], 2)
                captures = con.execute("SELECT id, estado, origen_id FROM ejecucion WHERE tipo = 'captura'").fetchall()
                self.assertEqual([(c["estado"], c["origen_id"]) for c in captures], [("completa", captured["id"])])
                rows = con.execute("SELECT estado, evidencia_id IS NOT NULL FROM captura WHERE ejecucion_id = ?",
                                   (captures[0]["id"],)).fetchall()
                self.assertEqual([tuple(r) for r in rows], [("capturada", 1)] * 3)
                self.assertEqual(auditoria.portal_options(con, prepared["id"])["archivos"], ["escaneo.xml"])
            self.assertEqual(self.store.detail(prepared["id"])["estado"], "preparada")
            after = self.store.detail(captured["id"])
            self.assertEqual({k: after[k] for k in ("estado", "total", "capturas", "grupos")},
                             {k: before[k] for k in ("estado", "total", "capturas", "grupos")})
            self.reopen()
        # Las carpetas antiguas no se modifican.
        for job_id, original in originals.items():
            self.assertEqual((self.store.directory(job_id) / "trabajo.json").read_bytes(), original)

    def test_folder_that_cannot_be_migrated_is_kept_and_reported(self):
        job = self.create()
        self.make_legacy(job["id"])
        for item in (self.store.directory(job["id"]) / "entradas").iterdir():
            item.unlink()
        with redirect_stderr(io.StringIO()) as errors:
            self.reopen()
        self.assertIn(job["id"], errors.getvalue())
        self.assertEqual(self.store.list(), [])
        self.assertTrue((self.store.directory(job["id"]) / "trabajo.json").is_file())

    def bootstrap_failures(self):
        status, content = self.request("/api/bootstrap")
        self.assertEqual(status, 200)
        return json.loads(content)["migration_failures"]

    def break_legacy_inputs(self, job_id):
        """Quita los Nmap guardados de una ejecución antigua, como si se hubieran borrado a mano."""
        entries = self.store.directory(job_id) / "entradas"
        saved = {item.name: item.read_bytes() for item in entries.iterdir()}
        for item in entries.iterdir():
            item.unlink()
        return entries, saved

    def test_portal_tells_which_old_run_could_not_be_migrated_and_why(self):
        job = self.create()
        self.make_legacy(job["id"])
        self.break_legacy_inputs(job["id"])
        with redirect_stderr(io.StringIO()):
            self.reopen()
        # La ejecución no está en el historial: sin este aviso, el usuario no sabría que existe.
        self.assertEqual(json.loads(self.request("/api/jobs")[1]), [])
        failures = self.bootstrap_failures()
        self.assertEqual([item["id"] for item in failures], [job["id"]])
        self.assertEqual(failures[0]["nombre"], "Prueba de portal")
        self.assertIn("No se conservan los Nmap", failures[0]["error"])

    def test_unmigrated_run_is_retried_at_the_next_startup(self):
        job = self.create()
        original = self.make_legacy(job["id"])
        self.assertEqual(self.bootstrap_failures(), [])  # un arranque sin problemas no avisa de nada
        entries, saved = self.break_legacy_inputs(job["id"])
        with redirect_stderr(io.StringIO()):
            self.reopen()
        self.assertEqual(len(self.bootstrap_failures()), 1)
        # Arreglada la causa, el siguiente arranque migra la ejecución y el aviso desaparece.
        for name, data in saved.items():
            (entries / name).write_bytes(data)
        self.reopen()
        self.assertEqual(self.bootstrap_failures(), [])
        self.assertEqual([item["id"] for item in self.store.list()], [job["id"]])
        self.assertEqual((self.store.directory(job["id"]) / "trabajo.json").read_bytes(), original)

    def test_page_shows_the_migration_notice(self):
        self.assertIn(b'id="migration-notice"', self.request("/")[1])
        self.assertIn(b"migration_failures", self.request("/app.js")[1])

    def store_options(self, job_id, value):
        """Deja en la base las opciones de una ejecución tal cual: texto, o un valor que se guarda como JSON."""
        with closing(self.store.database()) as con, con:
            con.execute("UPDATE ejecucion SET opciones = ? WHERE id = ?",
                        (value if isinstance(value, str) else json.dumps(value), job_id))

    def capture_rows(self, capture):
        with closing(self.store.database()) as con:
            state = con.execute("SELECT estado, terminada FROM ejecucion WHERE id = ?", (capture,)).fetchone()
            rows = con.execute("SELECT estado, codigo_http, titulo, error, evidencia_id IS NOT NULL AS evidencia "
                               "FROM captura WHERE ejecucion_id = ? ORDER BY url", (capture,)).fetchall()
        return state, rows

    def test_old_options_missing_fields_get_the_defaults_of_a_new_run(self):
        healthy, old = self.create(), self.create()
        before = self.store.detail(healthy["id"])
        # Una ejecución ya migrada cuyas opciones no traen puertos, por_servicio ni los demás campos.
        self.store_options(old["id"], {"archivos": ["escaneo.xml"], "captura": {"timeout": 5, "delay": 0}})
        self.reopen()
        self.assertEqual({item["id"] for item in self.store.list()}, {healthy["id"], old["id"]})
        self.assertEqual(self.store.detail(healthy["id"]), before)
        detail = self.store.detail(old["id"])
        self.assertEqual((detail["estado"], detail["total"], detail["error"]), ("preparada", 3, ""))
        self.assertEqual(detail["opciones"], web.options_from({"timeout": 5, "delay": 0}))

    def test_old_run_file_with_missing_options_is_stored_with_the_defaults_of_a_new_run(self):
        healthy, old = self.create(), self.create()
        expected = self.store.jobs[old["id"]]["opciones"]
        self.make_legacy(old["id"])
        path = self.store.directory(old["id"]) / "trabajo.json"
        meta = json.loads(path.read_text(encoding="utf-8"))
        meta["opciones"] = {"hilos": 6, "timeout": 5, "delay": 0, "formato": "jpeg"}  # antes de existir las demás
        path.write_text(json.dumps(meta), encoding="utf-8")
        self.reopen()
        self.assertEqual(self.bootstrap_failures(), [])
        with closing(self.store.database()) as con:
            self.assertEqual(auditoria.portal_options(con, old["id"])["captura"], expected)
        self.assertEqual({item["id"] for item in self.store.list()}, {healthy["id"], old["id"]})
        detail = self.store.detail(old["id"])
        self.assertEqual((detail["estado"], detail["error"], detail["opciones"]), ("preparada", "", expected))

    def test_one_run_that_cannot_be_loaded_does_not_stop_the_portal(self):
        healthy, broken = self.create(), self.create()
        before = self.store.detail(healthy["id"])
        for stored in ({"archivos": [], "captura": {"puertos": "8080"}}, {"archivos": [], "captura": "texto"},
                       {"archivos": [], "captura": None}, "esto no es json"):
            with self.subTest(stored=stored):
                self.store_options(broken["id"], stored)
                with redirect_stderr(io.StringIO()) as errors:
                    self.reopen()
                self.assertIn(broken["id"], errors.getvalue())
                self.assertEqual({item["id"] for item in self.store.list()}, {healthy["id"], broken["id"]})
                self.assertEqual(self.store.detail(healthy["id"]), before)
                detail = self.store.detail(broken["id"])
                self.assertEqual((detail["estado"], detail["total"], detail["grupos"]), ("error", 0, []))
                self.assertTrue(detail["error"].startswith("No se pudo cargar esta ejecución"), detail["error"])
                for technical in ("KeyError", "TypeError", "JSONDecodeError", "Traceback"):
                    self.assertNotIn(technical, detail["error"])
        self.assertEqual(self.request("/api/jobs/" + broken["id"] + "/delete", {})[0], 200)  # se puede quitar

    def test_an_active_capture_is_closed_even_if_its_run_cannot_be_loaded(self):
        job = self.create()
        with closing(self.store.database()) as con:
            capture = auditoria.start_capture(con, job["id"], {}, self.store.jobs[job["id"]]["grupos"])
            with con:
                con.execute("UPDATE ejecucion SET estado = 'en_curso', terminada = NULL WHERE id = ?", (capture,))
        self.store_options(job["id"], "esto no es json")
        with redirect_stderr(io.StringIO()):
            self.reopen()
        self.assertEqual(self.capture_rows(capture)[0]["estado"], "interrumpida")
        self.assertTrue((self.store.directory(job["id"]) / "parar").is_file())

    def test_capture_with_a_missing_image_still_gets_its_final_state(self):
        job = self.create()
        real_main = cli.main

        def main_then_lose_an_image(args):
            code = real_main(args)
            # El manifiesto ya cita las tres imágenes; una desaparece antes de registrarlas.
            first_image(Path(args[args.index("-o") + 1])).unlink()
            return code

        with patch.object(cli, "main", main_then_lose_an_image), redirect_stderr(io.StringIO()) as errors:
            capture = self.run_engine(job["id"])
        state, rows = self.capture_rows(capture)
        self.assertEqual(state["estado"], "completa")
        self.assertTrue(state["terminada"])
        self.assertEqual(sorted((r["estado"], r["evidencia"]) for r in rows),
                         [("capturada", 1), ("capturada", 1), ("sin_captura", 0)])
        lost = next(r for r in rows if r["estado"] == "sin_captura")
        self.assertEqual((lost["codigo_http"], lost["titulo"]), (200, "=test"))  # conserva lo que vio el motor
        self.assertIn("no está en disco", lost["error"])
        self.assertIn(job["id"], errors.getvalue())
        self.assertIn("no están en disco", errors.getvalue())
        self.assertEqual(self.store.detail(job["id"])["estado"], "completa")
        # Con la captura cerrada en la base, al reabrir no se vuelve a cerrar.
        self.reopen()
        self.assertEqual(self.store.detail(job["id"])["estado"], "completa")
        self.assertFalse((self.store.directory(job["id"]) / "parar").exists())

    def test_final_state_is_saved_even_if_the_results_cannot_be_recorded(self):
        job = self.create()
        with patch("dedalo.web.auditoria.record_captures", side_effect=OSError("disco lleno")), \
                redirect_stderr(io.StringIO()) as errors:
            capture = self.run_engine(job["id"])
        state, _ = self.capture_rows(capture)
        self.assertEqual((state["estado"], bool(state["terminada"])), ("completa", True))
        self.assertIn("disco lleno", errors.getvalue())
        self.assertEqual(self.store.detail(job["id"])["estado"], "completa")

    def test_old_run_with_a_missing_image_is_migrated_without_that_image(self):
        job = self.create()
        self.run_engine(job["id"])
        first_image(self.store.directory(job["id"]) / "resultado").unlink()
        self.make_legacy(job["id"])
        with redirect_stderr(io.StringIO()) as errors:
            self.reopen()
        self.assertEqual(self.bootstrap_failures(), [])
        with closing(self.store.database()) as con:
            capture = auditoria.capture_of(con, job["id"])
        state, rows = self.capture_rows(capture)
        self.assertEqual(state["estado"], "completa")
        self.assertEqual(sorted((r["estado"], r["evidencia"]) for r in rows),
                         [("capturada", 1), ("capturada", 1), ("sin_captura", 0)])
        self.assertIn("no están en disco", errors.getvalue())
        self.assertEqual(self.store.detail(job["id"])["estado"], "completa")

    def test_old_run_whose_results_cannot_be_recorded_keeps_at_least_its_state(self):
        def lose_the_ip(job_id):
            path = self.store.directory(job_id) / "resultado" / "ejecucion.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            del manifest["grupos"][0]["resultados"][0]["ip"]  # KeyError al registrar
            path.write_text(json.dumps(manifest), encoding="utf-8")

        def image_is_a_folder(job_id):
            image = first_image(self.store.directory(job_id) / "resultado")
            image.unlink()
            image.mkdir()  # no se puede leer como archivo: OSError, no «no existe»

        for damage in (lose_the_ip, image_is_a_folder):
            with self.subTest(damage=damage.__name__):
                job = self.create()
                self.run_engine(job["id"])
                damage(job["id"])
                self.make_legacy(job["id"])
                with redirect_stderr(io.StringIO()) as errors:
                    self.reopen()
                self.assertEqual(self.bootstrap_failures(), [])
                self.assertIn("sin sus resultados", errors.getvalue())
                with closing(self.store.database()) as con:
                    capture = auditoria.capture_of(con, job["id"])
                state, rows = self.capture_rows(capture)
                self.assertEqual((state["estado"], len(rows)), ("completa", 0))
                self.assertEqual(self.store.detail(job["id"])["estado"], "completa")

    def test_folder_whose_trabajo_json_names_another_run_is_reported(self):
        job = self.create()
        self.make_legacy(job["id"])
        path = self.store.directory(job["id"]) / "trabajo.json"
        meta = json.loads(path.read_text(encoding="utf-8"))
        meta["id"] = "a" * 32  # una copia de otra ejecución, o editada a mano
        path.write_text(json.dumps(meta), encoding="utf-8")
        original = path.read_bytes()
        with redirect_stderr(io.StringIO()) as errors:
            self.reopen()
        failures = self.bootstrap_failures()
        self.assertEqual([item["id"] for item in failures], [job["id"]])
        self.assertEqual(failures[0]["nombre"], "Prueba de portal")
        self.assertIn("no coincide", failures[0]["error"])
        self.assertIn(job["id"], errors.getvalue())
        self.assertEqual(self.store.list(), [])
        self.assertEqual(path.read_bytes(), original)

    def test_old_active_run_is_migrated_as_interrupted_and_its_engine_told_to_stop(self):
        active = {state: self.create() for state in ("en_cola", "en_curso", "deteniendo")}
        quiet = {state: self.create() for state in ("preparada", "completa")}
        for state, job in {**active, **quiet}.items():
            self.make_legacy(job["id"])
            path = self.store.directory(job["id"]) / "trabajo.json"
            meta = json.loads(path.read_text(encoding="utf-8"))
            meta["estado"] = state
            path.write_text(json.dumps(meta), encoding="utf-8")
        stop_file = lambda job: self.store.directory(job["id"]) / "parar"
        self.assertFalse(any(stop_file(job).exists() for job in [*active.values(), *quiet.values()]))
        self.reopen()
        for state, job in active.items():
            with self.subTest(state=state):
                self.assertEqual(self.store.detail(job["id"])["estado"], "interrumpida")
                self.assertTrue(stop_file(job).is_file())
                self.assertIn("se cerró", self.store.detail(job["id"])["error"])
        for state, job in quiet.items():
            with self.subTest(state=state):
                self.assertFalse(stop_file(job).exists())
        self.assertEqual(self.bootstrap_failures(), [])

    def test_old_active_run_is_still_migrated_if_the_stop_file_cannot_be_written(self):
        job = self.create()
        self.make_legacy(job["id"])
        path = self.store.directory(job["id"]) / "trabajo.json"
        meta = json.loads(path.read_text(encoding="utf-8"))
        meta["estado"] = "en_curso"
        path.write_text(json.dumps(meta), encoding="utf-8")
        with patch("dedalo.web.Path.touch", side_effect=PermissionError("denegado")), redirect_stderr(io.StringIO()) as errors:
            self.reopen()
        self.assertEqual(self.bootstrap_failures(), [])
        self.assertEqual(self.store.detail(job["id"])["estado"], "interrumpida")
        self.assertIn("denegado", errors.getvalue())

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
        with patch("dedalo.web.subprocess.run") as run:
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
        original_meta = self.make_legacy(job["id"])  # como una ejecución anterior a la base
        self.reopen()
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
        with patch("dedalo.web.auditoria.import_nmap", side_effect=sqlite3.OperationalError("disco lleno")):
            self.assertEqual(self.request("/api/jobs", self.payload())[0], 500)
        self.assertFalse(self.store.jobs)
        self.assertEqual([p.name for p in Path(self.temp.name).iterdir() if p.is_dir()], [])

    def test_long_import_does_not_block_the_portal_and_uses_the_latest_scope(self):
        started, release = threading.Event(), threading.Event()
        original = auditoria.import_nmap

        def slow_import(*args, **kwargs):
            started.set()
            release.wait(5)
            return original(*args, **kwargs)

        result = {}
        with patch("dedalo.web.auditoria.import_nmap", side_effect=slow_import):
            upload = threading.Thread(target=lambda: result.update(response=self.request("/api/jobs", self.payload())))
            upload.start()
            self.assertTrue(started.wait(5))
            # Con la importación en marcha, el portal responde y la ficha se puede editar.
            self.assertEqual(self.request("/api/jobs")[0], 200)
            status, _ = self.request("/api/audits/" + self.audit["id"], {"nombre": "Cliente", "incluir": "10.10.0.0/17",
                                                                        "excluir": "10.10.5.10"})
            self.assertEqual(status, 200)
            release.set()
            upload.join(10)
        status, content = result["response"]
        self.assertEqual(status, 201, content)
        job = json.loads(content)
        self.assertEqual((job["total"], job["fuera_alcance"]), (1, {"fuera": 1, "excluida": 2}))

    def test_failure_after_import_removes_it_from_the_database(self):
        with patch("dedalo.web.write_scope_files", side_effect=OSError("Archivo ocupado")):
            self.assertEqual(self.request("/api/jobs", self.payload())[0], 500)
        self.assertFalse(self.store.jobs)
        with closing(self.store.database()) as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM ejecucion").fetchone()[0], 0)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM activo").fetchone()[0], 0)

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

    def test_logo_is_served_and_used_as_brand_and_tab_icon(self):
        with self.opener.open(self.url + "/logo.png", timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["Content-Type"], "image/png")
            content = response.read()
        self.assertEqual(content[:8], b"\x89PNG\r\n\x1a\n")
        # Se descarga en cada carga de la página (no-store): la copia del portal es la ligera.
        self.assertLess(len(content), 64 * 1024)
        page = self.request("/")[1].decode("utf-8")
        brand = re.search(r'<a class="brand"[^>]*>(.*?)</a>', page).group(1)
        self.assertRegex(brand, r'<img [^>]*src="/logo\.png"')
        self.assertRegex(page, r'<link rel="icon" href="/logo\.png"')


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
        with patch("dedalo.web.gowitness.find_gowitness", return_value="fake"), patch("dedalo.web.gowitness.find_chrome", return_value="fake"):
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
        with patch("dedalo.web.gowitness.find_gowitness", return_value="fake"), patch("dedalo.web.gowitness.find_chrome", return_value=None), \
             patch("dedalo.web.subprocess.run", side_effect=run):
            self.assertEqual(self.request("/api/jobs/" + job["id"] + "/start", {})[0], 202)
            self.assertTrue(started.wait(3))
        directory = self.store.directory(job["id"])
        self.assertIn("--solo-rangos", self.command)
        self.assertEqual(self.command[self.command.index("--excluir") + 1], str(directory / "excluir.txt"))
        # Por defecto, gorod y reintento con el otro motor.
        self.assertEqual(self.command[self.command.index("--driver") + 1], "gorod")
        self.assertNotIn("--sin-reintento", self.command)

    def test_browser_engine_options_reach_the_engine(self):
        data = self.payload()
        data["opciones"].update(driver="chromedp", reintentar=False)
        status, content = self.request("/api/jobs", data)
        self.assertEqual(status, 201, content)
        job = json.loads(content)
        self.assertEqual((job["opciones"]["driver"], job["opciones"]["reintentar"]), ("chromedp", False))
        started = threading.Event()
        def run(command, **kwargs):
            self.command = command
            started.set()
            class Result:
                returncode = 0
            return Result()
        with patch("dedalo.web.gowitness.find_gowitness", return_value="fake"), patch("dedalo.web.gowitness.find_chrome", return_value=None), \
             patch("dedalo.web.subprocess.run", side_effect=run):
            self.assertEqual(self.request("/api/jobs/" + job["id"] + "/start", {})[0], 202)
            self.assertTrue(started.wait(3))
        self.assertEqual(self.command[self.command.index("--driver") + 1], "chromedp")
        self.assertIn("--sin-reintento", self.command)
        for invalid in ({"driver": "firefox"}, {"reintentar": "si"}):
            data = self.payload()
            data["opciones"].update(invalid)
            with self.subTest(invalid=invalid):
                self.assertEqual(self.request("/api/jobs", data)[0], 400)


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
            with patch("dedalo.cli.gowitness.find_gowitness", return_value="fake"), patch("dedalo.cli.gowitness.find_chrome", return_value="fake"), patch("dedalo.cli.gowitness.scan_subnet", side_effect=scan), redirect_stdout(io.StringIO()):
                result = cli.main(["capturar", str(ROOT / "ejemplos/escaneo.xml"), "-o", str(output), "--stop-file", str(marker)])
            self.assertEqual(result, 130)
            manifest = report.load_manifest(output)
            self.assertEqual(manifest["estado"], "interrumpida")
            self.assertEqual(manifest["grupos"][0]["capturas"], 2)
            self.assertEqual(manifest["grupos"][1]["estado"], "pendiente")
