import argparse
from contextlib import closing, redirect_stderr, redirect_stdout
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

from dedalo import auditoria, cli, favicones, gowitness, report, web
from dedalo.web import PortalStore, PortalServer
from tests.test_dedalo import ROOT, fake_database
from tests.test_gowitness_fingerprint import build_gowitness_db


def first_image(results):
    """Primera captura guardada de un resultado: resultado/rango/subred/capturas/*.png."""
    return sorted(Path(results).glob("*/*/capturas/*.png"))[0]


def model_answering(level="alta"):
    """Modelo falso, sin red, que contesta lo mismo a cada host."""
    def model(prompt, name, host, timeout=120, schema=None):
        return json.dumps({"rol": "R", "nivel": level, "motivo": "m", "siguiente": "s"})
    return model


def model_waiting_at(call, release, level="alta"):
    """Modelo falso que en la pregunta número `call` espera a `release`, como uno lento; anota cada pregunta."""
    def model(prompt, name, host, timeout=120, schema=None):
        model.calls.append(prompt)
        if len(model.calls) == call:
            release.wait(10)
        return json.dumps({"rol": "R", "nivel": level, "motivo": "m", "siguiente": "s"})
    model.calls = []
    return model


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

    def stored(self, job_id):
        with closing(self.store.database()) as con:
            return auditoria.has_execution(con, job_id)

    def assert_whole(self, job_id):
        """La ejecución sigue en el historial, en la base y con su carpeta."""
        self.assertIn(job_id, self.store.jobs)
        self.assertTrue(self.stored(job_id))
        self.assertTrue((self.store.directory(job_id) / "entradas" / "nmap-00.txt").is_file())

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
        with patch.object(Path, "rename", side_effect=PermissionError("Archivo ocupado")):
            self.assertEqual(self.request(route, {})[0], 500)
        self.assert_whole(job["id"])

    def test_delete_keeps_folder_and_job_when_database_fails(self):
        job = self.create()
        directory = self.store.directory(job["id"])
        route = "/api/jobs/" + job["id"] + "/delete"
        with patch("dedalo.web.auditoria.delete_execution", side_effect=sqlite3.OperationalError("database is locked")):
            self.assertEqual(self.request(route, {})[0], 500)
        # Sin borrar de la base no se borra nada, y se puede reintentar.
        self.assert_whole(job["id"])
        self.assertEqual(self.request(route, {})[0], 200)
        self.assertFalse(directory.exists())
        self.assertFalse(self.stored(job["id"]))

    def test_delete_completes_when_only_removing_the_folder_fails(self):
        job = self.create()
        directory = self.store.directory(job["id"])
        # Las ejecuciones migradas conservan su trabajo.json: lo que quede en disco no debe volver al reabrir.
        (directory / "trabajo.json").write_text(json.dumps({"id": job["id"]}), encoding="utf-8")
        errors = io.StringIO()
        with patch("dedalo.web.shutil.rmtree", side_effect=PermissionError("Archivo ocupado")), redirect_stderr(errors):
            self.assertEqual(self.request("/api/jobs/" + job["id"] + "/delete", {})[0], 200)
        self.assertIn(job["id"], errors.getvalue())
        self.assertNotIn(job["id"], self.store.jobs)
        self.assertFalse(self.stored(job["id"]))
        self.assertFalse(directory.exists())
        [left] = [path for path in Path(self.temp.name).iterdir() if job["id"] in path.name]
        # Un solo carácter más que la original: en Windows las rutas largas rozan los 260.
        self.assertEqual(len(left.name), len(job["id"]) + 1)
        # Al reabrir el portal se termina el borrado.
        self.reopen()
        self.assertEqual(self.store.list(), [])
        self.assertFalse(left.exists())

    def test_reopening_restores_a_run_whose_folder_could_not_go_back(self):
        job = self.create()
        rename, calls = Path.rename, []

        def fails_going_back(path, target):
            calls.append(target)
            if len(calls) > 1:
                raise PermissionError("Archivo ocupado")
            return rename(path, target)

        with patch.object(Path, "rename", fails_going_back), \
                patch("dedalo.web.auditoria.delete_execution", side_effect=sqlite3.OperationalError("database is locked")):
            self.assertEqual(self.request("/api/jobs/" + job["id"] + "/delete", {})[0], 500)
        self.assertFalse(self.store.directory(job["id"]).exists())
        self.reopen()
        self.assert_whole(job["id"])

    def test_reopening_never_follows_a_link_named_like_a_set_aside_run(self):
        outside = Path(self.temp.name) / "fuera"
        outside.mkdir()
        (outside / "dato.txt").write_text("x", encoding="utf-8")
        link = Path(self.temp.name) / ("." + "a" * 32)
        if os.name == "nt":
            import _winapi
            _winapi.CreateJunction(str(outside), str(link))
        else:
            link.symlink_to(outside, target_is_directory=True)
        self.reopen()
        self.assertTrue((outside / "dato.txt").is_file())

    @staticmethod
    def until(condition):
        deadline = time.monotonic() + 10
        while not condition() and time.monotonic() < deadline:
            time.sleep(.02)

    def settled(self, job_id):
        """Espera a que el análisis de una ejecución deje de estar en marcha y devuelve el detalle."""
        self.until(lambda: self.store.detail(job_id)["analisis"]["estado"] not in ("en_cola", "en_curso", "deteniendo"))
        return self.store.detail(job_id)

    def analyse(self, job_id, model):
        """Lanza el análisis con un modelo falso y espera a que termine."""
        with patch("dedalo.web.modelo.generate", side_effect=model):
            status, content = self.request("/api/jobs/" + job_id + "/analizar", {})
            self.assertEqual(status, 202, content)
            return self.settled(job_id)

    def test_analysis_requires_the_session_token_and_same_origin(self):
        job = self.create()
        with patch("dedalo.web.modelo.generate") as model:
            for route in ("analizar", "detener-analisis"):
                for headers in ({"X-Dedalo-Token": "wrong"}, {"Origin": "https://example.org"}):
                    with self.subTest(route=route, headers=headers):
                        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/" + route, {}, headers)[0], 403)
            self.assertIsNone(self.store.detail(job["id"])["analisis"])
        model.assert_not_called()

    def test_the_portal_lists_the_local_models_and_the_default(self):
        models = [{"nombre": "fsec-analyst:latest", "tamano": "8.0B"}]
        with patch("dedalo.web.modelo.list_models", return_value=models) as listed:
            status, content = self.request("/api/modelos")
        self.assertEqual((status, json.loads(content)), (200, {"modelos": models, "predeterminado": web.modelo.DEFAULT_MODEL, "error": ""}))
        listed.assert_called_once_with(web.modelo.OLLAMA)

    def test_the_model_list_explains_when_ollama_does_not_answer(self):
        with patch("dedalo.web.modelo.list_models", side_effect=ValueError("No se pudo hablar con Ollama")):
            status, content = self.request("/api/modelos")
        self.assertEqual((status, json.loads(content)["modelos"], json.loads(content)["error"]),
                         (200, [], "No se pudo hablar con Ollama"))

    def test_the_analysis_uses_the_model_chosen_in_the_portal(self):
        job, names = self.create(), []

        def model(prompt, name, host, timeout=120, schema=None):
            names.append(name)
            return json.dumps({"rol": "R", "nivel": "media", "motivo": "m", "siguiente": "s"})

        with patch("dedalo.web.modelo.generate", side_effect=model):
            status, content = self.request("/api/jobs/" + job["id"] + "/analizar", {"modelo": "qwen3:8b"})
            self.assertEqual(status, 202, content)
            self.settled(job["id"])
        self.assertEqual(set(names), {"qwen3:8b"})
        with closing(self.store.database()) as con:
            options = json.loads(con.execute("SELECT opciones FROM ejecucion WHERE tipo = 'analisis'").fetchone()[0])
        self.assertEqual(options["modelo"], "qwen3:8b")  # queda anotado con qué modelo se analizó

    def test_a_model_name_that_is_not_a_local_model_is_refused(self):
        job = self.create()
        with patch("dedalo.web.modelo.generate") as model:
            for chosen in ("gpt-oss:120b-cloud", "", 7, "x" * 300, "modelo con espacios"):
                with self.subTest(chosen=chosen):
                    self.assertEqual(self.request("/api/jobs/" + job["id"] + "/analizar", {"modelo": chosen})[0], 400)
            self.assertIsNone(self.store.detail(job["id"])["analisis"])
        model.assert_not_called()

    def credential_probe(self, resultado):
        """Prueba de credenciales falsa, sin red: `resultado(ip, objetivo) -> bool`."""
        return patch("dedalo.web.probador.probar", side_effect=resultado)

    def settled_credentials(self, job_id):
        """Espera a que la prueba de credenciales deje de estar en marcha y devuelve el detalle."""
        self.until(lambda: self.store.detail(job_id)["credenciales"]["estado"] not in ("en_cola", "en_curso", "deteniendo"))
        return self.store.detail(job_id)

    def settled_discovery(self, job_id):
        """Espera a que el descubrimiento deje de estar en marcha y devuelve el detalle."""
        self.until(lambda: self.store.detail(job_id)["descubrimiento"]["estado"] not in ("en_cola", "en_curso", "deteniendo"))
        return self.store.detail(job_id)

    def test_credential_test_needs_the_token_and_same_origin(self):
        job = self.create()
        with patch("dedalo.web.probador.probar") as probar:
            for route in ("probar-credenciales", "detener-credenciales"):
                for headers in ({"X-Dedalo-Token": "wrong"}, {"Origin": "https://example.org"}):
                    self.assertEqual(self.request("/api/jobs/" + job["id"] + "/" + route, {}, headers)[0], 403)
            self.assertIsNone(self.store.detail(job["id"])["credenciales"])
        probar.assert_not_called()

    def test_running_a_credential_test_stores_what_got_in(self):
        job = self.create()
        def probar(ip, objetivo):
            return objetivo["clave"] == "admin"
        with self.credential_probe(probar):
            self.assertEqual(self.request("/api/jobs/" + job["id"] + "/probar-credenciales", {})[0], 202)
            detail = self.settled_credentials(job["id"])
        self.assertEqual(detail["credenciales"]["estado"], "completa")
        # al menos un «entró» si el laboratorio de prueba tiene un servicio web con admin/admin
        self.assertTrue(any(r["estado"] == "entrada" for r in detail["credenciales_resultados"]) or detail["credenciales_resultados"] == [])

    def test_a_credential_test_in_progress_is_not_restarted(self):
        job = self.create()
        self.store.jobs[job["id"]]["estado"] = "en_curso"
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/probar-credenciales", {})[0], 409)
        self.store.jobs[job["id"]]["estado"] = "preparada"

    def test_a_broken_catalog_does_not_stop_the_portal(self):
        with patch("dedalo.web.catalogo.cargar", side_effect=ValueError("catálogo roto")), redirect_stderr(io.StringIO()):
            self.reopen()  # _load vuelve a correr al reabrir el portal
        self.assertEqual(self.request("/api/jobs")[0], 200)  # el portal sigue en pie

    def test_credentials_need_the_scope_defined(self):
        audit = self.store.create_audit({"nombre": "Sin alcance", "incluir": ""})
        job = json.loads(self.request("/api/jobs", payload() | {"auditoria": audit["id"]})[1])
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/probar-credenciales", {})[0], 409)

    FTP_DOS = ("<?xml version='1.0'?><nmaprun>"
               "<host><status state='up'/><address addr='10.10.1.1' addrtype='ipv4'/><ports>"
               "<port protocol='tcp' portid='21'><state state='open'/><service name='ftp' product='vsftpd'/></port></ports></host>"
               "<host><status state='up'/><address addr='10.10.1.2' addrtype='ipv4'/><ports>"
               "<port protocol='tcp' portid='21'><state state='open'/><service name='ftp' product='vsftpd'/></port></ports></host>"
               "</nmaprun>")

    def test_a_host_excluded_mid_run_is_not_connected_to(self):
        contenido = [{"nombre": "dos.xml", "contenido": self.FTP_DOS}]
        job = json.loads(self.request("/api/jobs", {"nombre": "Dos FTP", "archivos": contenido,
                                                    "opciones": {}, "auditoria": self.audit["id"]})[1])
        conectados, started, release = [], threading.Event(), threading.Event()

        def probar(ip, objetivo):
            conectados.append(ip)
            if len(conectados) == 1:
                started.set(); release.wait(10)
            return False

        with patch("dedalo.web.probador.probar", side_effect=probar):
            self.assertEqual(self.request("/api/jobs/" + job["id"] + "/probar-credenciales", {})[0], 202)
            started.wait(10)  # está conectando al primer host
            self.store.update_audit(self.audit["id"], {"nombre": "Cliente de prueba", "incluir": "10.10.0.0/17", "excluir": "10.10.1.2"})
            release.set()
            self.settled_credentials(job["id"])
        # El segundo host, excluido a mitad, no se llega a conectar: el alcance se recomprueba en vivo.
        self.assertNotIn("10.10.1.2", conectados)
        self.assertIn("10.10.1.1", conectados)

    def test_discovery_needs_the_token_and_same_origin(self):
        job = self.create()
        with patch("dedalo.web.descubrimiento.sweep") as sweep:
            for route in ("descubrir", "detener-descubrimiento"):
                for headers in ({"X-Dedalo-Token": "wrong"}, {"Origin": "https://example.org"}):
                    self.assertEqual(self.request("/api/jobs/" + job["id"] + "/" + route, {}, headers)[0], 403)
            self.assertIsNone(self.store.detail(job["id"])["descubrimiento"])
        sweep.assert_not_called()

    def test_discovery_needs_the_scope_defined(self):
        audit = self.store.create_audit({"nombre": "Sin alcance", "incluir": ""})
        job = json.loads(self.request("/api/jobs", payload() | {"auditoria": audit["id"]})[1])
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/descubrir", {"modo": "nombres"})[0], 409)

    def test_names_discovery_stores_results(self):
        job = self.create()
        def sweep(addresses, mode, domain="", *, scope=None, timeout=2.0, delay=0.0, workers=4, stop=None, progress=None):
            return [{"ip": a, "encontrado": True, "nombre": "host-" + a.split(".")[-1], "detalle": "", "error": ""} for a in addresses[:1]]
        with patch("dedalo.web.descubrimiento.sweep", side_effect=sweep):
            self.assertEqual(self.request("/api/jobs/" + job["id"] + "/descubrir", {"modo": "nombres"})[0], 202)
            detail = self.settled_discovery(job["id"])
        self.assertEqual(detail["descubrimiento"]["estado"], "completa")
        self.assertTrue(detail["descubrimiento_resultados"])
        self.assertTrue(all(r["modo"] == "nombres" for r in detail["descubrimiento_resultados"]))

    def test_a_host_excluded_mid_sweep_is_not_queried(self):
        job = self.create()  # ficha con incluir 10.10.0.0/17
        consultados, started, release = [], threading.Event(), threading.Event()
        def sweep(addresses, mode, domain="", *, scope=None, timeout=2.0, delay=0.0, workers=4, stop=None, progress=None):
            for ip in addresses:
                if scope.status(ip) != web.targets.Scope.IN:  # el portal pasa un alcance VIVO
                    continue
                consultados.append(ip)
                if len(consultados) == 1:
                    started.set(); release.wait(10)
            return [{"ip": ip, "encontrado": False, "nombre": "", "detalle": "", "error": ""} for ip in consultados]
        with patch("dedalo.web.descubrimiento.sweep", side_effect=sweep), \
                patch("dedalo.web.descubrimiento.expand", return_value=["10.10.0.1", "10.10.0.2"]):
            self.assertEqual(self.request("/api/jobs/" + job["id"] + "/descubrir", {"modo": "servidores"})[0], 202)
            started.wait(10)
            self.store.update_audit(self.audit["id"], {"nombre": "Cliente de prueba", "incluir": "10.10.0.0/17", "excluir": "10.10.0.2"})
            release.set()
            self.settled_discovery(job["id"])
        self.assertNotIn("10.10.0.2", consultados)

    def test_networks_route_lists_detected_subnets(self):
        with patch("dedalo.web.redes.detectar", return_value=["10.30.4.0/24"]):
            status, content = self.request("/api/redes")
        self.assertEqual((status, json.loads(content)), (200, {"redes": ["10.30.4.0/24"]}))

    def test_a_sweep_error_ends_the_discovery_in_error(self):
        job = self.create()
        with patch("dedalo.web.descubrimiento.sweep", side_effect=ValueError("Dominio inválido: 'x y'")), \
                redirect_stderr(io.StringIO()):
            self.assertEqual(self.request("/api/jobs/" + job["id"] + "/descubrir", {"modo": "servidores"})[0], 202)
            detail = self.settled_discovery(job["id"])
        self.assertEqual(detail["descubrimiento"]["estado"], "error")
        self.assertIn("Dominio", detail["descubrimiento"]["error"])  # el mensaje de sweep, no un genérico

    def catalogo_temporal(self):
        tmp = Path(self.temp.name) / "credenciales.json"
        tmp.write_bytes(web.catalogo.RUTA.read_bytes())  # copia de la semilla: los tests NO tocan el real
        self.store.catalogo_ruta = tmp
        return tmp

    def test_catalogo_needs_the_token_and_same_origin(self):
        body = {"producto": "x", "servicio": "ftp", "credenciales": [{"usuario": "a", "clave": "b"}]}
        for headers in ({"X-Dedalo-Token": "wrong"}, {"Origin": "https://example.org"}):
            self.assertEqual(self.request("/api/catalogo", body, headers)[0], 403)

    def test_catalogo_adds_a_factory_credential_and_reloads(self):
        tmp = self.catalogo_temporal()
        body = {"fabricante": "ACME", "producto": "RouterOS", "version": "", "servicio": "ftp",
                "fuente": "manual del fabricante", "credenciales": [{"usuario": "admin", "clave": "admin"}]}
        self.assertEqual(self.request("/api/catalogo", body)[0], 200)
        self.assertIn("RouterOS", tmp.read_text("utf-8"))               # escrito en el fichero
        with closing(self.store.database()) as con:
            self.assertTrue(any(e["producto"] == "RouterOS" for e in web.catalogo.entradas(con)))  # recargado

    def test_catalogo_rejects_an_invalid_entry(self):
        self.catalogo_temporal()
        body = {"producto": "x", "servicio": "ssh", "credenciales": [{"usuario": "a", "clave": "b"}]}
        self.assertEqual(self.request("/api/catalogo", body)[0], 400)

    def test_page_has_the_add_to_catalog_dialog(self):
        page, script = self.request("/")[1], self.request("/app.js")[1]
        for needle in (b'id="catalog-dialog"', b'id="catalog-form"', b'id="catalog-factory"'):
            self.assertIn(needle, page)
        self.assertIn("de fábrica".encode(), page)          # aviso de gobernanza
        self.assertIn(b"data-add-catalog", script)          # botón por servicio del inventario
        self.assertIn(b'request("/api/catalogo"', script)

    def test_progress_counts_the_hosts_already_answered(self):
        job, release = self.create(), threading.Event()
        model = model_waiting_at(2, release)
        with patch("dedalo.web.modelo.generate", side_effect=model):
            self.assertEqual(self.request("/api/jobs/" + job["id"] + "/analizar", {})[0], 202)
            self.until(lambda: len(model.calls) == 2)
            self.assertEqual(self.store.detail(job["id"])["analisis"]["progreso"], {"hechos": 1, "total": 2})
            release.set()
            detail = self.settled(job["id"])
        self.assertEqual(detail["analisis"]["estado"], "completa")
        self.assertNotIn("progreso", detail["analisis"])

    def test_a_running_analysis_stops_after_the_current_host_and_keeps_the_last_result(self):
        job, release = self.create(), threading.Event()
        before = self.analyse(job["id"], model_answering())["prioridades"]
        model = model_waiting_at(1, release, "baja")
        with patch("dedalo.web.modelo.generate", side_effect=model):
            self.assertEqual(self.request("/api/jobs/" + job["id"] + "/analizar", {})[0], 202)
            self.until(lambda: len(model.calls) == 1)
            status, content = self.request("/api/jobs/" + job["id"] + "/detener-analisis", {})
            self.assertEqual((status, json.loads(content)["analisis"]["estado"]), (200, "deteniendo"), content)
            release.set()
            detail = self.settled(job["id"])
        self.assertEqual(len(model.calls), 1)  # el segundo host ya no se pregunta
        self.assertEqual((detail["analisis"]["estado"], detail["prioridades"]), ("interrumpida", before))
        self.assertIn("Detenido", detail["analisis"]["error"])

    def test_a_stop_asked_during_the_last_host_lets_the_analysis_finish(self):
        job, release = self.create(), threading.Event()
        model = model_waiting_at(2, release)  # el segundo de dos hosts es el último
        with patch("dedalo.web.modelo.generate", side_effect=model):
            self.assertEqual(self.request("/api/jobs/" + job["id"] + "/analizar", {})[0], 202)
            self.until(lambda: len(model.calls) == 2)
            self.assertEqual(self.request("/api/jobs/" + job["id"] + "/detener-analisis", {})[0], 200)
            release.set()
            detail = self.settled(job["id"])
        self.assertEqual((detail["analisis"]["estado"], len(detail["prioridades"])), ("completa", 2))

    def test_deleting_the_run_stops_its_analysis_at_the_next_host(self):
        job, release = self.create(), threading.Event()
        model = model_waiting_at(1, release)
        errors = io.StringIO()
        with patch("dedalo.web.modelo.generate", side_effect=model), redirect_stderr(errors):
            self.assertEqual(self.request("/api/jobs/" + job["id"] + "/analizar", {})[0], 202)
            self.until(lambda: len(model.calls) == 1)
            self.assertEqual(self.request("/api/jobs/" + job["id"] + "/delete", {})[0], 200)
            release.set()
            self.until(lambda: not self.store.analysis_progress)
        self.assertEqual(len(model.calls), 1)  # el segundo host ya no se pregunta
        self.assertNotIn("Error del portal", errors.getvalue())

    def test_progress_is_dropped_when_an_analysis_does_not_complete(self):
        job = self.create()
        with redirect_stderr(io.StringIO()):
            self.analyse(job["id"], ValueError("¿Está arrancado Ollama?"))
        self.assertEqual(self.store.analysis_progress, {})

    def test_a_queued_analysis_is_cancelled_before_it_starts(self):
        first, second, third = self.create(), self.create(), self.create()
        release = threading.Event()
        model = model_waiting_at(1, release)
        with patch("dedalo.web.modelo.generate", side_effect=model):
            for job in (first, second, third):
                self.assertEqual(self.request("/api/jobs/" + job["id"] + "/analizar", {})[0], 202)
            self.until(lambda: len(model.calls) == 1)
            status, content = self.request("/api/jobs/" + second["id"] + "/detener-analisis", {})
            self.assertEqual((status, json.loads(content)["analisis"]["estado"]), (200, "cancelada"), content)
            release.set()
            self.settled(third["id"])  # la cola pasó por el segundo antes de llegar al tercero
        self.assertEqual(len(model.calls), 4)  # dos hosts del primero y dos del tercero; del segundo, ninguno
        self.assertEqual(self.store.detail(second["id"])["analisis"]["estado"], "cancelada")

    def test_only_an_analysis_in_progress_can_be_stopped(self):
        job = self.create()
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/detener-analisis", {})[0], 409)
        self.analyse(job["id"], model_answering())
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/detener-analisis", {})[0], 409)

    def test_analysis_prioritises_the_hosts_in_scope_with_the_local_model(self):
        job = self.create()
        self.assertIsNone(self.store.detail(job["id"])["analisis"])
        calls = []

        def model(prompt, name, host, timeout=120, schema=None):
            calls.append((prompt, name, host, schema))
            level = "alta" if '"10.10.5.10"' in prompt else "media"
            return json.dumps({"rol": "Servidor web", "nivel": level, "motivo": "Por sus puertos.", "siguiente": "Revisar."})

        detail = self.analyse(job["id"], model)
        self.assertEqual((detail["analisis"]["estado"], detail["analisis"]["error"]), ("completa", ""))
        self.assertEqual([(p["ip"], p["nivel"]) for p in detail["prioridades"]], [("10.10.5.10", "alta"), ("10.10.6.20", "media")])
        self.assertFalse(any("192.168.1.8" in call[0] for call in calls))  # fuera de alcance: no se analiza
        self.assertEqual({(name, host) for _, name, host, _ in calls}, {(web.modelo.DEFAULT_MODEL, web.modelo.OLLAMA)})
        self.assertTrue(all(schema == web.prioridad.ESQUEMA for *_, schema in calls))  # el modelo contesta con el esquema

    def test_analysis_without_the_model_ends_in_error_and_says_why(self):
        job = self.create()
        with redirect_stderr(io.StringIO()):
            detail = self.analyse(job["id"], ValueError("No se pudo usar el modelo. ¿Está arrancado Ollama?"))
        self.assertEqual(detail["analisis"]["estado"], "error")
        self.assertIn("Ollama", detail["analisis"]["error"])
        self.assertEqual(detail["prioridades"], [])
        self.assertEqual(self.request("/api/jobs")[0], 200)  # el portal sigue

    def test_hosts_without_open_ports_are_not_sent_to_the_model(self):
        xml = ('<nmaprun><host><status state="up"/><address addr="10.10.5.10" addrtype="ipv4"/><ports>'
               '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host>'
               '<host><status state="up"/><address addr="10.10.5.11" addrtype="ipv4"/></host></nmaprun>')
        status, content = self.request("/api/jobs", self.payload() | {
            "archivos": [{"nombre": "vivos.xml", "contenido": xml}]})
        self.assertEqual(status, 201, content)
        job, prompts = json.loads(content), []

        def model(prompt, name, host, timeout=120, schema=None):
            prompts.append(prompt)
            return json.dumps({"rol": "R", "nivel": "media", "motivo": "m", "siguiente": "s"})

        detail = self.analyse(job["id"], model)
        self.assertEqual([p["ip"] for p in detail["prioridades"]], ["10.10.5.10"])
        self.assertFalse(any('"10.10.5.11"' in prompt for prompt in prompts))

    def test_a_host_taken_out_of_scope_leaves_the_prioritisation(self):
        job = self.create()

        self.assertEqual(len(self.analyse(job["id"], model_answering())["prioridades"]), 2)
        self.store.update_audit(self.audit["id"], {"nombre": "Cliente de prueba", "incluir": "10.10.0.0/17",
                                                   "excluir": "10.10.6.20"})
        self.assertEqual([p["ip"] for p in self.store.detail(job["id"])["prioridades"]], ["10.10.5.10"])

    def test_a_database_failure_in_one_analysis_does_not_stop_the_queue(self):
        first, second = self.create(), self.create()
        real, seen = auditoria.observed_hosts, []

        def flaky(con, job_id):
            seen.append(job_id)
            if len(seen) == 1:
                raise sqlite3.OperationalError("database is locked")
            return real(con, job_id)

        with patch("dedalo.web.auditoria.observed_hosts", side_effect=flaky), \
                patch("dedalo.web.modelo.generate", side_effect=model_answering()), redirect_stderr(io.StringIO()):
            for job in (first, second):
                self.assertEqual(self.request("/api/jobs/" + job["id"] + "/analizar", {})[0], 202)
            deadline = time.monotonic() + 10
            while self.store.detail(second["id"])["analisis"]["estado"] in ("en_cola", "en_curso") and time.monotonic() < deadline:
                time.sleep(.02)
        self.assertTrue(self.store.worker.is_alive())
        self.assertEqual(self.store.detail(second["id"])["analisis"]["estado"], "completa")
        self.assertEqual(self.store.detail(first["id"])["analisis"]["estado"], "error")

    def test_an_analysis_that_cannot_be_saved_ends_in_error(self):
        job = self.create()

        with patch("dedalo.web.auditoria.finish_analysis", side_effect=sqlite3.OperationalError("disk I/O error")), \
                redirect_stderr(io.StringIO()):
            detail = self.analyse(job["id"], model_answering())
        self.assertEqual(detail["analisis"]["estado"], "error")
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/analizar", {})[0], 202)  # se puede volver a intentar

    def test_a_failed_reanalysis_keeps_showing_the_previous_result(self):
        job = self.create()
        before = self.analyse(job["id"], model_answering())["prioridades"]
        with redirect_stderr(io.StringIO()):
            detail = self.analyse(job["id"], ValueError("¿Está arrancado Ollama?"))
        self.assertEqual((detail["analisis"]["estado"], detail["analisis"]["error"]), ("error", "¿Está arrancado Ollama?"))
        self.assertEqual(detail["prioridades"], before)

    def test_an_interrupted_reanalysis_keeps_showing_the_previous_result(self):
        job = self.create()
        before = self.analyse(job["id"], model_answering())["prioridades"]
        self.pending_analysis(job["id"], "en_curso")  # el portal se cerró a mitad del segundo análisis
        self.reopen()
        detail = self.store.detail(job["id"])
        self.assertEqual((detail["analisis"]["estado"], detail["prioridades"]), ("interrumpida", before))

    def test_a_run_being_captured_is_not_analysed(self):
        job = self.create()
        self.store.jobs[job["id"]]["estado"] = "en_curso"
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/analizar", {})[0], 409)
        self.assertIsNone(self.store.detail(job["id"])["analisis"])
        self.store.jobs[job["id"]]["estado"] = "preparada"

    def pending_analysis(self, job_id, state="en_cola"):
        """Un análisis que quedó en la base sin terminar, sin pasar por la cola."""
        with closing(self.store.database()) as con:
            analysis = auditoria.start_analysis(con, job_id, {"modelo": "m"})
            auditoria.set_state(con, analysis, state)

    def test_a_second_analysis_waits_for_the_first(self):
        job = self.create()
        self.pending_analysis(job["id"])
        self.assertEqual(self.request("/api/jobs/" + job["id"] + "/analizar", {})[0], 409)
        self.assertEqual(self.store.detail(job["id"])["analisis"]["estado"], "en_cola")

    def test_an_analysis_cut_by_closing_the_portal_is_marked_interrupted(self):
        job = self.create()
        self.pending_analysis(job["id"], "en_curso")
        self.reopen()
        analysis = self.store.detail(job["id"])["analisis"]
        self.assertEqual(analysis["estado"], "interrumpida")
        self.assertTrue(analysis["error"])

    def test_closing_the_portal_stops_the_analysis_between_hosts(self):
        job = self.create()
        calls = []

        def model(prompt, name, host, timeout=120, schema=None):
            calls.append(prompt)
            self.store.closing = True  # el usuario cierra el portal mientras el modelo contesta al primer host
            return json.dumps({"rol": "R", "nivel": "alta", "motivo": "m", "siguiente": "s"})

        detail = self.analyse(job["id"], model)
        self.assertEqual(len(calls), 1)  # el segundo host ya no se pregunta
        self.assertEqual((detail["analisis"]["estado"], detail["prioridades"]), ("interrumpida", []))

    def test_nothing_in_scope_means_an_empty_analysis_without_calling_the_model(self):
        other = self.store.create_audit({"nombre": "Otra ficha", "incluir": "172.16.0.0/16"})
        status, content = self.request("/api/jobs", payload() | {"auditoria": other["id"]})
        self.assertEqual(status, 201, content)
        detail = self.analyse(json.loads(content)["id"], AssertionError("no debería llamar al modelo"))
        self.assertEqual((detail["analisis"]["estado"], detail["prioridades"]), ("completa", []))

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

    def test_target_captured_with_the_other_scheme_is_shown_served_and_not_duplicated(self):
        job = self.create()
        meta = self.store.jobs[job["id"]]
        root = self.store.directory(job["id"]) / "resultado"
        group = meta["grupos"][0]
        target = group["objetivos"][0]
        other = gowitness.other_scheme(target["url"])
        fake_database(root / group["carpeta"], [other])   # solo respondió el otro esquema
        report.collect_group(root, group)
        report.write_index(root, {"version": 1, "grupos": meta["grupos"]})
        self.assertEqual(group["resultados"][0]["url"], target["url"])
        # El portal lo da por capturado y sirve la imagen.
        status, content = self.request("/api/jobs/" + job["id"])
        self.assertEqual(status, 200)
        shown = json.loads(content)["grupos"][0]["objetivos"][0]
        self.assertEqual((shown["url"], shown["estado"]), (target["url"], "capturada"))
        self.assertTrue(shown["imagen"])
        self.assertEqual(self.request(shown["imagen"])[:1], (200,))
        self.assertEqual(self.request(shown["imagen"])[1], b"test-image")
        # El zip nombra la imagen con el esquema de la fila que respondió.
        with zipfile.ZipFile(io.BytesIO(self.request("/api/jobs/" + job["id"] + "/download/captures/0")[1])) as archive:
            scheme = other.split(":", 1)[0]
            self.assertIn(f"{target['ip']}_{target['port']}_{scheme}.png", archive.namelist())
        # En la base no queda una fila pendiente huérfana junto a otra capturada.
        with closing(self.store.database()) as con:
            capture = auditoria.start_capture(con, job["id"], {}, meta["grupos"])
            auditoria.record_captures(con, capture, {"grupos": meta["grupos"]}, root, self.store.root)
            rows = con.execute("SELECT url, estado FROM captura WHERE ejecucion_id = ? ORDER BY url", (capture,)).fetchall()
        self.assertEqual(len(rows), len({t["url"] for g in meta["grupos"] for t in g["objetivos"]}))
        self.assertEqual({r["url"]: r["estado"] for r in rows}[target["url"]], "capturada")
        self.assertNotIn(other, [r["url"] for r in rows])

    def test_version_detection_reads_the_fingerprint_of_the_other_scheme(self):
        job = self.create()
        meta = self.store.jobs[job["id"]]
        root = self.store.directory(job["id"]) / "resultado"
        group = meta["grupos"][0]
        target = group["objetivos"][0]
        (root / group["carpeta"]).mkdir(parents=True, exist_ok=True)
        # gowitness solo guardó el otro esquema; el servicio consta como capturado con la URL del objetivo.
        build_gowitness_db(root / group["carpeta"] / gowitness.DB_NAME, gowitness.other_scheme(target["url"]))
        with closing(self.store.database()) as con:
            capture = auditoria.start_capture(con, job["id"], {}, meta["grupos"])
            with con:
                con.execute("UPDATE captura SET estado = 'capturada' WHERE ejecucion_id = ? AND url = ?",
                            (capture, target["url"]))
            version = auditoria.start_version(con, job["id"], {"engine": "ollama", "model": "m"})
        seen = []
        with patch("dedalo.web.modelo.generador", return_value=lambda prompt: ""), \
                patch("dedalo.web.fingerprint.detectar", side_effect=lambda items, *a, **k: seen.extend(items) or []):
            self.store._detect(job["id"], version, "ollama", "m")
        self.assertEqual([i["url"] for i in seen], [target["url"]])
        self.assertIn("nginx/1.18.0", seen[0]["datos"]["headers"].values())

    def _prepared_version(self):
        """Un trabajo con un servicio capturado con éxito y su detección lista; (job_id, version_id, target)."""
        job = self.create()
        meta = self.store.jobs[job["id"]]
        root = self.store.directory(job["id"]) / "resultado"
        group = meta["grupos"][0]
        target = group["objetivos"][0]
        (root / group["carpeta"]).mkdir(parents=True, exist_ok=True)
        build_gowitness_db(root / group["carpeta"] / gowitness.DB_NAME, target["url"])
        with closing(self.store.database()) as con:
            capture = auditoria.start_capture(con, job["id"], {}, meta["grupos"])
            with con:
                con.execute("UPDATE captura SET estado = 'capturada' WHERE ejecucion_id = ? AND url = ?",
                            (capture, target["url"]))
            version = auditoria.start_version(con, job["id"], {"engine": "ollama", "model": "m"})
        return job["id"], version, target

    def test_version_detection_identifies_the_favicon_against_the_catalog(self):
        job_id, version, target = self._prepared_version()
        contenido = b"favicon de prueba de la tarea 5"
        catalogo = {"mmh3": {favicones.mmh3_shodan(contenido): {"producto": "RouterOS", "version": "6.49",
                                                                 "fuente": "demo"}},
                    "sha256": {}}
        seen = []
        with patch("dedalo.web.modelo.generador", return_value=lambda prompt: ""), \
                patch("dedalo.web.fingerprint.detectar", side_effect=lambda items, *a, **k: seen.extend(items) or []), \
                patch("dedalo.web.favicones.cargar", return_value=catalogo), \
                patch("dedalo.web.favicones.descargar", return_value=contenido) as descargar:
            self.store._detect(job_id, version, "ollama", "m")
        self.assertEqual(descargar.call_count, 1)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["datos"]["favicon"]["producto"], "RouterOS")

    def test_version_detection_does_not_download_the_favicon_when_out_of_scope_live(self):
        job_id, version, target = self._prepared_version()
        # El alcance cambia DESPUÉS de capturar: el servicio queda fuera justo antes de detectar.
        self.store.update_audit(self.audit["id"], {"nombre": "Cliente de prueba", "incluir": "192.0.2.0/24"})
        seen = []
        with patch("dedalo.web.modelo.generador", return_value=lambda prompt: ""), \
                patch("dedalo.web.fingerprint.detectar", side_effect=lambda items, *a, **k: seen.extend(items) or []), \
                patch("dedalo.web.favicones.descargar") as descargar:
            self.store._detect(job_id, version, "ollama", "m")
        descargar.assert_not_called()
        self.assertEqual(len(seen), 1)
        self.assertNotIn("favicon", seen[0]["datos"])

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

    def test_page_has_the_prioritisation_tab(self):
        page, script = self.request("/")[1], self.request("/app.js")[1]
        for needle in (b'data-tab="priority"', b'id="analyze-job"', b'id="stop-analysis"', b'id="priority-tools"',
                       b'id="model-select"', b'id="model-hint"'):
            self.assertIn(needle, page)
        self.assertIn(b'action("analizar", {modelo: $("model-select").value})', script)  # se analiza con el modelo elegido
        self.assertIn(b'action("detener-analisis")', script)
        self.assertIn(b'request("/api/modelos")', script)
        self.assertIn(b"escapeHtml(model.nombre)", script)  # los nombres vienen de Ollama: nunca entran como HTML
        self.assertIn(b"escapeHtml(item.siguiente)", script)  # la respuesta del modelo nunca entra como HTML

    def test_page_has_the_credentials_tab(self):
        page, script = self.request("/")[1], self.request("/app.js")[1]
        for needle in (b'data-tab="credentials"', b'id="credential-tools"', b'id="test-credentials"', b'id="stop-credentials"'):
            self.assertIn(needle, page)
        self.assertIn(b'action("probar-credenciales")', script)
        self.assertIn(b'action("detener-credenciales")', script)
        self.assertIn(b"escapeHtml(item.usuario)", script)  # lo que devuelve el objetivo nunca entra como HTML
        self.assertIn(b"confirm(", script)  # la prueba activa pide confirmación

    def test_scope_hint_says_how_to_authorize_all_ranges(self):
        page = self.request("/")[1]
        self.assertIn(b"0.0.0.0/0", page)
        self.assertIn("todos los rangos".encode(), page)

    def test_url_bar_option_defaults_to_on(self):
        job = self.create()
        self.assertIs(self.store.detail(job["id"])["opciones"]["barra_url"], True)

    def test_capture_without_url_bar_passes_the_flag(self):
        p = self.payload()
        p["opciones"] = {**p["opciones"], "barra_url": False}
        job = json.loads(self.request("/api/jobs", p)[1])
        recibido = {}
        def run(command, **kwargs):
            recibido["cmd"] = command
            class R:
                returncode = 0
            return R()
        with patch("dedalo.web.gowitness.find_gowitness", return_value="fake"), \
             patch("dedalo.web.gowitness.find_chrome", return_value="fake"), \
             patch("dedalo.web.subprocess.run", side_effect=run):
            self.request("/api/jobs/" + job["id"] + "/start", {})
            self.until(lambda: self.store.detail(job["id"])["estado"] not in ("en_cola", "en_curso"))
        self.assertIn("--sin-barra-url", recibido["cmd"])

    def test_page_has_the_url_bar_option(self):
        page = self.request("/")[1]
        self.assertIn(b'id="opt-url-bar"', page)
        self.assertIn("Barra de URL".encode(), page)

    def test_page_has_the_discovery_tab(self):
        page, script = self.request("/")[1], self.request("/app.js")[1]
        for needle in (b'data-tab="discovery"', b'id="discovery-tools"', b'id="discover-job"',
                       b'id="stop-discovery"', b'id="discovery-mode"'):
            self.assertIn(needle, page)
        self.assertIn(b'action("descubrir", {modo: $("discovery-mode").value})', script)
        self.assertIn(b'action("detener-descubrimiento")', script)
        self.assertIn(b"escapeHtml(item.nombre)", script)  # lo que devuelve el objetivo nunca entra como HTML

    def test_page_has_the_detect_networks_buttons(self):
        page, script = self.request("/")[1], self.request("/app.js")[1]
        self.assertIn(b'id="detect-networks"', page)          # en el formulario de ficha
        self.assertIn(b'id="detect-networks-scope"', page)    # en la pestaña Descubrimiento
        self.assertIn(b'request("/api/redes")', script)
        self.assertIn(b'"audit-include"', script)             # rellena los rangos autorizados

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

    def finish_without_engine(self, job_id):
        """Deja la ejecución lanzada y terminada en la base, con sus URL planificadas, sin pasar por el motor."""
        meta = self.store.jobs[job_id]
        with closing(self.store.database()) as con:
            capture = auditoria.start_capture(con, job_id, meta["opciones"], meta["grupos"])
            auditoria.set_state(con, capture, "completa")

    def test_runs_are_planned_when_opened_not_at_startup(self):
        prepared, launched = self.create(), self.create()
        self.finish_without_engine(launched["id"])
        self.reopen()
        expected = {job_id: self.store.detail(job_id) for job_id in (prepared["id"], launched["id"])}
        with patch("dedalo.web.cli.group_hosts", wraps=cli.group_hosts) as grouping:
            self.reopen()
            self.store.list()
            self.assertEqual(grouping.call_count, 0)  # ni arrancar ni el sondeo calculan planes
            for job_id, detail in expected.items():
                self.assertEqual(self.store.detail(job_id), detail)
                self.store.detail(job_id)
            self.assertEqual(grouping.call_count, 2)  # uno por ejecución abierta, y queda guardado

    def test_a_run_whose_plan_cannot_be_built_says_why_when_opened(self):
        job = self.create()
        self.finish_without_engine(job["id"])
        (self.store.directory(job["id"]) / "rangos.txt").write_text("no es una red\n", encoding="utf-8")
        self.reopen()
        with redirect_stderr(io.StringIO()) as errors:
            detail = self.store.detail(job["id"])
        self.assertIn(job["id"], errors.getvalue())
        self.assertEqual((detail["estado"], detail["total"], detail["grupos"]), ("completa", 0, []))
        self.assertTrue(detail["error"].startswith("No se pudo cargar esta ejecución"), detail["error"])

    def test_a_passing_failure_while_planning_does_not_mark_the_run_as_broken(self):
        job = self.create()
        self.reopen()
        with patch("dedalo.web.auditoria.observed_hosts", side_effect=PermissionError("Archivo ocupado")):
            with self.assertRaises(PermissionError):
                self.store.detail(job["id"])
        # Al volver a abrirla se calcula bien y se puede lanzar.
        detail = self.store.detail(job["id"])
        self.assertEqual((detail["estado"], detail["total"], detail["error"]), ("preparada", 3, ""))

    def test_editing_the_scope_plans_runs_loaded_without_a_plan(self):
        job = self.create()
        self.reopen()
        with patch("dedalo.web.cli.group_hosts", wraps=cli.group_hosts) as grouping:
            self.store.update_audit(self.audit["id"], {"nombre": "Cliente de prueba", "incluir": "10.10.5.0/24"})
            self.assertEqual(grouping.call_count, 0)  # sin abrir no se planifica: solo cambia su alcance en disco
        self.assertEqual((self.store.directory(job["id"]) / "rangos.txt").read_text(encoding="utf-8"), "10.10.5.0/24\n")
        self.assertEqual(self.store.detail(job["id"])["total"], 2)  # solo 10.10.5.10, con el 80 y el 443

    def test_a_run_loaded_without_a_plan_can_be_launched_without_opening_it(self):
        job = self.create()
        self.reopen()
        state, rows = self.capture_rows(self.run_engine(job["id"]))
        self.assertEqual((state["estado"], len(rows)), ("completa", 3))

    def test_opening_a_run_plans_it_without_blocking_the_portal(self):
        job = self.create()
        self.reopen()
        original, blocked = cli.group_hosts, []

        def grouping(*args, **kwargs):
            poll = threading.Thread(target=self.store.list)
            poll.start()
            poll.join(timeout=2)
            blocked.append(poll.is_alive())
            return original(*args, **kwargs)

        with patch("dedalo.web.cli.group_hosts", side_effect=grouping):
            self.assertEqual(self.store.detail(job["id"])["total"], 3)
        self.assertEqual(blocked, [False])  # el sondeo respondió mientras se calculaba el plan

    def test_a_scope_edited_while_a_run_is_being_planned_wins(self):
        job = self.create()
        self.reopen()
        original, edits = cli.group_hosts, []

        def grouping(*args, **kwargs):
            if not edits:
                edits.append(self.store.update_audit(self.audit["id"], {"nombre": "Cliente de prueba",
                                                                         "incluir": "10.10.5.0/24"}))
            return original(*args, **kwargs)

        with patch("dedalo.web.cli.group_hosts", side_effect=grouping):
            self.assertEqual(self.store.detail(job["id"])["total"], 2)

    def test_history_poll_returns_only_what_the_list_shows(self):
        job = self.create()
        with patch.object(PortalStore, "_manifest", side_effect=AssertionError("el sondeo no lee manifiestos")):
            items = self.store.list()
        self.assertEqual(items, [{"id": job["id"], "nombre": job["nombre"], "fecha": job["fecha"],
                                  "estado": "preparada", "auditoria": self.audit["id"]}])

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
                                          puerto=server.server_address[1], abrir=False,
                                          modelo=web.modelo.DEFAULT_MODEL, ollama=web.modelo.OLLAMA, arrancar_ollama=False,
                                          dns_dominio="example.com", catalogo=None)
                with self.assertRaisesRegex(ValueError, "ya está en uso"):
                    web.serve_portal(args)
            finally:
                server.server_close()
                store.close()
            # El portal que no pudo arrancar liberó su carpeta de datos.
            PortalStore(second_data).close()


class ModelOptionTests(unittest.TestCase):
    def test_the_portal_uses_a_small_local_model_unless_told_otherwise(self):
        with patch.dict(os.environ):
            os.environ.pop("DEDALO_MODELO", None)  # el equipo que pasa los tests puede tenerla puesta
            args = cli.build_parser().parse_args(["web"])
        self.assertEqual((args.modelo, args.ollama), (web.modelo.DEFAULT_MODEL, web.modelo.OLLAMA))

    def test_the_default_model_can_come_from_the_environment(self):
        with patch.dict(os.environ, {"DEDALO_MODELO": "fsec-analyst:latest"}):
            self.assertEqual(cli.build_parser().parse_args(["web"]).modelo, "fsec-analyst:latest")
            self.assertEqual(cli.build_parser().parse_args(["web", "--modelo", "qwen3:8b"]).modelo, "qwen3:8b")  # la opción manda

    def test_spaces_around_the_model_in_the_environment_are_ignored(self):
        with patch.dict(os.environ, {"DEDALO_MODELO": " fsec-analyst:latest "}):  # «set X=valor » en cmd deja el espacio
            self.assertEqual(cli.build_parser().parse_args(["web"]).modelo, "fsec-analyst:latest")

    def test_a_cloud_model_in_the_environment_is_refused(self):
        errors = io.StringIO()
        with patch.dict(os.environ, {"DEDALO_MODELO": "gpt-oss:120b-cloud"}), redirect_stderr(errors), \
                self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["web"])
        self.assertIn("nube", errors.getvalue())

    def test_the_model_server_must_be_on_this_machine(self):
        errors = io.StringIO()
        with redirect_stderr(errors), self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["web", "--ollama", "http://10.0.0.5:11434"])
        self.assertIn("este equipo", errors.getvalue())

    def test_a_cloud_model_is_refused_at_startup(self):
        errors = io.StringIO()
        with redirect_stderr(errors), self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["web", "--modelo", "gpt-oss:120b-cloud"])
        self.assertIn("nube", errors.getvalue())

    def test_the_one_click_launcher_starts_ollama_and_the_command_does_not_by_default(self):
        self.assertFalse(cli.build_parser().parse_args(["web"]).arrancar_ollama)
        self.assertIn(b"--arrancar-ollama", (ROOT / "iniciar_portal.cmd").read_bytes())

    def test_the_portal_starts_ollama_only_when_asked(self):
        class Stop(Exception):
            pass

        for flags, calls in (([], 0), (["--arrancar-ollama"], 1)):
            args = cli.build_parser().parse_args(["web", "--datos", "datos", *flags])
            with self.subTest(flags=flags), patch("dedalo.web.ensure_gowitness"), \
                    patch("dedalo.web.PortalStore", side_effect=Stop), redirect_stdout(io.StringIO()) as output, \
                    patch("dedalo.web.modelo.ensure_running", return_value=(True, "Ollama arrancado.")) as ensure:
                with self.assertRaises(Stop):
                    web.serve_portal(args)
            self.assertEqual(ensure.call_count, calls)
            self.assertEqual("Ollama arrancado." in output.getvalue(), bool(calls))

    def test_the_chosen_model_reaches_the_portal(self):
        args = cli.build_parser().parse_args(["web", "--datos", "datos", "--modelo", "qwen2.5:7b",
                                              "--ollama", "http://127.0.0.1:9999"])

        class Stop(Exception):
            pass

        with patch("dedalo.web.ensure_gowitness"), patch("dedalo.web.PortalStore", side_effect=Stop) as store:
            with self.assertRaises(Stop):
                web.serve_portal(args)
        self.assertEqual((store.call_args.kwargs["model"], store.call_args.kwargs["ollama"]),
                         ("qwen2.5:7b", "http://127.0.0.1:9999"))


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
