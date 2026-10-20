import json
import queue
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import closing

from dedalo.web import PortalStore, PortalServer


def sembrar_captura(con):
    """Una importación con una captura completa y un servicio capturado."""
    with con:
        con.execute("INSERT INTO auditoria (id, nombre, creada) VALUES ('a1', 'C', 't')")
        con.execute("INSERT INTO alcance (auditoria_id, tipo, cidr) VALUES ('a1', 'incluir', '10.10.5.3/32')")
        con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, nombre, estado, creada) "
                    "VALUES ('imp', 'a1', 'importacion', 'N', 'completa', 't')")
        asset = con.execute("INSERT INTO activo (auditoria_id, ip) VALUES ('a1', '10.10.5.3')").lastrowid
        svc = con.execute("INSERT INTO servicio (activo_id, protocolo, puerto) VALUES (?, 'tcp', 443)", (asset,)).lastrowid
        con.execute("INSERT INTO ejecucion (id, auditoria_id, tipo, origen_id, nombre, estado, creada) "
                    "VALUES ('cap', 'a1', 'captura', 'imp', 'N', 'completa', 't')")
        con.execute("INSERT INTO captura (ejecucion_id, servicio_id, url, estado) "
                    "VALUES ('cap', ?, 'https://10.10.5.3/', 'capturada')", (svc,))


class VersionConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = PortalStore(self.temp.name)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_por_defecto_apagada(self):
        self.assertFalse(self.store.version_config()["enabled"])

    def test_guardar_y_leer_el_ajuste(self):
        cfg = self.store.set_version_config({"enabled": True, "engine": "claude", "model": "claude-sonnet-5-5"})
        self.assertTrue(cfg["enabled"])
        self.assertEqual(cfg["engine"], "claude")
        self.assertTrue(cfg.get("aviso"))  # con Claude avisa de que los datos salen
        self.assertEqual(self.store.version_config()["model"], "claude-sonnet-5-5")

    def test_engine_invalido_falla(self):
        with self.assertRaises(ValueError):
            self.store.set_version_config({"enabled": True, "engine": "otro"})

    def test_apagada_no_encola_tras_la_captura(self):
        with closing(self.store.database()) as con:
            sembrar_captura(con)
        self.store._maybe_queue_version("imp")
        with self.assertRaises(queue.Empty):
            self.store.pending.get_nowait()

    def test_encendida_encola_tras_la_captura(self):
        with closing(self.store.database()) as con:
            sembrar_captura(con)
        self.store.set_version_config({"enabled": True, "engine": "ollama", "model": "llama3.2:3b"})
        self.store._maybe_queue_version("imp")
        kind, payload = self.store.pending.get_nowait()
        self.assertEqual(kind, "version")
        self.assertEqual(payload[0], "imp")
        self.assertEqual(payload[2], "ollama")


class VersionEndpointTests(unittest.TestCase):
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

    def pedir(self, data=None, token=True):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-Dedalo-Token"] = self.store.token
        req = urllib.request.Request(self.url + "/api/version-config",
                                     data=json.dumps(data).encode() if data is not None else None, headers=headers)
        try:
            r = self.opener.open(req, timeout=5)
        except urllib.error.HTTPError as exc:
            r = exc
        with r:
            return r.status, r.read()

    def test_post_sin_token_rechazado(self):
        status, _ = self.pedir({"enabled": True, "engine": "ollama"}, token=False)
        self.assertEqual(status, 403)

    def test_post_guarda_y_get_devuelve(self):
        status, _ = self.pedir({"enabled": True, "engine": "claude", "model": "claude-sonnet-5-5"})
        self.assertEqual(status, 200)
        status, body = self.pedir()  # GET
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["engine"], "claude")


if __name__ == "__main__":
    import urllib.error
    unittest.main()
