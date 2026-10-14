import base64
from contextlib import contextmanager
import ftplib
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import threading
import unittest
from unittest.mock import patch

from dedalo import probador
from tests.test_dedalo import ROOT


class Panel(BaseHTTPRequestHandler):
    def do_GET(self):  # HTTP Basic: admin/admin
        if self.headers.get("Authorization") == "Basic " + base64.b64encode(b"admin:admin").decode():
            self.send_response(200); self.end_headers()
        else:
            self.send_response(401); self.send_header("WWW-Authenticate", "Basic realm=x"); self.end_headers()

    def do_POST(self):  # formulario: usuario=admin&clave=admin
        cuerpo = self.rfile.read(int(self.headers["Content-Length"])).decode()
        if "usuario=admin" in cuerpo and "clave=admin" in cuerpo:
            self.send_response(302); self.send_header("Location", "/panel"); self.end_headers()
        else:
            self.send_response(200); self.end_headers(); self.wfile.write(b"login incorrect")

    def log_message(self, *a):
        pass


class FakeFTP:
    """Doble de ftplib.FTP: solo deja entrar a ftp/ftp, como el servidor de mentira del laboratorio."""
    def __init__(self, timeout=None):
        self.timeout = timeout

    def connect(self, host, port):
        self.host, self.port = host, port

    def login(self, usuario="", clave=""):
        if (usuario, clave) != ("ftp", "ftp"):
            raise ftplib.error_perm("530 Login incorrect")
        return "230 Login successful"

    def close(self):
        pass


@contextmanager
def sirviendo(handler):
    servidor = HTTPServer(("127.0.0.1", 0), handler)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True); hilo.start()
    try:
        yield servidor.server_address[1]
    finally:
        servidor.shutdown(); servidor.server_close(); hilo.join()


@contextmanager
def sirviendo_https(handler):
    servidor = HTTPServer(("127.0.0.1", 0), handler)
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # certificado autofirmado de prueba
    contexto.load_cert_chain(ROOT / "tests/fixtures/local-cert.pem", ROOT / "tests/fixtures/local-key.pem")
    servidor.socket = contexto.wrap_socket(servidor.socket, server_side=True)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True); hilo.start()
    try:
        yield servidor.server_address[1]
    finally:
        servidor.shutdown(); servidor.server_close(); hilo.join()


class ProbadorTests(unittest.TestCase):
    def objetivo(self, servicio, puerto, usuario, clave, receta=None, https=False):
        return {"puerto": puerto, "protocolo": "tcp", "servicio": servicio, "https": https,
                "usuario": usuario, "clave": clave, "receta": receta}

    def test_http_basic_true_with_the_right_password_false_with_the_wrong_one(self):
        with sirviendo(Panel) as puerto:
            self.assertTrue(probador.probar("127.0.0.1", self.objetivo("http-basic", puerto, "admin", "admin")))
            self.assertFalse(probador.probar("127.0.0.1", self.objetivo("http-basic", puerto, "admin", "malo")))

    def test_http_form_reads_the_recipe_success_signal(self):
        receta = {"ruta": "/login", "campo_usuario": "usuario", "campo_clave": "clave", "exito": {"texto_falla": "incorrect"}}
        with sirviendo(Panel) as puerto:
            self.assertTrue(probador.probar("127.0.0.1", self.objetivo("http-form", puerto, "admin", "admin", receta)))
            self.assertFalse(probador.probar("127.0.0.1", self.objetivo("http-form", puerto, "admin", "malo", receta)))

    def test_an_unreachable_service_raises(self):
        with self.assertRaises(OSError):
            probador.probar("127.0.0.1", self.objetivo("http-basic", 1, "admin", "admin"), timeout=1)

    def test_a_self_signed_https_panel_is_probed_without_verifying(self):
        with sirviendo_https(Panel) as puerto:
            self.assertTrue(probador.probar("127.0.0.1", self.objetivo("http-basic", puerto, "admin", "admin", https=True)))

    def test_ftp_true_with_the_right_password_false_with_the_wrong_one(self):
        with patch("dedalo.probador.ftplib.FTP", FakeFTP):
            self.assertTrue(probador.probar("127.0.0.1", self.objetivo("ftp", 21, "ftp", "ftp")))
            self.assertFalse(probador.probar("127.0.0.1", self.objetivo("ftp", 21, "ftp", "malo")))
