"""Regla de paso del proxy de alcance y sus fuentes de alcance."""

import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from dedalo import proxy, targets


class ReglaDePasoTests(unittest.TestCase):
    def test_regla_de_paso(self):
        s = targets.Scope(["10.10.0.0/16", "8.8.8.0/24"], ["10.10.5.20/32", "1.1.1.1/32"])
        self.assertEqual(proxy.decidir("10.10.5.20", s), proxy.EXCLUIDA)
        self.assertEqual(proxy.decidir("1.1.1.1", s), proxy.EXCLUIDA)      # pública pero excluida
        self.assertIsNone(proxy.decidir("10.10.1.1", s))                      # en alcance
        self.assertIsNone(proxy.decidir("8.8.4.4", s))                        # pública
        self.assertEqual(proxy.decidir("192.168.1.1", s), proxy.FUERA)
        self.assertEqual(proxy.decidir("100.64.0.1", s), proxy.FUERA)        # CGNAT no es global
        self.assertEqual(proxy.decidir("::ffff:10.10.5.20", s), proxy.EXCLUIDA)
        self.assertEqual(proxy.decidir("8.8.4.4", None), proxy.ILEGIBLE)

    def test_ipv6_mapeada_se_juzga_como_su_ipv4(self):
        s = targets.Scope(["10.10.0.0/16"], [])
        self.assertIsNone(proxy.decidir("::ffff:10.10.1.1", s))
        self.assertEqual(proxy.decidir("::ffff:192.168.1.1", s), proxy.FUERA)
        self.assertIsNone(proxy.decidir("::ffff:8.8.4.4", s))

    def test_nombre_con_una_ip_excluida_usa_otra(self):
        s = targets.Scope(["10.10.0.0/16"], ["10.10.5.20/32"])
        self.assertEqual(proxy.elegir_ip(["10.10.5.20", "10.10.5.21"], s), ("10.10.5.21", None))
        self.assertEqual(proxy.elegir_ip(["10.10.5.20"], s), (None, proxy.EXCLUIDA))

    def test_elegir_ip_sin_direcciones_ni_alcance(self):
        s = targets.Scope(["10.10.0.0/16"], [])
        self.assertEqual(proxy.elegir_ip([], s), (None, None))
        self.assertEqual(proxy.elegir_ip(["10.10.1.1"], None), (None, proxy.ILEGIBLE))

    def test_consola_con_excluir_no_abre_lo_interno(self):
        s = proxy.alcance_de_consola(["10.0.0.5"], [], False, ["10.0.0.9/32"])
        self.assertIsNone(proxy.decidir("10.0.0.5", s))
        self.assertEqual(proxy.decidir("10.0.0.6", s), proxy.FUERA)

    def test_consola_con_rangos_solo_si_solo_rangos(self):
        sin = proxy.alcance_de_consola(["10.0.0.5"], ["10.1.0.0/16"], False, [])
        con = proxy.alcance_de_consola(["10.0.0.5"], ["10.1.0.0/16"], True, [])
        self.assertEqual(proxy.decidir("10.1.2.3", sin), proxy.FUERA)
        self.assertIsNone(proxy.decidir("10.1.2.3", con))

    def test_consola_acepta_objetivos_ipv6(self):
        s = proxy.alcance_de_consola(["fd00::5"], [], False, [])
        self.assertIsNone(proxy.decidir("fd00::5", s))
        self.assertEqual(proxy.decidir("fd00::6", s), proxy.FUERA)

    def test_alcance_fijo_devuelve_el_mismo(self):
        s = targets.Scope(["10.0.0.0/8"], [])
        self.assertIs(proxy.AlcanceFijo(s).actual(), s)


class AlcanceVivoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ruta = Path(self.tmp.name) / "alcance.json"

    def escribir(self, incluir, excluir=()):
        self.ruta.write_text(json.dumps({"incluir": list(incluir), "excluir": list(excluir)}), encoding="utf-8")

    def test_alcance_vivo_lee_el_fichero(self):
        self.escribir(["10.0.0.0/8"], ["10.0.0.9/32"])
        vivo = proxy.AlcanceVivo(self.ruta)
        self.assertIsNone(proxy.decidir("10.0.0.1", vivo.actual()))
        self.assertEqual(proxy.decidir("10.0.0.9", vivo.actual()), proxy.EXCLUIDA)

    def test_alcance_vivo_relee_si_cambia(self):
        self.escribir(["10.0.0.0/8"])
        vivo = proxy.AlcanceVivo(str(self.ruta))
        self.assertIsNone(proxy.decidir("10.0.0.1", vivo.actual()))
        self.escribir(["10.0.0.0/8"], ["10.0.0.1/32"])  # cambia el tamaño
        self.assertEqual(proxy.decidir("10.0.0.1", vivo.actual()), proxy.EXCLUIDA)

    def test_alcance_vivo_no_relee_si_no_cambia(self):
        self.escribir(["10.0.0.0/8"])
        vivo = proxy.AlcanceVivo(self.ruta)
        primero = vivo.actual()
        with mock.patch.object(Path, "read_text", side_effect=AssertionError("no debía releer")):
            self.assertIs(vivo.actual(), primero)

    def test_alcance_vivo_ilegible_corta_todo(self):
        self.escribir(["10.0.0.0/8"])
        vivo = proxy.AlcanceVivo(self.ruta)
        self.assertIsNotNone(vivo.actual())
        self.ruta.unlink()
        self.assertIsNone(vivo.actual())
        self.assertEqual(proxy.decidir("8.8.4.4", vivo.actual()), proxy.ILEGIBLE)

    def test_alcance_vivo_con_json_roto_corta_todo(self):
        self.ruta.write_text("{\"incluir\": [", encoding="utf-8")
        with mock.patch.object(proxy.time, "sleep"):
            self.assertIsNone(proxy.AlcanceVivo(self.ruta).actual())

    def test_alcance_vivo_con_contenido_invalido_corta_todo(self):
        self.ruta.write_text(json.dumps({"incluir": ["no-es-una-red"], "excluir": []}), encoding="utf-8")
        with mock.patch.object(proxy.time, "sleep"):
            self.assertIsNone(proxy.AlcanceVivo(self.ruta).actual())

    def test_alcance_vivo_reintenta_un_fallo_momentaneo(self):
        self.escribir(["10.0.0.0/8"])
        original = Path.read_text
        llamadas = []

        def falla_una_vez(ruta, *args, **kwargs):
            llamadas.append(1)
            if len(llamadas) == 1:
                raise PermissionError("el fichero se está reemplazando")
            return original(ruta, *args, **kwargs)

        with mock.patch.object(Path, "read_text", falla_una_vez):
            actual = proxy.AlcanceVivo(self.ruta).actual()
        self.assertIsNotNone(actual)
        self.assertGreaterEqual(len(llamadas), 2)


# Alcance de las pruebas del servidor: 127.0.0.0/8 deja llegar a los servidores locales del test.
ALCANCE = targets.Scope(["127.0.0.0/8", "10.10.0.0/16"], ["10.10.5.20/32"])
ESPERA = 5


def prohibido():
    """`conectar` que hace fallar el test si se llama: prueba de que no se contacta."""
    return mock.Mock(side_effect=AssertionError("no debía conectar"))


def resolvedor(*ips):
    """`resolver` falso que devuelve `ips` para cualquier nombre."""
    return mock.Mock(side_effect=lambda host, puerto, *a, **k: [
        (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, puerto))
        for ip in ips])


class AlcanceCambiante:
    """Fuente de alcance que el test cambia entre conexiones."""

    def __init__(self, scope):
        self.scope = scope

    def actual(self):
        return self.scope


class ServidorDePrueba:
    """Servidor de una sola conexión en 127.0.0.1 que guarda lo que recibe.

    En modo "eco" devuelve lo que le llega; en modo "http" lee una petición, responde
    `ok` con `Connection: close` y sigue leyendo hasta que el otro lado cierre."""

    RESPUESTA = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

    def __init__(self, modo):
        self.modo = modo
        self.recibido = b""
        self.escucha = socket.create_server(("127.0.0.1", 0))
        self.escucha.settimeout(ESPERA)
        self.puerto = self.escucha.getsockname()[1]
        self.hilo = threading.Thread(target=self._servir, daemon=True)
        self.hilo.start()

    def _servir(self):
        try:
            conexion, _ = self.escucha.accept()
        except OSError:
            return
        with conexion:
            conexion.settimeout(ESPERA)
            if self.modo == "eco":
                while datos := conexion.recv(65536):
                    conexion.sendall(datos)
                return
            while b"\r\n\r\n" not in self.recibido:
                self.recibido += conexion.recv(65536)
            conexion.sendall(self.RESPUESTA)
            conexion.shutdown(socket.SHUT_WR)
            while datos := conexion.recv(65536):
                self.recibido += datos

    def cerrar(self):
        self.hilo.join(ESPERA)
        self.escucha.close()


class ServidorProxyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ruta = Path(self.tmp.name) / "proxy.jsonl"

    def arrancar(self, alcance=ALCANCE, timeout=3, **kwargs):
        if isinstance(alcance, targets.Scope):
            alcance = proxy.AlcanceFijo(alcance)
        servidor = proxy.Proxy(alcance, timeout, **kwargs)
        puerto = servidor.iniciar()
        self.addCleanup(servidor.parar)
        self.assertEqual(servidor.url, f"http://127.0.0.1:{puerto}")
        servidor.registro(self.ruta)
        return servidor

    def servidor_local(self, modo):
        servidor = ServidorDePrueba(modo)
        self.addCleanup(servidor.cerrar)
        return servidor

    def cliente(self, servidor):
        conexion = socket.create_connection(("127.0.0.1", int(servidor.url.rsplit(":", 1)[1])), timeout=ESPERA)
        self.addCleanup(conexion.close)
        return conexion

    def pedir(self, servidor, peticion: bytes):
        """Manda `peticion` al proxy y devuelve (conexión, cabecera de la respuesta)."""
        conexion = self.cliente(servidor)
        conexion.sendall(peticion)
        return conexion, self.leer_cabecera(conexion)

    @staticmethod
    def leer_cabecera(conexion) -> str:
        datos = b""
        while b"\r\n\r\n" not in datos:
            bloque = conexion.recv(1)
            if not bloque:
                break
            datos += bloque
        return datos.decode("latin-1")

    @staticmethod
    def leer_todo(conexion) -> bytes:
        datos = b""
        while bloque := conexion.recv(65536):
            datos += bloque
        return datos

    def lineas(self):
        if not self.ruta.exists():
            return []
        return [json.loads(linea) for linea in self.ruta.read_text(encoding="utf-8").splitlines()]

    def par_de_sockets(self):
        """Extremo que devuelve el `conectar` falso y el que se queda el test."""
        propio, ajeno = socket.socketpair()
        self.addCleanup(propio.close)
        self.addCleanup(ajeno.close)
        ajeno.settimeout(ESPERA)
        return propio, ajeno

    # --- CONNECT ---

    def test_connect_en_alcance_hace_tunel(self):
        eco = self.servidor_local("eco")
        servidor = self.arrancar()
        conexion, cabecera = self.pedir(servidor, f"CONNECT 127.0.0.1:{eco.puerto} HTTP/1.1\r\n"
                                                  f"Host: 127.0.0.1:{eco.puerto}\r\n\r\n".encode())
        self.assertTrue(cabecera.startswith("HTTP/1.1 200 Connection Established\r\n"), cabecera)
        conexion.sendall(b"hola")
        self.assertEqual(conexion.recv(4), b"hola")
        conexion.sendall(b"y adios")
        self.assertEqual(conexion.recv(7), b"y adios")
        conexion.close()
        eco.cerrar()
        self.assertFalse(eco.hilo.is_alive())       # el proxy cerró el lado del servidor
        self.assertEqual(self.lineas(), [])

    def test_connect_excluido_403_sin_conectar(self):
        conectar = prohibido()
        servidor = self.arrancar(conectar=conectar)
        conexion, cabecera = self.pedir(servidor, b"CONNECT 10.10.5.20:443 HTTP/1.1\r\nHost: 10.10.5.20:443\r\n\r\n")
        self.assertTrue(cabecera.startswith("HTTP/1.1 403 Forbidden\r\n"), cabecera)
        self.assertIn("Content-Length: 0\r\n", cabecera)
        self.assertEqual(self.leer_todo(conexion), b"")       # sin cuerpo, y cierra
        conectar.assert_not_called()
        self.assertEqual(self.lineas(), [
            {"destino": "10.10.5.20:443", "ip": "10.10.5.20", "puerto": 443, "motivo": "excluida"}])

    def test_publico_pasa_y_no_se_anota(self):
        propio, ajeno = self.par_de_sockets()
        conectar = mock.Mock(return_value=propio)
        servidor = self.arrancar(conectar=conectar)
        conexion, cabecera = self.pedir(servidor, b"CONNECT 8.8.4.4:443 HTTP/1.1\r\n\r\n")
        self.assertTrue(cabecera.startswith("HTTP/1.1 200 "), cabecera)
        conexion.sendall(b"tls")
        self.assertEqual(ajeno.recv(3), b"tls")
        ajeno.sendall(b"vuelta")
        self.assertEqual(conexion.recv(6), b"vuelta")
        conectar.assert_called_once_with(("8.8.4.4", 443), timeout=3)
        self.assertEqual(self.lineas(), [])

    def test_privada_fuera_de_alcance_se_corta(self):
        conectar = prohibido()
        servidor = self.arrancar(conectar=conectar)
        _, cabecera = self.pedir(servidor, b"CONNECT [fd00::1]:8443 HTTP/1.1\r\n\r\n")
        self.assertTrue(cabecera.startswith("HTTP/1.1 403 "), cabecera)
        conectar.assert_not_called()
        self.assertEqual(self.lineas(), [
            {"destino": "[fd00::1]:8443", "ip": "fd00::1", "puerto": 8443, "motivo": "fuera_de_alcance"}])

    def test_alcance_se_consulta_en_cada_conexion(self):
        propio, _ = self.par_de_sockets()
        conectar = mock.Mock(return_value=propio)
        alcance = AlcanceCambiante(targets.Scope(["10.10.0.0/16"], []))
        servidor = self.arrancar(alcance, conectar=conectar)
        _, cabecera = self.pedir(servidor, b"CONNECT 10.10.1.1:443 HTTP/1.1\r\n\r\n")
        self.assertTrue(cabecera.startswith("HTTP/1.1 200 "), cabecera)
        alcance.scope = targets.Scope(["10.10.0.0/16"], ["10.10.1.1/32"])
        _, cabecera = self.pedir(servidor, b"CONNECT 10.10.1.1:443 HTTP/1.1\r\n\r\n")
        self.assertTrue(cabecera.startswith("HTTP/1.1 403 "), cabecera)
        self.assertEqual(conectar.call_count, 1)
        self.assertEqual([l["motivo"] for l in self.lineas()], ["excluida"])

    def test_alcance_ilegible_corta_hasta_lo_publico(self):
        conectar = prohibido()
        servidor = self.arrancar(AlcanceCambiante(None), conectar=conectar)
        _, cabecera = self.pedir(servidor, b"CONNECT 8.8.4.4:443 HTTP/1.1\r\n\r\n")
        self.assertTrue(cabecera.startswith("HTTP/1.1 403 "), cabecera)
        conectar.assert_not_called()
        self.assertEqual(self.lineas(), [
            {"destino": "8.8.4.4:443", "ip": "8.8.4.4", "puerto": 443, "motivo": "alcance_ilegible"}])

    # --- Nombres ---

    def test_nombre_se_resuelve_y_conecta_a_la_ip_comprobada(self):
        propio, ajeno = self.par_de_sockets()
        conectar = mock.Mock(return_value=propio)
        resolver = resolvedor("10.10.5.20", "10.10.1.1")    # la primera, excluida, se salta
        servidor = self.arrancar(conectar=conectar, resolver=resolver)
        conexion, cabecera = self.pedir(servidor, b"CONNECT intranet.test:8443 HTTP/1.1\r\n\r\n")
        self.assertTrue(cabecera.startswith("HTTP/1.1 200 "), cabecera)
        self.assertEqual(resolver.call_args.args[:2], ("intranet.test", 8443))
        conectar.assert_called_once_with(("10.10.1.1", 8443), timeout=3)
        conexion.sendall(b"x")
        self.assertEqual(ajeno.recv(1), b"x")
        self.assertEqual(self.lineas(), [])

    def test_nombre_excluido_se_corta_sin_conectar(self):
        conectar = prohibido()
        servidor = self.arrancar(conectar=conectar, resolver=resolvedor("10.10.5.20"))
        _, cabecera = self.pedir(servidor, b"CONNECT intranet.test:443 HTTP/1.1\r\n\r\n")
        self.assertTrue(cabecera.startswith("HTTP/1.1 403 "), cabecera)
        conectar.assert_not_called()
        self.assertEqual(self.lineas(), [
            {"destino": "intranet.test:443", "ip": "10.10.5.20", "puerto": 443, "motivo": "excluida"}])

    def test_direccion_que_no_es_ip_se_corta(self):
        conectar = prohibido()
        servidor = self.arrancar(conectar=conectar, resolver=resolvedor("no-es-una-ip"))
        _, cabecera = self.pedir(servidor, b"CONNECT raro.test:443 HTTP/1.1\r\n\r\n")
        self.assertTrue(cabecera.startswith("HTTP/1.1 403 "), cabecera)
        conectar.assert_not_called()
        self.assertEqual(self.lineas(), [
            {"destino": "raro.test:443", "ip": None, "puerto": 443, "motivo": "fuera_de_alcance"}])

    def test_nombre_sin_resolver_502_y_fallo_error(self):
        conectar = prohibido()
        resolver = mock.Mock(side_effect=socket.gaierror("no existe"))
        servidor = self.arrancar(conectar=conectar, resolver=resolver)
        _, cabecera = self.pedir(servidor, b"CONNECT nadie.test:443 HTTP/1.1\r\n\r\n")
        self.assertTrue(cabecera.startswith("HTTP/1.1 502 Bad Gateway\r\n"), cabecera)
        conectar.assert_not_called()
        self.assertEqual(self.lineas(), [
            {"destino": "nadie.test:443", "ip": None, "puerto": 443, "fallo": "error"}])

    # --- Fallos de conexión ---

    def test_puerto_cerrado_502_y_fallo_anotado(self):
        conectar = mock.Mock(side_effect=ConnectionRefusedError())
        servidor = self.arrancar(conectar=conectar)
        _, cabecera = self.pedir(servidor, b"CONNECT 10.10.1.1:81 HTTP/1.1\r\n\r\n")
        self.assertTrue(cabecera.startswith("HTTP/1.1 502 Bad Gateway\r\n"), cabecera)
        self.assertIn("Content-Length: 0\r\n", cabecera)
        conectar.side_effect = TimeoutError()
        _, cabecera = self.pedir(servidor, b"GET http://10.10.1.1:82/ HTTP/1.1\r\nHost: 10.10.1.1:82\r\n\r\n")
        self.assertTrue(cabecera.startswith("HTTP/1.1 502 "), cabecera)
        conectar.side_effect = OSError("red inalcanzable")
        _, cabecera = self.pedir(servidor, b"CONNECT 10.10.1.1:83 HTTP/1.1\r\n\r\n")
        self.assertTrue(cabecera.startswith("HTTP/1.1 502 "), cabecera)
        self.assertEqual(self.lineas(), [
            {"destino": "10.10.1.1:81", "ip": "10.10.1.1", "puerto": 81, "fallo": "rechazada"},
            {"destino": "10.10.1.1:82", "ip": "10.10.1.1", "puerto": 82, "fallo": "sin_respuesta"},
            {"destino": "10.10.1.1:83", "ip": "10.10.1.1", "puerto": 83, "fallo": "error"}])

    # --- HTTP con URL absoluta ---

    def test_http_absoluto_se_reenvia_en_forma_de_origen(self):
        web = self.servidor_local("http")
        servidor = self.arrancar()
        conexion = self.cliente(servidor)
        conexion.sendall(f"GET http://127.0.0.1:{web.puerto}/ruta?x=1#frag HTTP/1.1\r\n"
                         f"Host: 127.0.0.1:{web.puerto}\r\nProxy-Connection: keep-alive\r\n"
                         "Connection: keep-alive\r\nAccept: */*\r\n\r\n".encode())
        respuesta = self.leer_todo(conexion)
        self.assertEqual(respuesta, ServidorDePrueba.RESPUESTA)
        web.cerrar()
        peticion = web.recibido.decode("latin-1")
        self.assertTrue(peticion.startswith("GET /ruta?x=1 HTTP/1.1\r\n"), peticion)
        self.assertIn("\r\nConnection: close\r\n", peticion)
        self.assertIn(f"\r\nHost: 127.0.0.1:{web.puerto}\r\n", peticion)
        self.assertIn("\r\nAccept: */*\r\n", peticion)
        self.assertNotIn("Proxy-Connection", peticion)
        self.assertNotIn("keep-alive", peticion)

    def test_http_con_cuerpo_reenvia_solo_su_longitud(self):
        web = self.servidor_local("http")
        servidor = self.arrancar()
        conexion = self.cliente(servidor)
        conexion.sendall(f"POST http://127.0.0.1:{web.puerto}/form HTTP/1.1\r\nHost: x\r\n"
                         "Content-Length: 5\r\n\r\nhola!sobra".encode())
        self.assertEqual(self.leer_todo(conexion), ServidorDePrueba.RESPUESTA)
        web.cerrar()
        self.assertTrue(web.recibido.endswith(b"\r\n\r\nhola!"), web.recibido)

    def test_http_una_peticion_por_conexion(self):
        primero = self.servidor_local("http")
        segundo = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(segundo.close)
        otro = segundo.getsockname()[1]
        servidor = self.arrancar()
        conexion = self.cliente(servidor)
        conexion.sendall(f"GET http://127.0.0.1:{primero.puerto}/uno HTTP/1.1\r\nHost: a\r\n\r\n"
                         f"GET http://127.0.0.1:{otro}/dos HTTP/1.1\r\nHost: b\r\n\r\n".encode())
        self.assertEqual(self.leer_todo(conexion), ServidorDePrueba.RESPUESTA)  # una respuesta y cierra
        primero.cerrar()
        self.assertEqual(primero.recibido.count(b"GET "), 1, primero.recibido)
        segundo.setblocking(False)
        with self.assertRaises(BlockingIOError):         # al segundo servidor no llegó nadie
            segundo.accept()

    def test_http_excluido_403_sin_conectar(self):
        conectar = prohibido()
        servidor = self.arrancar(conectar=conectar)
        _, cabecera = self.pedir(servidor, b"GET http://10.10.5.20/x.js HTTP/1.1\r\nHost: 10.10.5.20\r\n\r\n")
        self.assertTrue(cabecera.startswith("HTTP/1.1 403 "), cabecera)
        conectar.assert_not_called()
        self.assertEqual(self.lineas(), [
            {"destino": "10.10.5.20:80", "ip": "10.10.5.20", "puerto": 80, "motivo": "excluida"}])

    # --- Peticiones que no valen ---

    def test_peticion_no_valida_400(self):
        conectar = prohibido()
        servidor = self.arrancar(conectar=conectar)
        for peticion in (b"GET /relativa HTTP/1.1\r\nHost: x\r\n\r\n",
                         b"GET https://10.10.1.1/ HTTP/1.1\r\n\r\n",
                         b"GET http://10.10.1.1:0/ HTTP/1.1\r\n\r\n",
                         b"CONNECT 10.10.1.1 HTTP/1.1\r\n\r\n",
                         b"CONNECT 10.10.1.1:99999 HTTP/1.1\r\n\r\n",
                         b"CONNECT 10.10.1.1:443\r\n\r\n",
                         b"CONNECT 10.10.1.1:443 HTTP/1.1\r\nsin dos puntos\r\n\r\n"):
            with self.subTest(peticion=peticion):
                _, cabecera = self.pedir(servidor, peticion)
                self.assertTrue(cabecera.startswith("HTTP/1.1 400 Bad Request\r\n"), cabecera)
        conectar.assert_not_called()
        self.assertEqual(self.lineas(), [])

    def test_cabeceras_demasiado_grandes_400(self):
        conectar = prohibido()
        servidor = self.arrancar(conectar=conectar)
        _, cabecera = self.pedir(servidor, b"CONNECT 10.10.1.1:443 HTTP/1.1\r\nX: " + b"a" * (64 * 1024 - 35))
        self.assertTrue(cabecera.startswith("HTTP/1.1 400 "), cabecera)
        conectar.assert_not_called()

    def test_conexion_sin_peticion_se_cierra_sin_responder(self):
        servidor = self.arrancar(timeout=0.2, conectar=prohibido())
        self.assertEqual(self.leer_todo(self.cliente(servidor)), b"")

    def test_cabecera_a_medias_400_al_vencer_el_tiempo(self):
        servidor = self.arrancar(timeout=0.2, conectar=prohibido())
        _, cabecera = self.pedir(servidor, b"CONNECT 10.10.1.1:443 HTTP/1.1\r\n")
        self.assertTrue(cabecera.startswith("HTTP/1.1 400 "), cabecera)

    # --- Registro ---

    def test_registro_cambia_de_fichero_y_none_deja_de_anotar(self):
        servidor = self.arrancar(conectar=prohibido())
        otra = Path(self.tmp.name) / "otra.jsonl"
        servidor.registro(otra)
        self.pedir(servidor, b"CONNECT 10.10.5.20:443 HTTP/1.1\r\n\r\n")
        servidor.registro(None)
        self.pedir(servidor, b"CONNECT 10.10.5.20:444 HTTP/1.1\r\n\r\n")
        self.assertEqual(self.lineas(), [])
        self.assertEqual([json.loads(l)["puerto"] for l in otra.read_text(encoding="utf-8").splitlines()], [443])

    def test_solo_escucha_en_local(self):
        servidor = self.arrancar()
        self.assertEqual(servidor._servidor.server_address[0], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
