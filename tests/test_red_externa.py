"""Las salidas a internet (NVD y GitHub) contra un servidor HTTP local: nunca red real.

Las URL de los feeds y de las APIs son constantes de módulo; aquí se apuntan a 127.0.0.1.
"""

import gzip
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from dedalo import auditoria, cve, db, exploits, internet


class _Servidor:
    """Servidor local en un hilo. `rutas` asocia ruta -> (código, cuerpo en bytes); registra cada petición."""

    def __init__(self, rutas):
        self.rutas = rutas
        self.peticiones = []
        servidor = self

        class Manejador(BaseHTTPRequestHandler):
            def do_GET(self):
                servidor.peticiones.append((self.path, dict(self.headers)))
                ruta = self.path.split("?")[0]
                codigo, cuerpo = servidor.rutas.get(ruta, (404, b""))
                self.send_response(codigo)
                self.send_header("Content-Length", str(len(cuerpo)))
                self.end_headers()
                self.wfile.write(cuerpo)

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Manejador)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.hilo = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)

    def __enter__(self):
        self.hilo.start()
        return self

    def __exit__(self, *args):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.hilo.join()

    def rutas_pedidas(self):
        return [p.split("?")[0] for p, _ in self.peticiones]


def cve_nvd(cve_id="CVE-2021-0001", criterios=None, estado="Analyzed", metricas=None, descripciones=None):
    """Una entrada `vulnerabilities[].cve` del formato 2.0 de la NVD."""
    criterios = criterios if criterios is not None else [{"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"}]
    return {"cve": {
        "id": cve_id, "published": "2021-05-01T10:00:00.000", "vulnStatus": estado,
        "descriptions": descripciones or [{"lang": "es", "value": "texto en español"}, {"lang": "en", "value": "Overflow in httpd."}],
        "metrics": metricas if metricas is not None else {"cvssMetricV31": [
            {"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
        "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": criterios}]}]}}


def feed(*entradas, bom=False, comprimido=True):
    cuerpo = json.dumps({"vulnerabilities": list(entradas)}).encode("utf-8")
    if bom:
        cuerpo = b"\xef\xbb\xbf" + cuerpo
    return gzip.compress(cuerpo) if comprimido else cuerpo


class NormalizarNvdTests(unittest.TestCase):
    def test_version_exacta_se_normaliza_a_rango_cerrado_de_un_solo_valor(self):
        entrada = cve_nvd(criterios=[{"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}])
        item = cve.item_desde_nvd(entrada)
        self.assertEqual(item["cpes"], [{"parte": "a", "vendor": "apache", "producto": "http_server", "v_ini": "2.4.49",
                                         "v_ini_incl": 1, "v_fin": "2.4.49", "v_fin_incl": 1}])

    def test_version_exacta_no_casa_con_otras_versiones_tras_guardar(self):
        entrada = cve_nvd(criterios=[{"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}])
        with tempfile.TemporaryDirectory() as d:
            con = db.connect(d)
            cve.guardar_cves(con, [cve.item_desde_nvd(entrada)])
            self.assertEqual([c["id"] for c in cve.cves_de(con, "cpe:/a:apache:http_server:2.4.49")], ["CVE-2021-0001"])
            self.assertEqual(cve.cves_de(con, "cpe:/a:apache:http_server:2.4.50"), [])
            self.assertEqual(cve.cves_de(con, "cpe:/a:apache:http_server:2.4.48"), [])
            con.close()

    def test_rangos_con_sus_extremos(self):
        criterios = [
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
             "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.50"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
             "versionStartExcluding": "1.0", "versionEndIncluding": "1.9"},
        ]
        reglas = cve.item_desde_nvd(cve_nvd(criterios=criterios))["cpes"]
        self.assertEqual((reglas[0]["v_ini"], reglas[0]["v_ini_incl"], reglas[0]["v_fin"], reglas[0]["v_fin_incl"]),
                         ("2.4.0", 1, "2.4.50", 0))
        self.assertEqual((reglas[1]["v_ini"], reglas[1]["v_ini_incl"], reglas[1]["v_fin"], reglas[1]["v_fin_incl"]),
                         ("1.0", 0, "1.9", 1))

    def test_comodin_de_version_sin_rango_vale_para_todas(self):
        regla = cve.item_desde_nvd(cve_nvd())["cpes"][0]
        self.assertIsNone(regla["v_ini"])
        self.assertIsNone(regla["v_fin"])

    def test_solo_las_reglas_vulnerables_y_sin_repetir(self):
        criterios = [
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"},
        ]
        reglas = cve.item_desde_nvd(cve_nvd(criterios=criterios))["cpes"]
        self.assertEqual([r["producto"] for r in reglas], ["http_server"])

    def test_componentes_del_cpe_con_dos_puntos_escapados(self):
        criterios = [{"vulnerable": True, "criteria": r"cpe:2.3:a:ac\:me:pro\.d:1.0:*:*:*:*:*:*:*"}]
        regla = cve.item_desde_nvd(cve_nvd(criterios=criterios))["cpes"][0]
        self.assertEqual((regla["vendor"], regla["producto"], regla["v_ini"]), ("ac:me", "pro.d", "1.0"))

    def test_severidad_y_cvss_prefieren_la_version_mas_nueva_y_caen_a_v2(self):
        v2 = {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}]}
        item = cve.item_desde_nvd(cve_nvd(metricas=v2))
        self.assertEqual((item["severidad"], item["cvss"]), ("MEDIUM", 5.0))
        item = cve.item_desde_nvd(cve_nvd())
        self.assertEqual((item["severidad"], item["cvss"]), ("CRITICAL", 9.8))
        item = cve.item_desde_nvd(cve_nvd(metricas={}))
        self.assertEqual((item["severidad"], item["cvss"]), ("", None))

    def test_resumen_en_ingles_y_publicada(self):
        item = cve.item_desde_nvd(cve_nvd())
        self.assertEqual(item["resumen"], "Overflow in httpd.")
        self.assertEqual(item["publicada"], "2021-05-01T10:00:00.000")
        self.assertEqual(item["id"], "CVE-2021-0001")

    def test_rechazadas_y_entradas_mal_formadas_dan_none(self):
        self.assertIsNone(cve.item_desde_nvd(cve_nvd(estado="Rejected")))
        for malo in (None, [], {}, {"cve": []}, {"cve": {"id": ""}}, {"cve": {"id": 5}}):
            self.assertIsNone(cve.item_desde_nvd(malo))


class SinInternetNoTocaLaRedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.con = db.connect(self.temp.name)
        self.addCleanup(self.con.close)

    def test_las_tres_funciones_son_no_op_y_no_abren_conexiones(self):
        with mock.patch.object(internet, "peticion", side_effect=AssertionError("tocó la red")) as peticion, \
                mock.patch.object(socket.socket, "connect", side_effect=AssertionError("abrió un socket")), \
                mock.patch.object(socket, "create_connection", side_effect=AssertionError("abrió un socket")):
            mensajes = []
            self.assertIsNone(cve.actualizar_base(self.con, Path(self.temp.name) / "nvd", True, log=mensajes.append))
            self.assertEqual(cve.consultar_online("cpe:/a:apache:http_server:2.4.49", True), [])
            self.assertEqual(exploits.buscar_github("CVE-2021-41773", True, token="t"), [])
            self.assertEqual(peticion.call_count, 0)
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM cve").fetchone()[0], 0)
        self.assertIsNone(auditoria.get_config(self.con, "nvd_actualizada"))
        self.assertFalse((Path(self.temp.name) / "nvd").exists())


class ActualizarBaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.con = db.connect(self.temp.name)
        self.addCleanup(self.con.close)
        self.destino = Path(self.temp.name) / "nvd"
        self.anio = datetime.now(timezone.utc).year

    def _parchear(self, servidor):
        return mock.patch.multiple(cve, NVD_FEED_ANUAL=servidor.base + "/feeds/nvdcve-2.0-{anio}.json.gz",
                                   NVD_FEED_MODIFICADA=servidor.base + "/feeds/nvdcve-2.0-modified.json.gz")

    def _rutas_anuales(self, **extra):
        rutas = {f"/feeds/nvdcve-2.0-{a}.json.gz": (200, feed()) for a in range(self.anio - 9, self.anio + 1)}
        rutas.update(extra)
        return rutas

    def test_primera_vez_descarga_los_ultimos_diez_anios_y_puebla_la_base(self):
        nuevo = f"/feeds/nvdcve-2.0-{self.anio}.json.gz"
        rutas = self._rutas_anuales(**{nuevo: (200, feed(cve_nvd("CVE-2026-1111", criterios=[
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]), bom=True))})
        with _Servidor(rutas) as s, self._parchear(s):
            mensajes = []
            cve.actualizar_base(self.con, self.destino, False, log=mensajes.append)
            pedidas = s.rutas_pedidas()
        self.assertEqual(sorted(pedidas), sorted(f"/feeds/nvdcve-2.0-{a}.json.gz" for a in range(self.anio - 9, self.anio + 1)))
        self.assertEqual([c["id"] for c in cve.cves_de(self.con, "cpe:/a:apache:http_server:2.4.49")], ["CVE-2026-1111"])
        self.assertTrue(mensajes)
        marca = auditoria.get_config(self.con, "nvd_actualizada")
        self.assertIsNotNone(marca)
        self.assertLess(abs(datetime.fromisoformat(marca) - datetime.now(timezone.utc)), timedelta(minutes=5))
        # No deja los ficheros descargados.
        self.assertEqual(list(self.destino.glob("*")), [])

    def test_con_datos_recientes_solo_baja_el_feed_de_modificadas(self):
        auditoria.set_config(self.con, "nvd_actualizada", (datetime.now(timezone.utc) - timedelta(days=2)).isoformat())
        rutas = {"/feeds/nvdcve-2.0-modified.json.gz": (200, feed(cve_nvd("CVE-2026-2222")))}
        with _Servidor(rutas) as s, self._parchear(s):
            cve.actualizar_base(self.con, self.destino, False, log=lambda *_: None)
            pedidas = s.rutas_pedidas()
        self.assertEqual(pedidas, ["/feeds/nvdcve-2.0-modified.json.gz"])
        self.assertEqual(self.con.execute("SELECT id FROM cve").fetchall()[0][0], "CVE-2026-2222")

    def test_con_datos_viejos_vuelve_a_bajar_todo(self):
        auditoria.set_config(self.con, "nvd_actualizada", (datetime.now(timezone.utc) - timedelta(days=30)).isoformat())
        with _Servidor(self._rutas_anuales()) as s, self._parchear(s):
            cve.actualizar_base(self.con, self.destino, False, log=lambda *_: None)
            self.assertEqual(len(s.peticiones), 10)

    def test_marca_ilegible_se_trata_como_primera_vez(self):
        auditoria.set_config(self.con, "nvd_actualizada", "basura")
        with _Servidor(self._rutas_anuales()) as s, self._parchear(s):
            cve.actualizar_base(self.con, self.destino, False, log=lambda *_: None)
            self.assertEqual(len(s.peticiones), 10)

    def test_si_un_feed_falla_no_rompe_ni_marca_como_actualizada(self):
        rutas = self._rutas_anuales(**{f"/feeds/nvdcve-2.0-{self.anio}.json.gz": (200, feed(cve_nvd("CVE-2026-3333"))),
                                       f"/feeds/nvdcve-2.0-{self.anio - 1}.json.gz": (503, b"")})
        with _Servidor(rutas) as s, self._parchear(s):
            mensajes = []
            cve.actualizar_base(self.con, self.destino, False, log=mensajes.append)
        self.assertIsNone(auditoria.get_config(self.con, "nvd_actualizada"))
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM cve").fetchone()[0], 1)  # lo bueno sí se guardó
        self.assertTrue(any("503" in m or "No se pudo" in m for m in mensajes))

    def test_feed_roto_se_ignora(self):
        rutas = self._rutas_anuales(**{f"/feeds/nvdcve-2.0-{self.anio}.json.gz": (200, gzip.compress(b"{no es json"))})
        with _Servidor(rutas) as s, self._parchear(s):
            cve.actualizar_base(self.con, self.destino, False, log=lambda *_: None)
        self.assertIsNone(auditoria.get_config(self.con, "nvd_actualizada"))

    def test_acepta_json_sin_comprimir_y_con_bom(self):
        auditoria.set_config(self.con, "nvd_actualizada", datetime.now(timezone.utc).isoformat())
        rutas = {"/feeds/nvdcve-2.0-modified.json.gz": (200, feed(cve_nvd("CVE-2026-4444"), bom=True, comprimido=False))}
        with _Servidor(rutas) as s, self._parchear(s):
            cve.actualizar_base(self.con, self.destino, False, log=lambda *_: None)
        self.assertEqual(self.con.execute("SELECT id FROM cve").fetchall()[0][0], "CVE-2026-4444")


class ConsultarOnlineTests(unittest.TestCase):
    def test_consulta_la_api_por_cpe_y_devuelve_items_de_guardar_cves(self):
        cuerpo = json.dumps({"vulnerabilities": [cve_nvd("CVE-2021-41773", criterios=[
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]), cve_nvd("CVE-2021-0000", estado="Rejected")]})
        cuerpo = b"\xef\xbb\xbf" + cuerpo.encode("utf-8")
        with _Servidor({"/api": (200, cuerpo)}) as s, mock.patch.object(cve, "NVD_API_URL", s.base + "/api"):
            items = cve.consultar_online("cpe:/a:apache:http_server:2.4.49", False)
            consulta = s.peticiones[0][0]
        self.assertEqual([i["id"] for i in items], ["CVE-2021-41773"])
        self.assertEqual(items[0]["cpes"][0]["v_ini"], "2.4.49")
        self.assertIn("virtualMatchString=cpe%3A2.3%3Aa%3Aapache%3Ahttp_server%3A2.4.49", consulta)

    def test_cpe_con_vendor_comodin_y_sin_version(self):
        with _Servidor({"/api": (200, b'{"vulnerabilities": []}')}) as s, mock.patch.object(cve, "NVD_API_URL", s.base + "/api"):
            self.assertEqual(cve.consultar_online("cpe:/a:*:nginx:*", False), [])
            self.assertIn("virtualMatchString=cpe%3A2.3%3Aa%3A%2A%3Anginx%3A%2A", s.peticiones[0][0])

    def test_cpe_ilegible_no_sale_a_la_red_y_da_none(self):
        with mock.patch.object(internet, "peticion", side_effect=AssertionError("tocó la red")):
            self.assertIsNone(cve.consultar_online("esto no es un cpe", False))

    def test_sin_internet_sigue_dando_lista_vacia(self):
        with mock.patch.object(internet, "peticion", side_effect=AssertionError("tocó la red")):
            self.assertEqual(cve.consultar_online("cpe:/a:apache:http_server:2.4.49", True), [])

    def test_consulta_correcta_sin_cve_da_lista_vacia_no_none(self):
        cuerpo = b'{"resultsPerPage": 500, "totalResults": 0, "vulnerabilities": []}'
        with _Servidor({"/api": (200, cuerpo)}) as s, mock.patch.object(cve, "NVD_API_URL", s.base + "/api"):
            resultado = cve.consultar_online("cpe:/a:apache:http_server:2.4.49", False)
        self.assertIsNotNone(resultado)
        self.assertEqual(resultado, [])

    def test_errores_de_red_y_http_dan_none(self):
        for codigo in (403, 429, 503):
            with _Servidor({"/api": (codigo, b"")}) as s, mock.patch.object(cve, "NVD_API_URL", s.base + "/api"):
                self.assertIsNone(cve.consultar_online("cpe:/a:apache:http_server:2.4.49", False), codigo)
        with mock.patch.object(cve, "NVD_API_URL", "http://127.0.0.1:1/api"):  # puerto cerrado
            self.assertIsNone(cve.consultar_online("cpe:/a:apache:http_server:2.4.49", False))

    def test_respuesta_ilegible_o_demasiado_grande_da_none(self):
        for cuerpo in (b"<html>", b'{"sin": "vulnerabilities"}'):
            with _Servidor({"/api": (200, cuerpo)}) as s, mock.patch.object(cve, "NVD_API_URL", s.base + "/api"):
                self.assertIsNone(cve.consultar_online("cpe:/a:apache:http_server:2.4.49", False))
        with _Servidor({"/api": (200, b'{"vulnerabilities": []}' + b" " * 100)}) as s,                 mock.patch.object(cve, "NVD_API_URL", s.base + "/api"), mock.patch.object(cve, "MAX_RESPUESTA_API", 50):
            self.assertIsNone(cve.consultar_online("cpe:/a:apache:http_server:2.4.49", False))

    def test_resultado_truncado_da_none(self):
        cuerpo = json.dumps({"resultsPerPage": 1, "totalResults": 3, "vulnerabilities": [cve_nvd("CVE-2021-0001")]}).encode()
        with _Servidor({"/api": (200, cuerpo)}) as s, mock.patch.object(cve, "NVD_API_URL", s.base + "/api"):
            self.assertIsNone(cve.consultar_online("cpe:/a:apache:http_server:2.4.49", False))


class BuscarGithubTests(unittest.TestCase):
    def _respuesta(self):
        return json.dumps({"items": [
            {"html_url": "https://github.com/a/poc-1"}, {"html_url": "https://github.com/b/poc-2"},
            {"html_url": "https://evil.example/c"}, {"html_url": 5}, "basura", {}]}).encode("utf-8")

    def test_devuelve_enlaces_a_repos_de_github(self):
        with _Servidor({"/search": (200, self._respuesta())}) as s, mock.patch.object(exploits, "GITHUB_BUSQUEDA_URL", s.base + "/search"):
            enlaces = exploits.buscar_github("CVE-2021-41773", False)
            consulta, cabeceras = s.peticiones[0]
        self.assertEqual(enlaces, ["https://github.com/a/poc-1", "https://github.com/b/poc-2"])
        self.assertIn("CVE-2021-41773", consulta)
        self.assertNotIn("Authorization", cabeceras)

    def test_el_id_se_pasa_en_mayusculas(self):
        with _Servidor({"/search": (200, b'{"items": []}')}) as s, mock.patch.object(exploits, "GITHUB_BUSQUEDA_URL", s.base + "/search"):
            exploits.buscar_github("cve-2021-41773", False)
            self.assertIn("CVE-2021-41773", s.peticiones[0][0])

    def test_id_que_no_es_cve_no_sale_a_la_red(self):
        with mock.patch.object(internet, "peticion", side_effect=AssertionError("tocó la red")):
            for malo in ("", "no es un cve", "CVE-2021-1", "CVE-2021-41773 OR user:x", None):
                self.assertEqual(exploits.buscar_github(malo, False), [])

    def test_con_token_lo_envia_como_bearer(self):
        with _Servidor({"/search": (200, b'{"items": []}')}) as s, mock.patch.object(exploits, "GITHUB_BUSQUEDA_URL", s.base + "/search"):
            exploits.buscar_github("CVE-2021-41773", False, token="ghp_prueba")
            self.assertEqual(s.peticiones[0][1].get("Authorization"), "Bearer ghp_prueba")

    def test_limite_agotado_o_fallo_degrada_a_vacio(self):
        for codigo in (403, 429, 500):
            with _Servidor({"/search": (codigo, b'{"message": "rate limit"}')}) as s, \
                    mock.patch.object(exploits, "GITHUB_BUSQUEDA_URL", s.base + "/search"):
                self.assertEqual(exploits.buscar_github("CVE-2021-41773", False), [])
        with _Servidor({"/search": (200, b"no json")}) as s, mock.patch.object(exploits, "GITHUB_BUSQUEDA_URL", s.base + "/search"):
            self.assertEqual(exploits.buscar_github("CVE-2021-41773", False), [])
        with mock.patch.object(exploits, "GITHUB_BUSQUEDA_URL", "http://127.0.0.1:1/search"):
            self.assertEqual(exploits.buscar_github("CVE-2021-41773", False), [])


KEV_PRUEBA = json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-41773"}, {"cveID": "cve-2022-0847"}, {"cveID": "basura"}]}).encode("utf-8")
EDB_PRUEBA = b'id,file,description,date_published,codes\r\n50383,exploits/multiple/50383.txt,Apache 2.4.49,2021-10-05,CVE-2021-41773;OSVDB-1\r\n'


class _Respuesta:
    """Respuesta falsa de `internet.peticion`: sirve `cuerpo` y, si se pide, falla a mitad de la lectura."""

    def __init__(self, cuerpo, falla_a_mitad=False):
        self.cuerpo, self.falla_a_mitad = cuerpo, falla_a_mitad

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, n=-1):
        if self.falla_a_mitad:
            raise ConnectionResetError("se cortó la conexión a mitad de descarga")
        return self.cuerpo[:n] if n >= 0 else self.cuerpo


class ActualizarFuentesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.destino = Path(self.temp.name) / "vulnerabilidades"
        self.kev = self.destino / "kev.json"
        self.edb = self.destino / "files_exploits.csv"

    def _parchear(self, servidor):
        return mock.patch.multiple(exploits, KEV_URL=servidor.base + "/kev.json", EXPLOITDB_URL=servidor.base + "/files_exploits.csv")

    def _rutas(self, **extra):
        rutas = {"/kev.json": (200, KEV_PRUEBA), "/files_exploits.csv": (200, EDB_PRUEBA)}
        rutas.update(extra)
        return rutas

    def _restos(self):
        return sorted(p.name for p in self.destino.glob("*") if p.name not in ("kev.json", "files_exploits.csv"))

    def test_las_urls_apuntan_a_las_fuentes_oficiales(self):
        self.assertTrue(exploits.KEV_URL.startswith("https://www.cisa.gov/") and exploits.KEV_URL.endswith("known_exploited_vulnerabilities.json"))
        self.assertTrue(exploits.EXPLOITDB_URL.startswith("https://") and exploits.EXPLOITDB_URL.endswith("files_exploits.csv"))

    def test_sin_internet_no_toca_la_red_ni_crea_ficheros(self):
        with mock.patch.object(internet, "peticion", side_effect=AssertionError("tocó la red")) as peticion, \
                mock.patch.object(socket.socket, "connect", side_effect=AssertionError("abrió un socket")):
            mensajes = []
            self.assertIsNone(exploits.actualizar_fuentes(self.destino, True, log=mensajes.append))
            self.assertEqual(peticion.call_count, 0)
        self.assertFalse(self.destino.exists())
        self.assertEqual(mensajes, [])

    def test_descarga_las_dos_fuentes_y_cargar_las_lee_bien(self):
        with _Servidor(self._rutas()) as s, self._parchear(s):
            mensajes = []
            exploits.actualizar_fuentes(self.destino, False, log=mensajes.append)
            self.assertEqual(sorted(s.rutas_pedidas()), ["/files_exploits.csv", "/kev.json"])
        self.assertEqual(exploits.cargar_kev(self.kev), {"CVE-2021-41773", "CVE-2022-0847"})
        self.assertEqual(exploits.cargar_exploitdb(self.edb), {"CVE-2021-41773": ["https://www.exploit-db.com/exploits/50383"]})
        self.assertTrue(mensajes)
        self.assertEqual(self._restos(), [])  # sin ficheros temporales

    def test_un_bom_de_origen_no_rompe_la_lectura(self):
        rutas = self._rutas(**{"/kev.json": (200, b"\xef\xbb\xbf" + KEV_PRUEBA), "/files_exploits.csv": (200, b"\xef\xbb\xbf" + EDB_PRUEBA)})
        with _Servidor(rutas) as s, self._parchear(s):
            exploits.actualizar_fuentes(self.destino, False, log=lambda *_: None)
        self.assertEqual(exploits.cargar_kev(self.kev), {"CVE-2021-41773", "CVE-2022-0847"})
        self.assertIn("CVE-2021-41773", exploits.cargar_exploitdb(self.edb))

    def test_si_una_fuente_falla_no_impide_la_otra_ni_rompe(self):
        for caida, otra in (("/kev.json", self.edb), ("/files_exploits.csv", self.kev)):
            with self.subTest(caida=caida), _Servidor(self._rutas(**{caida: (503, b"")})) as s, self._parchear(s):
                with tempfile.TemporaryDirectory() as t:
                    destino = Path(t) / "v"
                    mensajes = []
                    exploits.actualizar_fuentes(destino, False, log=mensajes.append)
                    self.assertTrue(destino.joinpath(otra.name).exists())
                    self.assertFalse(destino.joinpath("kev.json" if otra is self.edb else "files_exploits.csv").exists())
                    self.assertEqual(len(list(destino.glob("*"))), 1)  # ni parciales
                    self.assertTrue(any("No se pudo" in m for m in mensajes))

    def test_servidor_inalcanzable_no_rompe_ni_deja_ficheros(self):
        with mock.patch.multiple(exploits, KEV_URL="http://127.0.0.1:1/kev.json", EXPLOITDB_URL="http://127.0.0.1:1/f.csv"):
            exploits.actualizar_fuentes(self.destino, False, log=lambda *_: None)
        self.assertEqual(list(self.destino.glob("*")), [])

    def test_descarga_cortada_a_mitad_no_deja_fichero_a_medias(self):
        with mock.patch.object(internet, "peticion", return_value=_Respuesta(KEV_PRUEBA, falla_a_mitad=True)):
            exploits.actualizar_fuentes(self.destino, False, log=lambda *_: None)
        self.assertEqual(list(self.destino.glob("*")), [])
        self.assertEqual(exploits.cargar_kev(self.kev), set())

    def _servidor_truncado(self, cuerpo, anunciado, con_longitud=True):
        """Servidor crudo que anuncia `anunciado` bytes de Content-Length, envía solo `cuerpo` y cierra."""
        escucha = socket.socket()
        escucha.bind(("127.0.0.1", 0))
        escucha.listen(5)
        self.addCleanup(escucha.close)

        def atender():
            while True:
                try:
                    conexion, _ = escucha.accept()
                except OSError:
                    return
                with conexion:
                    conexion.recv(4096)
                    cabecera = f"Content-Length: {anunciado}\r\n" if con_longitud else ""
                    conexion.sendall(("HTTP/1.1 200 OK\r\n" + cabecera + "Connection: close\r\n\r\n").encode() + cuerpo)

        threading.Thread(target=atender, daemon=True).start()
        return f"http://127.0.0.1:{escucha.getsockname()[1]}"

    def test_una_descarga_truncada_no_sustituye_al_fichero_bueno_previo(self):
        self.destino.mkdir(parents=True)
        self.kev.write_bytes(KEV_PRUEBA)
        self.edb.write_bytes(EDB_PRUEBA)
        for fichero in (self.kev, self.edb):
            os.utime(fichero, (time.time() - 3 * 86400,) * 2)
        antes = (self.kev.read_bytes(), self.edb.read_bytes())
        csv_cortado = b"id,file,description,date_published,codes\r\n"  # solo la cabecera: parece válido
        # El KEV de prueba es un JSON completo y válido: solo el Content-Length delata que faltan bytes.
        for nombre, cuerpo, anunciado in (("CSV", csv_cortado, len(csv_cortado) + 5000),
                                          ("KEV", KEV_PRUEBA, len(KEV_PRUEBA) + 5000)):
            with self.subTest(fuente=nombre):
                base = self._servidor_truncado(cuerpo, anunciado)
                mensajes = []
                kev_url = base if nombre == "KEV" else "http://127.0.0.1:1/kev.json"
                edb_url = base if nombre == "CSV" else "http://127.0.0.1:1/f.csv"
                with mock.patch.multiple(exploits, KEV_URL=kev_url, EXPLOITDB_URL=edb_url):
                    exploits.actualizar_fuentes(self.destino, False, log=mensajes.append)
                self.assertEqual((self.kev.read_bytes(), self.edb.read_bytes()), antes)
                self.assertTrue(any("No se pudo descargar " + ("Exploit-DB" if nombre == "CSV" else "CISA KEV") in m for m in mensajes))
                self.assertEqual(self._restos(), [])

    def test_sin_content_length_un_csv_que_no_acaba_en_salto_de_linea_se_rechaza(self):
        self.destino.mkdir(parents=True)
        self.edb.write_bytes(EDB_PRUEBA)
        os.utime(self.edb, (time.time() - 3 * 86400,) * 2)
        cortado = EDB_PRUEBA + b"50384,exploits/multiple/50384.txt,Cort"
        base = self._servidor_truncado(cortado, 0, con_longitud=False)
        with mock.patch.multiple(exploits, KEV_URL="http://127.0.0.1:1/kev.json", EXPLOITDB_URL=base):
            exploits.actualizar_fuentes(self.destino, False, log=lambda *_: None)
        self.assertEqual(self.edb.read_bytes(), EDB_PRUEBA)

    def test_un_fichero_bueno_previo_sobrevive_a_una_descarga_fallida_o_basura(self):
        self.destino.mkdir(parents=True)
        self.kev.write_bytes(KEV_PRUEBA)
        self.edb.write_bytes(EDB_PRUEBA)
        for fichero in (self.kev, self.edb):  # vencidos: toca volver a bajarlos
            os.utime(fichero, (time.time() - 3 * 86400,) * 2)
        antes = (self.kev.read_bytes(), self.edb.read_bytes())
        rutas = {"/kev.json": (200, b'{"vulnerabilities": [{"cveI'), "/files_exploits.csv": (200, b"<html>mantenimiento</html>")}
        with _Servidor(rutas) as s, self._parchear(s):
            exploits.actualizar_fuentes(self.destino, False, log=lambda *_: None)
            self.assertEqual(len(s.peticiones), 2)
        self.assertEqual((self.kev.read_bytes(), self.edb.read_bytes()), antes)
        self.assertEqual(self._restos(), [])

    def test_contenido_que_no_es_el_esperado_no_se_guarda(self):
        malos = {"/kev.json": [b"no es json", b'{"otra": []}', b'{"vulnerabilities": []}', b'{"vulnerabilities": 5}'],
                 "/files_exploits.csv": [b"", b"a,b,c\r\n1,2,3\r\n", b"\xff\xfe\x00 no es utf-8"]}
        for ruta, cuerpos in malos.items():
            for cuerpo in cuerpos:
                with self.subTest(ruta=ruta, cuerpo=cuerpo), _Servidor(self._rutas(**{ruta: (200, cuerpo)})) as s, self._parchear(s):
                    with tempfile.TemporaryDirectory() as t:
                        destino = Path(t) / "v"
                        exploits.actualizar_fuentes(destino, False, log=lambda *_: None)
                        self.assertFalse(destino.joinpath(ruta.lstrip("/")).exists())
                        self.assertEqual(len(list(destino.glob("*"))), 1)

    def test_una_descarga_mayor_que_el_tope_se_descarta(self):
        with _Servidor(self._rutas()) as s, self._parchear(s), mock.patch.multiple(exploits, MAX_KEV=10, MAX_EXPLOITDB=10):
            exploits.actualizar_fuentes(self.destino, False, log=lambda *_: None)
        self.assertEqual(list(self.destino.glob("*")), [])

    def test_con_ficheros_recientes_no_vuelve_a_descargar(self):
        with _Servidor(self._rutas()) as s, self._parchear(s):
            exploits.actualizar_fuentes(self.destino, False, log=lambda *_: None)
            self.assertEqual(len(s.peticiones), 2)
            exploits.actualizar_fuentes(self.destino, False, log=lambda *_: None)
            self.assertEqual(len(s.peticiones), 2)

    def test_un_fichero_vencido_se_vuelve_a_bajar_y_solo_ese(self):
        with _Servidor(self._rutas()) as s, self._parchear(s):
            exploits.actualizar_fuentes(self.destino, False, log=lambda *_: None)
            os.utime(self.kev, (time.time() - 3 * 86400,) * 2)
            exploits.actualizar_fuentes(self.destino, False, log=lambda *_: None)
            self.assertEqual(s.rutas_pedidas()[2:], ["/kev.json"])


if __name__ == "__main__":
    unittest.main()
