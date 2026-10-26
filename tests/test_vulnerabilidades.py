import tempfile
import unittest
from unittest import mock

from dedalo import cve, db, vulnerabilidades
from dedalo.auditoria import set_config

CPE_HTTPD = "cpe:/a:apache:http_server:2.4.49"
CPE_SIN_VERSION = "cpe:/a:apache:http_server"


def regla(producto, vendor="apache", v_ini=None, v_fin=None):
    return {"parte": "a", "vendor": vendor, "producto": producto,
            "v_ini": v_ini, "v_ini_incl": 1, "v_fin": v_fin, "v_fin_incl": 0}


def item(cve_id, cpes, severidad="HIGH", cvss=7.5):
    return {"id": cve_id, "publicada": "2026-01-01T00:00:00Z", "severidad": severidad, "cvss": cvss,
            "resumen": cve_id, "cpes": cpes}


def sin_github(cve_id, sin_internet, token=None):
    return []


def nmap(*cpes):
    """Los pares (fuente, cpe) que recibe cruzar_servicio, todos como si los hubiera dado Nmap."""
    return [("nmap", cpe) for cpe in cpes]


class BaseTemporal(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.con = db.connect(self.temp.name)

    def tearDown(self):
        self.con.close()
        self.temp.cleanup()


class CruzarServicioTests(BaseTemporal):
    def test_cve_critica_con_exploit_confirmado_pasa_por_delante_de_un_poc(self):
        cve.guardar_cves(self.con, [item("CVE-2026-0001", [regla("http_server", v_fin="2.4.50")], "CRITICAL", 9.8),
                                    item("CVE-2026-0002", [regla("nginx", vendor="f5", v_fin="2.0")], "MEDIUM", 5.0)])

        def github(cve_id, sin_internet, token=None):
            return ["https://github.com/x/poc"] if cve_id == "CVE-2026-0002" else []

        # Dos servicios: Apache (CVE crítica en KEV) y nginx (CVE media con solo un PoC de GitHub).
        apache = vulnerabilidades.cruzar_servicio(self.con, nmap(CPE_HTTPD),{"CVE-2026-0001"}, {}, False, github)
        nginx = vulnerabilidades.cruzar_servicio(self.con, nmap("cpe:/a:f5:nginx:1.0"),{"CVE-2026-0001"}, {}, False, github)
        self.assertEqual(apache["estado"], "ok")
        self.assertEqual(apache["vulns"][0]["cve"], "CVE-2026-0001")
        self.assertEqual(apache["vulns"][0]["exploit_nivel"], "confirmado")
        self.assertEqual(apache["vulns"][0]["severidad"], "CRITICAL")
        self.assertEqual(nginx["vulns"][0]["exploit_nivel"], "sin_verificar")
        self.assertEqual(nginx["vulns"][0]["enlaces_exploit"], ["https://github.com/x/poc"])
        self.assertLess(vulnerabilidades.orden(apache["vulns"]), vulnerabilidades.orden(nginx["vulns"]))

    def test_forma_de_cada_vulnerabilidad(self):
        cve.guardar_cves(self.con, [item("CVE-2026-0001", [regla("http_server")])])
        res = vulnerabilidades.cruzar_servicio(self.con, [("deteccion", CPE_SIN_VERSION)], set(),
                                               {"CVE-2026-0001": ["https://edb/1"]}, False, sin_github)
        self.assertEqual(res["vulns"], [{
            "cve": "CVE-2026-0001", "severidad": "HIGH", "enlace": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
            "exploit_nivel": "confirmado", "enlaces_exploit": ["https://edb/1"],
            "origen_cpe": CPE_SIN_VERSION, "fuente_cpe": "deteccion", "sin_version": True}])

    def test_sin_base_local_y_sin_internet_es_sin_datos_no_ok_vacio(self):
        with mock.patch.object(cve, "consultar_online") as online:
            res = vulnerabilidades.cruzar_servicio(self.con, nmap(CPE_HTTPD),set(), {}, True, sin_github)
        self.assertEqual(res, {"estado": "sin_datos", "vulns": []})
        online.assert_not_called()  # con el interruptor no se llama ni a la consulta

    def test_sin_base_local_y_consulta_fallida_es_sin_datos(self):
        with mock.patch.object(cve, "consultar_online", return_value=None):
            res = vulnerabilidades.cruzar_servicio(self.con, nmap(CPE_HTTPD),set(), {}, False, sin_github)
        self.assertEqual(res["estado"], "sin_datos")

    def test_consultado_con_cero_cve_es_ok_vacio(self):
        with mock.patch.object(cve, "consultar_online", return_value=[]):
            res = vulnerabilidades.cruzar_servicio(self.con, nmap(CPE_HTTPD),set(), {}, False, sin_github)
        self.assertEqual(res, {"estado": "ok", "vulns": []})

    def test_base_local_completa_sin_cve_del_producto_es_ok_aunque_falle_la_consulta(self):
        set_config(self.con, "nvd_actualizada", "2026-10-20T00:00:00+00:00")
        with mock.patch.object(cve, "consultar_online", return_value=None):
            res = vulnerabilidades.cruzar_servicio(self.con, nmap(CPE_HTTPD),set(), {}, False, sin_github)
        self.assertEqual(res, {"estado": "ok", "vulns": []})
        res = vulnerabilidades.cruzar_servicio(self.con, nmap(CPE_HTTPD),set(), {}, True, sin_github)
        self.assertEqual(res, {"estado": "ok", "vulns": []})

    def test_base_completa_que_conoce_el_producto_no_sale_si_la_version_no_esta_afectada(self):
        cve.guardar_cves(self.con, [item("CVE-2026-0001", [regla("http_server", v_fin="2.4.50")])])
        online = mock.Mock(return_value=None)
        with mock.patch.object(cve, "consultar_online", online):
            # Base incompleta: conocer el producto no basta, se pregunta.
            vulnerabilidades.cruzar_servicio(self.con, nmap("cpe:/a:apache:http_server:2.4.60"),set(), {}, False, sin_github)
            online.assert_called_once()
            online.reset_mock()
            set_config(self.con, "nvd_actualizada", "2026-10-20T00:00:00+00:00")
            res = vulnerabilidades.cruzar_servicio(self.con, nmap("cpe:/a:apache:http_server:2.4.60"),set(), {}, False, sin_github)
        self.assertEqual(res, {"estado": "ok", "vulns": []})
        online.assert_not_called()

    def test_base_completa_y_vendor_de_nmap_distinto_del_de_la_nvd_no_sale_limpio(self):
        # nginx: Nmap da igor_sysoev; la NVD, f5. vsftpd: Nmap da vsftpd; la NVD, beasts.
        cve.guardar_cves(self.con, [item("CVE-2026-0001", [regla("nginx", vendor="f5", v_fin="1.25.0")]),
                                    item("CVE-2026-0002", [regla("vsftpd", vendor="beasts", v_fin="3.0.0")])])
        set_config(self.con, "nvd_actualizada", "2026-10-20T00:00:00+00:00")
        for cpe, esperada in (("cpe:/a:igor_sysoev:nginx:1.20.0", "CVE-2026-0001"), ("cpe:/a:vsftpd:vsftpd:2.3.4", "CVE-2026-0002")):
            with self.subTest(cpe=cpe):
                res = vulnerabilidades.cruzar_servicio(self.con, nmap(cpe), set(), {}, True, sin_github)
                self.assertEqual([v["cve"] for v in res["vulns"]], [esperada])

    def test_un_cpe_se_consulta_una_sola_vez_por_cruce(self):
        online = mock.Mock(return_value=[item("CVE-2026-0001", [regla("http_server")])])
        memo = vulnerabilidades.Memo()
        with mock.patch.object(cve, "consultar_online", online):
            for _ in range(2):  # dos servicios del mismo cruce con el mismo CPE
                res = vulnerabilidades.cruzar_servicio(self.con, nmap(CPE_HTTPD),set(), {}, False, sin_github, memo=memo)
                self.assertEqual([v["cve"] for v in res["vulns"]], ["CVE-2026-0001"])
        online.assert_called_once()

    def test_sin_cpes_no_hay_nada_que_cruzar(self):
        res = vulnerabilidades.cruzar_servicio(self.con, [], set(), {}, False, sin_github)
        self.assertEqual(res, {"estado": "sin_datos", "vulns": []})

    def test_online_solo_si_local_vacio_para_ese_cpe(self):
        cve.guardar_cves(self.con, [item("CVE-2026-0001", [regla("http_server")])])
        online = mock.Mock(return_value=[item("CVE-2026-0009", [regla("openssh", vendor="openbsd")], "critical", 9.0)])
        with mock.patch.object(cve, "consultar_online", online):
            res = vulnerabilidades.cruzar_servicio(
                self.con, nmap(CPE_HTTPD, "cpe:/a:openbsd:openssh:7.4"),set(), {}, False, sin_github)
        online.assert_called_once_with("cpe:/a:openbsd:openssh:7.4", False)
        self.assertEqual({v["cve"]: v["origen_cpe"] for v in res["vulns"]},
                         {"CVE-2026-0001": CPE_HTTPD, "CVE-2026-0009": "cpe:/a:openbsd:openssh:7.4"})
        online_vuln = next(v for v in res["vulns"] if v["cve"] == "CVE-2026-0009")
        self.assertEqual(online_vuln["severidad"], "CRITICAL")
        self.assertFalse(online_vuln["sin_version"])

    def test_online_con_cpe_sin_version_marca_sin_version(self):
        online = mock.Mock(return_value=[item("CVE-2026-0009", [regla("openssh", vendor="openbsd")])])
        with mock.patch.object(cve, "consultar_online", online):
            res = vulnerabilidades.cruzar_servicio(self.con, nmap("cpe:/a:openbsd:openssh"),set(), {}, False, sin_github)
        self.assertTrue(res["vulns"][0]["sin_version"])

    def test_github_solo_para_no_confirmadas_y_con_internet(self):
        cve.guardar_cves(self.con, [item("CVE-2026-0001", [regla("http_server")]),
                                    item("CVE-2026-0002", [regla("http_server")])])
        github = mock.Mock(return_value=["https://github.com/x/poc"])
        vulnerabilidades.cruzar_servicio(self.con, nmap(CPE_HTTPD),{"CVE-2026-0001"}, {}, False, github)
        github.assert_called_once_with("CVE-2026-0002", False)
        github.reset_mock()
        res = vulnerabilidades.cruzar_servicio(self.con, nmap(CPE_HTTPD),set(), {}, True, github)
        github.assert_not_called()
        self.assertEqual({v["exploit_nivel"] for v in res["vulns"]}, {"ninguno"})

    def test_cve_repetida_en_dos_cpes_sale_una_vez(self):
        cve.guardar_cves(self.con, [item("CVE-2026-0001", [regla("http_server")])])
        res = vulnerabilidades.cruzar_servicio(self.con, nmap(CPE_HTTPD, CPE_SIN_VERSION),set(), {}, False, sin_github)
        self.assertEqual([v["cve"] for v in res["vulns"]], ["CVE-2026-0001"])

    def test_cpe_sin_version_se_queda_con_las_de_mayor_cvss_y_no_busca_en_github(self):
        # Nmap pone cpe:/o:linux:linux_kernel en cada servicio de un Linux: sin versión casan todas las del producto.
        cve.guardar_cves(self.con, [item(f"CVE-2026-{n:04d}", [regla("http_server")], cvss=n / 10) for n in range(1, 51)])
        github = mock.Mock(return_value=["https://github.com/x/poc"])
        res = vulnerabilidades.cruzar_servicio(self.con, nmap(CPE_SIN_VERSION), set(), {}, False, github)
        self.assertEqual({v["cve"] for v in res["vulns"]}, {f"CVE-2026-{n:04d}" for n in range(31, 51)})
        # Lo mismo si las da la consulta en línea.
        online = [item(f"CVE-2026-{n:04d}", [regla("openssh", vendor="openbsd")], cvss=n / 10) for n in range(1, 31)]
        with mock.patch.object(cve, "consultar_online", return_value=online):
            res = vulnerabilidades.cruzar_servicio(self.con, nmap("cpe:/a:openbsd:openssh"),set(), {}, False, github)
        self.assertEqual({v["cve"] for v in res["vulns"]}, {f"CVE-2026-{n:04d}" for n in range(11, 31)})
        github.assert_not_called()
        self.assertEqual(vulnerabilidades.TOPE_SIN_VERSION, 20)

    def test_si_github_no_responde_no_se_le_vuelve_a_preguntar_en_el_cruce(self):
        cve.guardar_cves(self.con, [item("CVE-2026-0001", [regla("http_server")]), item("CVE-2026-0002", [regla("http_server")])])
        github = mock.Mock(return_value=None)  # 403/429 o fallo de red: no se pudo consultar
        res = vulnerabilidades.cruzar_servicio(self.con, nmap(CPE_HTTPD),set(), {}, False, github)
        self.assertEqual(github.call_count, 1)
        self.assertEqual({v["exploit_nivel"] for v in res["vulns"]}, {"ninguno"})

    def test_una_cve_se_busca_en_github_una_sola_vez_por_cruce(self):
        cve.guardar_cves(self.con, [item("CVE-2026-0001", [regla("http_server"), regla("nginx", vendor="f5")])])
        github = mock.Mock(return_value=["https://github.com/x/poc"])
        memo = vulnerabilidades.Memo()
        for cpe in (CPE_HTTPD, "cpe:/a:f5:nginx:1.0"):  # dos servicios del mismo cruce con la misma CVE
            res = vulnerabilidades.cruzar_servicio(self.con, nmap(cpe), set(), {}, False, github, memo=memo)
            self.assertEqual(res["vulns"][0]["enlaces_exploit"], ["https://github.com/x/poc"])
        github.assert_called_once_with("CVE-2026-0001", False)


class OrdenTests(unittest.TestCase):
    def vuln(self, severidad="HIGH", nivel="ninguno"):
        return {"cve": "CVE-2026-0001", "severidad": severidad, "exploit_nivel": nivel}

    def test_menor_es_mas_prioritario(self):
        confirmado = vulnerabilidades.orden([self.vuln("MEDIUM", "confirmado")])
        critica = vulnerabilidades.orden([self.vuln("CRITICAL")])
        cualquiera = vulnerabilidades.orden([self.vuln("LOW")])
        nada = vulnerabilidades.orden([])
        self.assertLess(confirmado, critica)
        self.assertLess(critica, cualquiera)
        self.assertLess(cualquiera, nada)

    def test_poc_sin_verificar_no_pasa_por_delante_de_una_cve(self):
        poc = vulnerabilidades.orden([self.vuln("LOW", "sin_verificar")])
        self.assertLessEqual(vulnerabilidades.orden([self.vuln("LOW")]), poc)
        self.assertLess(poc, vulnerabilidades.orden([]))

    def test_gana_la_mejor_de_la_lista(self):
        mixto = [self.vuln("LOW"), self.vuln("LOW", "confirmado")]
        self.assertEqual(vulnerabilidades.orden(mixto), vulnerabilidades.orden([self.vuln("LOW", "confirmado")]))

    def test_las_cve_de_un_cpe_sin_version_no_suben_la_prioridad(self):
        # Diseño, punto 12: sin versión no se sabe si la CVE afecta al servicio; se marca y no sube la prioridad.
        kernel = self.vuln("CRITICAL", "confirmado") | {"sin_version": True}
        self.assertEqual(vulnerabilidades.orden([kernel]), vulnerabilidades.orden([]))
        self.assertEqual(vulnerabilidades.orden([kernel, self.vuln("LOW")]), vulnerabilidades.orden([self.vuln("LOW")]))


class CpesDelServicioTests(unittest.TestCase):
    def lectura(self, producto, version, confianza):
        return {"producto": producto, "version": version, "confianza": confianza}

    def test_reune_el_cpe_de_nmap_y_el_de_una_deteccion_de_alta_confianza_marcando_su_origen(self):
        res = vulnerabilidades.cpes_del_servicio(["cpe:/a:openbsd:openssh:9.6"], [self.lectura("OpenSSH", "9.6", 90)])
        self.assertEqual(res, [("nmap", "cpe:/a:openbsd:openssh:9.6"), ("deteccion", "cpe:/a:*:openssh:9.6")])

    def test_el_umbral_de_alta_confianza_es_ochenta(self):
        self.assertEqual(vulnerabilidades.CONFIANZA_ALTA, 80)
        self.assertEqual(vulnerabilidades.cpes_del_servicio([], [self.lectura("nginx", "1.24.0", 80)]),
                         [("deteccion", "cpe:/a:*:nginx:1.24.0")])
        self.assertEqual(vulnerabilidades.cpes_del_servicio([], [self.lectura("nginx", "1.24.0", 79)]), [])

    def test_una_lectura_sin_confianza_no_sirve_para_construir_cpe(self):
        # Las tecnologías de gowitness llegan sin confianza: no son una detección fiable.
        self.assertEqual(vulnerabilidades.cpes_del_servicio([], [self.lectura("nginx", "1.24.0", None)]), [])

    def test_se_queda_con_el_token_limpio_de_la_version(self):
        res = vulnerabilidades.cpes_del_servicio([], [self.lectura("Apache", "2.4.59 (Debian)", 95),
                                                      self.lectura("OpenSSH", "v9.6p1 Ubuntu-3", 95)])
        self.assertEqual([cpe for _, cpe in res], ["cpe:/a:*:apache:2.4.59", "cpe:/a:*:openssh:9.6p1"])

    def test_una_version_sin_numero_sale_sin_version(self):
        res = vulnerabilidades.cpes_del_servicio([], [self.lectura("nginx", "desconocida", 95)])
        self.assertEqual(res, [("deteccion", "cpe:/a:*:nginx:*")])

    def test_un_cpe_repetido_se_queda_con_el_primero(self):
        res = vulnerabilidades.cpes_del_servicio(["cpe:/a:*:nginx:1.24.0"], [self.lectura("nginx", "1.24.0", 99)])
        self.assertEqual(res, [("nmap", "cpe:/a:*:nginx:1.24.0")])

    def test_ignora_cpe_de_nmap_que_no_son_texto(self):
        self.assertEqual(vulnerabilidades.cpes_del_servicio(["", None, "cpe:/a:x:y:1"], []), [("nmap", "cpe:/a:x:y:1")])

    def test_sin_producto_no_hay_cpe(self):
        self.assertEqual(vulnerabilidades.cpes_del_servicio([], [self.lectura("", "1.0", 99)]), [])


class OrdenarServiciosTests(unittest.TestCase):
    """El orden determinista con que se listan los servicios: confirmado, crítica, CVE, PoC, nada."""

    @staticmethod
    def servicio(ip, puerto, estado="ok", *vulns):
        return {"ip": ip, "protocolo": "tcp", "puerto": puerto, "estado": estado, "vulns": list(vulns)}

    @staticmethod
    def vuln(cve_id, severidad="HIGH", nivel="ninguno", cpe="c"):
        return {"cve": cve_id, "severidad": severidad, "exploit_nivel": nivel, "enlaces_exploit": [], "cpe": cpe, "fuente_cpe": "nmap"}

    def test_the_cves_of_a_cpe_without_version_are_marked_go_last_and_do_not_raise_the_priority(self):
        # Lo que vuelve de la base: el cpe guardado dice si traía versión.
        kernel = self.vuln("CVE-2026-0001", "CRITICAL", "confirmado", "cpe:/o:linux:linux_kernel")
        openssh = self.vuln("CVE-2026-0002", "LOW", cpe="cpe:/a:openbsd:openssh:9.6p1")
        solo_kernel, mixto = vulnerabilidades.ordenar_servicios([self.servicio("10.0.0.1", 80, "ok", kernel),
                                                                 self.servicio("10.0.0.1", 22, "ok", kernel, openssh)])[::-1]
        self.assertEqual(solo_kernel["prioridad"], 4)
        self.assertEqual(mixto["prioridad"], 2)
        self.assertEqual([(v["cve"], v["sin_version"]) for v in mixto["vulns"]], [("CVE-2026-0002", False), ("CVE-2026-0001", True)])

    def test_sorts_by_priority_then_numeric_ip_and_port(self):
        servicios = [
            self.servicio("10.0.0.10", 80),
            self.servicio("10.0.0.9", 80, "ok", self.vuln("CVE-2026-0002")),
            self.servicio("10.0.0.2", 443, "ok", self.vuln("CVE-2026-0003", "CRITICAL")),
            self.servicio("10.0.0.20", 22, "ok", self.vuln("CVE-2026-0004", "LOW", "confirmado")),
            self.servicio("10.0.0.2", 22, "ok", self.vuln("CVE-2026-0005")),
        ]
        orden = vulnerabilidades.ordenar_servicios(servicios)
        self.assertEqual([(s["ip"], s["puerto"], s["prioridad"]) for s in orden],
                         [("10.0.0.20", 22, 0), ("10.0.0.2", 443, 1), ("10.0.0.2", 22, 2), ("10.0.0.9", 80, 2), ("10.0.0.10", 80, 4)])

    def test_sorts_the_vulns_of_a_service_exploit_first_then_severity_then_cve(self):
        servicio = self.servicio("10.0.0.1", 22, "ok", self.vuln("CVE-2026-0003", "LOW"), self.vuln("CVE-2026-0002", "CRITICAL"),
                                 self.vuln("CVE-2026-0004", "MEDIUM", "sin_verificar"), self.vuln("CVE-2026-0001", "CRITICAL"),
                                 self.vuln("CVE-2026-0009", "LOW", "confirmado"))
        vulns = vulnerabilidades.ordenar_servicios([servicio])[0]["vulns"]
        self.assertEqual([v["cve"] for v in vulns],
                         ["CVE-2026-0009", "CVE-2026-0004", "CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"])

    def test_adds_the_nvd_link_and_does_not_touch_the_input(self):
        servicio = self.servicio("10.0.0.1", 22, "ok", self.vuln("CVE-2026-0001"))
        orden = vulnerabilidades.ordenar_servicios([servicio])
        self.assertEqual(orden[0]["vulns"][0]["enlace"], "https://nvd.nist.gov/vuln/detail/CVE-2026-0001")
        self.assertNotIn("prioridad", servicio)
        self.assertNotIn("enlace", servicio["vulns"][0])

    def test_no_data_does_not_get_a_priority_and_comes_after_the_clean_ones_only_by_address(self):
        orden = vulnerabilidades.ordenar_servicios([self.servicio("10.0.0.2", 80, "sin_datos"), self.servicio("10.0.0.1", 80)])
        self.assertEqual([(s["ip"], s["estado"], s["prioridad"]) for s in orden],
                         [("10.0.0.1", "ok", 4), ("10.0.0.2", "sin_datos", None)])

    def test_the_export_state_tells_every_case_apart(self):
        estado = vulnerabilidades.estado_servicio
        self.assertEqual(estado(None), "")
        self.assertEqual(estado(self.servicio("10.0.0.1", 80, "sin_datos")), "sin_datos")
        self.assertEqual(estado(self.servicio("10.0.0.1", 80)), "sin_vulnerabilidades")
        self.assertEqual(estado(self.servicio("10.0.0.1", 80, "ok", self.vuln("CVE-2026-0001"))), "con_vulnerabilidades")
