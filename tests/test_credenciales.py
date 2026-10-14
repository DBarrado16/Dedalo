import unittest

from dedalo import credenciales


def servicio(puerto, nombre, producto="", version="", tunel="", titulo=""):
    scripts = [{"id": "http-title", "output": titulo}] if titulo else []
    return {"puerto": puerto, "protocolo": "tcp", "servicio": nombre, "tunel": tunel,
            "producto": producto, "version": version, "detalle": "", "cpe": [], "scripts": scripts}


CATALOGO = [
    {"producto": "Panel de administración", "version": "", "servicio": "http-form", "usuario": "admin", "clave": "admin",
     "receta": {"ruta": "/login", "campo_usuario": "usuario", "campo_clave": "clave"}},
    {"producto": "lighttpd", "version": "1.*", "servicio": "http-basic", "usuario": "admin", "clave": "admin", "receta": None},
    {"producto": "vsftpd", "version": "", "servicio": "ftp", "usuario": "ftp", "clave": "ftp", "receta": None},
]


class MatchTests(unittest.TestCase):
    def test_a_web_port_takes_basic_and_form_an_ftp_port_takes_ftp(self):
        self.assertEqual(credenciales.tipos_de(servicio(8443, "https", tunel="ssl")), {"http-basic", "http-form"})
        self.assertEqual(credenciales.tipos_de(servicio(80, "http")), {"http-basic", "http-form"})
        self.assertEqual(credenciales.tipos_de(servicio(21, "ftp")), {"ftp"})
        self.assertEqual(credenciales.tipos_de(servicio(22, "ssh")), set())

    def test_https_is_detected_by_tunnel_name_or_port(self):
        self.assertTrue(credenciales.es_https(servicio(8443, "http", tunel="ssl")))
        self.assertTrue(credenciales.es_https(servicio(443, "http")))
        self.assertFalse(credenciales.es_https(servicio(80, "http")))

    def test_only_matching_products_and_versions_become_targets(self):
        activo = {"ip": "10.30.1.21", "servicios": [
            servicio(8443, "https", producto="lighttpd", version="1.4.69", tunel="ssl", titulo="Panel de administración"),
            servicio(21, "ftp", producto="vsftpd", version="3.0.5"),
            servicio(3389, "ms-wbt-server"),  # RDP: ninguna
        ]}
        objetivos = credenciales.objetivos(activo, CATALOGO)
        servicios = sorted({(o["puerto"], o["servicio"]) for o in objetivos})
        # El 8443 casa con el panel (form, por el título) y con lighttpd (basic, por el producto y versión 1.*); el 21 con vsftpd.
        self.assertEqual(servicios, [(21, "ftp"), (8443, "http-basic"), (8443, "http-form")])
        self.assertTrue(all(o["https"] for o in objetivos if o["puerto"] == 8443))

    def test_a_version_that_does_not_match_is_left_out(self):
        activo = {"ip": "x", "servicios": [servicio(80, "http", producto="lighttpd", version="2.0.0")]}
        self.assertEqual(credenciales.objetivos(activo, CATALOGO), [])  # lighttpd pide 1.*


class LoopTests(unittest.TestCase):
    def activo(self, ip="10.30.1.21"):
        return {"ip": ip, "servicios": [servicio(8443, "https", producto="lighttpd", version="1.4", tunel="ssl",
                                                  titulo="Panel de administración"), servicio(21, "ftp", producto="vsftpd")]}

    def test_records_entry_failure_and_counts_progress(self):
        vistos = []
        def probar(ip, objetivo):
            return objetivo["clave"] == "admin" and objetivo["servicio"] == "http-basic"
        avances = []
        filas = credenciales.probar_activos([self.activo()], CATALOGO, probar,
                                            avance=lambda h, t: avances.append((h, t)))
        por_servicio = {(f["puerto"], f["servicio"]): f["estado"] for f in filas}
        self.assertEqual(por_servicio[(8443, "http-basic")], "entrada")
        self.assertEqual(por_servicio[(8443, "http-form")], "fallo")
        self.assertEqual(por_servicio[(21, "ftp")], "fallo")
        entrada = next(f for f in filas if f["estado"] == "entrada")
        self.assertEqual((entrada["usuario"], entrada["clave"]), ("admin", "admin"))
        self.assertEqual(avances[0], (0, 3))
        self.assertEqual(avances[-1], (3, 3))

    def test_a_prober_error_is_recorded_without_stopping_the_run(self):
        def probar(ip, objetivo):
            if objetivo["servicio"] == "ftp":
                raise OSError("sin respuesta")
            return False
        filas = credenciales.probar_activos([self.activo()], CATALOGO, probar)
        ftp = next(f for f in filas if f["servicio"] == "ftp")
        self.assertEqual(ftp["estado"], "error")
        self.assertEqual(len(filas), 3)  # los otros servicios se probaron igual

    def test_stops_a_service_after_too_many_refusals(self):
        intentos = []
        def probar(ip, objetivo):
            intentos.append(objetivo["clave"]); return False
        entradas = [{"producto": "lighttpd", "version": "", "servicio": "http-basic", "usuario": "a", "clave": c, "receta": None}
                    for c in ("1", "2", "3", "4", "5")]
        credenciales.probar_activos([{"ip": "x", "servicios": [servicio(80, "http", producto="lighttpd")]}],
                                    entradas, probar, intentos=2)
        self.assertEqual(len(intentos), 2)  # se abandona tras 2 rechazos, no prueba las 5

    def test_parar_before_a_service_raises_interrumpido(self):
        with self.assertRaises(credenciales.Interrumpido):
            credenciales.probar_activos([self.activo()], CATALOGO, lambda ip, o: False, parar=lambda: True)
