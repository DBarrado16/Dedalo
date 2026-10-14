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
