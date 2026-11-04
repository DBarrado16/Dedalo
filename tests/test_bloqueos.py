"""Lo que el proxy de alcance cortó a cada web, y los mensajes de error de siempre."""

import csv
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from urllib.parse import urlsplit

from dedalo import gowitness, report


def base_sintetica(directory: Path, paginas: dict[str, list[str]]) -> None:
    """Base de gowitness con solo `results` y `network_logs` (columnas de la 3.2.0) y una captura por página."""
    (directory / gowitness.SHOTS_DIR).mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(directory / gowitness.DB_NAME)
    con.execute("CREATE TABLE results (id INTEGER PRIMARY KEY, url TEXT, final_url TEXT, response_code INTEGER, "
                "title TEXT, filename TEXT, failed INTEGER, failed_reason TEXT)")
    con.execute("CREATE TABLE network_logs (id INTEGER PRIMARY KEY, result_id INTEGER, request_type INTEGER, "
                "status_code INTEGER, url TEXT, remote_ip TEXT, mime_type TEXT, time DATETIME, content BLOB, error TEXT)")
    for numero, (url, peticiones) in enumerate(paginas.items(), start=1):
        captura = f"captura-{numero}.png"
        (directory / gowitness.SHOTS_DIR / captura).write_bytes(b"imagen")
        con.execute("INSERT INTO results VALUES (?, ?, ?, 200, 'web', ?, 0, '')", (numero, url, url, captura))
        for peticion in peticiones:
            con.execute("INSERT INTO network_logs (result_id, request_type, status_code, url, error) "
                        "VALUES (?, 0, 0, ?, 'net::ERR_TUNNEL_CONNECTION_FAILED')", (numero, peticion))
    con.commit()
    con.close()


def registro(path: Path, lineas: list[dict], cola: str = "") -> None:
    path.write_text("".join(json.dumps(linea) + "\n" for linea in lineas) + cola, encoding="utf-8")


def corte(destino: str, ip: str | None, puerto: int, motivo: str) -> dict:
    return {"destino": destino, "ip": ip, "puerto": puerto, "motivo": motivo}


def grupo(*urls: str) -> dict:
    objetivos = []
    for url in urls:
        partes = urlsplit(gowitness.explicit_port(url))
        objetivos.append({"ip": partes.hostname, "port": partes.port, "url": url})
    return {"rango": "10.0.0.0/24", "subred": "10.0.0.0/24", "carpeta": "subred", "objetivos": objetivos}


class BloqueosTests(unittest.TestCase):
    def test_corte_se_atribuye_a_la_pagina_que_lo_pidio(self):
        with tempfile.TemporaryDirectory() as temporal:
            raiz = Path(temporal)
            directorio = raiz / "subred"
            directorio.mkdir()
            base_sintetica(directorio, {
                "http://10.0.0.1:80/": ["http://10.0.0.1:80/", "https://CDN-Bloqueado.test/a.css"],
                "https://10.0.0.2:8443/": ["https://10.0.0.2:8443/", "http://[2001:DB8::5]:8080/s.js"],
            })
            cdn = corte("cdn-bloqueado.test:443", "203.0.113.9", 443, "fuera_de_alcance")
            ipv6 = corte("[2001:db8::5]:8080", "2001:db8::5", 8080, "excluida")
            registro(directorio / gowitness.PROXY_LOG, [
                cdn,
                {"destino": "10.0.0.7:80", "ip": "10.0.0.7", "puerto": 80, "fallo": "rechazada"},  # no es un corte
                cdn,  # repetido: una vez por página
            ], cola='{"destino": "[2001:db8::5]:80')  # última línea a medias
            registro(directorio / gowitness.RETRY_PROXY_LOG, [ipv6])

            por_pagina, sin_pagina = gowitness.read_blocked(directorio)
            self.assertEqual(por_pagina, {"http://10.0.0.1/": [cdn], "https://10.0.0.2:8443/": [ipv6]})
            self.assertEqual(sin_pagina, [])

            datos = grupo("http://10.0.0.1/", "https://10.0.0.2:8443/", "http://10.0.0.3/")
            report.collect_group(raiz, datos)
            self.assertEqual([fila["bloqueos"] for fila in datos["resultados"]], [[cdn], [ipv6], []])
            self.assertEqual(datos["bloqueos_sin_pagina"], [])

    def test_corte_sin_pagina_va_a_la_subred(self):
        with tempfile.TemporaryDirectory() as temporal:
            raiz = Path(temporal)
            directorio = raiz / "subred"
            directorio.mkdir()
            base_sintetica(directorio, {"http://10.0.0.1:80/": ["http://10.0.0.1:80/"]})
            # La redirección cortada dejó su página sin resultado: nadie la pidió en network_logs.
            redireccion = corte("redir-bloqueado.test:80", "198.51.100.4", 80, "fuera_de_alcance")
            registro(directorio / gowitness.SCHEME_PROXY_LOG, [redireccion, redireccion])

            self.assertEqual(gowitness.read_blocked(directorio), ({}, [redireccion]))
            datos = grupo("http://10.0.0.1/")
            report.collect_group(raiz, datos)
            self.assertEqual(datos["resultados"][0]["bloqueos"], [])
            self.assertEqual(datos["bloqueos_sin_pagina"], [redireccion])

    def test_puerto_cerrado_tras_el_proxy_conserva_el_mensaje_de_hoy(self):
        with tempfile.TemporaryDirectory() as temporal:
            directorio = Path(temporal)
            (directorio / gowitness.LOG_NAME).write_text(
                'ERRO failed to witness target target=https://10.0.0.1:443/ err="page load error net::ERR_TUNNEL_CONNECTION_FAILED"\n'
                'ERRO failed to witness target target=http://10.0.0.2:8080/ err="page load error net::ERR_HTTP_RESPONSE_CODE_FAILURE"\n'
                'ERRO failed to witness target target=http://10.0.0.3:80/ err="page load error net::ERR_TUNNEL_CONNECTION_FAILED"\n'
                'ERRO failed to witness target target=http://10.0.0.4:80/ err="page load error net::ERR_HTTP_RESPONSE_CODE_FAILURE"\n'
                'ERRO failed to witness target target=http://[2001:db8::1]:80/ err="page load error net::ERR_HTTP_RESPONSE_CODE_FAILURE"\n',
                encoding="utf-8")
            registro(directorio / gowitness.PROXY_LOG, [
                {"destino": "10.0.0.1:443", "ip": "10.0.0.1", "puerto": 443, "fallo": "rechazada"},
                {"destino": "10.0.0.2:8080", "ip": "10.0.0.2", "puerto": 8080, "fallo": "sin_respuesta"},
                {"destino": "10.0.0.3:80", "ip": "10.0.0.3", "puerto": 80, "fallo": "error"},
                corte("10.0.0.4:80", "10.0.0.4", 80, "excluida"),  # un corte no es un fallo de conexión
                {"destino": "[2001:db8::1]:80", "ip": "2001:db8::1", "puerto": 80, "fallo": "rechazada"},
            ])

            self.assertEqual(gowitness.read_failures(directorio), {
                "10.0.0.1:443": "rechazada", "10.0.0.2:8080": "sin_respuesta",
                "10.0.0.3:80": "error", "[2001:db8::1]:80": "rechazada"})
            errores = gowitness.read_errors(directorio)
            self.assertEqual(errores["https://10.0.0.1/"], "page load error net::ERR_CONNECTION_REFUSED")
            self.assertEqual(errores["http://10.0.0.2:8080/"], "page load error net::ERR_CONNECTION_TIMED_OUT")
            self.assertEqual(errores["http://10.0.0.3/"], "page load error net::ERR_TUNNEL_CONNECTION_FAILED")
            self.assertEqual(errores["http://10.0.0.4/"], "page load error net::ERR_HTTP_RESPONSE_CODE_FAILURE")
            self.assertEqual(errores["http://[2001:db8::1]/"], "page load error net::ERR_CONNECTION_REFUSED")

    def test_conexion_denegada_o_inalcanzable_tras_el_proxy_da_el_mensaje_de_hoy(self):
        with tempfile.TemporaryDirectory() as temporal:
            directorio = Path(temporal)
            (directorio / gowitness.LOG_NAME).write_text(
                'ERRO failed to witness target target=http://10.0.0.1:80/ err="page load error net::ERR_TUNNEL_CONNECTION_FAILED"\n'
                'ERRO failed to witness target target=https://10.0.0.2:443/ err="page load error net::ERR_HTTP_RESPONSE_CODE_FAILURE"\n',
                encoding="utf-8")
            registro(directorio / gowitness.PROXY_LOG, [
                {"destino": "10.0.0.1:80", "ip": "10.0.0.1", "puerto": 80, "fallo": "denegada"},
                {"destino": "10.0.0.2:443", "ip": "10.0.0.2", "puerto": 443, "fallo": "inalcanzable"},
            ])
            errores = gowitness.read_errors(directorio)
            # Sin proxy, Chrome daba ERR_NETWORK_ACCESS_DENIED, con su aviso de la VPN.
            self.assertEqual(errores["http://10.0.0.1/"],
                             "Acceso a la red denegado (ERR_NETWORK_ACCESS_DENIED). "
                             "Comprueba que el portal se haya iniciado con acceso a la red/VPN.")
            self.assertEqual(errores["https://10.0.0.2/"], "page load error net::ERR_ADDRESS_UNREACHABLE")

    def test_csv_lleva_lo_cortado(self):
        self.assertEqual(report.COLUMNS[-1], "cortado_fuera_alcance")
        manifiesto = {"grupos": [
            {"rango": "r", "subred": "s", "resultados": [
                {"rango": "r", "subred": "s", "ip": "10.0.0.1", "puerto": 80, "url": "http://10.0.0.1/",
                 "estado": "capturada", "bloqueos": [corte("10.20.0.5:443", "10.20.0.5", 443, "excluida"),
                                                     corte("cdn.test:443", "203.0.113.9", 443, "fuera_de_alcance")]},
                {"rango": "r", "subred": "s", "ip": "10.0.0.2", "puerto": 80, "url": "http://10.0.0.2/",
                 "estado": "capturada", "bloqueos": []},
                # Manifiesto de antes del proxy: la fila no trae la lista.
                {"rango": "r", "subred": "s", "ip": "10.0.0.3", "puerto": 80, "url": "http://10.0.0.3/",
                 "estado": "sin_captura"},
            ]},
            {"rango": "r", "subred": "t", "objetivos": [{"ip": "10.0.1.1", "port": 80, "url": "http://10.0.1.1/"}]},
        ]}
        filas = list(csv.DictReader(io.StringIO(report.index_bytes(manifiesto).decode("utf-8-sig"))))
        self.assertEqual([fila["cortado_fuera_alcance"] for fila in filas],
                         ["10.20.0.5:443 (excluida); cdn.test:443 (fuera_de_alcance)", "", "", ""])
        # Escribir el índice no toca las listas del manifiesto.
        self.assertEqual(len(manifiesto["grupos"][0]["resultados"][0]["bloqueos"]), 2)

    def test_sin_ficheros_del_proxy_no_cambia_nada(self):
        with tempfile.TemporaryDirectory() as temporal:
            raiz = Path(temporal)
            directorio = raiz / "subred"
            directorio.mkdir()
            base_sintetica(directorio, {"http://10.0.0.1:80/": ["http://10.0.0.1:80/", "https://cdn.test/a.css"]})
            mensaje = "page load error net::ERR_TUNNEL_CONNECTION_FAILED"
            (directorio / gowitness.LOG_NAME).write_text(
                f'ERRO failed to witness target target=http://10.0.0.2:80/ err="{mensaje}"\n', encoding="utf-8")

            self.assertEqual(gowitness.read_blocked(directorio), ({}, []))
            self.assertEqual(gowitness.read_failures(directorio), {})
            self.assertEqual(gowitness.read_errors(directorio), {"http://10.0.0.2/": mensaje})
            datos = grupo("http://10.0.0.1/", "http://10.0.0.2/")
            report.collect_group(raiz, datos)
            self.assertEqual([fila["bloqueos"] for fila in datos["resultados"]], [[], []])
            self.assertEqual(datos["resultados"][1]["error"], mensaje)
            self.assertEqual(datos["bloqueos_sin_pagina"], [])

        # Base de una gowitness sin network_logs y con registro del proxy: el corte queda en la subred.
        with tempfile.TemporaryDirectory() as temporal:
            directorio = Path(temporal)
            con = sqlite3.connect(directorio / gowitness.DB_NAME)
            con.execute("CREATE TABLE results (id INTEGER PRIMARY KEY, url TEXT, failed INTEGER)")
            con.commit()
            con.close()
            cdn = corte("cdn.test:443", "203.0.113.9", 443, "fuera_de_alcance")
            registro(directorio / gowitness.PROXY_LOG, [cdn])
            self.assertEqual(gowitness.read_blocked(directorio), ({}, [cdn]))


if __name__ == "__main__":
    unittest.main()
