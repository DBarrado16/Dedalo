"""Prueba real y reproducible: solo usa servidores en 127.0.0.0/8.

Ejecutar desde la raíz: python -m tests.integration_local
Conserva los resultados en pruebas_locales/ para poder abrir el visor.
"""

from __future__ import annotations

from datetime import datetime
import http.server
import json
import os
import re
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request

from dedalo import gowitness, report, views

ROOT = Path(__file__).resolve().parent.parent


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.server.name == "HTTP" and self.path == "/":
            self.send_response(302)
            self.send_header("Location", "/portal")
            self.end_headers()
            return
        page = f"""<!doctype html><html lang="es"><meta charset="utf-8">
<title>Prueba local {self.server.name}</title>
<style>body{{font:20px system-ui;background:#101827;color:#dce8ff;margin:70px}}
main{{max-width:850px;padding:44px;border:1px solid #30425f;border-radius:20px}}
small{{color:#66d9ba}}h1{{font-size:46px}}code{{color:#9bbfff}}</style>
<main><small>DEDALO / PRUEBA LOCAL</small><h1>Captura {self.server.name} correcta</h1>
<p>Esta página permite comprobar la captura y su asociación con la IP.</p>
<p><code>{self.server.server_address[0]}</code></p>
<p>{'Certificado autofirmado de pruebas.' if self.server.name == 'HTTPS' else 'Redirección HTTP resuelta hasta /portal.'}</p></main></html>""".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def log_message(self, *args):
        pass


def server(host, preferred, name):
    try:
        instance = http.server.ThreadingHTTPServer((host, preferred), Handler)
    except OSError:
        instance = http.server.ThreadingHTTPServer((host, 0), Handler)
    instance.name = name
    instance.daemon_threads = True
    return instance


def run(arguments, log, expected=0):
    result = subprocess.run([sys.executable, "-m", "dedalo", *arguments],
                            cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=180, env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    log.write_text(result.stdout + result.stderr, encoding="utf-8")
    print(result.stdout, flush=True)
    if result.returncode != expected:
        raise AssertionError(f"Esperaba código {expected}, recibido {result.returncode}: {result.stderr}; log: {log}")
    return result.stdout


def main():
    destination = ROOT / "pruebas_locales" / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    destination.mkdir(parents=True)
    http = server("127.0.0.1", 80, "HTTP")
    https = server("127.0.1.1", 443, "HTTPS")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ROOT / "tests/fixtures/local-cert.pem", ROOT / "tests/fixtures/local-key.pem")
    https.socket = context.wrap_socket(https.socket, server_side=True)
    refused = socket.socket()
    refused.bind(("127.0.0.1", 0))
    closed_port = refused.getsockname()[1]
    # Esquema equivocado: un HTTPS que se pide como http y un HTTP que se pide como https.
    https_as_http = server("127.0.2.1", 0, "HTTPS")
    https_as_http.socket = context.wrap_socket(https_as_http.socket, server_side=True)
    http_as_https = server("127.0.3.1", 0, "HTTP")
    servers = (http, https, https_as_http, http_as_https)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for thread in threads:
        thread.start()

    http_port, https_port = http.server_address[1], https.server_address[1]
    wrong_http_port, wrong_https_port = https_as_http.server_address[1], http_as_https.server_address[1]
    nmap = destination / "local.xml"
    nmap.write_text(f"""<nmaprun>
<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="{http_port}"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="{closed_port}"><state state="open"/><service name="http"/></port>
</ports></host>
<host><status state="up"/><address addr="127.0.1.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="{https_port}"><state state="open"/><service name="http" tunnel="ssl"/></port>
</ports></host>
<host><status state="up"/><address addr="127.0.2.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="{wrong_http_port}"><state state="open"/><service name="http"/></port>
</ports></host>
<host><status state="up"/><address addr="127.0.3.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="{wrong_https_port}"><state state="open"/><service name="http" tunnel="ssl"/></port>
</ports></host></nmaprun>""", encoding="utf-8")
    ranges = destination / "rangos.txt"
    ranges.write_text("127.0.0.0/8\n")
    output = destination / "resultado"
    try:
        browser = gowitness.find_chrome(None)
        if not browser:
            raise RuntimeError("Esta prueba necesita Chrome/Chromium/Edge instalado para evitar descargas.")
        args = ["capturar", str(nmap), "-r", str(ranges), "-o", str(output),
                "--puertos", f"{http_port}=http,{https_port}=https,{closed_port}=http,"
                             f"{wrong_http_port}=http,{wrong_https_port}=https",
                "--chrome", browser, "--timeout", "12", "--delay", "1", "--hilos", "2", "--formato", "png"]
        run(args + ["--simular"], destination / "simulacion.log")
        assert not output.exists()
        run(args, destination / "captura.log", expected=3)
        manifest = report.load_manifest(output)
        assert len(manifest["grupos"]) == 4
        assert sum(g["capturas"] for g in manifest["grupos"]) == 4
        assert sum(g["sin_captura"] for g in manifest["grupos"]) == 1
        rows = [row for g in manifest["grupos"] for row in g["resultados"]]
        successes = [row for row in rows if row["captura"]]
        assert {row["titulo"] for row in successes} == {"Prueba local HTTP", "Prueba local HTTPS"}
        # Esquema equivocado: la fila conserva la URL del objetivo y url_final lleva el otro esquema.
        wrong = {row["ip"]: row for row in rows if row["ip"] in ("127.0.2.1", "127.0.3.1")}
        for ip, target_scheme, real_scheme in (("127.0.2.1", "http", "https"), ("127.0.3.1", "https", "http")):
            row = wrong[ip]
            assert row["estado"] == "capturada", row
            assert row["url"].startswith(target_scheme + "://"), row
            assert row["url_final"].startswith(real_scheme + "://"), row
            group = next(g for g in manifest["grupos"] if g["subred"] == f"{ip.rsplit('.', 1)[0]}.0/24")
            assert (output / group["carpeta"] / gowitness.SCHEME_URLS).is_file()
            assert (output / group["carpeta"] / gowitness.SCHEME_LOG).is_file()
        assert next(row for row in successes if row["ip"] == "127.0.0.1")["url_final"].endswith("/portal")
        for row in successes:
            assert (output / row["captura"]).read_bytes().startswith(b"\x89PNG")
        for group in manifest["grupos"]:
            actual = gowitness.read_results(output / group["carpeta"] / gowitness.DB_NAME)
            requested = {gowitness.normalize_url(t["url"]) for t in group["objetivos"]}
            # La pasada de esquema solo añade el otro esquema de las URL que ella misma lista.
            scheme_file = output / group["carpeta"] / gowitness.SCHEME_URLS
            scheme_urls = ({gowitness.normalize_url(u) for u in scheme_file.read_text(encoding="utf-8").split()}
                           if scheme_file.is_file() else set())
            assert scheme_urls <= {gowitness.normalize_url(gowitness.other_scheme(t["url"]))
                                   for t in group["objetivos"]}
            assert set(actual).issubset(requested | scheme_urls), "gowitness añadió URLs no solicitadas"
            log_text = (output / group["carpeta"] / "gowitness.log").read_text(encoding="utf-8")
            attempted = {gowitness.normalize_url(u) for u in re.findall(r'target=(https?://[^\s"]+)', log_text)}
            assert attempted == requested, f"URLs ejecutadas distintas de las solicitadas: {attempted ^ requested}"
        run(args, destination / "repeticion.log", expected=1)

        run(["ver", str(output), "--listar"], destination / "listar.log")
        run(["ver", str(output), "127.0.0.0/24", "--preparar"], destination / "subred.log")
        run(["ver", str(output), "127.0.0.0/8", "--preparar"], destination / "rango.log")
        combined_output = run(["ver", str(output), "--preparar"], destination / "todo.log")
        view = Path(next(line.removeprefix("Vista: ") for line in combined_output.splitlines() if line.startswith("Vista: ")))
        assert len(gowitness.read_results(view / gowitness.DB_NAME)) == 4

        with socket.socket() as free_port:
            free_port.bind(("127.0.0.1", 0))
            viewer_port = free_port.getsockname()[1]
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        with (destination / "visor.log").open("w", encoding="utf-8") as log:
            process = subprocess.Popen([
                gowitness.find_gowitness(None), "report", "server",
                "--db-uri", "sqlite://gowitness.sqlite3", "--screenshot-path", "capturas",
                "--host", "127.0.0.1", "--port", str(viewer_port),
            ], cwd=view, stdout=log, stderr=subprocess.STDOUT, creationflags=flags)
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                for attempt in range(50):
                    if process.poll() is not None:
                        raise AssertionError("El visor terminó antes de arrancar")
                    try:
                        with opener.open(f"http://127.0.0.1:{viewer_port}/", timeout=1) as response:
                            page = response.read().decode()
                            assert response.status == 200 and "<html" in page.lower()
                        break
                    except (OSError, urllib.error.URLError):
                        time.sleep(0.2)
                else:
                    raise AssertionError("El visor no respondió")
            finally:
                process.terminate()
                process.wait(timeout=10)
        print(f"OK: HTTP + HTTPS + redirección + fallo + índices + vistas + servidor web.\nResultados: {output}", flush=True)
        (destination / "validacion.json").write_text(json.dumps({
            "resultado": "OK", "http_puerto": http_port, "https_puerto": https_port,
            "capturas": 4, "sin_captura": 1, "vista": str(view), "salida": str(output),
        }, indent=2), encoding="utf-8")
    finally:
        for instance in servers:
            instance.shutdown()
            instance.server_close()
        for thread in threads:
            thread.join(timeout=5)
        refused.close()


if __name__ == "__main__":
    main()
