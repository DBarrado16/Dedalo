"""Prueba real del portal. --manual deja las webs locales listas para probar la UI."""

import argparse
import csv
from datetime import datetime
import io
import json
from pathlib import Path
import re
import socket
import ssl
import threading
import time
import urllib.request

from .integration_local import ROOT, server
from dedalo import gowitness


def main():
    options = argparse.ArgumentParser()
    options.add_argument("--portal", default="http://127.0.0.1:8787")
    options.add_argument("--manual", action="store_true")
    args = options.parse_args()
    directory = ROOT / "pruebas_locales" / ("web-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    directory.mkdir(parents=True)
    http, https = server("127.0.0.1", 80, "HTTP"), server("127.0.1.1", 443, "HTTPS")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ROOT / "tests/fixtures/local-cert.pem", ROOT / "tests/fixtures/local-key.pem")
    https.socket = context.wrap_socket(https.socket, server_side=True)
    refused = socket.socket()
    refused.bind(("127.0.0.1", 0))
    closed_port = refused.getsockname()[1]
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (http, https)]
    for thread in threads:
        thread.start()
    http_port, https_port = http.server_address[1], https.server_address[1]
    content = f"""<nmaprun>
<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="{http_port}"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="{closed_port}"><state state="open"/><service name="http"/></port>
</ports></host>
<host><status state="up"/><address addr="127.0.1.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="{https_port}"><state state="open"/><service name="http" tunnel="ssl"/></port>
</ports></host></nmaprun>"""
    (directory / "local.xml").write_text(content, encoding="utf-8")
    (directory / "rangos.txt").write_text("127.0.0.0/17\n")
    ports = f"{http_port}=http,{https_port}=https,{closed_port}=http"
    print(f"Archivos: {directory}\nPuertos extra: {ports}", flush=True)
    try:
        if args.manual:
            print("Webs listas. Carga local.xml y rangos.txt en el portal. Ctrl+C para cerrar.", flush=True)
            while True:
                time.sleep(1)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        token = ""
        def request(route, data=None):
            req = urllib.request.Request(args.portal + route, data=json.dumps(data).encode() if data is not None else None,
                headers={"Content-Type":"application/json", "X-Dedalo-Token":token})
            with opener.open(req, timeout=10) as response:
                raw = response.read()
                return json.loads(raw) if response.headers.get("Content-Type","").startswith("application/json") else raw
        token = request("/api/bootstrap")["token"]
        audit = request("/api/audits", {"nombre":"Validación del portal", "incluir":"127.0.0.0/17"})
        job = request("/api/jobs", {"nombre":"Validación del portal · HTTP y HTTPS",
            "archivos":[{"nombre":"local.xml","contenido":content}], "auditoria":audit["id"],
            "opciones":{"puertos":ports,"timeout":12,"hilos":2,"delay":1,"formato":"png"}})
        assert job["total"] == 3 and job["subredes"] == 2 and job["estado"] == "preparada"
        job_id = job["id"]
        request(f"/api/jobs/{job_id}/start", {})
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            job = request(f"/api/jobs/{job_id}")
            if job["estado"] not in ("en_cola","en_curso","deteniendo"):
                break
            time.sleep(.3)
        assert job["estado"] == "parcial", job
        assert job["capturas"] == 2 and job["sin_captura"] == 1, job
        for group in job["grupos"]:
            for target in group["objetivos"]:
                if target["imagen"]:
                    assert request(target["imagen"]).startswith(b"\x89PNG")
        data = request(f"/api/jobs/{job_id}/download/csv").decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(data)))
        assert len(rows) == 3
        assert sum(r["estado"] == "capturada" for r in rows) == 2
        logs = request(f"/api/jobs/{job_id}/logs")["text"]
        assert "ERR_CONNECTION_REFUSED" in logs
        assert any(j["id"] == job_id for j in request("/api/jobs"))
        manifest = json.loads(request(f"/api/jobs/{job_id}/download/json"))
        assert manifest["estado"] == "parcial"
        (directory / "validacion.json").write_text(json.dumps({"resultado":"OK","job":job_id,"portal":args.portal}, indent=2))
        print(f"OK: carga web, revisión, cola, captura, progreso, imágenes, CSV, JSON y logs.\nPortal: {args.portal}/#{job_id}", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        for instance in (http, https):
            instance.shutdown()
            instance.server_close()
        for thread in threads:
            thread.join(timeout=5)
        refused.close()


if __name__ == "__main__":
    main()
