"""Cuánto tarda el portal en arrancar, en responder al sondeo del historial y en abrir una ejecución.

Crea un historial sintético en una carpeta temporal, sin red ni navegador: ejecuciones
de un /24 con un servicio web por host, la mitad ya lanzadas, y unas pocas grandes de
un /20 con dos puertos. Con los mismos datos se compara el antes y el después de un cambio.

Uso, desde la carpeta del repo:
    python -m tests.medir_portal [EJECUCIONES] [GRANDES]
Por defecto, 200 ejecuciones y 4 grandes. Generar el historial tarda unos minutos.
"""
import ipaddress
import statistics
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path.cwd()))
try:
    from dedalo import auditoria
    from dedalo.web import PortalStore
except ImportError:
    sys.exit("Ejecútalo desde la carpeta del repo de Dédalo.")


def nmap(network, ports):
    services = "".join(f'<port protocol="tcp" portid="{port}"><state state="open"/><service name="http"/></port>'
                       for port in ports)
    return "<nmaprun>" + "".join(f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>'
                                 f"<ports>{services}</ports></host>"
                                 for ip in ipaddress.ip_network(network).hosts()) + "</nmaprun>"


def seconds(action, repeat=1):
    times = []
    for _ in range(repeat):
        start = time.perf_counter()
        action()
        times.append(time.perf_counter() - start)
    return statistics.median(times)


def populate(store, runs, large):
    """Las ejecuciones impares quedan lanzadas y terminadas, con sus URL planificadas en la base."""
    audit = store.create_audit({"nombre": "Medición", "incluir": "10.0.0.0/8"})["id"]
    networks = [(f"10.{i // 256}.{i % 256}.0/24", [80]) for i in range(runs)]
    networks += [(f"10.200.{16 * i}.0/20", [80, 443]) for i in range(large)]
    launched = []
    for index, (network, ports) in enumerate(networks):
        job = store.create({"nombre": f"Ejecución {index}", "auditoria": audit, "opciones": {},
                            "archivos": [{"nombre": "escaneo.xml", "contenido": nmap(network, ports)}]})
        if index % 2:
            meta = store.jobs[job["id"]]
            with closing(store.database()) as con:
                capture = auditoria.start_capture(con, job["id"], meta["opciones"], meta["grupos"])
                auditoria.set_state(con, capture, "completa")
            launched.append(job["id"])
    return launched


def startup(root):
    start = time.perf_counter()
    store = PortalStore(root)
    elapsed = time.perf_counter() - start
    store.close()
    return elapsed


def main():
    runs = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    large = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
        root = Path(temporary) / "portal_datos"
        start = time.perf_counter()
        store = PortalStore(root)
        launched = populate(store, runs, large)
        store.close()
        print(f"Historial: {runs} ejecuciones de un /24 y {large} de un /20, {len(launched)} lanzadas; "
              f"generado en {time.perf_counter() - start:.1f} s", flush=True)
        opening = statistics.median(startup(root) for _ in range(3))
        store = PortalStore(root)
        try:
            poll = seconds(store.list, repeat=10)
            biggest = launched[-1]
            first = seconds(lambda: store.detail(biggest))
            again = seconds(lambda: store.detail(biggest), repeat=5)
        finally:
            store.close()
    print(f"Arranque: {opening:.3f} s (mediana de 3)")
    print(f"Sondeo del historial (/api/jobs): {poll:.3f} s (mediana de 10)")
    print(f"Abrir la ejecución grande lanzada: {first:.3f} s la primera vez, {again:.3f} s las siguientes")


if __name__ == "__main__":
    main()
