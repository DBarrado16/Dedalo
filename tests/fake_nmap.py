"""Nmap falso para las pruebas: no abre ninguna conexión.

Lee `-iL` y `--excludefile`, escribe un XML mínimo con un host `up` por IP (con un puerto
abierto de prueba) en el fichero de `-oX` y vuelca sus argumentos a `args.json`.
`FAKE_NMAP_ESPERA` (segundos) simula tardanza para probar la parada."""

import json
import os
import sys
import time


def _valor(args: list[str], opcion: str) -> str | None:
    return args[args.index(opcion) + 1] if opcion in args else None


def main(args: list[str]) -> int:
    print("fake nmap")
    print("aviso de prueba", file=sys.stderr)
    with open("args.json", "w", encoding="utf-8") as f:
        json.dump(args, f)
    espera = float(os.environ.get("FAKE_NMAP_ESPERA", "0"))
    limite = time.monotonic() + espera
    while time.monotonic() < limite:
        time.sleep(0.05)
    with open(_valor(args, "-iL"), encoding="utf-8") as f:
        ips = [linea.strip() for linea in f if linea.strip()]
    excluir = _valor(args, "--excludefile")
    if excluir:
        with open(excluir, encoding="utf-8") as f:
            fuera = {linea.strip() for linea in f}
        ips = [ip for ip in ips if ip not in fuera]
    hosts = "".join(
        f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http"/></port></ports></host>'
        for ip in ips)
    with open(_valor(args, "-oX"), "w", encoding="utf-8") as f:
        f.write(f'<?xml version="1.0"?><nmaprun scanner="nmap">{hosts}</nmaprun>')
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
