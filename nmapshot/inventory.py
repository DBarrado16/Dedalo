"""Inventario de todos los hosts y puertos abiertos importados, sin conexiones."""

import csv
import io
import ipaddress

from . import report, targets


def build(hosts, networks):
    resolver = targets.SubnetResolver(networks)
    assets = []
    for host in sorted(hosts, key=lambda h: (ipaddress.ip_address(h.ip).version, int(ipaddress.ip_address(h.ip)))):
        group, subnet = resolver.resolve(host.ip)
        services = []
        for protocol, ports in (("tcp", host.ports), ("udp", host.udp_ports)):
            for number, port in sorted(ports.items()):
                services.append({"puerto": number, "protocolo": protocol,
                                 "servicio": port.service, "tunel": port.tunnel,
                                 "producto": port.product, "version": port.version,
                                 "detalle": port.extrainfo, "cpe": port.cpe, "scripts": port.scripts})
        assets.append({"ip": host.ip, "nombres": host.hostnames, "rango": group,
                       "subred": str(subnet), "servicios": services, "scripts": host.scripts})
    services_total = sum(len(asset["servicios"]) for asset in assets)
    if len(assets) > 100_000 or services_total > 100_000:
        raise ValueError("El inventario admite hasta 100.000 activos o servicios por ejecución; divide los archivos.")
    return {"version": 1, "activos_total": len(assets), "servicios_total": services_total,
            "subredes_total": len({asset["subred"] for asset in assets}), "activos": assets}


def csv_bytes(data):
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["ip", "nombres", "rango", "subred", "protocolo", "puerto", "servicio",
                     "tunel", "producto", "version", "detalle", "cpe", "alcance"])
    for asset in data["activos"]:
        for service in asset["servicios"] or [{}]:
            row = [asset["ip"], "; ".join(asset["nombres"]), asset["rango"], asset["subred"]]
            row += [service.get(key, "") for key in ("protocolo", "puerto", "servicio", "tunel", "producto", "version", "detalle")]
            row += ["; ".join(service.get("cpe", [])), asset.get("alcance", "")]
            writer.writerow([report.csv_text(value) for value in row])
    return output.getvalue().encode("utf-8-sig")
