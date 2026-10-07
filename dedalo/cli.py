"""Interfaz de comandos de dedalo."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
import sqlite3
import subprocess
import sys
from xml.etree.ElementTree import ParseError

from . import __version__, gowitness, parser, report, targets, views


def positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("Debe ser mayor que cero")
    return number


def nonnegative(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("No puede ser negativo")
    return number


def port_number(value: str) -> int:
    number = positive(value)
    if number > 65535:
        raise argparse.ArgumentTypeError("El puerto debe estar entre 1 y 65535")
    return number


def build_parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(prog="dedalo", description="Capturas web desde resultados nmap, agrupadas por rango y subred.")
    command.add_argument("--version", action="version", version=__version__)
    subcommands = command.add_subparsers(dest="command", required=True)
    capture = subcommands.add_parser("capturar", help="Leer nmap y capturar sus servicios web")
    capture.add_argument("ficheros", nargs="+", help="Salidas nmap XML, grepable o normal")
    capture.add_argument("-r", "--rangos", help="Fichero con un CIDR por línea")
    capture.add_argument("--solo-rangos", action="store_true", help="Capturar solo las IP dentro de --rangos; sin rangos, ninguna")
    capture.add_argument("--excluir", help="Fichero con IP o CIDR que nunca se capturan")
    capture.add_argument("-o", "--salida", help="Carpeta nueva o vacía; por defecto salida/FECHA-HORA")
    capture.add_argument("--simular", "--dry-run", action="store_true", help="Mostrar URLs y subredes sin conectar ni crear archivos")
    capture.add_argument("--puertos", default="", help="Puertos adicionales: 8080=http,8443=https")
    capture.add_argument("--por-servicio", "--by-service", action="store_true", help="Incluir otros puertos identificados como HTTP por nmap")
    capture.add_argument("-t", "--hilos", type=positive, default=6, help="Capturas simultáneas por subred (6)")
    capture.add_argument("--timeout", type=positive, default=60, help="Tiempo máximo por URL en segundos (60)")
    capture.add_argument("--delay", type=nonnegative, default=10, help="Espera antes de capturar, segundos (10)")
    capture.add_argument("--formato", choices=["jpeg", "png"], default="jpeg")
    capture.add_argument("--pagina-completa", action="store_true", help="Capturar la página completa")
    capture.add_argument("--driver", choices=gowitness.DRIVERS, default=gowitness.DRIVERS[0],
                         help=f"Motor con el que gowitness maneja el navegador ({gowitness.DRIVERS[0]})")
    capture.add_argument("--sin-reintento", action="store_true",
                         help="No reintentar con el otro motor las páginas que cargan pero no dan imagen")
    capture.add_argument("--chrome", help="Ruta o nombre del ejecutable Chrome/Chromium/Edge")
    capture.add_argument("--gowitness", help="Ruta o nombre del ejecutable gowitness v3")
    capture.add_argument("--stop-file", help=argparse.SUPPRESS)

    portal = subcommands.add_parser("web", help="Operar desde el portal web local")
    portal.add_argument("--puerto", type=port_number, default=8787)
    portal.add_argument("--datos", default="portal_datos", help="Carpeta del historial y archivos subidos")
    portal.add_argument("--chrome", help="Navegador del servidor")
    portal.add_argument("--gowitness", help="Ejecutable de gowitness v3")
    portal.add_argument("--abrir", action="store_true", help="Abrir el portal en el navegador")

    show = subcommands.add_parser("ver", help="Abrir el visor de una subred, un rango o todo")
    show.add_argument("salida", help="Carpeta de una ejecución")
    show.add_argument("selector", nargs="?", help="CIDR de rango/subred o fuera_de_rango; omitido = todo")
    show.add_argument("--listar", action="store_true", help="Mostrar subredes y recuentos sin arrancar el visor")
    show.add_argument("--preparar", action="store_true", help="Preparar la vista e imprimir su carpeta sin arrancar el servidor")
    show.add_argument("--host", default="127.0.0.1", help="Dirección de escucha (127.0.0.1)")
    show.add_argument("--puerto", type=port_number, default=7171)
    show.add_argument("--gowitness", help="Ruta o nombre del ejecutable gowitness v3")

    setup = subcommands.add_parser("instalar", help=f"Descargar y verificar gowitness {gowitness.VERSION} en bin/")
    setup.add_argument("--forzar", action="store_true", help="Descargar aunque ya exista en bin/")
    return command


def folder_name(cidr: str) -> str:
    return cidr.replace("/", "_").replace(":", "_")


def plan(args) -> list[dict]:
    hosts = parser.merge([parser.parse_file(path) for path in args.ficheros])
    ranges = targets.read_networks_file(args.rangos) if args.rangos else []
    excluded = targets.read_networks_file(args.excluir) if getattr(args, "excluir", None) else []
    if getattr(args, "solo_rangos", False) or excluded:
        # El alcance se aplica aquí, justo antes de conectar (docs/CONTRATOS.md 0.3).
        scope = targets.Scope(ranges if args.solo_rangos else ["0.0.0.0/0", "::/0"], excluded)
        kept = [host for host in hosts if scope.status(host.ip) == scope.IN]
        if len(kept) < len(hosts):
            print(f"{len(hosts) - len(kept)} IP fuera de alcance o excluidas: no se capturan.", flush=True)
        hosts = kept
    return group_hosts(hosts, ranges, args.puertos, args.por_servicio)


def group_hosts(hosts, ranges, extra_ports="", by_service=False) -> list[dict]:
    mapping = {**targets.DEFAULT_PORTS, **targets.parse_port_map(extra_ports)}
    resolver = targets.SubnetResolver(ranges)
    selected = targets.select_targets(hosts, mapping, by_service)
    selected.sort(key=lambda t: (ipaddress.ip_address(t.ip).version, int(ipaddress.ip_address(t.ip)), t.port))
    grouped = {}
    for target in selected:
        range_name, subnet = resolver.resolve(target.ip)
        key = (range_name, str(subnet))
        group = grouped.setdefault(key, {
            "rango": range_name, "subred": str(subnet),
            "carpeta": f"{folder_name(range_name)}/{folder_name(str(subnet))}",
            "estado": "pendiente", "objetivos": [],
        })
        group["objetivos"].append({**asdict(target), "url": target.url})
    return list(grouped.values())


def capture(args) -> int:
    groups = plan(args)
    count = sum(len(g["objetivos"]) for g in groups)
    print(f"{count} URLs en {len(groups)} subredes.", flush=True)
    if args.simular:
        for group in groups:
            print(f"\n{group['rango']} -> {group['subred']}")
            for target in group["objetivos"]:
                print(f"  {target['url']}")
        return 0
    if not groups:
        print("No hay puertos web abiertos seleccionados. No se ha creado una salida.")
        return 0

    binary = gowitness.find_gowitness(args.gowitness)
    chrome = gowitness.find_chrome(args.chrome)
    opts = {"threads": args.hilos, "timeout": args.timeout, "delay": args.delay,
            "format": args.formato, "chrome": chrome, "fullpage": args.pagina_completa,
            "driver": args.driver, "retry": not args.sin_reintento}
    root = Path(args.salida or ("salida/" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))).resolve()
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise ValueError(f"La salida no está vacía: {root}. Usa una carpeta nueva para no mezclar ejecuciones.")
    root.mkdir(parents=True, exist_ok=True)
    # Creación exclusiva: dos procesos no pueden reclamar la misma salida vacía.
    with (root / report.MANIFEST).open("x", encoding="utf-8") as file:
        file.write("{}")
    manifest = {"version": 1, "dedalo": __version__,
                "inicio": datetime.now(timezone.utc).isoformat(), "estado": "en_curso",
                "entradas": [str(Path(p).resolve()) for p in args.ficheros],
                "rangos": args.rangos, "opciones": opts, "grupos": groups}
    report.write_index(root, manifest)
    print(f"Salida: {root}", flush=True)
    print(f"Navegador: {chrome or 'descarga automática de gowitness'}", flush=True)
    interrupted = False
    for position, group in enumerate(groups, 1):
        if getattr(args, "stop_file", None) and Path(args.stop_file).exists():
            interrupted = True
            break
        directory = report.inside(root, group["carpeta"])
        directory.mkdir(parents=True)
        group["estado"] = "en_curso"
        report.write_index(root, manifest)
        urls = [t["url"] for t in group["objetivos"]]
        print(f"[{position}/{len(groups)}] {group['rango']} -> {group['subred']}: {len(urls)} URLs...", flush=True)
        error = ""
        try:
            gowitness.scan_subnet(binary, directory, urls, opts)
            stopping = getattr(args, "stop_file", None) and Path(args.stop_file).exists()
            retry = gowitness.retry_candidates(directory, urls) if opts["retry"] and not stopping else []
            if retry:
                # La página respondió pero no hubo imagen: el otro motor a veces sí la obtiene.
                other = gowitness.other_driver(opts["driver"])
                print(f"  {len(retry)} sin imagen; se reintentan con el motor {other}...", flush=True)
                try:
                    gowitness.scan_subnet(binary, directory, retry, {**opts, "driver": other},
                                          gowitness.RETRY_URLS, gowitness.RETRY_LOG)
                except (OSError, subprocess.CalledProcessError) as exc:
                    # Lo capturado en la primera pasada sigue siendo válido.
                    print(f"  El reintento no pudo completarse: {exc}. Consulta {gowitness.RETRY_LOG}", file=sys.stderr)
        except KeyboardInterrupt:
            interrupted = True
            error = "Captura interrumpida por el usuario"
        except (OSError, subprocess.CalledProcessError) as exc:
            error = f"gowitness no pudo completar esta subred: {exc}. Consulta gowitness.log"
        try:
            report.collect_group(root, group, error)
        except (OSError, sqlite3.Error, ValueError) as exc:
            # No presentar como correctos resultados que no podemos verificar.
            group.update(estado="error", error=f"No se pudo leer la base: {exc}", capturas=0, sin_captura=len(urls))
            group["resultados"] = [
                {"rango": group["rango"], "subred": group["subred"], "ip": t["ip"],
                 "puerto": t["port"], "url": t["url"], "estado": "sin_captura", "error": group["error"]}
                for t in group["objetivos"]
            ]
            (directory / "sin_captura.txt").write_text("\n".join(urls) + "\n", encoding="utf-8")
        if interrupted:
            group["estado"] = "interrumpido"
        report.write_index(root, manifest)
        print(f"  {group['capturas']} capturas; {group['sin_captura']} sin captura.", flush=True)
        if group.get("error"):
            print(f"  {group['error']}", file=sys.stderr)
        if interrupted:
            break

    shots = sum(g.get("capturas", 0) for g in groups)
    has_error = any(g["estado"] == "error" for g in groups)
    manifest["estado"] = "interrumpida" if interrupted else ("completa" if shots == count and not has_error else "parcial")
    manifest["fin"] = datetime.now(timezone.utc).isoformat()
    report.write_index(root, manifest)
    print(f"Resultado: {shots}/{count} capturas. Índice: {root / 'indice.csv'}")
    print(f'Visor: python -m dedalo ver "{root}"')
    return 130 if interrupted else (1 if has_error else (3 if shots < count else 0))


def show(args) -> int:
    root = Path(args.salida).resolve()
    manifest = report.load_manifest(root)
    groups = views.select_groups(manifest, args.selector)
    if args.listar:
        for group in groups:
            print(f"{group['rango']} -> {group['subred']}: "
                  f"{group.get('capturas', 0)}/{len(group['objetivos'])} capturas ({group['estado']})")
        return 0
    binary = gowitness.find_gowitness(args.gowitness)
    directory = views.prepare_view(binary, root, groups)
    print(f"Vista: {directory}", flush=True)
    if not args.preparar:
        host = f"[{args.host}]" if ":" in args.host else args.host
        print(f"Abre http://{host}:{args.puerto} (Ctrl+C para cerrar).", flush=True)
        try:
            gowitness.serve(binary, directory, args.host, args.puerto)
        except KeyboardInterrupt:
            return 0
    return 0


def install(args) -> int:
    local = gowitness.local_binary()
    if local.is_file() and not args.forzar:
        _, expected = gowitness.release_for_this_system()
        state = "coincide con" if gowitness.sha256_of(local) == expected else "NO coincide con"
        print(f"Ya existe {local}; su SHA-256 {state} el gowitness {gowitness.VERSION} oficial. "
              "Usa --forzar para reemplazarlo.")
        return 0
    gowitness.install_gowitness()
    return 0


def main(argv: list[str] | None = None) -> int:
    command = build_parser()
    args = command.parse_args(argv)
    try:
        if args.command == "web":
            from .web import serve_portal
            return serve_portal(args)
        if args.command == "instalar":
            return install(args)
        return capture(args) if args.command == "capturar" else show(args)
    except KeyboardInterrupt:
        print("\nInterrumpido.", file=sys.stderr)
        return 130
    except (OSError, ValueError, ParseError, sqlite3.Error, subprocess.CalledProcessError, KeyError, TypeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
