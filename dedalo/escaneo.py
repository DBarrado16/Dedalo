"""Lanzar Nmap desde el portal: localizar el binario, presets, ejecución y filtrado de resultados."""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from .gowitness import _executable
from .parser import Host
from .targets import Scope


_PING = "-PE -PS21,22,23,25,80,135,139,443,445,3389,8080,8443"

# Opciones propias de cada preset (sin -oX/-iL/--excludefile, que se añaden por trozo).
PRESETS: dict[str, dict] = {
    "rapido": {"etiqueta": "Rápido", "puertos": 1000,
               "args": f"-sT --top-ports 1000 -sV --version-light -T4 {_PING} --max-retries 2 --host-timeout 15m".split()},
    "completo": {"etiqueta": "Completo", "puertos": 65535,
                 "args": f"-sT -p- -sV -T4 {_PING} --max-retries 2 --host-timeout 60m".split()},
    "vpn": {"etiqueta": "Red difícil / VPN", "puertos": 1000,
            "args": "-sT -Pn --top-ports 1000 -sV -T3 --max-retries 4 --host-timeout 20m".split()},
}

# Comunes a todos: sin DNS inverso (eso es el descubrimiento DNS).
COMUNES: list[str] = ["-n"]

# Orden de magnitud del tiempo por IP de cada preset (segundos, con los tiempos y reintentos de arriba y una
# red mixta de equipos vivos y muertos). Sirve para avisar de lo que se va a lanzar, no para prometer una hora.
SEGUNDOS_POR_IP: dict[str, float] = {"rapido": 1.0, "completo": 30.0, "vpn": 5.0}

# Por encima de estas IP, un preset lento (completo, vpn) merece un aviso antes de lanzarse.
PRESETS_LENTOS = ("completo", "vpn")
AVISO_IPS = 1024


def segundos_estimados(presets: list[str], n_ips: int) -> float:
    """Suma de segundos esperables de los presets sobre `n_ips` direcciones (ValueError si falta alguno)."""
    for preset in presets:
        if preset not in SEGUNDOS_POR_IP:
            raise ValueError(f"Perfil de escaneo desconocido: {preset}")
    return sum(SEGUNDOS_POR_IP[preset] for preset in presets) * max(n_ips, 0)


def estimar(presets: list[str], n_ips: int) -> str:
    """El tiempo orden de magnitud de escanear `n_ips` con `presets`, en texto ('≈ 4 min', '≈ 2 h', '≈ 23 días')."""
    if n_ips <= 0:
        return "nada que escanear"
    segundos = segundos_estimados(presets, n_ips)
    if segundos < 60:
        return "menos de 1 min"
    minutos = segundos / 60
    if minutos < 90:
        return f"≈ {round(minutos)} min"
    horas = minutos / 60
    if horas < 48:
        return f"≈ {round(horas)} h"
    return f"≈ {round(horas / 24)} días"


def trocear(include: list[str]) -> list[ipaddress.IPv4Network]:
    """Las redes IPv4 de `include` en bloques /24 alineados, sin solapar y en orden.

    Una red menor de /24 es un trozo de su tamaño; las redes IPv6 se ignoran."""
    redes = [red for red in (ipaddress.ip_network(texto, strict=False) for texto in include) if red.version == 4]
    trozos: list[ipaddress.IPv4Network] = []
    for red in ipaddress.collapse_addresses(redes):
        trozos.extend(red.subnets(new_prefix=24) if red.prefixlen < 24 else [red])
    return trozos


def objetivos_del_trozo(bloque: ipaddress.IPv4Network, scope: Scope) -> tuple[list[str], list[str]]:
    """(en_alcance, excluidas) del bloque; las que están fuera no van en ninguna lista."""
    en_alcance: list[str] = []
    excluidas: list[str] = []
    for ip in map(str, bloque):
        situacion = scope.status(ip)
        if situacion == scope.IN:
            en_alcance.append(ip)
        elif situacion == scope.EXCLUDED:
            excluidas.append(ip)
    return en_alcance, excluidas


def find_nmap(explicit: str | None) -> str:
    """Ruta absoluta al ejecutable de Nmap; sin ninguno, ValueError con ayuda."""
    if explicit:
        return _executable(explicit)
    if os.name == "nt":
        for base in ("ProgramFiles(x86)", "ProgramFiles"):
            if os.environ.get(base):
                path = Path(os.environ[base]) / "Nmap" / "nmap.exe"
                if path.is_file():
                    return str(path.resolve())
    found = shutil.which("nmap")
    # Uno en la carpeta actual no cuenta: en Windows shutil.which también mira ahí
    # (como en gowitness.find_gowitness y modelo.find_ollama).
    if found and Path(found).resolve().parent != Path.cwd().resolve():
        return str(Path(found).resolve())
    path = Path("/usr/bin/nmap")
    if path.is_file():
        return str(path)
    raise ValueError("No se encuentra Nmap. Instálalo (https://nmap.org/download) o indica su ruta.")


def nmap_version(binary: str) -> str | None:
    """La versión que dice `nmap --version` (p. ej. '7.95'), o None si no responde."""
    try:
        resultado = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError):
        return None
    encontrado = re.search(r"Nmap version ([\d.]+)", (resultado.stdout or "") + (resultado.stderr or ""))
    return encontrado.group(1) if encontrado else None


def escanear_trozo(nmap: str, preset: str, dentro: list[str], excluidas: list[str], carpeta: Path,
                   *, parar) -> dict:
    """Lanza Nmap sobre un trozo y espera a que acabe (o a que `parar()` devuelva True).

    Sin shell: la lista de argumentos la arma el código y las IP van en ficheros que escribe
    Dédalo (`objetivos.txt`, `excluir.txt`) dentro de `carpeta`, que es también el directorio
    de trabajo de Nmap. Ningún texto del usuario llega a la línea de comandos."""
    if preset not in PRESETS:
        raise ValueError(f"Preset de escaneo desconocido: {preset}")
    carpeta = Path(carpeta)
    (carpeta / "objetivos.txt").write_text("\n".join(dentro) + "\n", encoding="utf-8")
    comando = [nmap, *COMUNES, *PRESETS[preset]["args"], "-oX", "salida.xml", "-iL", "objetivos.txt"]
    if excluidas:
        (carpeta / "excluir.txt").write_text("\n".join(excluidas) + "\n", encoding="utf-8")
        comando += ["--excludefile", "excluir.txt"]
    inicio = datetime.now(timezone.utc).isoformat(timespec="seconds")
    relanzado = False
    # La salida de Nmap queda como evidencia del trozo; sin entrada ni consola heredadas.
    with open(carpeta / "nmap.out", "wb") as salida, open(carpeta / "nmap.err", "wb") as errores:
        proc = subprocess.Popen(comando, shell=False, cwd=carpeta, stdin=subprocess.DEVNULL,
                                stdout=salida, stderr=errores,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            while proc.poll() is None:
                if parar():
                    relanzado = True
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                    break
                time.sleep(0.1)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    fin = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {"comando": comando, "codigo": proc.returncode, "inicio": inicio, "fin": fin, "relanzado": relanzado}


def puertos_sondeados(presets: list[str]) -> int:
    """Cuántos puertos TCP sondea como mucho esta combinación de presets (ValueError si falta alguno)."""
    return max(PRESETS[p]["puertos"] for p in presets)


def limpiar_hosts(hosts: list[Host], puertos_sondeados: int | None = None) -> list[Host]:
    """Descarta hosts sin puertos abiertos (fantasmas de -Pn) y vacía los que responden en (casi) todo.

    `puertos_sondeados` es cuántos puertos TCP sondeó el escaneo; un host con el 90 % o más
    abiertos responde a todo (tarpit, firewall que contesta a todo) y entra sin puertos y con una
    observación. El 90 % aguanta que la detección de versión pode algún puerto. Sin ese dato no se marca.
    """
    tope = puertos_sondeados * 9 // 10 if puertos_sondeados else None
    limpios = []
    for host in hosts:
        if not host.ports and not host.udp_ports:
            continue
        if tope is not None and len(host.ports) >= tope:
            abiertos = len(host.ports)
            host.ports = {}
            host.scripts.append({"id": "dedalo-todos-los-puertos",
                                 "output": f"responde en todos los puertos ({abiertos} abiertos)"})
        limpios.append(host)
    return limpios
