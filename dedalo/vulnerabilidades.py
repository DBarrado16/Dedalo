"""Cruce de un servicio con sus vulnerabilidades: CVE (local primero, online de respaldo), nivel de exploit y prioridad.

Une `cve` (base local y consulta a la NVD) con `exploits` (KEV, Exploit-DB y PoC de GitHub). No toca la
base ni guarda nada. Quien llama decide el alcance: a `cruzar_servicio` solo deben llegar los CPE de
activos en alcance, recomprobado justo antes (CONTRATOS §0.3), porque aquí puede haber salida a internet.
"""

from __future__ import annotations

import ipaddress
import re

from . import cve, exploits
from .auditoria import get_config

# Confianza mínima (0-100) de una lectura de producto/versión de la detección para construir con ella un CPE.
# Las de gowitness llegan sin confianza y no cuentan; el umbral de la propia detección (MIN_CONFIANZA) es más bajo.
CONFIANZA_ALTA = 80

# CVE que se quedan de un CPE sin versión (las de mayor CVSS). Sin versión casan TODAS las del producto, y Nmap
# pone `cpe:/o:linux:linux_kernel` en cada servicio de un Linux: sin tope serían cientos por servicio.
TOPE_SIN_VERSION = 20

_TOKEN_VERSION = re.compile(r"[vV]?(\d[\w.+~-]*)")

URL_CVE = "https://nvd.nist.gov/vuln/detail/{id}"

# Niveles de exploit de cada vulnerabilidad.
CONFIRMADO = "confirmado"  # en CISA KEV o Exploit-DB
SIN_VERIFICAR = "sin_verificar"  # solo un PoC encontrado en GitHub
NINGUNO = "ninguno"


def _token_version(version) -> str:
    """El primer token numérico de una versión: «2.4.59 (Debian)» -> «2.4.59»; sin número, cadena vacía."""
    encontrado = _TOKEN_VERSION.match(version.strip()) if isinstance(version, str) else None
    return encontrado.group(1) if encontrado else ""


def cpes_del_servicio(cpe_nmap: list, lecturas: list[dict]) -> list[tuple[str, str]]:
    """[(fuente, cpe)] de un servicio: los de Nmap y los construidos con la detección de alta confianza.

    `fuente` es "nmap" o "deteccion". De la detección solo cuentan las lecturas con confianza >= CONFIANZA_ALTA
    y producto; la versión se limpia a su primer token antes de construir el CPE (cpe_desde_deteccion no lo hace,
    y un «2.4.59 (Debian)» no casaría con ningún rango). Un CPE repetido se queda con la primera fuente.
    """
    cpes: dict[str, str] = {}
    for cpe in cpe_nmap or []:
        if isinstance(cpe, str) and cpe.strip():
            cpes.setdefault(cpe.strip(), "nmap")
    for lectura in lecturas:
        confianza = lectura.get("confianza")
        if not isinstance(confianza, int) or isinstance(confianza, bool) or confianza < CONFIANZA_ALTA:
            continue
        cpe = cve.cpe_desde_deteccion(lectura.get("producto"), _token_version(lectura.get("version")))
        if cpe:
            cpes.setdefault(cpe, "deteccion")
    return [(fuente, cpe) for cpe, fuente in cpes.items()]


def _vuln(fila: dict, cpe: str, sin_version: bool, kev, edb, sin_internet: bool, buscar_github) -> dict:
    cve_id = fila["id"]
    exploit = exploits.exploit_de(cve_id, kev, edb)
    nivel, enlaces = exploit["nivel"], list(exploit["enlaces"])
    # Sin versión no se sabe si la CVE afecta al servicio: no se busca su PoC (serían búsquedas a ciegas).
    if nivel != CONFIRMADO and not sin_internet and not sin_version:
        poc = buscar_github(cve_id, sin_internet)
        if poc:
            nivel, enlaces = SIN_VERIFICAR, list(poc)
    severidad = fila.get("severidad")
    return {"cve": cve_id, "severidad": severidad.upper() if isinstance(severidad, str) else "",
            "enlace": URL_CVE.format(id=cve_id), "exploit_nivel": nivel, "enlaces_exploit": enlaces,
            "origen_cpe": cpe, "sin_version": sin_version}


def _por_cvss(fila: dict) -> tuple:
    """De más a menos grave, como `cve.cves_de`: CVSS de mayor a menor (sin CVSS al final) y luego por id."""
    cvss = fila.get("cvss")
    return (cvss is None, -(cvss or 0), fila["id"])


def _cves_del_cpe(con, cpe: str, sin_internet: bool) -> tuple[list[dict], bool, bool]:
    """(CVE del cpe, si el cpe no trae versión, si esa respuesta es fiable).

    Sin versión se quedan solo las TOPE_SIN_VERSION de mayor CVSS.
    """
    partes = cve._parsear_cpe(cpe)
    sin_version = partes is None or not partes[2]
    filas, fiable = cve.cves_de(con, cpe), True
    if not filas:
        online = None if sin_internet else cve.consultar_online(cpe, sin_internet)
        if online is not None:  # consultado: [] es «0 CVE», no «sin datos»
            filas = online
        else:  # sin consulta posible: la base local solo vale como «0 CVE» si está completa (marca de la NVD)
            fiable = get_config(con, "nvd_actualizada") is not None
    if sin_version:
        filas = sorted(filas, key=_por_cvss)[:TOPE_SIN_VERSION]
    return filas, sin_version, fiable


def cruzar_servicio(con, cpes: list[str], kev, edb, sin_internet: bool, buscar_github=exploits.buscar_github) -> dict:
    """Reúne las vulnerabilidades de un servicio a partir de sus CPE.

    Por cada cpe, primero la base local; solo si no da ninguna CVE para ese cpe, la consulta online (nunca con
    `sin_internet`). Un cpe sin versión se queda con sus TOPE_SIN_VERSION CVE de mayor CVSS. A cada CVE se le pone
    su nivel de exploit: "confirmado" (KEV/Exploit-DB), "sin_verificar" (solo un PoC en GitHub, buscado únicamente si
    no es confirmado, el cpe trae versión y hay salida a internet) o "ninguno".
    Una CVE que sale por dos cpe se cuenta una vez, con el primero.

    Devuelve {"estado", "vulns"}. `estado` es "sin_datos" cuando ningún cpe tuvo respuesta fiable: no hay CPE,
    o no hay base local completa (falta `config.nvd_actualizada`; que la tabla cve tenga filas no basta) y la consulta
    online no estuvo disponible (interruptor o fallo). Es distinto de "ok" con `vulns=[]`: eso es «se miró y no hay CVE».
    Cada vuln: {cve, severidad (en mayúsculas, como la NVD), enlace, exploit_nivel, enlaces_exploit, origen_cpe, sin_version}.
    """
    vulns: dict[str, dict] = {}
    respondido = False
    for cpe in cpes:
        filas, sin_version, fiable = _cves_del_cpe(con, cpe, sin_internet)
        respondido = respondido or fiable
        for fila in filas:
            if fila["id"] not in vulns:
                vulns[fila["id"]] = _vuln(fila, cpe, sin_version, kev, edb, sin_internet, buscar_github)
    return {"estado": "ok" if respondido else "sin_datos", "vulns": list(vulns.values())}


def orden(vulns: list[dict]) -> int:
    """Clave de prioridad de un servicio: MENOR = MÁS PRIORITARIO (se ordena de menor a mayor).

    0 exploit confirmado, 1 CVE crítica (severidad CRITICAL), 2 alguna CVE, 3 solo PoC sin verificar, 4 nada.
    Cuenta lo peor del servicio. Como un PoC solo se busca para una CVE, el 3 solo sale si se le pasan
    vulnerabilidades sin CVE reconocible; una CVE con PoC cuenta como CVE (2) o crítica (1).
    """
    if any(v.get("exploit_nivel") == CONFIRMADO for v in vulns):
        return 0
    if any(str(v.get("severidad", "")).upper() == "CRITICAL" for v in vulns):
        return 1
    if any(v.get("cve") for v in vulns):
        return 2
    if any(v.get("exploit_nivel") == SIN_VERIFICAR for v in vulns):
        return 3
    return 4


_SEVERIDAD = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_EXPLOIT = {CONFIRMADO: 0, SIN_VERIFICAR: 1}
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}\Z")


def _clave_vuln(vuln: dict) -> tuple:
    """Dentro de un servicio: primero lo que tiene exploit confirmado, luego PoC, luego por severidad y por CVE."""
    return (_EXPLOIT.get(vuln.get("exploit_nivel"), 2), _SEVERIDAD.get(str(vuln.get("severidad", "")).upper(), 4), vuln.get("cve", ""))


def _clave_servicio(servicio: dict) -> tuple:
    try:
        ip = ipaddress.ip_address(servicio["ip"])
        direccion = (ip.version, int(ip))
    except ValueError:
        direccion = (0, 0)
    return (servicio["prioridad"] if servicio["prioridad"] is not None else 4, direccion, servicio["ip"], servicio["protocolo"], servicio["puerto"])


def ordenar_servicios(servicios: list[dict]) -> list[dict]:
    """Los resultados de `auditoria.vuln_results` en orden determinista y con su prioridad (ver `orden`), sin tocar la entrada.

    Cada servicio sale con `prioridad` (0-4; `None` si no hubo datos: no se sabe si es limpio) y sus `vulns` ordenadas
    de más a menos urgentes, cada una con el `enlace` a su ficha en la NVD. Entre servicios: prioridad, luego IP
    (numérica), protocolo y puerto.
    """
    salida = []
    for servicio in servicios:
        vulns = [v | {"enlace": URL_CVE.format(id=v["cve"]) if _CVE_ID.match(v.get("cve", "")) else ""}
                 for v in sorted(servicio["vulns"], key=_clave_vuln)]
        prioridad = None if servicio["estado"] == "sin_datos" else orden(vulns)
        salida.append(servicio | {"vulns": vulns, "prioridad": prioridad})
    return sorted(salida, key=_clave_servicio)


def estado_servicio(servicio: dict | None) -> str:
    """Cómo se exporta lo que el cruce dijo de un servicio.

    "" no se cruzó (o no está en el resultado); "sin_datos" no se pudo mirar; "sin_vulnerabilidades" se miró y está limpio;
    "con_vulnerabilidades" tiene alguna CVE. «sin_datos» nunca se presenta como limpio.
    """
    if servicio is None:
        return ""
    if servicio["estado"] == "sin_datos":
        return "sin_datos"
    return "con_vulnerabilidades" if servicio["vulns"] else "sin_vulnerabilidades"


# Columnas con que las exportaciones (CSV del inventario e índice de capturas) cuentan el resultado del cruce.
COLUMNAS_EXPORTACION = ["vuln_estado", "vuln_prioridad", "vuln_cves", "vuln_severidades", "vuln_exploits", "vuln_enlaces"]


def campos_exportacion(estado: str, prioridad: int | None, vulns: list[dict]) -> dict[str, str]:
    """Las `COLUMNAS_EXPORTACION` de un servicio: `estado` (ver `estado_servicio`), su prioridad y sus `vulns` ya ordenadas.

    Las listas van alineadas (el CVE n-ésimo, su severidad n-ésima y su nivel de exploit n-ésimo), separadas por «; ».
    Los enlaces son los del exploit o PoC de cualquiera de ellas, sin repetir; solo se enlazan, nunca se descargan.
    """
    enlaces = list(dict.fromkeys(e for v in vulns for e in v.get("enlaces_exploit", [])))
    return {"vuln_estado": estado, "vuln_prioridad": "" if prioridad is None else str(prioridad),
            "vuln_cves": "; ".join(v["cve"] for v in vulns),
            "vuln_severidades": "; ".join(v.get("severidad", "") for v in vulns),
            "vuln_exploits": "; ".join(v.get("exploit_nivel", "") for v in vulns),
            "vuln_enlaces": "; ".join(enlaces)}


def columnas_tcp(servicios: list[dict]) -> dict[tuple[str, str], dict[str, str]]:
    """{(ip, "puerto"): columnas vuln_*} de los servicios TCP de `auditoria.vuln_results`, para el índice de capturas."""
    return {(s["ip"], str(s["puerto"])): campos_exportacion(estado_servicio(s), s["prioridad"], s["vulns"])
            for s in ordenar_servicios(servicios) if s["protocolo"] == "tcp"}
