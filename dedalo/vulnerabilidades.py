"""Cruce de un servicio con sus vulnerabilidades: CVE (local primero, online de respaldo), nivel de exploit y prioridad.

Une `cve` (base local y consulta a la NVD) con `exploits` (KEV, Exploit-DB y PoC de GitHub). No toca la
base ni guarda nada. Quien llama decide el alcance: a `cruzar_servicio` solo deben llegar los CPE de
activos en alcance, recomprobado justo antes (CONTRATOS §0.3), porque aquí puede haber salida a internet.
"""

from __future__ import annotations

from . import cve, exploits
from .auditoria import get_config

URL_CVE = "https://nvd.nist.gov/vuln/detail/{id}"

# Niveles de exploit de cada vulnerabilidad.
CONFIRMADO = "confirmado"  # en CISA KEV o Exploit-DB
SIN_VERIFICAR = "sin_verificar"  # solo un PoC encontrado en GitHub
NINGUNO = "ninguno"


def _vuln(fila: dict, cpe: str, sin_version: bool, kev, edb, sin_internet: bool, buscar_github) -> dict:
    cve_id = fila["id"]
    exploit = exploits.exploit_de(cve_id, kev, edb)
    nivel, enlaces = exploit["nivel"], list(exploit["enlaces"])
    if nivel != CONFIRMADO and not sin_internet:
        poc = buscar_github(cve_id, sin_internet)
        if poc:
            nivel, enlaces = SIN_VERIFICAR, list(poc)
    severidad = fila.get("severidad")
    return {"cve": cve_id, "severidad": severidad.upper() if isinstance(severidad, str) else "",
            "enlace": URL_CVE.format(id=cve_id), "exploit_nivel": nivel, "enlaces_exploit": enlaces,
            "origen_cpe": cpe, "sin_version": sin_version}


def _cves_del_cpe(con, cpe: str, sin_internet: bool) -> tuple[list[tuple[dict, bool]], bool]:
    """(CVE del cpe, si esa respuesta es fiable). Cada CVE va con su `sin_version`."""
    local = cve.cves_de(con, cpe)
    if local:
        return [(fila, bool(fila.get("sin_version"))) for fila in local], True
    online = None if sin_internet else cve.consultar_online(cpe, sin_internet)
    if online is not None:  # consultado: [] es «0 CVE», no «sin datos»
        partes = cve._parsear_cpe(cpe)
        sin_version = partes is None or not partes[2]
        return [(fila, sin_version) for fila in online], True
    # Sin consulta posible: la base local solo vale como respuesta «0 CVE» si está completa (marca de la NVD).
    return [], get_config(con, "nvd_actualizada") is not None


def cruzar_servicio(con, cpes: list[str], kev, edb, sin_internet: bool, buscar_github=exploits.buscar_github) -> dict:
    """Reúne las vulnerabilidades de un servicio a partir de sus CPE.

    Por cada cpe, primero la base local; solo si no da ninguna CVE para ese cpe, la consulta online (nunca con
    `sin_internet`). A cada CVE se le pone su nivel de exploit: "confirmado" (KEV/Exploit-DB), "sin_verificar"
    (solo un PoC en GitHub, buscado únicamente si no es confirmado y hay salida a internet) o "ninguno".
    Una CVE que sale por dos cpe se cuenta una vez, con el primero.

    Devuelve {"estado", "vulns"}. `estado` es "sin_datos" cuando ningún cpe tuvo respuesta fiable: no hay CPE,
    o no hay base local completa (falta `config.nvd_actualizada`; que la tabla cve tenga filas no basta) y la consulta
    online no estuvo disponible (interruptor o fallo). Es distinto de "ok" con `vulns=[]`: eso es «se miró y no hay CVE».
    Cada vuln: {cve, severidad (en mayúsculas, como la NVD), enlace, exploit_nivel, enlaces_exploit, origen_cpe, sin_version}.
    """
    vulns: dict[str, dict] = {}
    respondido = False
    for cpe in cpes:
        filas, fiable = _cves_del_cpe(con, cpe, sin_internet)
        respondido = respondido or fiable
        for fila, sin_version in filas:
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
