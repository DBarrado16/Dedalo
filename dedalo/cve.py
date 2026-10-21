"""Base local de CVE: reglas de aplicabilidad por CPE guardadas en SQLite y consulta por producto y versión.

Solo toca la base (tablas cve y cve_cpe); no contacta con nada. Los datos llegan ya normalizados:
quien los descargue (NVD) los convierte al formato de `guardar_cves`.
"""

from __future__ import annotations

import re
from urllib.parse import unquote


def _componente(texto: str) -> tuple[int, str]:
    """«10p1» -> (10, «p1»): los dígitos iniciales como número y el resto como sufijo."""
    digitos, sufijo = re.match(r"(\d*)(.*)", texto).groups()
    return int(digitos or 0), sufijo


def _componentes(version: str) -> list[tuple[int, str]]:
    return [_componente(parte) for parte in version.strip().lower().split(".")]


def comparar_versiones(a: str, b: str) -> int:
    """-1, 0 o 1 según `a` sea menor, igual o mayor que `b`.

    Se parte por puntos y cada componente por (dígitos iniciales como número, sufijo como texto):
    «7.4p1» < «7.10p1» porque 4 < 10, y «7.4p1» < «7.4p2» por el sufijo. Al más corto se le
    completa con ceros: «1.0» y «1.0.0» son iguales.
    """
    ca, cb = _componentes(a), _componentes(b)
    for i in range(max(len(ca), len(cb))):
        x = ca[i] if i < len(ca) else (0, "")
        y = cb[i] if i < len(cb) else (0, "")
        if x != y:
            return -1 if x < y else 1
    return 0


def _parsear_cpe(cpe: str):
    """(vendor, producto, versión) de un CPE 2.2 (`cpe:/a:v:p:ver`) o 2.3 (`cpe:2.3:a:v:p:ver:...`); None si no sirve.

    Una versión ausente, `*` o `-` sale como cadena vacía.
    """
    if not isinstance(cpe, str):
        return None
    texto = cpe.strip()
    if texto.startswith("cpe:2.3:"):
        campos = texto[len("cpe:2.3:"):].split(":")
    elif texto.startswith("cpe:/"):
        campos = [unquote(c) for c in texto[len("cpe:/"):].split(":")]
    else:
        return None
    campos += [""] * (4 - len(campos))
    vendor, producto, version = (c.strip().lower() for c in campos[1:4])
    if not producto or producto in ("*", "-"):
        return None
    return ("" if vendor in ("*", "-") else vendor), producto, ("" if version in ("*", "-") else version)


def _texto(valor) -> str:
    return valor if isinstance(valor, str) else ""


def _version_o_none(valor):
    return valor.strip() if isinstance(valor, str) and valor.strip() else None


def _regla(entrada):
    """Fila de cve_cpe de una regla válida; None si está mal formada (sin producto)."""
    if not isinstance(entrada, dict):
        return None
    producto = _texto(entrada.get("producto")).strip().lower()
    if not producto:
        return None
    return (_texto(entrada.get("parte")).strip().lower(), _texto(entrada.get("vendor")).strip().lower(), producto,
            _version_o_none(entrada.get("v_ini")), 1 if entrada.get("v_ini_incl") else 0,
            _version_o_none(entrada.get("v_fin")), 1 if entrada.get("v_fin_incl") else 0)


def guardar_cves(con, items: list[dict]) -> None:
    """Inserta o actualiza CVE y sus reglas cpe; repetirlo con los mismos datos no cambia nada.

    Cada item: {"id", "publicada", "severidad", "cvss", "resumen", "cpes": [regla, ...]}, con
    regla = {"parte", "vendor", "producto", "v_ini", "v_ini_incl", "v_fin", "v_fin_incl"}.
    Una regla sin rango vale para todas las versiones del producto. Las reglas de una CVE ya
    guardada se sustituyen por las nuevas. Las entradas mal formadas (sin id o sin producto)
    se ignoran. Todo o nada: si algo falla al escribir, no queda nada a medias.
    """
    with con:
        for item in items:
            if not isinstance(item, dict) or not _texto(item.get("id")).strip():
                continue
            cve_id = item["id"].strip()
            cvss = item.get("cvss")
            cvss = float(cvss) if isinstance(cvss, (int, float)) and not isinstance(cvss, bool) else None
            con.execute("INSERT INTO cve (id, publicada, severidad, cvss, resumen) VALUES (?, ?, ?, ?, ?) "
                        "ON CONFLICT (id) DO UPDATE SET publicada = excluded.publicada, severidad = excluded.severidad, "
                        "cvss = excluded.cvss, resumen = excluded.resumen",
                        (cve_id, _texto(item.get("publicada")), _texto(item.get("severidad")), cvss,
                         _texto(item.get("resumen"))))
            con.execute("DELETE FROM cve_cpe WHERE cve_id = ?", (cve_id,))
            cpes = item.get("cpes")
            reglas = [r for r in map(_regla, cpes) if r] if isinstance(cpes, list) else []
            con.executemany("INSERT INTO cve_cpe (cve_id, parte, vendor, producto, v_ini, v_ini_incl, v_fin, v_fin_incl) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [(cve_id, *r) for r in reglas])


def _en_rango(version: str, regla) -> bool:
    if regla["v_ini"] is not None:
        orden = comparar_versiones(version, regla["v_ini"])
        if orden < 0 or (orden == 0 and not regla["v_ini_incl"]):
            return False
    if regla["v_fin"] is not None:
        orden = comparar_versiones(version, regla["v_fin"])
        if orden > 0 or (orden == 0 and not regla["v_fin_incl"]):
            return False
    return True


def cves_de(con, cpe: str) -> list[dict]:
    """CVE que afectan al CPE: casan por producto (y vendor si el cpe lo trae) y la versión cae en el rango.

    Un CPE sin versión devuelve todas las CVE del producto con `sin_version=True`. Salen sin
    repetir, de más a menos grave. Un CPE que no se entiende no devuelve nada.
    """
    partes = _parsear_cpe(cpe)
    if partes is None:
        return []
    vendor, producto, version = partes
    sql = ("SELECT c.id, c.publicada, c.severidad, c.cvss, c.resumen, r.v_ini, r.v_ini_incl, r.v_fin, r.v_fin_incl "
           "FROM cve_cpe r JOIN cve c ON c.id = r.cve_id WHERE r.producto = ?")
    parametros = [producto]
    if vendor:
        sql += " AND (r.vendor = ? OR r.vendor = '')"
        parametros.append(vendor)
    salida: dict[str, dict] = {}
    for fila in con.execute(sql + " ORDER BY c.cvss IS NULL, c.cvss DESC, c.id", parametros):
        if fila["id"] in salida or (version and not _en_rango(version, fila)):
            continue
        salida[fila["id"]] = {"id": fila["id"], "publicada": fila["publicada"], "severidad": fila["severidad"],
                              "cvss": fila["cvss"], "resumen": fila["resumen"], "sin_version": not version}
    return list(salida.values())
