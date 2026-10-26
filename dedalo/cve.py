"""Base local de CVE: reglas de aplicabilidad por CPE guardadas en SQLite y consulta por producto y versión.

Consultar y guardar solo tocan la base (tablas cve y cve_cpe). Las únicas salidas a internet son
`actualizar_base` (feeds de la NVD) y `consultar_online` (API de la NVD), y las dos son no-op con el
interruptor `sin_internet`. Ambas convierten lo descargado al formato de `guardar_cves`.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import gzip
import http.client
import json
from pathlib import Path
import re
import urllib.parse
from urllib.parse import unquote
import zlib

from . import internet
from .auditoria import get_config, set_config

# Formato 2.0 de la NVD (el mismo en los feeds y en la API). Si cambia, se cambia aquí.
NVD_FEED_ANUAL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{anio}.json.gz"
NVD_FEED_MODIFICADA = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ANIOS_BASE = 10  # la base inicial cubre los últimos 10 años
DIAS_INCREMENTAL = 7  # el feed de modificadas cubre ~8 días; con una marca más vieja se baja todo
MAX_DESCARGA = 400 << 20  # tope de un feed comprimido
MAX_DESCOMPRIMIDO = 2 << 30  # tope de un feed ya descomprimido
MAX_RESPUESTA_API = 32 << 20  # tope de una respuesta de la API


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


def cpe_desde_deteccion(producto: str, version: str) -> str | None:
    """CPE 2.2 `cpe:/a:*:<producto>:<versión>` a partir del producto y la versión detectados; None sin producto.

    El vendor va como comodín: `cves_de` casa entonces solo por producto. Producto en minúsculas, con
    espacios (y `:`, que partiría el CPE) como `_`. Una versión vacía sale como `*`. Qué confianza basta
    para construirlo lo decide quien llama.
    """
    def limpio(valor) -> str:
        return re.sub(r"[\s:]+", "_", valor.strip().lower()) if isinstance(valor, str) else ""

    producto = limpio(producto)
    return f"cpe:/a:*:{producto}:{limpio(version) or '*'}" if producto else None


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

    El vendor solo filtra si la base lo conoce para ese producto: Nmap y la NVD no siempre lo llaman igual
    (nginx: `igor_sysoev` frente a `f5`; vsftpd: `vsftpd` frente a `beasts`), y uno que la NVD no tiene casa
    entonces solo por producto. Un CPE sin versión devuelve todas las CVE del producto con `sin_version=True`.
    Salen sin repetir, de más a menos grave. Un CPE que no se entiende no devuelve nada.
    """
    partes = _parsear_cpe(cpe)
    if partes is None:
        return []
    vendor, producto, version = partes
    sql = ("SELECT c.id, c.publicada, c.severidad, c.cvss, c.resumen, r.v_ini, r.v_ini_incl, r.v_fin, r.v_fin_incl "
           "FROM cve_cpe r JOIN cve c ON c.id = r.cve_id WHERE r.producto = ?")
    parametros = [producto]
    if vendor and con.execute("SELECT 1 FROM cve_cpe WHERE producto = ? AND vendor = ? LIMIT 1",
                              (producto, vendor)).fetchone():
        sql += " AND (r.vendor = ? OR r.vendor = '')"
        parametros.append(vendor)
    salida: dict[str, dict] = {}
    for fila in con.execute(sql + " ORDER BY c.cvss IS NULL, c.cvss DESC, c.id", parametros):
        if fila["id"] in salida or (version and not _en_rango(version, fila)):
            continue
        salida[fila["id"]] = {"id": fila["id"], "publicada": fila["publicada"], "severidad": fila["severidad"],
                              "cvss": fila["cvss"], "resumen": fila["resumen"], "sin_version": not version}
    return list(salida.values())


def producto_conocido(con, cpe: str) -> bool:
    """Si la base local tiene alguna regla para el producto del CPE (sea cual sea su versión o su vendor)."""
    partes = _parsear_cpe(cpe)
    if partes is None:
        return False
    return con.execute("SELECT 1 FROM cve_cpe WHERE producto = ? LIMIT 1", (partes[1],)).fetchone() is not None


# --- Salidas a internet: formato 2.0 de la NVD -> formato de `guardar_cves` ---

def _campos_cpe23(criterio: str) -> list[str]:
    """Campos de un CPE 2.3 (`cpe:2.3:parte:vendor:producto:versión:...`) sin los escapes de `\\:` y similares."""
    return [re.sub(r"\\(.)", r"\1", c) for c in re.split(r"(?<!\\):", criterio.strip())]


def _sin_comodin(valor: str) -> str:
    valor = valor.strip().lower()
    return "" if valor in ("*", "-") else valor


def _regla_nvd(coincidencia):
    """Regla de cve_cpe de un `cpeMatch` de la NVD; None si no es vulnerable o no se entiende.

    Con rango (`versionStart*`/`versionEnd*`) se copia tal cual. Con una versión concreta en el CPE y sin
    rango, la regla es el rango cerrado `v_ini = v_fin = versión`: sin rango, `cves_de` la leería como
    «todas las versiones del producto». Con `*` o `-` de versión y sin rango sí vale para todas.
    """
    if not isinstance(coincidencia, dict) or coincidencia.get("vulnerable") is not True:
        return None
    criterio = coincidencia.get("criteria")
    campos = _campos_cpe23(criterio) if isinstance(criterio, str) else []
    if len(campos) < 6 or campos[0].lower() != "cpe" or campos[1] != "2.3" or not _sin_comodin(campos[4]):
        return None
    regla = {"parte": _sin_comodin(campos[2]), "vendor": _sin_comodin(campos[3]), "producto": _sin_comodin(campos[4]),
             "v_ini": None, "v_ini_incl": 0, "v_fin": None, "v_fin_incl": 0}
    ini_incl, ini_excl = coincidencia.get("versionStartIncluding"), coincidencia.get("versionStartExcluding")
    fin_incl, fin_excl = coincidencia.get("versionEndIncluding"), coincidencia.get("versionEndExcluding")
    if any(isinstance(v, str) and v.strip() for v in (ini_incl, ini_excl, fin_incl, fin_excl)):
        regla["v_ini"], regla["v_ini_incl"] = (ini_incl, 1) if ini_incl else (ini_excl, 0)
        regla["v_fin"], regla["v_fin_incl"] = (fin_incl, 1) if fin_incl else (fin_excl, 0)
    elif _sin_comodin(campos[5]):
        regla["v_ini"] = regla["v_fin"] = _sin_comodin(campos[5])
        regla["v_ini_incl"] = regla["v_fin_incl"] = 1
    return regla


def _metrica_nvd(metricas) -> tuple[str, float | None]:
    """(severidad, puntuación base) de la métrica CVSS más nueva disponible; ("", None) si no hay."""
    if not isinstance(metricas, dict):
        return "", None
    for clave in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        lista = [m for m in metricas.get(clave) or [] if isinstance(m, dict)] if isinstance(metricas.get(clave), list) else []
        if not lista:
            continue
        metrica = next((m for m in lista if m.get("type") == "Primary"), lista[0])
        datos = metrica.get("cvssData") if isinstance(metrica.get("cvssData"), dict) else {}
        puntuacion = datos.get("baseScore")
        puntuacion = float(puntuacion) if isinstance(puntuacion, (int, float)) and not isinstance(puntuacion, bool) else None
        return _texto(datos.get("baseSeverity") or metrica.get("baseSeverity")).strip().upper(), puntuacion
    return "", None


def item_desde_nvd(entrada) -> dict | None:
    """Convierte una entrada `{"cve": {...}}` del formato 2.0 de la NVD al item de `guardar_cves`.

    None si está mal formada, sin id o rechazada por la NVD. Solo cuentan los `cpeMatch` vulnerables.
    """
    cve_nvd = entrada.get("cve") if isinstance(entrada, dict) else None
    if not isinstance(cve_nvd, dict) or not _texto(cve_nvd.get("id")).strip() or cve_nvd.get("vulnStatus") == "Rejected":
        return None
    descripciones = [d for d in cve_nvd.get("descriptions") or [] if isinstance(d, dict) and _texto(d.get("value"))] \
        if isinstance(cve_nvd.get("descriptions"), list) else []
    descripcion = next((d for d in descripciones if d.get("lang") == "en"), descripciones[0] if descripciones else {})
    severidad, cvss = _metrica_nvd(cve_nvd.get("metrics"))
    reglas: list[dict] = []
    for configuracion in cve_nvd.get("configurations") or [] if isinstance(cve_nvd.get("configurations"), list) else []:
        nodos = configuracion.get("nodes") if isinstance(configuracion, dict) else None
        for nodo in nodos if isinstance(nodos, list) else []:
            coincidencias = nodo.get("cpeMatch") if isinstance(nodo, dict) else None
            for coincidencia in coincidencias if isinstance(coincidencias, list) else []:
                regla = _regla_nvd(coincidencia)
                if regla and regla not in reglas:
                    reglas.append(regla)
    return {"id": cve_nvd["id"].strip(), "publicada": _texto(cve_nvd.get("published")), "severidad": severidad,
            "cvss": cvss, "resumen": _texto(descripcion.get("value")), "cpes": reglas}


def _items_de_json(texto: str) -> list[dict]:
    """Items de `guardar_cves` de un JSON de la NVD (`{"vulnerabilities": [...]}`); ValueError si no lo es."""
    datos = json.loads(texto)
    vulnerabilidades = datos.get("vulnerabilities") if isinstance(datos, dict) else None
    if not isinstance(vulnerabilidades, list):
        raise ValueError("el JSON de la NVD no trae «vulnerabilities»")
    return [item for item in map(item_desde_nvd, vulnerabilidades) if item]


def _leer_feed(ruta: Path) -> list[dict]:
    """Items de un feed descargado, comprimido (gzip) o no, con o sin BOM."""
    with ruta.open("rb") as f:
        gz = f.read(2) == b"\x1f\x8b"
    with (gzip.open(ruta, "rb") if gz else ruta.open("rb")) as f:
        crudo = f.read(MAX_DESCOMPRIMIDO + 1)
    if len(crudo) > MAX_DESCOMPRIMIDO:
        raise ValueError("el feed descomprimido es mayor de lo esperado")
    texto = crudo.decode("utf-8-sig")
    del crudo  # los bytes ya no hacen falta: que no sigan en memoria mientras se parsea el JSON
    return _items_de_json(texto)


def _marca(con, clave: str) -> datetime | None:
    """La fecha guardada en `config.<clave>` (en UTC si no trae zona); None si falta o no se entiende."""
    try:
        fecha = datetime.fromisoformat(get_config(con, clave) or "")
    except ValueError:
        return None
    return fecha if fecha.tzinfo else fecha.replace(tzinfo=timezone.utc)


def _marca_reciente(con, clave: str, ahora: datetime, vigencia: timedelta) -> bool:
    """Si la fecha de `config.<clave>` es de hace menos de `vigencia` (una fecha futura no vale)."""
    fecha = _marca(con, clave)
    return fecha is not None and timedelta(0) <= ahora - fecha < vigencia


def base_reciente(con, ahora: datetime, vigencia: timedelta) -> bool:
    """Si la base local de la NVD se completó hace menos de `vigencia` (marca `config.nvd_actualizada`)."""
    return _marca_reciente(con, "nvd_actualizada", ahora, vigencia)


def actualizar_base(con, destino: str | Path, sin_internet: bool, log=print) -> None:
    """Descarga los feeds de la NVD a `destino`, los vuelca en la base y anota `config.nvd_actualizada`.

    Con `sin_internet` no hace nada (ni crea `destino`). Con una actualización de hace menos de una semana, solo baja
    el feed de modificadas; si no, los feeds anuales de los últimos 10 años. Cada feed anual importado bien queda
    anotado en `config.nvd_feed_<año>`, y un reintento dentro de esa semana no lo vuelve a bajar. Un feed que falla
    se salta (y se cuenta en `log`): lo bueno queda guardado, pero la base no se marca como actualizada hasta tenerlos
    todos, y entonces con la fecha del feed más viejo (desde ahí tendrán que cubrir las modificadas).
    Los ficheros descargados se borran al terminar.
    """
    if sin_internet:
        return
    ahora = datetime.now(timezone.utc)
    vigencia = timedelta(days=DIAS_INCREMENTAL)
    carpeta = Path(destino)
    carpeta.mkdir(parents=True, exist_ok=True)
    incremental = base_reciente(con, ahora, vigencia)
    anuales = [str(anio) for anio in range(ahora.year - ANIOS_BASE + 1, ahora.year + 1)]
    if incremental:
        feeds = [("modificadas", NVD_FEED_MODIFICADA)]
    else:  # menos los que ya se bajaron bien hace poco: un reintento tras un fallo no repite los buenos
        feeds = [(anio, NVD_FEED_ANUAL.format(anio=anio)) for anio in anuales
                 if not _marca_reciente(con, f"nvd_feed_{anio}", ahora, vigencia)]
    fallos = 0
    for nombre, url in feeds:
        ruta = carpeta / f"nvd-{nombre}.json.gz"
        log(f"Descargando el feed «{nombre}» de la NVD...")
        try:
            internet.descargar(url, ruta, MAX_DESCARGA)
            items = _leer_feed(ruta)
        except (OSError, ValueError, EOFError, zlib.error, http.client.HTTPException) as exc:
            fallos += 1
            log(f"No se pudo importar el feed «{nombre}» de la NVD: {exc}")
            continue
        finally:
            ruta.unlink(missing_ok=True)
        guardar_cves(con, items)
        if not incremental:
            set_config(con, f"nvd_feed_{nombre}", ahora.isoformat(timespec="seconds"))
        log(f"Feed «{nombre}»: {len(items)} CVE guardadas.")
    if fallos:
        log("Actualización de la NVD incompleta; se reintentará la próxima vez.")
        return
    desde = ahora if incremental else min(_marca(con, f"nvd_feed_{anio}") for anio in anuales)
    set_config(con, "nvd_actualizada", desde.isoformat(timespec="seconds"))


def consultar_online(cpe: str, sin_internet: bool) -> list[dict] | None:
    """CVE del CPE según la API de la NVD, en el formato de `guardar_cves`.

    Devuelve `None` si NO se pudo consultar: CPE ilegible, error de red o HTTP (403/429/503 incluidos),
    respuesta ilegible o mayor que el tope, o resultado truncado (más CVE de las que caben en la página).
    Devuelve `[]` solo si la consulta fue correcta y la NVD no dio ninguna CVE, o si `sin_internet` está
    activo (no se consulta nada: tampoco hay datos). Así quien llama distingue «sin datos» de «sin vulnerabilidades».

    Es el respaldo cuando la base local no basta (no tiene el producto o no está completa). Consulta por
    `virtualMatchString`, que también casa con los rangos de versión. Quien llama decide el alcance antes: el CPE
    de un activo excluido no debe llegar aquí.
    """
    if sin_internet:
        return []
    partes = _parsear_cpe(cpe)
    if partes is None:
        return None
    vendor, producto, version = partes
    parte = (re.match(r"cpe:(?:2\.3:|/)([aoh])\b", cpe.strip().lower()) or [None, "a"])[1]
    consulta = urllib.parse.urlencode({"virtualMatchString": f"cpe:2.3:{parte}:{vendor or '*'}:{producto}:{version or '*'}",
                                       "resultsPerPage": 500})
    datos = internet.leer_json(f"{NVD_API_URL}?{consulta}", MAX_RESPUESTA_API)
    vulnerabilidades = datos.get("vulnerabilities") if isinstance(datos, dict) else None
    if not isinstance(vulnerabilidades, list):
        return None
    total = datos.get("totalResults")
    if isinstance(total, int) and not isinstance(total, bool) and total > len(vulnerabilidades):
        return None  # la NVD tiene más CVE de las que devolvió: un resultado truncado no vale como respuesta
    return [item for item in map(item_desde_nvd, vulnerabilidades) if item]
