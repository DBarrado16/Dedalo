"""Credenciales por defecto: empareja el fingerprint de cada servicio con el catálogo y prueba.

No contacta con ningún objetivo: eso lo hace probador.py. Aquí solo se decide qué credenciales
tocan a cada servicio y se recorre la lista llamando a un probador que se pasa como argumento.
"""

from __future__ import annotations

import fnmatch

_WEB = {"http", "https", "http-proxy", "http-alt", "https-alt"}
_FTP = {"ftp", "ftp-data"}


def _titulo(servicio: dict) -> str:
    return next((s.get("output", "") for s in servicio.get("scripts", []) if s.get("id") == "http-title"), "")


def es_https(servicio: dict) -> bool:
    return servicio.get("tunel") == "ssl" or servicio.get("servicio") == "https" or servicio.get("puerto") == 443


def tipos_de(servicio: dict) -> set[str]:
    if servicio.get("protocolo") != "tcp":
        return set()
    if servicio.get("servicio") in _WEB or servicio.get("tunel") == "ssl" or _titulo(servicio):
        return {"http-basic", "http-form"}
    if servicio.get("servicio") in _FTP or servicio.get("puerto") == 21:
        return {"ftp"}
    return set()


def _coincide(entrada: dict, producto: str, version: str) -> bool:
    if entrada["producto"].lower() not in producto.lower():
        return False
    patron = entrada["version"]
    return not patron or fnmatch.fnmatch(version or "", patron)


def _casa(entrada: dict, servicio: dict) -> bool:
    """Casa con lo que vio Nmap o con cualquier lectura de la captura (gowitness o IA)."""
    titulo = _titulo(servicio)
    if _coincide(entrada, f"{servicio.get('producto', '')} {titulo}", servicio.get("version") or ""):
        return True
    for lectura in servicio.get("lecturas", []):
        if _coincide(entrada, f"{lectura.get('producto', '')} {titulo}", lectura.get("version") or ""):
            return True
    return False


def objetivos(activo: dict, entradas: list[dict]) -> list[dict]:
    """Por cada servicio del activo, las credenciales del catálogo que le pegan (tipo, producto y versión)."""
    salida = []
    for servicio in activo.get("servicios", []):
        tipos = tipos_de(servicio)
        for entrada in entradas:
            if entrada["servicio"] in tipos and _casa(entrada, servicio):
                salida.append({"puerto": servicio["puerto"], "protocolo": servicio.get("protocolo", "tcp"),
                               "servicio": entrada["servicio"], "https": es_https(servicio),
                               "usuario": entrada["usuario"], "clave": entrada["clave"], "receta": entrada["receta"]})
    return salida


class Interrumpido(Exception):
    """Se pidió parar la prueba de credenciales (por ejemplo, porque se cierra el portal)."""


def probar_activos(activos, entradas, probar, parar=lambda: False, avance=lambda hechos, total: None,
                   intentos=5, pausa=lambda: None) -> list[dict]:
    """Prueba, servicio por servicio, las credenciales que le tocan; una fila de resultado por servicio."""
    # Un servicio puede tener varias credenciales; se agrupan para contar «servicios», no intentos.
    por_servicio: dict = {}
    for activo in activos:
        for obj in objetivos(activo, entradas):
            por_servicio.setdefault((activo["ip"], obj["puerto"], obj["servicio"]), []).append(obj)
    filas, total = [], len(por_servicio)
    avance(0, total)
    for (ip, puerto, servicio), objs in por_servicio.items():
        if parar():
            raise Interrumpido()
        fila = {"ip": ip, "puerto": puerto, "protocolo": objs[0]["protocolo"], "servicio": servicio,
                "estado": "fallo", "usuario": "", "clave": "", "detalle": ""}
        for numero, obj in enumerate(objs):
            if numero >= intentos:
                fila["detalle"] = f"Se abandonó tras {intentos} intentos sin entrar."
                break
            if numero:
                pausa()
            try:
                if probar(ip, obj):
                    fila.update(estado="entrada", usuario=obj["usuario"], clave=obj["clave"])
                    break
            except Exception as exc:  # servicio caído, receta inservible: ese servicio queda en error
                fila.update(estado="error", detalle=str(exc))
                break
        filas.append(fila)
        avance(len(filas), total)
    return [fila | {"orden": orden} for orden, fila in enumerate(_ordenar(filas))]


def _ordenar(filas):
    # Lo importante arriba: primero donde se entró, luego por IP y puerto.
    prioridad = {"entrada": 0, "fallo": 1, "error": 1}
    return sorted(filas, key=lambda f: (prioridad[f["estado"]], f["ip"], f["puerto"]))
