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


def _casa(entrada: dict, servicio: dict) -> bool:
    texto = f"{servicio.get('producto', '')} {_titulo(servicio)}".lower()
    if entrada["producto"].lower() not in texto:
        return False
    patron = entrada["version"]
    return not patron or fnmatch.fnmatch((servicio.get("version") or ""), patron)


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
