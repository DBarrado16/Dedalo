"""Catálogo curado de credenciales por defecto: fichero versionado volcado a SQLite.

La fuente de verdad es dedalo/datos/credenciales.json (revisable en git, licencia auditable).
Al arrancar se vuelca a la tabla credencial_catalogo; se recarga solo si el fichero cambió.
No contacta con nada.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

RUTA = Path(__file__).resolve().parent / "datos" / "credenciales.json"
SERVICIOS = ("http-basic", "http-form", "ftp")
_CAMPOS = ("fabricante", "producto", "version", "servicio", "usuario", "clave", "receta", "fuente", "licencia")


def _filas(datos: dict):
    """Una fila por credencial de cada entrada válida; las entradas mal formadas se ignoran."""
    for entrada in datos.get("entradas", []):
        if not isinstance(entrada, dict):
            continue
        producto, servicio = entrada.get("producto"), entrada.get("servicio")
        if not isinstance(producto, str) or not producto or servicio not in SERVICIOS:
            continue
        receta = json.dumps(entrada["receta"], ensure_ascii=False) if isinstance(entrada.get("receta"), dict) else ""
        for cred in entrada.get("credenciales", []):
            if not isinstance(cred, dict) or not isinstance(cred.get("usuario"), str) or not isinstance(cred.get("clave"), str):
                continue
            yield (entrada.get("fabricante", ""), producto, entrada.get("version", ""), servicio,
                   cred["usuario"], cred["clave"], receta, entrada.get("fuente", ""), entrada.get("licencia", ""))


def cargar(con, ruta: Path = RUTA) -> int:
    """Vuelca el fichero a credencial_catalogo si su huella cambió; devuelve cuántas filas cargó (0 si no recargó)."""
    datos = ruta.read_bytes()
    huella = hashlib.sha256(datos).hexdigest()
    guardada = con.execute("SELECT valor FROM config WHERE clave = 'catalogo_huella'").fetchone()
    if guardada and guardada[0] == huella:
        return 0
    filas = list(_filas(json.loads(datos)))
    with con:
        con.execute("DELETE FROM credencial_catalogo")
        con.executemany("INSERT INTO credencial_catalogo (fabricante, producto, version, servicio, usuario, clave, "
                        "receta, fuente, licencia) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", filas)
        con.execute("INSERT INTO config (clave, valor) VALUES ('catalogo_huella', ?) "
                    "ON CONFLICT (clave) DO UPDATE SET valor = excluded.valor", (huella,))
    return len(filas)


def entradas(con) -> list[dict]:
    filas = con.execute(f"SELECT {', '.join(_CAMPOS)} FROM credencial_catalogo ORDER BY id").fetchall()
    return [{**dict(fila), "receta": json.loads(fila["receta"]) if fila["receta"] else None} for fila in filas]


def _valida(entrada: dict) -> None:
    if not isinstance(entrada.get("producto"), str) or not entrada["producto"]:
        raise ValueError("La entrada necesita un producto.")
    if entrada.get("servicio") not in SERVICIOS:
        raise ValueError(f"Servicio no admitido: {entrada.get('servicio')!r}")
    creds = entrada.get("credenciales")
    if not isinstance(creds, list) or not creds:
        raise ValueError("La entrada necesita al menos una credencial.")
    for cred in creds:
        if not isinstance(cred, dict) or not isinstance(cred.get("usuario"), str) or not isinstance(cred.get("clave"), str):
            raise ValueError("Cada credencial necesita usuario y clave de texto.")
    if "receta" in entrada and not isinstance(entrada["receta"], dict):
        raise ValueError("La receta debe ser un objeto.")


def agregar(ruta: Path, entrada: dict) -> None:
    """Mete o fusiona una entrada en el catálogo (credenciales.json), de forma atómica.

    Si ya hay una entrada con el mismo (fabricante, producto, version, servicio), añade las
    credenciales que falten; si no, crea una entrada nueva. Valida antes de tocar el fichero;
    si algo no cuadra, lanza ValueError y no escribe nada.
    """
    _valida(entrada)
    ruta = Path(ruta)
    datos = json.loads(ruta.read_text("utf-8"))
    lista = datos.setdefault("entradas", [])
    clave = (entrada.get("fabricante", ""), entrada["producto"], entrada.get("version", ""), entrada["servicio"])
    existente = next((e for e in lista if (e.get("fabricante", ""), e.get("producto"),
                                           e.get("version", ""), e.get("servicio")) == clave), None)
    if existente is not None:
        actuales = existente.setdefault("credenciales", [])
        for cred in entrada["credenciales"]:
            if cred not in actuales:
                actuales.append(cred)
    else:
        nueva = {"fabricante": entrada.get("fabricante", ""), "producto": entrada["producto"],
                 "version": entrada.get("version", ""), "servicio": entrada["servicio"],
                 "credenciales": list(entrada["credenciales"]),
                 "fuente": entrada.get("fuente", ""), "licencia": entrada.get("licencia", "")}
        if isinstance(entrada.get("receta"), dict):
            nueva["receta"] = entrada["receta"]
        lista.append(nueva)
    tmp = ruta.with_name(ruta.name + ".tmp")
    tmp.write_text(json.dumps(datos, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, ruta)
