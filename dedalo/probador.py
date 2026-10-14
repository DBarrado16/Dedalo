"""Los tres probadores de credenciales por defecto, con librería estándar.

Conexión directa (sin el proxy del sistema) a la red auditada; en HTTPS no se verifica el
certificado, porque los aparatos suelen llevar uno autofirmado. El alcance lo comprueba quien
llama, justo antes (credenciales.py / web.py): aquí solo se intenta un login.
"""

from __future__ import annotations

import base64
import ftplib
import ssl
import urllib.error
import urllib.parse
import urllib.request

# Sin proxy: el tráfico va a la red auditada, no a un proxy del sistema.
_SIN_PROXY = urllib.request.ProxyHandler({})
_SIN_VERIFICAR = ssl.create_default_context()
_SIN_VERIFICAR.check_hostname = False
_SIN_VERIFICAR.verify_mode = ssl.CERT_NONE


class _SinRedireccion(urllib.request.HTTPRedirectHandler):
    """No sigue los 3xx: una redirección tras el POST es, de suyo, la señal de que se entró."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _url(ip: str, objetivo: dict, ruta: str = "/") -> str:
    esquema = "https" if objetivo["https"] else "http"
    anfitrion = f"[{ip}]" if ":" in ip else ip
    return f"{esquema}://{anfitrion}:{objetivo['puerto']}{ruta}"


def _abrir(request, timeout):
    opener = urllib.request.build_opener(_SIN_PROXY, urllib.request.HTTPSHandler(context=_SIN_VERIFICAR))
    return opener.open(request, timeout=timeout)


def _http_basic(ip, objetivo, timeout) -> bool:
    token = base64.b64encode(f"{objetivo['usuario']}:{objetivo['clave']}".encode()).decode()
    request = urllib.request.Request(_url(ip, objetivo), headers={"Authorization": "Basic " + token})
    try:
        with _abrir(request, timeout) as respuesta:
            return respuesta.status < 400
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return False
        raise


def _http_form(ip, objetivo, timeout) -> bool:
    receta = objetivo.get("receta") or {}
    if not receta.get("campo_usuario") or not receta.get("campo_clave"):
        raise ValueError("la receta del formulario no dice los campos de usuario/clave")
    campos = {receta["campo_usuario"]: objetivo["usuario"], receta["campo_clave"]: objetivo["clave"],
              **(receta.get("campos_fijos") or {})}
    datos = urllib.parse.urlencode(campos).encode()
    request = urllib.request.Request(_url(ip, objetivo, receta.get("ruta", "/")), data=datos)
    exito = receta.get("exito") or {}
    # No seguimos los 3xx: una redirección tras el login es, de suyo, señal de éxito, y seguirla
    # (sin cookie) suele devolver a la propia página de login o a una zona protegida que pide auth.
    opener = urllib.request.build_opener(_SIN_PROXY, urllib.request.HTTPSHandler(context=_SIN_VERIFICAR),
                                         _SinRedireccion())
    try:
        with opener.open(request, timeout=timeout) as respuesta:
            codigo, cuerpo = respuesta.status, respuesta.read(65536).decode("utf-8", "replace").lower()
    except urllib.error.HTTPError as exc:
        codigo, cuerpo = exc.code, exc.read(65536).decode("utf-8", "replace").lower()
    if exito.get("codigo"):
        return codigo == exito["codigo"]
    redirigido = 300 <= codigo < 400
    if exito.get("texto_falla"):
        return redirigido or exito["texto_falla"].lower() not in cuerpo
    return redirigido or codigo < 400  # sin señal en la receta: entró si redirige o no hubo error


def _ftp(ip, objetivo, timeout) -> bool:
    cliente = ftplib.FTP(timeout=timeout)
    cliente.connect(ip, objetivo["puerto"])
    try:
        cliente.login(objetivo["usuario"], objetivo["clave"])
        return True
    except ftplib.error_perm:
        return False
    finally:
        try:
            cliente.close()
        except OSError:
            pass


_PROBADORES = {"http-basic": _http_basic, "http-form": _http_form, "ftp": _ftp}


def probar(ip: str, objetivo: dict, timeout: float = 8) -> bool:
    return _PROBADORES[objetivo["servicio"]](ip, objetivo, timeout)
