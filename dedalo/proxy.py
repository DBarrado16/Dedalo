"""Proxy local de alcance para el navegador de la captura (docs/CONTRATOS.md 0.3).

Este módulo trae la regla de paso, las fuentes de alcance y el servidor del proxy,
que se apoya en ellas para decidir, justo antes de conectar, si una IP se contacta."""

from __future__ import annotations

import ipaddress
import json
import re
import selectors
import socket
import socketserver
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import targets

EXCLUIDA = "excluida"
FUERA = "fuera_de_alcance"
ILEGIBLE = "alcance_ilegible"

# Espera total máxima ante un alcance vivo a medias de escribir o reemplazar.
_REINTENTO_TOTAL = 0.2
_REINTENTO_PAUSA = 0.02


def decidir(ip: str, alcance: targets.Scope | None) -> str | None:
    """Motivo por el que NO se contacta con `ip`, o None si pasa.

    Orden: excluida corta; en alcance pasa; una IP pública pasa; el resto corta.
    Sin alcance legible no pasa nada, tampoco lo público (falla en cerrado)."""
    if alcance is None:
        return ILEGIBLE
    estado = alcance.status(ip)
    if estado == alcance.EXCLUDED:
        return EXCLUIDA
    if estado == alcance.IN:
        return None
    direccion = ipaddress.ip_address(ip)
    # ::ffff:a.b.c.d llega al mismo equipo que a.b.c.d: se juzga como IPv4.
    direccion = getattr(direccion, "ipv4_mapped", None) or direccion
    return None if direccion.is_global else FUERA


def elegir_ip(direcciones: list[str], alcance: targets.Scope | None) -> tuple[str | None, str | None]:
    """Primera IP que pasa la regla y, si ninguna, el motivo de la primera (None si no hay ninguna)."""
    primer_motivo = None
    for ip in direcciones:
        motivo = decidir(ip, alcance)
        if motivo is None:
            return ip, None
        if primer_motivo is None:
            primer_motivo = motivo
    return None, primer_motivo


def alcance_de_consola(ips_objetivo: list[str], rangos: list[str], solo_rangos: bool,
                       excluidos: list[str]) -> targets.Scope:
    """Alcance de una captura lanzada por consola: sus IP objetivo (como /32 o /128),
    más los rangos si se pidió limitarse a ellos, menos lo excluido."""
    incluir = [str(ipaddress.ip_network(ip)) for ip in ips_objetivo]
    if solo_rangos:
        incluir += list(rangos)
    return targets.Scope(incluir, list(excluidos))


class AlcanceFijo:
    """Alcance que no cambia durante la captura."""

    def __init__(self, scope: targets.Scope):
        self._scope = scope

    def actual(self) -> targets.Scope:
        return self._scope


class AlcanceVivo:
    """Alcance vigente leído de un fichero (el de `web.write_live_scope`), que se relee si cambia."""

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._firma = None
        self._scope = None

    def actual(self) -> targets.Scope | None:
        """El alcance vigente, o None si el fichero no se puede leer (entonces se corta todo)."""
        limite = time.monotonic() + _REINTENTO_TOTAL
        while True:
            try:
                estado = self._path.stat()
                firma = (estado.st_mtime_ns, estado.st_size)
                if firma != self._firma or self._scope is None:
                    datos = json.loads(self._path.read_text(encoding="utf-8"))
                    self._scope = targets.Scope(datos["incluir"], datos["excluir"])
                    self._firma = firma
                return self._scope
            except (OSError, ValueError, KeyError, TypeError):
                # Lo último leído ya no vale: si sigue ilegible, no se contacta con nadie.
                self._firma = None
                self._scope = None
                if time.monotonic() >= limite:
                    return None
                time.sleep(_REINTENTO_PAUSA)


# --- Servidor del proxy ---

_TOPE_CABECERAS = 64 * 1024
_BLOQUE = 64 * 1024
# Cabeceras de salto: son para el proxy y no llegan al servidor (tampoco las que nombre `Connection`).
_DE_SALTO = {"connection", "proxy-connection", "keep-alive", "proxy-authorization"}
_IMPRESCINDIBLES = {"host", "content-length", "transfer-encoding"}
_NOMBRE_CABECERA = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
# Nombre de equipo o IP (IPv6 con zona incluida); lo demás no se resuelve ni se conecta.
_HOST = re.compile(r"[A-Za-z0-9._%:-]+")
_PUERTO = re.compile(r"[0-9]{1,5}")
_VERSION = re.compile(r"HTTP/1\.[01]")


def _respuesta(codigo: int, texto: str) -> bytes:
    """Respuesta del propio proxy: sin cuerpo y cerrando la conexión."""
    return f"HTTP/1.1 {codigo} {texto}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("ascii")


_CORTADA = _respuesta(403, "Forbidden")
_SIN_CONEXION = _respuesta(502, "Bad Gateway")
_NO_VALIDA = _respuesta(400, "Bad Request")
_TUNEL_ABIERTO = b"HTTP/1.1 200 Connection Established\r\n\r\n"


class _PeticionNoValida(ValueError):
    """La petición del navegador no se entiende: se responde 400."""


class _SinPeticion(Exception):
    """El cliente cerró, o no pidió nada a tiempo: no hay a quién responder."""


class _Peticion:
    """A qué host y puerto quiere ir el navegador y qué se manda al servidor al conectar.

    `reenvio` es None en un CONNECT (túnel de bytes); en HTTP es la cabecera ya en forma de
    origen. `cuerpo` son los bytes del cliente que van tras ella (None: hasta que cierre)."""

    def __init__(self, host: str, puerto: int, reenvio: bytes | None = None, cuerpo: int | None = None):
        self.host = host
        self.puerto = puerto
        self.reenvio = reenvio
        self.cuerpo = cuerpo

    @property
    def destino(self) -> str:
        """`host:puerto` tal como lo pidió el navegador (IPv6 entre corchetes)."""
        return f"[{self.host}]:{self.puerto}" if ":" in self.host else f"{self.host}:{self.puerto}"


def _es_ip(texto: str) -> bool:
    try:
        ipaddress.ip_address(texto)
    except ValueError:
        return False
    return True


def _puerto(numero: int | None) -> int:
    if numero is None or not 1 <= numero <= 65535:
        raise _PeticionNoValida("puerto no válido")
    return numero


def _host(texto: str | None) -> str:
    if not texto or not _HOST.fullmatch(texto):
        raise _PeticionNoValida("host no válido")
    return texto


def _analizar(cabecera: bytes) -> _Peticion:
    """`CONNECT host:puerto` o una petición HTTP con URL absoluta; lo demás no vale."""
    lineas = cabecera.decode("latin-1").split("\r\n")
    partes = lineas[0].split(" ")
    if len(partes) != 3 or not _VERSION.fullmatch(partes[2]):
        raise _PeticionNoValida("línea de petición no válida")
    metodo, objetivo, version = partes
    campos = []
    for linea in lineas[1:]:
        nombre, dos_puntos, valor = linea.partition(":")
        if not dos_puntos or not _NOMBRE_CABECERA.fullmatch(nombre):
            raise _PeticionNoValida("cabecera no válida")
        campos.append((nombre, valor.strip(" \t")))

    if metodo == "CONNECT":
        host, _, puerto = objetivo.rpartition(":")
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        return _Peticion(_host(host), _puerto(int(puerto) if _PUERTO.fullmatch(puerto) else None))

    # Ni espacios ni controles: urlsplit los quitaría y la ruta reenviada sería otra.
    if objetivo[:7].lower() != "http://" or any(c <= " " or c == "\x7f" for c in objetivo):
        raise _PeticionNoValida("se espera una URL http:// absoluta")
    url = urlsplit(objetivo)
    try:
        numero = 80 if url.port is None else url.port
    except ValueError:
        numero = None
    host, puerto = _host(url.hostname), _puerto(numero)
    ruta = objetivo.partition("#")[0][7 + len(url.netloc):]
    if not ruta.startswith("/"):
        ruta = "/" + ruta

    nombres = {nombre.lower() for nombre, _ in campos}
    if "transfer-encoding" in nombres:
        cuerpo = None
    else:
        longitudes = {valor for nombre, valor in campos if nombre.lower() == "content-length"}
        if not longitudes:
            cuerpo = 0
        elif len(longitudes) == 1 and (valor := longitudes.pop()).isascii() and valor.isdigit():
            cuerpo = int(valor)
        else:
            raise _PeticionNoValida("Content-Length no válido")

    saltos = set(_DE_SALTO)
    for nombre, valor in campos:
        if nombre.lower() == "connection":
            saltos.update(t.strip().lower() for t in valor.split(","))
    saltos -= _IMPRESCINDIBLES
    salida = [f"{metodo} {ruta} {version}"]
    if "host" not in nombres:
        salida.append(f"Host: {url.netloc.rpartition('@')[2]}")
    salida += [f"{nombre}: {valor}" for nombre, valor in campos if nombre.lower() not in saltos]
    salida.append("Connection: close")  # una petición por conexión: el servidor cierra al responder
    reenvio = ("\r\n".join(salida) + "\r\n\r\n").encode("latin-1")
    return _Peticion(host, puerto, reenvio, cuerpo)


def _tunel(cliente: socket.socket, servidor: socket.socket, cuerpo: int | None) -> None:
    """Pasa bytes en los dos sentidos hasta que cualquiera de los dos lados cierre.

    `cuerpo`: bytes del cliente que aún se reenvían (None: sin tope). Lo que el cliente
    mande de más se descarta: en HTTP sería otra petición, quizá para otro servidor."""
    with selectors.DefaultSelector() as selector:
        selector.register(cliente, selectors.EVENT_READ, servidor)
        selector.register(servidor, selectors.EVENT_READ, cliente)
        while True:
            for clave, _ in selector.select():
                origen, destino = clave.fileobj, clave.data
                try:
                    datos = origen.recv(_BLOQUE)
                except OSError:
                    return
                if not datos:
                    return
                if origen is cliente and cuerpo is not None:
                    datos = datos[:cuerpo]
                    cuerpo -= len(datos)
                if datos:
                    try:
                        destino.sendall(datos)
                    except OSError:
                        return


class _Servidor(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self, proxy: Proxy):
        self.proxy = proxy
        super().__init__(("127.0.0.1", 0), _Atencion)


class _Atencion(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.server.proxy._atender(self.request)
        except OSError:
            pass  # el navegador o el servidor se fueron a mitad: no queda a quién responder


class Proxy:
    """Proxy HTTP local para el navegador de la captura: solo conecta con lo que pasa la regla.

    Cada conexión se decide justo antes de conectar, con el alcance de ese momento, y va a
    la IP comprobada (nunca se vuelve a resolver). Lo cortado recibe 403 y lo que no se pudo
    conectar, 502, los dos sin cuerpo y anotados en el registro en curso. `timeout` es el de
    conexión con el servidor y el tope para recibir la cabecera del navegador."""

    def __init__(self, alcance, timeout: float, resolver=socket.getaddrinfo,
                 conectar=socket.create_connection):
        self._alcance = alcance
        self._timeout = timeout
        self._resolver = resolver
        self._conectar = conectar
        self._cerrojo_alcance = threading.Lock()   # AlcanceVivo no es seguro entre hilos
        self._cerrojo_registro = threading.Lock()
        self._registro: Path | None = None
        self._servidor: _Servidor | None = None
        self._hilo: threading.Thread | None = None

    def iniciar(self) -> int:
        """Escucha en 127.0.0.1, en un puerto que elige el sistema, y lo devuelve."""
        if self._servidor is not None:
            raise RuntimeError("el proxy ya está en marcha")
        self._servidor = _Servidor(self)
        self._hilo = threading.Thread(target=self._servidor.serve_forever, kwargs={"poll_interval": 0.05},
                                      name="dedalo-proxy", daemon=True)
        self._hilo.start()
        return self._servidor.server_address[1]

    def parar(self) -> None:
        """Deja de aceptar conexiones; los túneles abiertos acaban cuando cierra uno de sus lados."""
        servidor, self._servidor = self._servidor, None
        if servidor is None:
            return
        servidor.shutdown()
        servidor.server_close()
        self._hilo.join()

    @property
    def url(self) -> str:
        if self._servidor is None:
            raise RuntimeError("el proxy no está en marcha")
        return f"http://127.0.0.1:{self._servidor.server_address[1]}"

    def registro(self, path: str | Path | None) -> None:
        """Fichero JSON Lines donde se anotan, desde ahora, los cortes y fallos (None: no anotar)."""
        with self._cerrojo_registro:
            self._registro = Path(path) if path is not None else None

    def _anotar(self, linea: dict) -> None:
        with self._cerrojo_registro:
            if self._registro is None:
                return
            try:
                with open(self._registro, "a", encoding="utf-8", newline="\n") as fichero:
                    fichero.write(json.dumps(linea, ensure_ascii=False) + "\n")
            except OSError as error:
                # Sin registro se sigue cortando igual; solo se pierde la anotación.
                print(f"Proxy: no se pudo anotar en {self._registro}: {error}", file=sys.stderr)

    def _leer_cabecera(self, cliente: socket.socket) -> tuple[bytes, bytes]:
        """Cabecera de la petición (sin la línea en blanco final) y lo que llegó tras ella."""
        limite = time.monotonic() + self._timeout
        datos = b""
        while True:
            fin = datos.find(b"\r\n\r\n")
            if fin >= 0:
                if fin + 4 > _TOPE_CABECERAS:
                    raise _PeticionNoValida("cabecera demasiado grande")
                return datos[:fin], datos[fin + 4:]
            if len(datos) >= _TOPE_CABECERAS:
                raise _PeticionNoValida("cabecera demasiado grande")
            resta = limite - time.monotonic()
            if resta <= 0:
                break
            cliente.settimeout(resta)
            try:
                bloque = cliente.recv(_BLOQUE)
            except TimeoutError:
                break
            if not bloque:
                raise _SinPeticion()
            datos += bloque
        # Venció el tiempo: una conexión abierta de antemano y sin usar se cierra sin más.
        if not datos:
            raise _SinPeticion()
        raise _PeticionNoValida("cabecera incompleta")

    def _direcciones(self, host: str, puerto: int) -> list[str]:
        if _es_ip(host):
            return [host]
        infos = self._resolver(host, puerto, type=socket.SOCK_STREAM)
        return list(dict.fromkeys(str(info[4][0]) for info in infos))

    def _abrir(self, cliente: socket.socket, peticion: _Peticion) -> socket.socket | None:
        """Decide y conecta. Si no se conecta, lo anota, responde al navegador y devuelve None."""
        linea = {"destino": peticion.destino, "ip": None, "puerto": peticion.puerto}
        try:
            direcciones = self._direcciones(peticion.host, peticion.puerto)
        except (OSError, UnicodeError, ValueError):
            direcciones = []
        if not direcciones:
            linea["fallo"] = "error"
            self._anotar(linea)
            cliente.sendall(_SIN_CONEXION)
            return None

        with self._cerrojo_alcance:
            alcance = self._alcance.actual()
        # Lo que no es una IP (basura del resolvedor) no se juzga ni se contacta.
        validas = [direccion for direccion in direcciones if _es_ip(direccion)]
        ip, motivo = elegir_ip(validas, alcance)
        if ip is None:
            linea["ip"] = validas[0] if validas else None
            linea["motivo"] = motivo or (ILEGIBLE if alcance is None else FUERA)
            self._anotar(linea)
            cliente.sendall(_CORTADA)
            return None

        linea["ip"] = ip
        try:
            return self._conectar((ip, peticion.puerto), timeout=self._timeout)
        except ConnectionRefusedError:
            linea["fallo"] = "rechazada"
        except TimeoutError:
            linea["fallo"] = "sin_respuesta"
        except OSError:
            linea["fallo"] = "error"
        self._anotar(linea)
        cliente.sendall(_SIN_CONEXION)
        return None

    def _atender(self, cliente: socket.socket) -> None:
        try:
            cabecera, sobrante = self._leer_cabecera(cliente)
            peticion = _analizar(cabecera)
        except _SinPeticion:
            return
        except _PeticionNoValida:
            cliente.sendall(_NO_VALIDA)
            return
        servidor = self._abrir(cliente, peticion)
        if servidor is None:
            return
        with servidor:
            cliente.settimeout(self._timeout)    # tope para un envío atascado, no para esperar
            servidor.settimeout(self._timeout)
            cuerpo = peticion.cuerpo
            if peticion.reenvio is None:
                cliente.sendall(_TUNEL_ABIERTO)
                primero = sobrante
            else:
                adelantado = sobrante if cuerpo is None else sobrante[:cuerpo]
                if cuerpo is not None:
                    cuerpo -= len(adelantado)
                primero = peticion.reenvio + adelantado
            if primero:
                servidor.sendall(primero)
            _tunel(cliente, servidor, cuerpo)
