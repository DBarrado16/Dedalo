"""Llamada a un modelo local (Ollama) por HTTP, solo con librería estándar.

Los metadatos del cliente solo van a un Ollama de este mismo equipo (docs/CONTRATOS.md 0.4):
nunca a otra máquina ni a través del proxy del sistema.
"""

from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

from . import targets

OLLAMA = "http://127.0.0.1:11434"
# Modelo pequeño por defecto, que corra en equipos modestos; se cambia con --modelo, con
# DEDALO_MODELO o eligiendo otro en el portal.
DEFAULT_MODEL = "llama3.2:3b"
_MODEL_NAME = re.compile(r"[\w.:/-]{1,200}")

# Motor opcional por API de Claude (a conciencia; los datos salen del equipo). La clave va en
# una variable de entorno, nunca en la base ni en el repo.
CLAVE_ENV = "ANTHROPIC_API_KEY"
CLAUDE_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_VERSION = "2023-06-01"
CLAUDE_DEFAULT = "claude-sonnet-5-5"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Una redirección llevaría la petición a otra dirección: se trata como un error."""

    def redirect_request(self, *args, **kwargs):
        return None


# Sin ProxyHandler, urllib usaría HTTP_PROXY o el proxy de Windows también para 127.0.0.1.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def extraer_objeto_json(text: str) -> dict:
    """El primer objeto JSON del texto de un modelo, que puede venir entre prosa o fences.

    Lo comparten los `parse_result` de cada análisis (prioridad, fingerprint): la validación por
    campos es de cada uno, pero sacar el objeto del texto del modelo es el mismo punto frágil.
    """
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("la respuesta no trae un objeto JSON")
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        raise ValueError(f"la respuesta no es JSON válido ({exc.msg})") from exc


def check_local(host: str) -> str:
    """Devuelve la URL si apunta a este equipo (http o https en loopback); si no, ValueError."""
    parts = urllib.parse.urlsplit(host)
    if parts.scheme not in ("http", "https") or not targets.is_local_host(parts.hostname or ""):
        raise ValueError(f"El servidor del modelo tiene que estar en este equipo (127.0.0.1, ::1 o localhost): {host}")
    return host


def check_model(name: str) -> str:
    """Devuelve el nombre si es el de un modelo que corre en este equipo; si no, ValueError.

    Ollama atiende los modelos de etiqueta «cloud» o «…-cloud» (gpt-oss:120b-cloud) desde el
    mismo servidor local, pero manda la pregunta a su nube. El nombre puede llegar del
    navegador: solo se admite la forma de los de Ollama (como huggingface.co/org/modelo:etiqueta).
    """
    if not isinstance(name, str) or not _MODEL_NAME.fullmatch(name):
        raise ValueError(f"Nombre de modelo no válido: {str(name)[:60]!r}")
    if _cloud(name):
        raise ValueError(f"El modelo «{name}» corre en la nube de Ollama y los datos del cliente saldrían "
                         "del equipo: usa un modelo descargado.")
    return name


def _cloud(name: str) -> bool:
    tag = name.rpartition(":")[2].lower() if ":" in name else ""
    return tag == "cloud" or tag.endswith("-cloud")


def list_models(host: str = OLLAMA, timeout: int = 5) -> list[dict]:
    """Modelos descargados en el Ollama de este equipo que pueden contestar, por nombre y con su tamaño.

    Quedan fuera los de la nube (por su etiqueta o porque Ollama los marca como remotos) y los
    que no generan texto (solo embeddings). Si Ollama no responde, ValueError.
    """
    check_local(host)
    try:
        with _OPENER.open(urllib.request.Request(host.rstrip("/") + "/api/tags"), timeout=timeout) as response:
            entries = json.loads(response.read())["models"]
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException) as exc:
        raise ValueError(f"No se pudo hablar con Ollama en {host}: {exc}. ¿Está arrancado?") from exc
    models = []
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            continue
        remote = any(key.startswith("remote") for key in entry)
        # Un Ollama antiguo no dice qué sabe hacer cada modelo: entonces se ofrece.
        capabilities = entry.get("capabilities")
        answers = not isinstance(capabilities, list) or "completion" in capabilities
        details = entry.get("details") if isinstance(entry.get("details"), dict) else {}
        if not remote and answers and not _cloud(entry["name"]):
            models.append({"nombre": entry["name"], "tamano": str(details.get("parameter_size") or "")})
    return sorted(models, key=lambda model: model["nombre"].lower())


def answers(host: str = OLLAMA, timeout: int = 2) -> bool:
    """Si el Ollama de este equipo responde."""
    try:
        list_models(host, timeout)
        return True
    except ValueError:
        return False


def find_ollama() -> str | None:
    """El ejecutable de Ollama: primero donde lo deja su instalador de Windows y, si no, en el PATH.

    Uno en la carpeta actual no cuenta: en Windows, shutil.which también mira ahí, y el lanzador
    se sitúa en la carpeta del repo; un ollama.exe u ollama.cmd dejado en ella no debe ejecutarse.
    """
    local = os.environ.get("LOCALAPPDATA")
    installed = Path(local) / "Programs" / "Ollama" / "ollama.exe" if local else None
    if installed and installed.is_file():
        return str(installed)
    found = shutil.which("ollama")
    if found and Path(found).resolve().parent != Path.cwd().resolve():
        return found
    return None


def ensure_running(host: str = OLLAMA, wait: float = 20) -> tuple[bool, str]:
    """Si Ollama no responde en este equipo y está instalado, lo arranca en segundo plano.

    Devuelve si lo ha arrancado y un aviso para la terminal. Lo arranca sin modelos de la nube
    (OLLAMA_NO_CLOUD): así ni un alias local de uno de ellos saca los datos del equipo. Sigue en
    marcha al cerrar el portal, como cuando lo abre el usuario: pararlo a la fuerza podría dejar
    colgado el proceso del modelo ocupando la memoria de la GPU.
    """
    parts = urllib.parse.urlsplit(check_local(host))
    if answers(host):
        return False, ""
    binary = find_ollama()
    if binary is None:
        return False, ("Ollama no está instalado: el portal funciona, pero la priorización con IA no estará "
                       "disponible hasta que lo instales (https://ollama.com).")
    failed = (f"No se pudo arrancar Ollama ({binary}): el portal funciona, pero la priorización con IA "
              "no estará disponible hasta que lo arranques.")
    # Donde Dédalo lo va a buscar: el puerto de --ollama o, si no lo lleva, el de su esquema.
    address = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    env = {**os.environ, "OLLAMA_HOST": f"{address}:{port}", "OLLAMA_NO_CLOUD": "1"}
    try:
        # Sin shell ni ventana, y en su propia sesión (en Linux, el Ctrl+C que cierra el portal no le
        # llega); su salida no hace falta: si falla, se ve en que no responde.
        process = subprocess.Popen([binary, "serve"], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError as exc:  # por ejemplo, un antivirus que lo bloquea: el portal arranca igual
        return False, f"{failed} ({exc})"
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline and process.poll() is None:
        if answers(host):
            return True, f"Ollama no estaba en marcha: arrancado en segundo plano en {host}, sin modelos de la nube."
        time.sleep(0.5)
    if answers(host):
        return False, ""  # ya estaba en marcha y tardó en contestar; el lanzado no pudo usar el puerto
    if process.poll() is None:
        return True, ("Ollama se está arrancando en segundo plano, pero tarda en responder: cuando lo haga, "
                      "vuelve a abrir la pestaña Priorización.")
    return False, failed


def generate(prompt: str, model: str, host: str = OLLAMA, timeout: int = 120, schema: dict | None = None) -> str:
    """Pide al modelo una respuesta entera (sin streaming) y devuelve su texto.

    La respuesta se pide en JSON (con `schema`, Ollama la ajusta a ese esquema JSON) y sin
    razonamiento en voz alta: un modelo de razonamiento tardaba 142 s por pregunta pensando
    antes de contestar, y así tarda 35 s.
    """
    check_local(host)
    check_model(model)
    # Temperatura 0: la misma pregunta da siempre la misma respuesta (traza de auditoría reproducible).
    data = json.dumps({"model": model, "prompt": prompt, "stream": False, "format": schema or "json", "think": False,
                       "options": {"temperature": 0}})
    request = urllib.request.Request(host.rstrip("/") + "/api/generate", data=data.encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            text = json.loads(response.read()).get("response")
    # URLError es OSError; JSON roto es ValueError; una respuesta cortada es HTTPException.
    except (OSError, ValueError, AttributeError, http.client.HTTPException) as exc:
        if isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError):
            raise ValueError(f"El modelo «{model}» tardó más de {timeout} s en responder. "
                             "Prueba con un modelo más pequeño con --modelo.") from exc
        raise ValueError(f"No se pudo usar el modelo «{model}» en {host}: {exc}. "
                         "¿Está arrancado Ollama y descargado ese modelo?") from exc
    if not isinstance(text, str):
        raise ValueError(f"El modelo «{model}» no devolvió texto. ¿Está arrancado Ollama y descargado ese modelo?")
    return text


def generate_claude(prompt: str, model: str, api_key: str | None = None, timeout: int = 120,
                    schema: dict | None = None, url: str = CLAUDE_URL) -> str:
    """Pide una respuesta a la API de Claude y devuelve su texto. A conciencia: los datos salen del equipo.

    La clave sale de `api_key` o de la variable de entorno; nunca de la base ni del repo. `schema` se
    acepta por paridad con generate (Ollama); aquí el JSON se pide en el propio prompt y lo valida
    quien llama (fingerprint.parse_result). Errores de red/HTTP/JSON -> ValueError.
    """
    clave = api_key or os.environ.get(CLAVE_ENV)
    if not clave:
        raise ValueError(f"Falta la clave de la API de Claude: define la variable de entorno {CLAVE_ENV}.")
    data = json.dumps({"model": model, "max_tokens": 1024,
                       "messages": [{"role": "user", "content": prompt}]})
    request = urllib.request.Request(url, data=data.encode("utf-8"), headers={
        "Content-Type": "application/json", "x-api-key": clave, "anthropic-version": CLAUDE_VERSION})
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            cuerpo = json.loads(response.read())
        texto = next((b.get("text") for b in cuerpo.get("content", []) if b.get("type") == "text"), None)
    except (OSError, ValueError, AttributeError, http.client.HTTPException) as exc:
        if isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError):
            raise ValueError(f"La API de Claude tardó más de {timeout} s en responder.") from exc
        raise ValueError(f"No se pudo usar la API de Claude con «{model}»: {exc}.") from exc
    if not isinstance(texto, str):
        raise ValueError(f"La API de Claude no devolvió texto con «{model}».")
    return texto


def generador(engine: str, model: str, host: str, timeout: int = 120, schema: dict | None = None):
    """Devuelve un generate(prompt)->texto según el motor elegido: Ollama en local o Claude por API."""
    if engine == "ollama":
        return lambda prompt: generate(prompt, model, host, timeout=timeout, schema=schema)
    if engine == "claude":
        return lambda prompt: generate_claude(prompt, model, timeout=timeout, schema=schema)
    raise ValueError(f"Motor de IA desconocido: {engine!r}")
