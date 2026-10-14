"""Llamada a un modelo local (Ollama) por HTTP, solo con librería estándar.

Los metadatos del cliente solo van a un Ollama de este mismo equipo (docs/CONTRATOS.md 0.4):
nunca a otra máquina ni a través del proxy del sistema.
"""

from __future__ import annotations

import http.client
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from . import targets

OLLAMA = "http://127.0.0.1:11434"
# Modelo pequeño por defecto, que corra en equipos modestos; se cambia con --modelo, con
# DEDALO_MODELO o eligiendo otro en el portal.
DEFAULT_MODEL = "llama3.2:3b"
_MODEL_NAME = re.compile(r"[\w.:/-]{1,200}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Una redirección llevaría la petición a otra dirección: se trata como un error."""

    def redirect_request(self, *args, **kwargs):
        return None


# Sin ProxyHandler, urllib usaría HTTP_PROXY o el proxy de Windows también para 127.0.0.1.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


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
        answers = "completion" in entry.get("capabilities", ["completion"])
        if not remote and answers and not _cloud(entry["name"]):
            models.append({"nombre": entry["name"], "tamano": (entry.get("details") or {}).get("parameter_size", "")})
    return sorted(models, key=lambda model: model["nombre"].lower())


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
