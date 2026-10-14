"""Llamada a un modelo local (Ollama) por HTTP, solo con librería estándar."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

OLLAMA = "http://127.0.0.1:11434"
# Modelo pequeño por defecto, que corra en equipos modestos; el portal lo cambia con --modelo.
DEFAULT_MODEL = "llama3.2:3b"


def generate(prompt: str, model: str, host: str = OLLAMA, timeout: int = 120, schema: dict | None = None) -> str:
    """Pide al modelo una respuesta entera (sin streaming) y devuelve su texto.

    La respuesta se pide en JSON (con `schema`, Ollama la ajusta a ese esquema JSON) y sin
    razonamiento en voz alta: un modelo de razonamiento tardaba 142 s por pregunta pensando
    antes de contestar, y así tarda 35 s.
    """
    # Temperatura 0: la misma pregunta da siempre la misma respuesta (traza de auditoría reproducible).
    data = json.dumps({"model": model, "prompt": prompt, "stream": False, "format": schema or "json", "think": False,
                       "options": {"temperature": 0}})
    request = urllib.request.Request(host.rstrip("/") + "/api/generate", data=data.encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = json.loads(response.read()).get("response")
    except (OSError, ValueError, AttributeError) as exc:  # URLError es OSError; JSON roto es ValueError
        if isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError):
            raise ValueError(f"El modelo «{model}» tardó más de {timeout} s en responder. "
                             "Prueba con un modelo más pequeño con --modelo.") from exc
        raise ValueError(f"No se pudo usar el modelo «{model}» en {host}: {exc}. "
                         "¿Está arrancado Ollama y descargado ese modelo?") from exc
    if not isinstance(text, str):
        raise ValueError(f"El modelo «{model}» no devolvió texto. ¿Está arrancado Ollama y descargado ese modelo?")
    return text
