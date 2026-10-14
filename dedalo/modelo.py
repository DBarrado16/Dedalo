"""Llamada a un modelo local (Ollama) por HTTP, solo con librería estándar."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

OLLAMA = "http://127.0.0.1:11434"


def generate(prompt: str, model: str, host: str = OLLAMA, timeout: int = 120) -> str:
    """Pide al modelo una respuesta entera (sin streaming) y devuelve su texto."""
    data = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
    request = urllib.request.Request(host.rstrip("/") + "/api/generate", data=data,
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = json.loads(response.read()).get("response")
    except (OSError, ValueError, AttributeError) as exc:  # URLError es OSError; JSON roto es ValueError
        raise ValueError(f"No se pudo usar el modelo «{model}» en {host}: {exc}. "
                         "¿Está arrancado Ollama y descargado ese modelo?") from exc
    if not isinstance(text, str):
        raise ValueError(f"El modelo «{model}» no devolvió texto. ¿Está arrancado Ollama y descargado ese modelo?")
    return text
