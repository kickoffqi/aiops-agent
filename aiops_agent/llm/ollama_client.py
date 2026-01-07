# aiops_agent/llm/ollama_client.py
from __future__ import annotations
import json
import time
from typing import Any, Dict, List, Optional
import requests


class OllamaClient:
    def __init__(self, base_url: str = "http://localhost:11434", timeout_s: int = 180):
        self.base_url = base_url.rstrip("/")
        self.timeout = (10, timeout_s)  # (connect, read)

    def generate_json(self, model: str, prompt: str) -> Dict[str, Any]:
        """
        Use /api/generate with format=json and stream=false.
        Returns parsed JSON object (not string).
        """
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": model,
            "prompt": prompt,
            "format": "json",
            "stream": False,
        }
        r = requests.post(url, json=payload, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()

        # Ollama returns {"response": "<json string>", ...}
        resp_text = data.get("response", "")
        if not resp_text:
            raise ValueError(f"Ollama empty response. raw={data!r}")

        try:
            return json.loads(resp_text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Ollama returned non-JSON response: {resp_text[:200]!r}") from e

    def chat_json(self, model: str, system: str, user: str) -> Dict[str, Any]:
        """
        Optional: /api/chat path. Only use if you really want messages-style.
        """
        url = f"{self.base_url}/api/chat"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "format": "json",
            "stream": False,
        }
        r = requests.post(url, json=payload, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()

        # chat returns {"message": {"role": "...", "content": "<json string>"}}
        content = (data.get("message") or {}).get("content", "")
        if not content:
            raise ValueError(f"Ollama empty chat message. raw={data!r}")

        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Ollama chat returned non-JSON content: {content[:200]!r}") from e