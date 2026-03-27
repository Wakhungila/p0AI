"""
pin0ccsAI — Ollama Client
Async HTTP client for Ollama. Handles model routing, retries, and structured output.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncGenerator, Optional

import httpx

from core.logger import get_logger

log = get_logger(__name__)


class OllamaError(Exception):
    pass


class OllamaClient:
    """
    Thin async wrapper around the Ollama /api/generate and /api/chat endpoints.
    All agents use this — model selection is done at call time.
    """

    def __init__(self, base_url: str = "http://localhost:11434", timeout: int = 120):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(self.timeout, connect=10),
        )
        return self

    async def __aexit__(self, *_):
        if self._client:
            await self._client.aclose()

    def _ensure_client(self):
        if self._client is None:
            raise RuntimeError("OllamaClient must be used as async context manager")

    # ─── Core Generation ─────────────────────────────────────────────────────

    async def generate(
        self,
        model: str,
        prompt: str,
        system: str = "",
        temperature: float = 0.3,
        max_tokens: int = 2048,
        retries: int = 3,
    ) -> str:
        """Single-turn generation. Returns full response string."""
        self._ensure_client()
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if system:
            payload["system"] = system

        for attempt in range(retries):
            try:
                resp = await self._client.post("/api/generate", json=payload)
                resp.raise_for_status()
                data = resp.json()
                return data.get("response", "").strip()
            except httpx.HTTPStatusError as e:
                log.warning("ollama.http_error", status=e.response.status_code,
                            attempt=attempt + 1, model=model)
                if attempt == retries - 1:
                    raise OllamaError(f"Ollama HTTP {e.response.status_code}") from e
                await asyncio.sleep(2 ** attempt)
            except httpx.ConnectError:
                raise OllamaError(
                    f"Cannot reach Ollama at {self.base_url}. "
                    "Is `ollama serve` running?"
                )

    async def chat(
        self,
        model: str,
        messages: list[dict[str, str]],
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> str:
        """Multi-turn chat format. messages = [{'role': 'user'|'assistant', 'content': '...'}]"""
        self._ensure_client()
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        resp = await self._client.post("/api/chat", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data.get("message", {}).get("content", "").strip()

    async def generate_json(
        self,
        model: str,
        prompt: str,
        system: str = "",
        temperature: float = 0.1,
        retries: int = 3,
    ) -> dict | list:
        """
        Generate and parse JSON output.
        Appends instruction to return ONLY valid JSON.
        """
        json_prompt = (
            prompt + "\n\nRespond ONLY with valid JSON. "
            "No markdown, no explanation, no backticks."
        )
        raw = await self.generate(
            model=model,
            prompt=json_prompt,
            system=system,
            temperature=temperature,
            retries=retries,
        )
        # Strip common LLM wrapping artifacts
        cleaned = raw.strip()
        for fence in ["```json", "```JSON", "```"]:
            cleaned = cleaned.replace(fence, "")
        cleaned = cleaned.strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as e:
            log.warning("ollama.json_parse_error", raw=raw[:300], error=str(e))
            # Attempt to extract first JSON object/array
            import re
            match = re.search(r'(\{.*\}|\[.*\])', cleaned, re.DOTALL)
            if match:
                return json.loads(match.group(1))
            raise OllamaError(f"Model did not return valid JSON: {cleaned[:200]}") from e

    async def stream(
        self,
        model: str,
        prompt: str,
        system: str = "",
        temperature: float = 0.3,
    ) -> AsyncGenerator[str, None]:
        """Streaming generation — yields tokens as they arrive."""
        self._ensure_client()
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": True,
            "options": {"temperature": temperature},
        }
        if system:
            payload["system"] = system

        async with self._client.stream("POST", "/api/generate", json=payload) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if line:
                    try:
                        chunk = json.loads(line)
                        token = chunk.get("response", "")
                        if token:
                            yield token
                        if chunk.get("done"):
                            break
                    except json.JSONDecodeError:
                        continue

    # ─── Health Check ─────────────────────────────────────────────────────────

    async def health_check(self) -> dict[str, Any]:
        """Returns list of loaded models and confirms Ollama is reachable."""
        self._ensure_client()
        try:
            resp = await self._client.get("/api/tags")
            resp.raise_for_status()
            data = resp.json()
            models = [m["name"] for m in data.get("models", [])]
            return {"status": "ok", "models": models}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def ensure_model(self, model: str) -> bool:
        """Check if a model is available locally."""
        health = await self.health_check()
        if health["status"] != "ok":
            return False
        available = health.get("models", [])
        # Match prefix (qwen2.5-coder:7b matches qwen2.5-coder:7b-instruct etc.)
        return any(model.split(":")[0] in m for m in available)

    # ─── Model Lifecycle ──────────────────────────────────────────────────────

    async def get_loaded_models(self) -> list[str]:
        """
        Return names of models currently loaded in Ollama's memory.
        Uses /api/ps (Ollama ≥ 0.1.33). Falls back to empty list on older versions.
        """
        self._ensure_client()
        try:
            resp = await self._client.get("/api/ps")
            resp.raise_for_status()
            data = resp.json()
            return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []

    async def preload_model(self, model: str) -> float:
        """
        Trigger Ollama to load a model into memory without generating tokens.
        Uses keep_alive=-1 (keep forever) and num_predict=0 (generate nothing).

        This is the warm-up call — send it during no-LLM phases so the next
        model is hot by the time the first real inference call arrives.

        Returns: elapsed seconds for the load (0.0 if already loaded or on error).
        """
        self._ensure_client()
        t0 = asyncio.get_event_loop().time()
        try:
            resp = await self._client.post(
                "/api/generate",
                json={
                    "model": model,
                    "prompt": "",
                    "keep_alive": -1,       # keep in memory until explicitly unloaded
                    "options": {"num_predict": 0},  # generate zero tokens
                },
            )
            resp.raise_for_status()
            elapsed = asyncio.get_event_loop().time() - t0
            log.info("ollama.model_preloaded",
                     model=model, elapsed_s=round(elapsed, 2))
            return elapsed
        except Exception as e:
            elapsed = asyncio.get_event_loop().time() - t0
            log.warning("ollama.preload_failed",
                        model=model, error=str(e), elapsed_s=round(elapsed, 2))
            return 0.0

    async def unload_model(self, model: str) -> bool:
        """
        Explicitly release a model from Ollama's memory.
        Uses keep_alive=0 which signals Ollama to unload immediately.

        Call this after a phase's model is no longer needed so the next
        model has the full RAM budget available for loading.

        Returns True on success, False on error.
        """
        self._ensure_client()
        try:
            resp = await self._client.post(
                "/api/generate",
                json={
                    "model": model,
                    "prompt": "",
                    "keep_alive": 0,        # unload immediately
                    "options": {"num_predict": 0},
                },
            )
            resp.raise_for_status()
            log.info("ollama.model_unloaded", model=model)
            return True
        except Exception as e:
            log.warning("ollama.unload_failed", model=model, error=str(e))
            return False

    async def swap_models(
        self,
        unload: str,
        preload: str,
        overlap_ok: bool = False,
    ) -> dict[str, float]:
        """
        Explicitly swap from one model to another.

        overlap_ok=False (default, 8GB-safe):
            Unload the old model first, then preload the new one.
            Guarantees RAM is free before the new model loads.
            Costs: unload_time + load_time, but never exceeds RAM budget.

        overlap_ok=True (16GB+ systems):
            Fire both operations concurrently — Ollama handles the
            eviction when RAM pressure forces it. Faster on paper but
            risks OOM on constrained systems.

        Returns dict with timing: {unload_s, load_s, total_s}
        """
        t0 = asyncio.get_event_loop().time()

        if overlap_ok:
            unload_task = asyncio.create_task(self.unload_model(unload))
            load_elapsed = await self.preload_model(preload)
            await unload_task
            unload_elapsed = 0.0  # concurrent, not separately measured
        else:
            await self.unload_model(unload)
            unload_elapsed = asyncio.get_event_loop().time() - t0
            load_start = asyncio.get_event_loop().time()
            load_elapsed = await self.preload_model(preload)

        total = asyncio.get_event_loop().time() - t0
        return {
            "unload_s": round(unload_elapsed, 2),
            "load_s": round(load_elapsed, 2),
            "total_s": round(total, 2),
        }
