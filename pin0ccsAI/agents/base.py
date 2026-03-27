"""
pin0ccsAI — Base Agent
Abstract base for all agents. Provides shared LLM access, config, and logging.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from core.config import Config
from core.database import Database
from core.logger import get_logger
from core.ollama_client import OllamaClient


class BaseAgent(ABC):
    """
    All agents (Tester, Debator, Strategy, Knowledge) extend this.
    Provides: config, db, ollama client, logger.
    """

    name: str = "base"

    def __init__(self, config: Config, db: Database, ollama: OllamaClient):
        self.config = config
        self.db = db
        self.ollama = ollama
        self.log = get_logger(f"agent.{self.name}")

    @property
    def model(self) -> str:
        """Override in subclass to return the agent's assigned model."""
        return self.config.models.tester

    async def think(self, prompt: str, system: str = "", temperature: float = 0.3) -> str:
        """Single-shot reasoning call."""
        return await self.ollama.generate(
            model=self.model,
            prompt=prompt,
            system=system,
            temperature=temperature,
        )

    async def think_json(self, prompt: str, system: str = "", temperature: float = 0.1) -> Any:
        """Reasoning call that returns parsed JSON."""
        return await self.ollama.generate_json(
            model=self.model,
            prompt=prompt,
            system=system,
            temperature=temperature,
        )

    async def setup(self) -> None:
        """Optional async initialization. Called before first use."""
        pass

    async def teardown(self) -> None:
        """Optional cleanup."""
        pass
