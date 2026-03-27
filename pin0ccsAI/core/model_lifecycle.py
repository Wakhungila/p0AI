"""
pin0ccsAI — Model Lifecycle Manager  [v0.4 — background preload architecture]

Owns all model loading/unloading decisions so the orchestrator stays
readable and the swap count stays bounded at 2 per scan.

Swap schedule (maximum 2 model swaps per scan):
  Window A  Recon phase (subprocesses, no LLM, 20-120 s)
            → start_preload(mistral) fires in background

  Swap 1    Strategy starts — await wait_for_model(mistral) → already warm
            Strategy finishes → transition(mistral → qwen2.5) fires in background:
              8GB  mode: sequential unload mistral then preload qwen2.5
              16GB mode: concurrent unload + preload

  (warm)    Tester starts — await wait_for_model(qwen2.5) → already warm
            Tester finishes → transition(qwen2.5 → llama3.1) fires in background
            Stored XSS + Web3 (pure HTTP, 10-60 s) run concurrently with load

  Swap 2    Debator starts — await wait_for_model(llama3.1) → already warm

Total cold-start waits hidden behind other work: ~0 s on typical targets.
Total model swaps counted and logged in scan.complete.
"""
from __future__ import annotations

import asyncio
import time
from typing import Optional

from core.logger import get_logger
from core.ollama_client import OllamaClient

log = get_logger(__name__)


class ModelLifecycleManager:
    """
    Manages model loading/unloading for a single scan session.
    One instance per scan, created by the orchestrator.

    API:
        start_preload(model)       — fire background load, non-blocking
        await wait_for_model(model) — ensure model is ready, returns wait_s
        await transition(a, b)     — release a, begin loading b in background
        await release_current()    — explicit unload of current model
        summary()                  — dict of swap metrics
        log_summary()              — emit all metrics to structured log
    """

    def __init__(
        self,
        ollama: OllamaClient,
        model_strategy: str,
        model_tester: str,
        model_debator: str,
        max_swaps: int = 2,
        overlap_ok: bool = False,
    ):
        self._ollama = ollama
        self._model_strategy = model_strategy
        self._model_tester = model_tester
        self._model_debator = model_debator
        self._max_swaps = max_swaps
        self._overlap_ok = overlap_ok

        self._current_model: Optional[str] = None
        self._swap_count: int = 0
        self._swap_log: list[dict] = []

        # Background preload tasks keyed by model name
        self._preload_tasks: dict[str, asyncio.Task] = {}

        self._scan_start: float = time.monotonic()

    # ─── Public API ──────────────────────────────────────────────────────────

    def start_preload(self, model: str) -> None:
        """
        Fire a background preload task. Non-blocking.

        If a preload for this model is already running, this is a no-op.
        If a completed task exists for this model, it is replaced.
        """
        existing = self._preload_tasks.get(model)
        if existing and not existing.done():
            log.debug("model_lifecycle.preload_already_running", model=model)
            return

        log.info("model_lifecycle.preload_start", model=model,
                 scan_elapsed_s=round(time.monotonic() - self._scan_start, 1))
        task = asyncio.create_task(
            self._preload_worker(model),
            name=f"preload_{model}",
        )
        self._preload_tasks[model] = task

    async def wait_for_model(self, model: str) -> float:
        """
        Ensure model is loaded. Returns seconds waited (0.0 if already hot).

        Three paths:
          Hot  — preload task completed before this call → 0.0 s wait
          Warm — preload task still running → await remaining load time
          Cold — no preload started → triggers synchronous load, logs warning
        """
        task = self._preload_tasks.get(model)

        if task is None:
            # If this model is already active, nothing to do
            if self._current_model == model:
                return 0.0

            # Cold path — shouldn't happen in normal flow
            log.warning("model_lifecycle.cold_load", model=model,
                        hint="start_preload() was not called during the preceding "
                             "no-LLM phase. Model loads synchronously now.")
            t0 = time.monotonic()
            await self._ollama.preload_model(model)
            wait = time.monotonic() - t0
            self._record_swap(self._current_model, model, wait, was_warm=False)
            self._current_model = model
            return wait

        if task.done():
            wait = 0.0
            log.info("model_lifecycle.already_warm", model=model,
                     scan_elapsed_s=round(time.monotonic() - self._scan_start, 1))
        else:
            t0 = time.monotonic()
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=180)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                log.warning("model_lifecycle.preload_timeout", model=model)
            wait = time.monotonic() - t0
            log.info("model_lifecycle.waited_for_preload",
                     model=model, wait_s=round(wait, 2))

        if self._current_model != model:
            self._record_swap(self._current_model, model,
                              wait, was_warm=(wait < 0.5))
            self._current_model = model

        return wait

    async def transition(self, from_model: str, to_model: str) -> None:
        """
        Release from_model and begin preloading to_model. Non-blocking.

        Fires a background task and returns immediately. The caller should
        call await wait_for_model(to_model) before the first LLM call.

        Respects max_swaps ceiling — if already at the limit, logs a warning
        and skips the preload (model will cold-load when needed).
        """
        if self._swap_count >= self._max_swaps:
            log.warning("model_lifecycle.swap_ceiling_reached",
                        swap_count=self._swap_count,
                        max_swaps=self._max_swaps,
                        skipping=to_model)
            return

        log.info("model_lifecycle.transition_triggered",
                 from_model=from_model, to_model=to_model,
                 swap_number=self._swap_count + 1,
                 overlap_ok=self._overlap_ok)

        if self._overlap_ok:
            # 16GB+ mode: unload and load concurrently
            asyncio.create_task(self._ollama.unload_model(from_model),
                                name=f"unload_{from_model}")
            self.start_preload(to_model)
        else:
            # 8GB mode: unload first, then load — prevents OOM during transition
            task = asyncio.create_task(
                self._sequential_transition(from_model, to_model),
                name=f"seq_{from_model}_to_{to_model}",
            )
            # Register the sequential task as the preload tracker
            # wait_for_model(to_model) will await this task's completion
            self._preload_tasks[to_model] = asyncio.create_task(
                self._wait_for_sequential(from_model, to_model),
                name=f"preload_after_{to_model}",
            )

    async def release_current(self) -> None:
        """Explicitly unload the current model and clear current_model state."""
        if self._current_model:
            model = self._current_model
            log.info("model_lifecycle.releasing", model=model)
            await self._ollama.unload_model(model)
            self._current_model = None

    # ─── Summary ─────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        total_wait = sum(s["wait_s"] for s in self._swap_log)
        return {
            "swap_count": self._swap_count,
            "max_swaps": self._max_swaps,
            "total_swap_wait_s": round(total_wait, 2),
            "swaps_were_warm": all(s["was_warm"] for s in self._swap_log)
                               if self._swap_log else True,
            "swaps": self._swap_log,
        }

    def log_summary(self) -> None:
        s = self.summary()
        log.info("model_lifecycle.summary",
                 swap_count=s["swap_count"],
                 max_swaps=s["max_swaps"],
                 total_swap_wait_s=s["total_swap_wait_s"],
                 all_warm=s["swaps_were_warm"])
        for swap in s["swaps"]:
            fn = log.info if swap["was_warm"] else log.warning
            fn("model_lifecycle.swap_detail",
               swap_n=swap["swap_n"],
               from_model=swap["from"],
               to_model=swap["to"],
               wait_s=swap["wait_s"],
               was_warm=swap["was_warm"],
               scan_elapsed_s=swap["scan_elapsed_s"])

    # ─── Private ─────────────────────────────────────────────────────────────

    async def _preload_worker(self, model: str) -> None:
        t0 = time.monotonic()
        elapsed = await self._ollama.preload_model(model)
        wall = time.monotonic() - t0
        log.info("model_lifecycle.preload_complete",
                 model=model, load_s=round(elapsed, 2), wall_s=round(wall, 2),
                 scan_elapsed_s=round(time.monotonic() - self._scan_start, 1))

    async def _sequential_transition(
        self, from_model: str, to_model: str
    ) -> None:
        """Unload → then preload. 8GB-safe sequential path."""
        t0 = time.monotonic()
        await self._ollama.unload_model(from_model)
        unload_s = time.monotonic() - t0
        log.info("model_lifecycle.unloaded",
                 model=from_model, unload_s=round(unload_s, 2))
        await self._ollama.preload_model(to_model)
        total_s = time.monotonic() - t0
        log.info("model_lifecycle.sequential_transition_complete",
                 from_model=from_model, to_model=to_model,
                 total_s=round(total_s, 2))

    async def _wait_for_sequential(
        self, from_model: str, to_model: str
    ) -> None:
        """
        Companion task for the sequential path. Waits for the sequential
        transition task to complete so wait_for_model(to_model) has
        something meaningful to shield and await.
        """
        task_name = f"seq_{from_model}_to_{to_model}"
        for _ in range(400):   # poll up to 40 s
            matching = [t for t in asyncio.all_tasks()
                        if t.get_name() == task_name]
            if not matching:
                return          # task completed or was never started
            if matching[0].done():
                return
            await asyncio.sleep(0.1)

    def _record_swap(
        self,
        from_model: Optional[str],
        to_model: str,
        wait_s: float,
        was_warm: bool,
    ) -> None:
        self._swap_count += 1
        entry = {
            "swap_n": self._swap_count,
            "from": from_model or "(none)",
            "to": to_model,
            "wait_s": round(wait_s, 2),
            "was_warm": was_warm,
            "scan_elapsed_s": round(time.monotonic() - self._scan_start, 1),
        }
        self._swap_log.append(entry)
