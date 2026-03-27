"""
pin0ccsAI — LLM Budget Tracker
Tracks LLM call counts per model and phase.
Enforces per-phase ceilings to prevent runaway spending on low-resource systems.
Reports cache savings at the end of each scan.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from core.logger import get_logger

log = get_logger(__name__)


@dataclass
class BudgetEntry:
    model: str
    phase: str
    calls_made: int = 0
    calls_skipped_cache: int = 0
    ceiling: int = 999


class LLMBudget:
    """
    Lightweight counter injected into Tester and Strategy agents.
    Call .charge() before each LLM call — returns False if over ceiling,
    in which case the caller should skip the LLM call and use fallback.
    Call .record_cache_hit() when a cached result is used instead.

    Ceilings (configurable, these are 8GB-safe defaults):
      tester_mutation  : 8   (one batch call per vuln_type, max 8 types)
      tester_business  : 1   (one call for all business logic, whole phase)
      strategy_score   : 1   (one batch AI scoring call per scan)
      strategy_plan    : 1   (one attack plan call per scan)
      debator_validate : unlimited (every finding must be validated)
      debator_cvss     : 10  (CVSS scoring capped — low ROI beyond 10)
    """

    # Default ceilings — override via config if needed
    DEFAULT_CEILINGS: dict[str, int] = {
        "tester_mutation":  8,
        "tester_business":  1,
        "strategy_score":   1,
        "strategy_plan":    1,
        "debator_validate": 9999,
        "debator_cvss":     10,
        "knowledge_extract": 9999,
    }

    def __init__(self, ceilings: Optional[dict[str, int]] = None):
        self._ceilings = {**self.DEFAULT_CEILINGS, **(ceilings or {})}
        self._counts: dict[str, int] = defaultdict(int)
        self._cache_hits: dict[str, int] = defaultdict(int)
        self._denied: dict[str, int] = defaultdict(int)

    def charge(self, budget_key: str) -> bool:
        """
        Attempt to consume one unit of the named budget.
        Returns True  → call is allowed, counter incremented.
        Returns False → ceiling reached, caller must use fallback.
        """
        ceiling = self._ceilings.get(budget_key, 9999)
        current = self._counts[budget_key]
        if current >= ceiling:
            self._denied[budget_key] += 1
            log.debug("llm_budget.denied",
                      key=budget_key, used=current, ceiling=ceiling)
            return False
        self._counts[budget_key] += 1
        log.debug("llm_budget.charged",
                  key=budget_key, used=self._counts[budget_key], ceiling=ceiling)
        return True

    def record_cache_hit(self, budget_key: str) -> None:
        """Record that a cache served this request — no LLM call was made."""
        self._cache_hits[budget_key] += 1

    def total_calls(self) -> int:
        return sum(self._counts.values())

    def total_cache_hits(self) -> int:
        return sum(self._cache_hits.values())

    def summary(self) -> dict:
        total_llm = self.total_calls()
        total_cached = self.total_cache_hits()
        total_denied = sum(self._denied.values())
        total_requests = total_llm + total_cached + total_denied

        savings_pct = (
            round((total_cached + total_denied) / total_requests * 100)
            if total_requests > 0 else 0
        )

        return {
            "llm_calls_made": total_llm,
            "cache_hits": total_cached,
            "calls_denied_by_ceiling": total_denied,
            "total_requests": total_requests,
            "llm_savings_pct": savings_pct,
            "by_key": {
                k: {
                    "calls": self._counts.get(k, 0),
                    "cache_hits": self._cache_hits.get(k, 0),
                    "denied": self._denied.get(k, 0),
                    "ceiling": self._ceilings.get(k, 9999),
                }
                for k in set(
                    list(self._counts.keys())
                    + list(self._cache_hits.keys())
                    + list(self._denied.keys())
                )
            },
        }

    def log_summary(self) -> None:
        s = self.summary()
        log.info(
            "llm_budget.summary",
            llm_calls=s["llm_calls_made"],
            cache_hits=s["cache_hits"],
            denied=s["calls_denied_by_ceiling"],
            savings_pct=s["llm_savings_pct"],
        )
        for key, data in s["by_key"].items():
            if data["calls"] or data["cache_hits"] or data["denied"]:
                log.info(
                    "llm_budget.by_key",
                    key=key,
                    calls=data["calls"],
                    cache_hits=data["cache_hits"],
                    denied=data["denied"],
                    ceiling=data["ceiling"],
                )
