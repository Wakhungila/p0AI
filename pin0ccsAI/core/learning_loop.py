"""
pin0ccsAI — Learning Loop

Closes the feedback cycle by writing confirmed findings back into:
  1. The knowledge base (KB) — payload text for future extraction
  2. ExploitMemory — structured (vuln_type, endpoint_pattern, payload)
     records with success-rate scoring for direct reuse by TesterAgent

This was the missing half of the learning system in v0.1:
  External sources → KB → Tester          (always worked)
  Confirmed findings → KB + ExploitMemory  (this module)

What gets stored per finding:
  - The exact payload that triggered the vulnerability (high value)
  - The vuln type (for KB search indexing)
  - A technique description derived from the steps to reproduce
  - The normalised endpoint pattern (for ExploitMemory pattern matching)
  - The target URL as source context

What does NOT get stored:
  - Full HTTP responses (too large, privacy risk)
  - Session cookies or auth tokens
  - PII from evidence strings
  - CVSS vectors (not useful as payload material)

The payload cache is also invalidated for the vuln type so the next scan
picks up the newly learned payloads immediately.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Optional

from core.database import Database
from core.exploit_memory import ExploitMemory
from core.logger import get_logger
from core.models import Finding
from core.payload_cache import PayloadCache

log = get_logger(__name__)


class LearningLoop:
    """
    Ingests confirmed findings into the KB and ExploitMemory,
    then invalidates the payload cache so future scans benefit.
    """

    def __init__(
        self,
        db: Database,
        cache: PayloadCache,
        exploit_memory: Optional[ExploitMemory] = None,
    ):
        self.db = db
        self.cache = cache
        # ExploitMemory shares the same SQLite file — no extra connection overhead
        self._memory = exploit_memory or ExploitMemory(db_path=str(db.db_path))

    def ingest_findings(
        self,
        findings: list[Finding],
        session_id: str,
        target_url: str,
    ) -> dict:
        """
        Write confirmed findings to KB + ExploitMemory, invalidate cache.

        Returns stats: {new_kb, duplicate_kb, new_memory, updated_memory,
                        cache_invalidated}
        """
        new_kb = 0
        duplicate_kb = 0
        new_memory = 0
        updated_memory = 0
        invalidated_types: set[str] = set()

        for finding in findings:
            if not finding.confirmed or finding.false_positive:
                continue
            if not finding.payload:
                continue

            payload = self._sanitise_payload(finding.payload)
            if not payload:
                continue

            # ── KB entry (text search + LLM training data) ────────────────
            stored_kb = self._store_kb(finding, payload, target_url, session_id)
            if stored_kb:
                new_kb += 1
            else:
                duplicate_kb += 1

            # ── ExploitMemory entry (structured, pattern-indexed) ──────────
            endpoint_url = finding.endpoint or finding.url or target_url
            is_new = self._memory.record_success(
                vuln_type=finding.vuln_type.value,
                endpoint_url=endpoint_url,
                payload=payload,
                severity=finding.severity.value,
                session_id=session_id,
            )
            if is_new:
                new_memory += 1
            else:
                updated_memory += 1

            invalidated_types.add(finding.vuln_type.value)
            log.debug("learning_loop.finding_processed",
                      finding_id=finding.id,
                      vuln_type=finding.vuln_type.value,
                      kb_new=stored_kb, memory_new=is_new)

        # Invalidate payload mutation cache for affected vuln types
        for vuln_type in invalidated_types:
            deleted = self.cache.invalidate(vuln_type=vuln_type)
            if deleted:
                log.info("learning_loop.cache_invalidated",
                         vuln_type=vuln_type, entries_evicted=deleted)

        stats = {
            "new_kb": new_kb,
            "duplicate_kb": duplicate_kb,
            "new_memory": new_memory,
            "updated_memory": updated_memory,
            "cache_invalidated": sorted(invalidated_types),
        }
        if new_kb or new_memory:
            log.info("learning_loop.complete", **stats)
        return stats

    def record_failed_attempt(
        self,
        vuln_type: str,
        endpoint_url: str,
        payload: str,
    ) -> None:
        """
        Signal that a payload from ExploitMemory was tried and did not fire.
        Decreases the success_rate for that (vuln_type, pattern, payload) row.
        Only affects existing rows — never inserts.
        """
        if not payload:
            return
        self._memory.record_failure(
            vuln_type=vuln_type,
            endpoint_url=endpoint_url,
            payload=payload,
        )

    # ─── Private helpers ─────────────────────────────────────────────────────

    def _store_kb(
        self,
        finding: Finding,
        payload: str,
        target_url: str,
        session_id: str,
    ) -> bool:
        """Write a KB entry for LLM ingestion. Returns True if new."""
        technique = self._steps_to_technique(finding)
        hash_input = f"{finding.vuln_type.value}:{payload}"
        content_hash = hashlib.sha256(hash_input.encode()).hexdigest()

        entry = {
            "source": f"confirmed_finding:{session_id[:8]}",
            "title": (
                f"[Confirmed] {finding.vuln_type.value} — "
                f"{finding.title[:80]}"
            ),
            "url": target_url,
            "content": (
                f"Vuln: {finding.vuln_type.value}\n"
                f"URL: {finding.url}\n"
                f"Technique: {technique}\n"
                f"Confidence: {finding.confidence:.0%}\n"
                f"Severity: {finding.severity.value}"
            ),
            "vuln_types": [finding.vuln_type.value],
            "payloads": [payload],
            "techniques": [technique] if technique else [],
            "cve": "",
            "hash": content_hash,
        }
        return self.db.save_kb_entry(entry)

    def _steps_to_technique(self, finding: Finding) -> str:
        if finding.steps_to_reproduce:
            steps = finding.steps_to_reproduce[:2]
            return " → ".join(s.lstrip("0123456789. ") for s in steps)[:200]
        if finding.impact:
            return finding.impact[:200]
        return f"{finding.vuln_type.value} via {finding.parameter or 'unknown parameter'}"

    def _sanitise_payload(self, payload: str) -> str:
        import re
        if re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$',
                    payload.strip()):
            return ""
        if re.match(r'^[0-9a-fA-F]{32,}$', payload.strip()):
            return ""
        if re.match(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            payload.strip(), re.I
        ):
            return ""
        return payload.strip()

