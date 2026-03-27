"""
pin0ccsAI — Payload Cache
Caches AI-generated payload mutations keyed by (vuln_type, tech_fingerprint).
Backed by SQLite so cache survives process restarts.
Eliminates the dominant source of repeated LLM calls in the Tester Agent.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Generator, Optional

from core.logger import get_logger

log = get_logger(__name__)

# Cache TTL — entries older than this are treated as stale and regenerated
_DEFAULT_TTL_HOURS = 72


class PayloadCache:
    """
    SQLite-backed payload mutation cache.

    Key  = SHA-256( vuln_type + sorted(tech_stack) )
    Value = JSON list of payload strings

    Design decisions:
    - Separate table in the same knowledge.db file — no extra file
    - TTL of 72 hours: stale enough for variety, fresh enough to pick up
      KB updates when update-kb has been run between scans
    - hit() returns payloads OR None (caller decides whether to regenerate)
    - store() is idempotent: same key overwrites with fresh timestamp
    """

    def __init__(self, db_path: str = "./data/kb/knowledge.db",
                 ttl_hours: int = _DEFAULT_TTL_HOURS):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(hours=ttl_hours)
        self._init_table()
        log.debug("payload_cache.ready", path=str(self.db_path), ttl_h=ttl_hours)

    # ─── Public API ───────────────────────────────────────────────────────────

    def hit(self, vuln_type: str, tech_stack: list[str]) -> Optional[list[str]]:
        """
        Return cached payloads if present and fresh, else None.
        Caller should regenerate on None and call store() with the result.
        """
        key = self._make_key(vuln_type, tech_stack)
        with self._conn() as conn:
            row = conn.execute(
                "SELECT payloads, cached_at FROM payload_cache WHERE cache_key = ?",
                (key,)
            ).fetchone()

        if not row:
            log.debug("payload_cache.miss", vuln_type=vuln_type, key=key[:12])
            return None

        payloads_json, cached_at_str = row
        cached_at = datetime.fromisoformat(cached_at_str)
        age = datetime.utcnow() - cached_at

        if age > self.ttl:
            log.debug("payload_cache.stale", vuln_type=vuln_type,
                      age_h=age.total_seconds() / 3600)
            return None

        payloads = json.loads(payloads_json)
        log.debug("payload_cache.hit", vuln_type=vuln_type,
                  count=len(payloads), age_h=round(age.total_seconds() / 3600, 1))
        return payloads

    def store(self, vuln_type: str, tech_stack: list[str],
              payloads: list[str]) -> None:
        """Persist a payload list. Overwrites any existing entry for this key."""
        if not payloads:
            return
        key = self._make_key(vuln_type, tech_stack)
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO payload_cache
                   (cache_key, vuln_type, tech_fingerprint, payloads, cached_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    key,
                    vuln_type,
                    json.dumps(sorted(tech_stack)),
                    json.dumps(payloads),
                    datetime.utcnow().isoformat(),
                ),
            )
        log.debug("payload_cache.stored", vuln_type=vuln_type,
                  count=len(payloads), key=key[:12])

    def invalidate(self, vuln_type: Optional[str] = None) -> int:
        """
        Evict stale entries (older than TTL) or all entries for a vuln_type.
        Returns number of rows deleted.
        """
        cutoff = (datetime.utcnow() - self.ttl).isoformat()
        with self._conn() as conn:
            if vuln_type:
                cur = conn.execute(
                    "DELETE FROM payload_cache WHERE vuln_type = ?", (vuln_type,)
                )
            else:
                cur = conn.execute(
                    "DELETE FROM payload_cache WHERE cached_at < ?", (cutoff,)
                )
            deleted = cur.rowcount
        if deleted:
            log.info("payload_cache.evicted", deleted=deleted, vuln_type=vuln_type)
        return deleted

    def stats(self) -> dict:
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM payload_cache"
            ).fetchone()[0]
            by_type = conn.execute(
                "SELECT vuln_type, COUNT(*) FROM payload_cache GROUP BY vuln_type"
            ).fetchall()
            stale_cutoff = (datetime.utcnow() - self.ttl).isoformat()
            stale = conn.execute(
                "SELECT COUNT(*) FROM payload_cache WHERE cached_at < ?",
                (stale_cutoff,)
            ).fetchone()[0]
        return {
            "total": total,
            "stale": stale,
            "by_type": {r[0]: r[1] for r in by_type},
        }

    # ─── Internals ───────────────────────────────────────────────────────────

    def _make_key(self, vuln_type: str, tech_stack: list[str]) -> str:
        """
        Deterministic cache key from vuln_type + sorted normalised tech list.
        Tech stack is normalised to lowercase and sorted so that
        ["React", "Django"] and ["django", "react"] produce the same key.
        """
        normalised_tech = sorted(t.lower().strip() for t in tech_stack if t)
        raw = vuln_type + ":" + ",".join(normalised_tech)
        return hashlib.sha256(raw.encode()).hexdigest()

    def _init_table(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS payload_cache (
                    cache_key      TEXT PRIMARY KEY,
                    vuln_type      TEXT NOT NULL,
                    tech_fingerprint TEXT,
                    payloads       TEXT NOT NULL,
                    cached_at      TEXT NOT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_pc_vuln_type "
                "ON payload_cache(vuln_type)"
            )

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
