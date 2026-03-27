"""
pin0ccsAI — Scan Checkpoint

Persists scan phase state to SQLite so a crashed or interrupted scan can
be resumed from the last completed phase rather than starting over.

Phases (in execution order):
  0  recon
  1  strategy
  2  tester
  3  web3
  4  debator
  5  report

When a phase completes, its output is serialised to the checkpoints table.
On resume, completed phases are skipped and their outputs are deserialised
back into Python objects.

Why SQLite and not a JSON file:
  - Already open (same knowledge.db connection)
  - Atomic writes — no partial checkpoint files
  - queryable for status display
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Generator, Optional

from core.logger import get_logger

log = get_logger(__name__)

# Phase constants — used as checkpoint keys
PHASE_RECON     = "recon"
PHASE_STRATEGY  = "strategy"
PHASE_TESTER    = "tester"
PHASE_WEB3      = "web3"
PHASE_DEBATOR   = "debator"
PHASE_REPORT    = "report"

_PHASE_ORDER = [
    PHASE_RECON, PHASE_STRATEGY, PHASE_TESTER,
    PHASE_WEB3, PHASE_DEBATOR, PHASE_REPORT,
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_checkpoints (
    session_id  TEXT NOT NULL,
    phase       TEXT NOT NULL,
    payload     TEXT NOT NULL,   -- JSON-serialised phase output
    saved_at    TEXT NOT NULL,
    PRIMARY KEY (session_id, phase)
);
CREATE INDEX IF NOT EXISTS idx_ckpt_session
    ON scan_checkpoints(session_id);
"""


class CheckpointManager:
    """
    Saves and loads phase outputs for a single scan session.
    One instance per scan session, created by the orchestrator.
    """

    def __init__(self, db_path: str, session_id: str):
        self.db_path = Path(db_path)
        self.session_id = session_id
        self._init_table()

    # ─── Public API ───────────────────────────────────────────────────────────

    def save(self, phase: str, data: Any) -> None:
        """
        Persist the output of a completed phase.
        data must be JSON-serialisable.
        """
        payload = json.dumps(data, default=str)
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO scan_checkpoints
                   (session_id, phase, payload, saved_at)
                   VALUES (?, ?, ?, ?)""",
                (self.session_id, phase, payload,
                 datetime.utcnow().isoformat()),
            )
        log.debug("checkpoint.saved", session=self.session_id[:8], phase=phase)

    def load(self, phase: str) -> Optional[Any]:
        """
        Return deserialised phase output, or None if not checkpointed.
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT payload FROM scan_checkpoints "
                "WHERE session_id=? AND phase=?",
                (self.session_id, phase),
            ).fetchone()
        if not row:
            return None
        return json.loads(row[0])

    def is_done(self, phase: str) -> bool:
        """Return True if this phase has a saved checkpoint."""
        return self.load(phase) is not None

    def completed_phases(self) -> list[str]:
        """Return list of phase names that have been checkpointed."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT phase FROM scan_checkpoints WHERE session_id=? "
                "ORDER BY saved_at",
                (self.session_id,),
            ).fetchall()
        return [r[0] for r in rows]

    def resume_from_phase(self) -> str:
        """
        Return the name of the first phase that has NOT been checkpointed.
        Returns PHASE_RECON if nothing has been checkpointed yet.
        """
        done = set(self.completed_phases())
        for phase in _PHASE_ORDER:
            if phase not in done:
                return phase
        return PHASE_REPORT  # everything done — just re-run report

    def clear(self) -> None:
        """Delete all checkpoints for this session (used after clean run)."""
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM scan_checkpoints WHERE session_id=?",
                (self.session_id,),
            )
        log.debug("checkpoint.cleared", session=self.session_id[:8])

    def status(self) -> dict:
        """Return checkpoint status for CLI display."""
        done = self.completed_phases()
        remaining = [p for p in _PHASE_ORDER if p not in done]
        return {
            "session_id": self.session_id,
            "completed_phases": done,
            "remaining_phases": remaining,
            "resume_from": self.resume_from_phase(),
            "is_resumable": bool(done) and bool(remaining),
        }

    # ─── Serialisers for Complex Phase Outputs ────────────────────────────────

    def save_recon(self, recon) -> None:
        """Serialise ReconResult — stores enough to rebuild for Strategy/Tester."""
        from core.models import Endpoint
        data = {
            "target_url": recon.target.url,
            "subdomains": recon.subdomains,
            "live_hosts": recon.live_hosts,
            "tech_stack": recon.tech_stack,
            "open_ports": recon.open_ports,
            "graphql_endpoints": recon.graphql_endpoints,
            "api_endpoints": recon.api_endpoints,
            "endpoints": [
                {
                    "url": ep.url,
                    "method": ep.method,
                    "status_code": ep.status_code,
                    "content_type": ep.content_type,
                    "tech_stack": ep.tech_stack,
                    "params": ep.params,
                    "headers": ep.headers,
                    "crown_jewel_score": ep.crown_jewel_score,
                    "is_authenticated": ep.is_authenticated,
                    "notes": ep.notes,
                }
                for ep in recon.endpoints
            ],
            "crown_jewels": [
                {"url": ep.url, "crown_jewel_score": ep.crown_jewel_score}
                for ep in recon.crown_jewels
            ],
        }
        self.save(PHASE_RECON, data)

    def load_recon(self, target):
        """Deserialise a checkpointed ReconResult."""
        from core.models import Endpoint, ReconResult
        data = self.load(PHASE_RECON)
        if not data:
            return None
        recon = ReconResult(target=target)
        recon.subdomains = data.get("subdomains", [])
        recon.live_hosts = data.get("live_hosts", [])
        recon.tech_stack = data.get("tech_stack", {})
        recon.open_ports = data.get("open_ports", {})
        recon.graphql_endpoints = data.get("graphql_endpoints", [])
        recon.api_endpoints = data.get("api_endpoints", [])
        recon.endpoints = [
            Endpoint(
                url=ep["url"],
                method=ep.get("method", "GET"),
                status_code=ep.get("status_code", 0),
                content_type=ep.get("content_type", ""),
                tech_stack=ep.get("tech_stack", []),
                params=ep.get("params", []),
                headers=ep.get("headers", {}),
                crown_jewel_score=ep.get("crown_jewel_score", 0),
                is_authenticated=ep.get("is_authenticated", False),
                notes=ep.get("notes", ""),
            )
            for ep in data.get("endpoints", [])
        ]
        recon.crown_jewels = [
            Endpoint(
                url=cj["url"],
                crown_jewel_score=cj.get("crown_jewel_score", 0),
            )
            for cj in data.get("crown_jewels", [])
        ]
        log.info("checkpoint.recon_restored",
                 endpoints=len(recon.endpoints),
                 crown_jewels=len(recon.crown_jewels))
        return recon

    def save_attack_plan(self, attack_plan: list[dict]) -> None:
        self.save(PHASE_STRATEGY, attack_plan)

    def load_attack_plan(self) -> Optional[list[dict]]:
        return self.load(PHASE_STRATEGY)

    def save_raw_findings(self, findings: list) -> None:
        self.save(PHASE_TESTER, [f.to_dict() for f in findings])

    def load_raw_findings(self) -> Optional[list[dict]]:
        return self.load(PHASE_TESTER)

    # ─── Internals ───────────────────────────────────────────────────────────

    def _init_table(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
