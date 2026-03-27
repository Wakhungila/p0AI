"""
pin0ccsAI — Persistence Layer
SQLite-backed storage for sessions, confirmed findings, and the knowledge base.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional

from core.models import Finding, ScanSession, Severity, VulnType
from core.logger import get_logger

log = get_logger(__name__)

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    target_url  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running',
    started_at  TEXT NOT NULL,
    completed_at TEXT,
    notes       TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS findings (
    id                  TEXT PRIMARY KEY,
    session_id          TEXT REFERENCES sessions(id),
    title               TEXT NOT NULL,
    vuln_type           TEXT,
    severity            TEXT,
    url                 TEXT,
    endpoint            TEXT,
    method              TEXT,
    parameter           TEXT,
    payload             TEXT,
    evidence            TEXT,
    steps_to_reproduce  TEXT,   -- JSON array
    impact              TEXT,
    remediation         TEXT,
    cvss_score          REAL,
    cvss_vector         TEXT,
    confidence          REAL,
    confirmed           INTEGER DEFAULT 0,
    false_positive      INTEGER DEFAULT 0,
    tool                TEXT,
    raw_output          TEXT,
    discovered_at       TEXT,
    validated_at        TEXT,
    extra               TEXT    -- JSON blob
);

CREATE TABLE IF NOT EXISTS kb_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT NOT NULL,
    title       TEXT NOT NULL,
    url         TEXT,
    content     TEXT,
    vuln_types  TEXT,   -- JSON array of VulnType strings
    payloads    TEXT,   -- JSON array of extracted payloads
    techniques  TEXT,   -- JSON array of technique strings
    cve         TEXT,
    ingested_at TEXT NOT NULL,
    hash        TEXT UNIQUE   -- SHA256 of content to avoid duplicates
);

CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_confirmed ON findings(confirmed);
CREATE INDEX IF NOT EXISTS idx_kb_vuln_types ON kb_entries(vuln_types);
"""


class Database:
    def __init__(self, db_path: str = "./data/kb/knowledge.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
        log.info("database.ready", path=str(self.db_path))

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ─── Sessions ────────────────────────────────────────────────────────────

    def create_session(self, session: ScanSession) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO sessions (id, target_url, status, started_at, notes) VALUES (?,?,?,?,?)",
                (session.id, session.target.url if session.target else "", session.status,
                 session.started_at.isoformat(), session.notes),
            )
        log.debug("session.created", session_id=session.id)

    def update_session_status(self, session_id: str, status: str,
                               completed_at: Optional[datetime] = None) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE sessions SET status=?, completed_at=? WHERE id=?",
                (status, completed_at.isoformat() if completed_at else None, session_id),
            )

    def get_session(self, session_id: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            return dict(row) if row else None

    def list_sessions(self, limit: int = 20) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ─── Findings ────────────────────────────────────────────────────────────

    def save_finding(self, finding: Finding, session_id: str) -> None:
        with self._conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO findings (
                    id, session_id, title, vuln_type, severity, url, endpoint,
                    method, parameter, payload, evidence, steps_to_reproduce,
                    impact, remediation, cvss_score, cvss_vector, confidence,
                    confirmed, false_positive, tool, raw_output, discovered_at,
                    validated_at, extra
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                finding.id, session_id, finding.title,
                finding.vuln_type.value, finding.severity.value,
                finding.url, finding.endpoint, finding.method,
                finding.parameter, finding.payload, finding.evidence,
                json.dumps(finding.steps_to_reproduce),
                finding.impact, finding.remediation,
                finding.cvss_score, finding.cvss_vector,
                finding.confidence, int(finding.confirmed), int(finding.false_positive),
                finding.tool, finding.raw_output,
                finding.discovered_at.isoformat(),
                finding.validated_at.isoformat() if finding.validated_at else None,
                json.dumps(finding.extra),
            ))
        log.debug("finding.saved", finding_id=finding.id, confirmed=finding.confirmed)

    def get_confirmed_findings(self, session_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE session_id=? AND confirmed=1 AND false_positive=0",
                (session_id,)
            ).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                d["steps_to_reproduce"] = json.loads(d.get("steps_to_reproduce") or "[]")
                d["extra"] = json.loads(d.get("extra") or "{}")
                results.append(d)
            return results

    def get_all_findings(self, session_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE session_id=? ORDER BY severity",
                (session_id,)
            ).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                d["steps_to_reproduce"] = json.loads(d.get("steps_to_reproduce") or "[]")
                results.append(d)
            return results

    # ─── Knowledge Base ───────────────────────────────────────────────────────

    def save_kb_entry(self, entry: dict) -> bool:
        """Returns True if new, False if duplicate (by content hash)."""
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT id FROM kb_entries WHERE hash=?", (entry.get("hash"),)
            ).fetchone()
            if existing:
                return False
            conn.execute("""
                INSERT INTO kb_entries
                    (source, title, url, content, vuln_types, payloads, techniques,
                     cve, ingested_at, hash)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                entry.get("source", ""),
                entry.get("title", ""),
                entry.get("url", ""),
                entry.get("content", ""),
                json.dumps(entry.get("vuln_types", [])),
                json.dumps(entry.get("payloads", [])),
                json.dumps(entry.get("techniques", [])),
                entry.get("cve", ""),
                datetime.utcnow().isoformat(),
                entry.get("hash", ""),
            ))
            return True

    def search_kb(self, vuln_type: Optional[str] = None, keyword: Optional[str] = None,
                  limit: int = 10) -> list[dict]:
        with self._conn() as conn:
            if vuln_type:
                rows = conn.execute(
                    "SELECT * FROM kb_entries WHERE vuln_types LIKE ? ORDER BY ingested_at DESC LIMIT ?",
                    (f"%{vuln_type}%", limit)
                ).fetchall()
            elif keyword:
                rows = conn.execute(
                    "SELECT * FROM kb_entries WHERE title LIKE ? OR content LIKE ? "
                    "ORDER BY ingested_at DESC LIMIT ?",
                    (f"%{keyword}%", f"%{keyword}%", limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM kb_entries ORDER BY ingested_at DESC LIMIT ?", (limit,)
                ).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                d["vuln_types"] = json.loads(d.get("vuln_types") or "[]")
                d["payloads"] = json.loads(d.get("payloads") or "[]")
                d["techniques"] = json.loads(d.get("techniques") or "[]")
                results.append(d)
            return results

    def get_payloads_for_vuln(self, vuln_type: str, limit: int = 50) -> list[str]:
        """Pull extracted payloads from KB for a specific vuln type."""
        entries = self.search_kb(vuln_type=vuln_type, limit=limit)
        payloads = []
        for e in entries:
            payloads.extend(e.get("payloads", []))
        return list(set(payloads))

    def kb_stats(self) -> dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM kb_entries").fetchone()[0]
            sources = conn.execute(
                "SELECT source, COUNT(*) as cnt FROM kb_entries GROUP BY source"
            ).fetchall()
            return {"total": total, "by_source": {r["source"]: r["cnt"] for r in sources}}
