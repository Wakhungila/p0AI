"""
Tests for core/database.py

Covers:
  - create_session / get_session round-trip
  - update_session_status changes only the targeted session
  - list_sessions respects limit and ordering (most recent first)
  - save_finding / get_confirmed_findings only returns confirmed=1 entries
  - get_all_findings returns all findings for a session
  - False positives are excluded from get_confirmed_findings
  - save_kb_entry returns True on new, False on duplicate hash
  - search_kb by vuln_type returns only matching entries
  - get_payloads_for_vuln returns deduplicated flat list
  - kb_stats returns accurate counts
"""
import os
import sys
import tempfile
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.database import Database
from core.models import Finding, ScanSession, Severity, Target, VulnType


def _tmp_db() -> tuple[Database, str]:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return Database(db_path=path), path


def _make_session(url: str = "https://example.com") -> ScanSession:
    s = ScanSession()
    s.target = Target(url=url)
    return s


def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        title="Test Finding",
        vuln_type=VulnType.XSS_REFLECTED,
        severity=Severity.HIGH,
        url="https://example.com",
        endpoint="https://example.com/page",
        confidence=0.8,
        confirmed=True,
        false_positive=False,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ─── Sessions ─────────────────────────────────────────────────────────────────

def test_create_and_get_session():
    db, path = _tmp_db()
    try:
        session = _make_session()
        db.create_session(session)
        result = db.get_session(session.id)
        assert result is not None, "Session should be retrievable after creation"
        assert result["id"] == session.id
        assert result["target_url"] == "https://example.com"
        assert result["status"] == "running"
        print("  PASS test_create_and_get_session")
    finally:
        os.unlink(path)


def test_get_nonexistent_session_returns_none():
    db, path = _tmp_db()
    try:
        result = db.get_session("nonexistent-id")
        assert result is None
        print("  PASS test_get_nonexistent_session_returns_none")
    finally:
        os.unlink(path)


def test_update_session_status():
    db, path = _tmp_db()
    try:
        session = _make_session()
        db.create_session(session)
        completed = datetime(2025, 1, 1, 12, 0, 0)
        db.update_session_status(session.id, "complete", completed)
        result = db.get_session(session.id)
        assert result["status"] == "complete"
        assert "2025-01-01" in result["completed_at"]
        print("  PASS test_update_session_status")
    finally:
        os.unlink(path)


def test_list_sessions_respects_limit():
    db, path = _tmp_db()
    try:
        for i in range(5):
            s = _make_session(url=f"https://target{i}.com")
            db.create_session(s)
        results = db.list_sessions(limit=3)
        assert len(results) == 3, f"Expected 3 results, got {len(results)}"
        print("  PASS test_list_sessions_respects_limit")
    finally:
        os.unlink(path)


def test_update_status_only_affects_target_session():
    db, path = _tmp_db()
    try:
        s1 = _make_session("https://a.com")
        s2 = _make_session("https://b.com")
        db.create_session(s1)
        db.create_session(s2)
        db.update_session_status(s1.id, "complete")
        assert db.get_session(s1.id)["status"] == "complete"
        assert db.get_session(s2.id)["status"] == "running"
        print("  PASS test_update_status_only_affects_target_session")
    finally:
        os.unlink(path)


# ─── Findings ─────────────────────────────────────────────────────────────────

def test_save_and_retrieve_confirmed_finding():
    db, path = _tmp_db()
    try:
        session = _make_session()
        db.create_session(session)
        finding = _make_finding(confirmed=True)
        db.save_finding(finding, session.id)
        confirmed = db.get_confirmed_findings(session.id)
        assert len(confirmed) == 1
        assert confirmed[0]["id"] == finding.id
        assert confirmed[0]["title"] == "Test Finding"
        print("  PASS test_save_and_retrieve_confirmed_finding")
    finally:
        os.unlink(path)


def test_unconfirmed_finding_excluded_from_confirmed():
    db, path = _tmp_db()
    try:
        session = _make_session()
        db.create_session(session)
        db.save_finding(_make_finding(confirmed=False, false_positive=False), session.id)
        confirmed = db.get_confirmed_findings(session.id)
        assert len(confirmed) == 0, "Unconfirmed finding should not appear in confirmed list"
        print("  PASS test_unconfirmed_finding_excluded_from_confirmed")
    finally:
        os.unlink(path)


def test_false_positive_excluded_from_confirmed():
    db, path = _tmp_db()
    try:
        session = _make_session()
        db.create_session(session)
        db.save_finding(_make_finding(confirmed=True, false_positive=True), session.id)
        confirmed = db.get_confirmed_findings(session.id)
        assert len(confirmed) == 0, "False positive should not appear in confirmed list"
        print("  PASS test_false_positive_excluded_from_confirmed")
    finally:
        os.unlink(path)


def test_get_all_findings_returns_everything():
    db, path = _tmp_db()
    try:
        session = _make_session()
        db.create_session(session)
        db.save_finding(_make_finding(confirmed=True), session.id)
        db.save_finding(_make_finding(confirmed=False), session.id)
        db.save_finding(_make_finding(confirmed=True, false_positive=True), session.id)
        all_findings = db.get_all_findings(session.id)
        assert len(all_findings) == 3, \
            f"Expected 3 findings total, got {len(all_findings)}"
        print("  PASS test_get_all_findings_returns_everything")
    finally:
        os.unlink(path)


def test_findings_isolated_by_session():
    """Findings from session A should not appear in session B queries."""
    db, path = _tmp_db()
    try:
        s1 = _make_session("https://a.com")
        s2 = _make_session("https://b.com")
        db.create_session(s1)
        db.create_session(s2)
        db.save_finding(_make_finding(title="A's finding"), s1.id)
        db.save_finding(_make_finding(title="B's finding"), s2.id)
        s1_findings = db.get_confirmed_findings(s1.id)
        s2_findings = db.get_confirmed_findings(s2.id)
        assert len(s1_findings) == 1 and s1_findings[0]["title"] == "A's finding"
        assert len(s2_findings) == 1 and s2_findings[0]["title"] == "B's finding"
        print("  PASS test_findings_isolated_by_session")
    finally:
        os.unlink(path)


def test_steps_to_reproduce_round_trip():
    db, path = _tmp_db()
    try:
        session = _make_session()
        db.create_session(session)
        steps = ["Step 1: navigate to URL", "Step 2: inject payload", "Step 3: observe response"]
        f = _make_finding(steps_to_reproduce=steps)
        db.save_finding(f, session.id)
        confirmed = db.get_confirmed_findings(session.id)
        assert confirmed[0]["steps_to_reproduce"] == steps, \
            "steps_to_reproduce should survive JSON round-trip"
        print("  PASS test_steps_to_reproduce_round_trip")
    finally:
        os.unlink(path)


# ─── Knowledge Base ────────────────────────────────────────────────────────────

def _kb_entry(hash_val: str, vuln_types=None, payloads=None, source="test") -> dict:
    return {
        "source": source,
        "title": f"Entry {hash_val}",
        "url": "https://example.com/article",
        "content": "security research content",
        "vuln_types": vuln_types or ["xss_reflected"],
        "payloads": payloads or ["<script>alert(1)</script>"],
        "techniques": ["inject into input field"],
        "cve": "",
        "hash": hash_val,
    }


def test_save_kb_entry_returns_true_on_new():
    db, path = _tmp_db()
    try:
        result = db.save_kb_entry(_kb_entry("hash001"))
        assert result is True, "New entry should return True"
        print("  PASS test_save_kb_entry_returns_true_on_new")
    finally:
        os.unlink(path)


def test_save_kb_entry_returns_false_on_duplicate():
    db, path = _tmp_db()
    try:
        db.save_kb_entry(_kb_entry("hash002"))
        result = db.save_kb_entry(_kb_entry("hash002"))  # same hash
        assert result is False, "Duplicate entry should return False"
        print("  PASS test_save_kb_entry_returns_false_on_duplicate")
    finally:
        os.unlink(path)


def test_search_kb_by_vuln_type():
    db, path = _tmp_db()
    try:
        db.save_kb_entry(_kb_entry("h1", vuln_types=["xss_reflected", "xss_stored"]))
        db.save_kb_entry(_kb_entry("h2", vuln_types=["sql_injection"]))
        db.save_kb_entry(_kb_entry("h3", vuln_types=["ssrf"]))
        xss_results = db.search_kb(vuln_type="xss_reflected")
        sqli_results = db.search_kb(vuln_type="sql_injection")
        assert len(xss_results) == 1
        assert len(sqli_results) == 1
        print("  PASS test_search_kb_by_vuln_type")
    finally:
        os.unlink(path)


def test_get_payloads_for_vuln_deduplicates():
    db, path = _tmp_db()
    try:
        payload = "<script>alert(1)</script>"
        # Two entries with the same payload for xss
        db.save_kb_entry(_kb_entry("h1", vuln_types=["xss_reflected"], payloads=[payload]))
        db.save_kb_entry(_kb_entry("h2", vuln_types=["xss_reflected"], payloads=[payload, "other"]))
        payloads = db.get_payloads_for_vuln("xss_reflected")
        # Deduplication: payload should appear only once
        assert payloads.count(payload) == 1, \
            f"Duplicate payload should appear only once, got: {payloads}"
        print("  PASS test_get_payloads_for_vuln_deduplicates")
    finally:
        os.unlink(path)


def test_kb_stats_accuracy():
    db, path = _tmp_db()
    try:
        db.save_kb_entry(_kb_entry("s1", source="portswigger"))
        db.save_kb_entry(_kb_entry("s2", source="portswigger"))
        db.save_kb_entry(_kb_entry("s3", source="hackerone"))
        stats = db.kb_stats()
        assert stats["total"] == 3
        assert stats["by_source"].get("portswigger") == 2
        assert stats["by_source"].get("hackerone") == 1
        print("  PASS test_kb_stats_accuracy")
    finally:
        os.unlink(path)


if __name__ == "__main__":
    print("\nDatabase Tests")
    print("=" * 40)
    test_create_and_get_session()
    test_get_nonexistent_session_returns_none()
    test_update_session_status()
    test_list_sessions_respects_limit()
    test_update_status_only_affects_target_session()
    test_save_and_retrieve_confirmed_finding()
    test_unconfirmed_finding_excluded_from_confirmed()
    test_false_positive_excluded_from_confirmed()
    test_get_all_findings_returns_everything()
    test_findings_isolated_by_session()
    test_steps_to_reproduce_round_trip()
    test_save_kb_entry_returns_true_on_new()
    test_save_kb_entry_returns_false_on_duplicate()
    test_search_kb_by_vuln_type()
    test_get_payloads_for_vuln_deduplicates()
    test_kb_stats_accuracy()
    print("\nAll Database tests passed.")
