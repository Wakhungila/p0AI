"""
Tests for core/checkpoint.py

Covers:
  - save() and load() round-trip for arbitrary JSON-serialisable data
  - is_done() returns False before save, True after
  - completed_phases() returns phases in insertion order
  - resume_from_phase() returns first uncompleted phase
  - resume_from_phase() returns PHASE_REPORT when all phases done
  - clear() removes all checkpoints for the session
  - clear() does not affect other sessions
  - Different sessions are isolated — no cross-contamination
  - save_recon() / load_recon() preserves endpoints and crown_jewels
  - save_attack_plan() / load_attack_plan() round-trips a plan list
  - save_raw_findings() / load_raw_findings() preserves finding dicts
  - status() reports correct is_resumable flag
  - Overwriting a phase checkpoint (INSERT OR REPLACE) works correctly
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Shared stubs — installs structlog/httpx/yaml/pluggy mocks
import sys; sys.path.insert(0, __file__.rsplit('/', 2)[0])
import tests.stubs  # noqa: F401 — side-effect: installs all stubs

from core.checkpoint import (
    CheckpointManager,
    PHASE_RECON, PHASE_STRATEGY, PHASE_TESTER,
    PHASE_WEB3, PHASE_DEBATOR, PHASE_REPORT,
    _PHASE_ORDER,
)


def _tmp_ckpt(session_id: str = "test-session-001") -> tuple[CheckpointManager, str]:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return CheckpointManager(db_path=path, session_id=session_id), path


# ─── Basic save / load ────────────────────────────────────────────────────────

def test_load_returns_none_before_save():
    ckpt, path = _tmp_ckpt()
    try:
        assert ckpt.load(PHASE_RECON) is None
    finally:
        os.unlink(path)
    print("  PASS test_load_returns_none_before_save")


def test_save_and_load_dict():
    ckpt, path = _tmp_ckpt()
    try:
        data = {"key": "value", "count": 42, "nested": {"a": [1, 2, 3]}}
        ckpt.save(PHASE_RECON, data)
        result = ckpt.load(PHASE_RECON)
        assert result == data
    finally:
        os.unlink(path)
    print("  PASS test_save_and_load_dict")


def test_save_and_load_list():
    ckpt, path = _tmp_ckpt()
    try:
        data = [{"phase": "auth", "targets": ["https://a.com"]}]
        ckpt.save(PHASE_STRATEGY, data)
        result = ckpt.load(PHASE_STRATEGY)
        assert result == data
    finally:
        os.unlink(path)
    print("  PASS test_save_and_load_list")


def test_overwrite_checkpoint():
    ckpt, path = _tmp_ckpt()
    try:
        ckpt.save(PHASE_RECON, {"v": 1})
        ckpt.save(PHASE_RECON, {"v": 2})  # overwrite
        result = ckpt.load(PHASE_RECON)
        assert result == {"v": 2}, f"Expected v=2, got {result}"
    finally:
        os.unlink(path)
    print("  PASS test_overwrite_checkpoint")


# ─── is_done / completed_phases ──────────────────────────────────────────────

def test_is_done_false_before_save():
    ckpt, path = _tmp_ckpt()
    try:
        assert ckpt.is_done(PHASE_RECON) is False
    finally:
        os.unlink(path)
    print("  PASS test_is_done_false_before_save")


def test_is_done_true_after_save():
    ckpt, path = _tmp_ckpt()
    try:
        ckpt.save(PHASE_RECON, {"done": True})
        assert ckpt.is_done(PHASE_RECON) is True
    finally:
        os.unlink(path)
    print("  PASS test_is_done_true_after_save")


def test_completed_phases_order():
    ckpt, path = _tmp_ckpt()
    try:
        ckpt.save(PHASE_RECON, {})
        ckpt.save(PHASE_STRATEGY, {})
        ckpt.save(PHASE_TESTER, {})
        done = ckpt.completed_phases()
        assert done == [PHASE_RECON, PHASE_STRATEGY, PHASE_TESTER]
    finally:
        os.unlink(path)
    print("  PASS test_completed_phases_order")


# ─── resume_from_phase ────────────────────────────────────────────────────────

def test_resume_from_phase_returns_recon_when_nothing_done():
    ckpt, path = _tmp_ckpt()
    try:
        assert ckpt.resume_from_phase() == PHASE_RECON
    finally:
        os.unlink(path)
    print("  PASS test_resume_from_phase_returns_recon_when_nothing_done")


def test_resume_from_phase_skips_completed():
    ckpt, path = _tmp_ckpt()
    try:
        ckpt.save(PHASE_RECON, {})
        ckpt.save(PHASE_STRATEGY, {})
        assert ckpt.resume_from_phase() == PHASE_TESTER
    finally:
        os.unlink(path)
    print("  PASS test_resume_from_phase_skips_completed")


def test_resume_from_phase_returns_report_when_all_done():
    ckpt, path = _tmp_ckpt()
    try:
        for phase in _PHASE_ORDER:
            ckpt.save(phase, {})
        assert ckpt.resume_from_phase() == PHASE_REPORT
    finally:
        os.unlink(path)
    print("  PASS test_resume_from_phase_returns_report_when_all_done")


# ─── clear ────────────────────────────────────────────────────────────────────

def test_clear_removes_all_checkpoints():
    ckpt, path = _tmp_ckpt()
    try:
        ckpt.save(PHASE_RECON, {})
        ckpt.save(PHASE_STRATEGY, {})
        ckpt.clear()
        assert ckpt.completed_phases() == []
        assert not ckpt.is_done(PHASE_RECON)
    finally:
        os.unlink(path)
    print("  PASS test_clear_removes_all_checkpoints")


def test_clear_does_not_affect_other_sessions():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ckpt_a = CheckpointManager(path, "session-a")
        ckpt_b = CheckpointManager(path, "session-b")
        ckpt_a.save(PHASE_RECON, {"a": 1})
        ckpt_b.save(PHASE_RECON, {"b": 2})
        ckpt_a.clear()
        assert not ckpt_a.is_done(PHASE_RECON)
        assert ckpt_b.is_done(PHASE_RECON), "session-b checkpoint should survive"
        assert ckpt_b.load(PHASE_RECON) == {"b": 2}
    finally:
        os.unlink(path)
    print("  PASS test_clear_does_not_affect_other_sessions")


# ─── Session isolation ────────────────────────────────────────────────────────

def test_sessions_are_isolated():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ckpt_a = CheckpointManager(path, "sess-a")
        ckpt_b = CheckpointManager(path, "sess-b")
        ckpt_a.save(PHASE_RECON, {"for": "a"})
        assert ckpt_b.load(PHASE_RECON) is None, \
            "Session B should not see session A's checkpoint"
    finally:
        os.unlink(path)
    print("  PASS test_sessions_are_isolated")


# ─── Recon serialiser ─────────────────────────────────────────────────────────

def test_save_and_load_recon():
    from core.models import Endpoint, ReconResult, Target
    ckpt, path = _tmp_ckpt()
    try:
        target = Target(url="https://example.com")
        recon = ReconResult(target=target)
        recon.subdomains = ["https://api.example.com"]
        recon.live_hosts = ["https://example.com", "https://api.example.com"]
        recon.tech_stack = {"https://example.com": ["nginx", "Django"]}
        recon.endpoints = [
            Endpoint(url="https://example.com/api/v1/users",
                     method="GET", status_code=200, crown_jewel_score=75)
        ]
        recon.crown_jewels = [recon.endpoints[0]]
        recon.graphql_endpoints = ["https://example.com/graphql"]

        ckpt.save_recon(recon)
        restored = ckpt.load_recon(target)

        assert restored is not None
        assert restored.subdomains == recon.subdomains
        assert restored.live_hosts == recon.live_hosts
        assert restored.tech_stack == recon.tech_stack
        assert len(restored.endpoints) == 1
        assert restored.endpoints[0].url == "https://example.com/api/v1/users"
        assert restored.endpoints[0].crown_jewel_score == 75
        assert len(restored.crown_jewels) == 1
        assert restored.graphql_endpoints == ["https://example.com/graphql"]
    finally:
        os.unlink(path)
    print("  PASS test_save_and_load_recon")


# ─── Attack plan serialiser ───────────────────────────────────────────────────

def test_save_and_load_attack_plan():
    ckpt, path = _tmp_ckpt()
    try:
        plan = [
            {"phase": "Auth testing", "targets": ["https://a.com/login"],
             "vuln_types": ["auth_bypass", "idor"], "priority": 1},
            {"phase": "API fuzzing", "targets": ["https://a.com/api/v1/"],
             "vuln_types": ["sqli", "ssrf"], "priority": 2},
        ]
        ckpt.save_attack_plan(plan)
        restored = ckpt.load_attack_plan()
        assert restored == plan
    finally:
        os.unlink(path)
    print("  PASS test_save_and_load_attack_plan")


# ─── Raw findings serialiser ──────────────────────────────────────────────────

def test_save_and_load_raw_findings():
    from core.models import Finding, Severity, VulnType
    ckpt, path = _tmp_ckpt()
    try:
        findings = [
            Finding(
                title="Test XSS", vuln_type=VulnType.XSS_REFLECTED,
                severity=Severity.HIGH, url="https://a.com", confidence=0.65,
                steps_to_reproduce=["step 1", "step 2"],
            ),
            Finding(
                title="Test SQLi", vuln_type=VulnType.SQLI,
                severity=Severity.CRITICAL, url="https://a.com/api",
                payload="' OR 1=1--", confidence=0.70,
            ),
        ]
        ckpt.save_raw_findings(findings)
        restored_dicts = ckpt.load_raw_findings()
        assert restored_dicts is not None
        assert len(restored_dicts) == 2
        titles = [d["title"] for d in restored_dicts]
        assert "Test XSS" in titles
        assert "Test SQLi" in titles
    finally:
        os.unlink(path)
    print("  PASS test_save_and_load_raw_findings")


# ─── Status ──────────────────────────────────────────────────────────────────

def test_status_is_resumable_false_when_nothing_done():
    ckpt, path = _tmp_ckpt()
    try:
        s = ckpt.status()
        assert s["is_resumable"] is False
    finally:
        os.unlink(path)
    print("  PASS test_status_is_resumable_false_when_nothing_done")


def test_status_is_resumable_true_when_partially_done():
    ckpt, path = _tmp_ckpt()
    try:
        ckpt.save(PHASE_RECON, {})
        s = ckpt.status()
        assert s["is_resumable"] is True
        assert PHASE_RECON in s["completed_phases"]
        assert PHASE_STRATEGY in s["remaining_phases"]
    finally:
        os.unlink(path)
    print("  PASS test_status_is_resumable_true_when_partially_done")


if __name__ == "__main__":
    print("\nCheckpointManager Tests")
    print("=" * 40)
    test_load_returns_none_before_save()
    test_save_and_load_dict()
    test_save_and_load_list()
    test_overwrite_checkpoint()
    test_is_done_false_before_save()
    test_is_done_true_after_save()
    test_completed_phases_order()
    test_resume_from_phase_returns_recon_when_nothing_done()
    test_resume_from_phase_skips_completed()
    test_resume_from_phase_returns_report_when_all_done()
    test_clear_removes_all_checkpoints()
    test_clear_does_not_affect_other_sessions()
    test_sessions_are_isolated()
    test_save_and_load_recon()
    test_save_and_load_attack_plan()
    test_save_and_load_raw_findings()
    test_status_is_resumable_false_when_nothing_done()
    test_status_is_resumable_true_when_partially_done()
    print("\nAll CheckpointManager tests passed.")
