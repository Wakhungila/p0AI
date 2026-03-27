"""
Tests for core/learning_loop.py

Covers:
  - Confirmed finding with payload is stored in KB
  - Unconfirmed finding is NOT stored
  - False positive is NOT stored
  - Finding with empty payload is NOT stored
  - Same payload + vuln_type combination is deduplicated (same hash)
  - Different payloads for same vuln_type are stored as separate entries
  - Same payload for different vuln_types are stored as separate entries
  - JWT payload is sanitised (rejected — not a reusable payload)
  - Long hex string is sanitised (rejected — looks like session ID)
  - UUID-only payload is sanitised (rejected)
  - Normal XSS payload passes sanitisation
  - cache.invalidate() is called for each affected vuln_type
  - Stats returned correctly: new, duplicate, cache_invalidated
  - Steps to reproduce are converted to technique string
"""
import os
import sys
import tempfile
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Shared stubs — installs structlog/httpx/yaml/pluggy mocks
import sys; sys.path.insert(0, __file__.rsplit('/', 2)[0])
import tests.stubs  # noqa: F401 — side-effect: installs all stubs

from core.database import Database
from core.learning_loop import LearningLoop
from core.models import Finding, Severity, VulnType
from core.payload_cache import PayloadCache


def _setup() -> tuple[LearningLoop, Database, PayloadCache, str]:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = Database(db_path=path)
    cache = PayloadCache(db_path=path)
    loop = LearningLoop(db=db, cache=cache)
    return loop, db, cache, path


def _confirmed_finding(
    payload: str = "<script>alert(1)</script>",
    vuln_type: VulnType = VulnType.XSS_REFLECTED,
    confirmed: bool = True,
    false_positive: bool = False,
    steps: list = None,
) -> Finding:
    return Finding(
        title="Test finding",
        vuln_type=vuln_type,
        severity=Severity.HIGH,
        url="https://example.com/search",
        parameter="q",
        payload=payload,
        evidence="response text",
        steps_to_reproduce=steps or ["1. Navigate to URL", "2. Inject payload"],
        confirmed=confirmed,
        false_positive=false_positive,
        confidence=0.85,
    )


# ─── Core filtering ───────────────────────────────────────────────────────────

def test_confirmed_finding_is_stored():
    loop, db, cache, path = _setup()
    try:
        finding = _confirmed_finding()
        stats = loop.ingest_findings([finding], "sess001", "https://example.com")
        assert stats["new_kb"] == 1, f"Expected 1 new KB entry, got {stats}"
        # Verify it's in the KB
        payloads = db.get_payloads_for_vuln("xss_reflected")
        assert "<script>alert(1)</script>" in payloads
    finally:
        os.unlink(path)
    print("  PASS test_confirmed_finding_is_stored")


def test_unconfirmed_finding_is_not_stored():
    loop, db, cache, path = _setup()
    try:
        finding = _confirmed_finding(confirmed=False)
        stats = loop.ingest_findings([finding], "sess001", "https://example.com")
        assert stats["new_kb"] == 0
    finally:
        os.unlink(path)
    print("  PASS test_unconfirmed_finding_is_not_stored")


def test_false_positive_is_not_stored():
    loop, db, cache, path = _setup()
    try:
        finding = _confirmed_finding(confirmed=True, false_positive=True)
        stats = loop.ingest_findings([finding], "sess001", "https://example.com")
        assert stats["new_kb"] == 0
    finally:
        os.unlink(path)
    print("  PASS test_false_positive_is_not_stored")


def test_empty_payload_is_not_stored():
    loop, db, cache, path = _setup()
    try:
        finding = _confirmed_finding(payload="")
        stats = loop.ingest_findings([finding], "sess001", "https://example.com")
        assert stats["new_kb"] == 0
    finally:
        os.unlink(path)
    print("  PASS test_empty_payload_is_not_stored")


# ─── Deduplication ───────────────────────────────────────────────────────────

def test_same_payload_same_vulntype_is_deduplicated():
    loop, db, cache, path = _setup()
    try:
        finding = _confirmed_finding(payload="' OR 1=1--",
                                     vuln_type=VulnType.SQLI)
        stats1 = loop.ingest_findings([finding], "sess001", "https://a.com")
        stats2 = loop.ingest_findings([finding], "sess002", "https://b.com")
        assert stats1["new_kb"] == 1
        assert stats2["duplicate_kb"] == 1, \
            f"Second ingest should be duplicate KB entry. Got {stats2}"
    finally:
        os.unlink(path)
    print("  PASS test_same_payload_same_vulntype_is_deduplicated")


def test_different_payloads_same_vulntype_both_stored():
    loop, db, cache, path = _setup()
    try:
        f1 = _confirmed_finding(payload="<script>alert(1)</script>",
                                vuln_type=VulnType.XSS_REFLECTED)
        f2 = _confirmed_finding(payload="<img src=x onerror=alert(2)>",
                                vuln_type=VulnType.XSS_REFLECTED)
        stats = loop.ingest_findings([f1, f2], "sess001", "https://a.com")
        assert stats["new_kb"] == 2, f"Expected 2 new KB entries, got {stats}"
    finally:
        os.unlink(path)
    print("  PASS test_different_payloads_same_vulntype_both_stored")


def test_same_payload_different_vulntype_both_stored():
    """The hash includes vuln_type so same payload for different types is new."""
    loop, db, cache, path = _setup()
    try:
        payload = "{{7*7}}"
        f1 = _confirmed_finding(payload=payload, vuln_type=VulnType.SSTI)
        f2 = _confirmed_finding(payload=payload, vuln_type=VulnType.XSS_REFLECTED)
        stats = loop.ingest_findings([f1, f2], "sess001", "https://a.com")
        assert stats["new_kb"] == 2
    finally:
        os.unlink(path)
    print("  PASS test_same_payload_different_vulntype_both_stored")


# ─── Payload sanitisation ────────────────────────────────────────────────────

def test_jwt_payload_is_rejected():
    loop, _, _, path = _setup()
    try:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = loop._sanitise_payload(jwt)
        assert result == "", f"JWT should be rejected, got '{result}'"
    finally:
        os.unlink(path)
    print("  PASS test_jwt_payload_is_rejected")


def test_long_hex_payload_is_rejected():
    loop, _, _, path = _setup()
    try:
        hex_token = "a" * 32  # 32-char hex string = session ID pattern
        result = loop._sanitise_payload(hex_token)
        assert result == "", f"Long hex should be rejected, got '{result}'"
    finally:
        os.unlink(path)
    print("  PASS test_long_hex_payload_is_rejected")


def test_uuid_payload_is_rejected():
    loop, _, _, path = _setup()
    try:
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        result = loop._sanitise_payload(uuid)
        assert result == "", f"UUID should be rejected, got '{result}'"
    finally:
        os.unlink(path)
    print("  PASS test_uuid_payload_is_rejected")


def test_xss_payload_passes_sanitisation():
    loop, _, _, path = _setup()
    try:
        payload = "<script>alert(document.cookie)</script>"
        result = loop._sanitise_payload(payload)
        assert result == payload, f"XSS payload should pass, got '{result}'"
    finally:
        os.unlink(path)
    print("  PASS test_xss_payload_passes_sanitisation")


def test_sqli_payload_passes_sanitisation():
    loop, _, _, path = _setup()
    try:
        payload = "' OR EXTRACTVALUE(1,CONCAT(0x7e,version()))--"
        result = loop._sanitise_payload(payload)
        assert result == payload
    finally:
        os.unlink(path)
    print("  PASS test_sqli_payload_passes_sanitisation")


def test_lfi_payload_passes_sanitisation():
    loop, _, _, path = _setup()
    try:
        payload = "../../../../etc/passwd"
        result = loop._sanitise_payload(payload)
        assert result == payload
    finally:
        os.unlink(path)
    print("  PASS test_lfi_payload_passes_sanitisation")


def test_short_hex_passes_sanitisation():
    """Short hex strings (< 32 chars) should not be rejected."""
    loop, _, _, path = _setup()
    try:
        payload = "0x41414141"  # common XSS/SQLi hex, only 10 chars
        result = loop._sanitise_payload(payload)
        assert result == payload
    finally:
        os.unlink(path)
    print("  PASS test_short_hex_passes_sanitisation")


# ─── Cache invalidation ───────────────────────────────────────────────────────

def test_cache_invalidated_for_stored_vuln_types():
    loop, db, cache, path = _setup()
    try:
        # Pre-populate cache for xss_reflected
        cache.store("xss_reflected", ["django"], ["cached_payload"])
        assert cache.hit("xss_reflected", ["django"]) is not None

        # Ingest a confirmed XSS finding
        finding = _confirmed_finding(vuln_type=VulnType.XSS_REFLECTED)
        stats = loop.ingest_findings([finding], "sess001", "https://a.com")

        assert "xss_reflected" in stats["cache_invalidated"], \
            f"xss_reflected should be in cache_invalidated: {stats}"
        # Cache entry should now be gone
        assert cache.hit("xss_reflected", ["django"]) is None, \
            "Cache should be invalidated after learning"
    finally:
        os.unlink(path)
    print("  PASS test_cache_invalidated_for_stored_vuln_types")


def test_cache_not_invalidated_when_nothing_stored():
    loop, db, cache, path = _setup()
    try:
        cache.store("xss_reflected", [], ["cached_payload"])
        # Unconfirmed finding — nothing stored
        finding = _confirmed_finding(confirmed=False)
        stats = loop.ingest_findings([finding], "sess001", "https://a.com")
        assert stats["cache_invalidated"] == []
        # Cache should still be intact
        assert cache.hit("xss_reflected", []) is not None
    finally:
        os.unlink(path)
    print("  PASS test_cache_not_invalidated_when_nothing_stored")


# ─── Technique extraction ─────────────────────────────────────────────────────

def test_steps_converted_to_technique():
    loop, _, _, path = _setup()
    try:
        finding = _confirmed_finding(
            steps=["1. Navigate to /search", "2. Inject payload in q param"]
        )
        technique = loop._steps_to_technique(finding)
        assert "Navigate to /search" in technique
        assert "→" in technique  # steps are joined with arrow
    finally:
        os.unlink(path)
    print("  PASS test_steps_converted_to_technique")


def test_technique_falls_back_to_impact():
    loop, _, _, path = _setup()
    try:
        finding = _confirmed_finding()
        finding.steps_to_reproduce = []   # explicitly empty — forces impact fallback
        finding.impact = "Attacker can execute arbitrary JS"
        technique = loop._steps_to_technique(finding)
        assert "Attacker can execute" in technique
    finally:
        os.unlink(path)
    print("  PASS test_technique_falls_back_to_impact")


# ─── Stats ────────────────────────────────────────────────────────────────────

def test_stats_are_accurate():
    loop, db, cache, path = _setup()
    try:
        findings = [
            _confirmed_finding(payload="<script>1</script>",
                               vuln_type=VulnType.XSS_REFLECTED),
            _confirmed_finding(payload="' OR 1=1",
                               vuln_type=VulnType.SQLI),
            _confirmed_finding(confirmed=False),       # skipped
            _confirmed_finding(payload="<script>1</script>",
                               vuln_type=VulnType.XSS_REFLECTED),  # duplicate
        ]
        stats = loop.ingest_findings(findings, "sess001", "https://a.com")
        assert stats["new_kb"] == 2
        assert stats["duplicate_kb"] == 1
        assert len(stats["cache_invalidated"]) == 2
    finally:
        os.unlink(path)
    print("  PASS test_stats_are_accurate")


if __name__ == "__main__":
    print("\nLearningLoop Tests")
    print("=" * 40)
    test_confirmed_finding_is_stored()
    test_unconfirmed_finding_is_not_stored()
    test_false_positive_is_not_stored()
    test_empty_payload_is_not_stored()
    test_same_payload_same_vulntype_is_deduplicated()
    test_different_payloads_same_vulntype_both_stored()
    test_same_payload_different_vulntype_both_stored()
    test_jwt_payload_is_rejected()
    test_long_hex_payload_is_rejected()
    test_uuid_payload_is_rejected()
    test_xss_payload_passes_sanitisation()
    test_sqli_payload_passes_sanitisation()
    test_lfi_payload_passes_sanitisation()
    test_short_hex_passes_sanitisation()
    test_cache_invalidated_for_stored_vuln_types()
    test_cache_not_invalidated_when_nothing_stored()
    test_steps_converted_to_technique()
    test_technique_falls_back_to_impact()
    test_stats_are_accurate()
    print("\nAll LearningLoop tests passed.")
