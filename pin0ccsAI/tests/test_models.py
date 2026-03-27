"""
Tests for core/models.py

Covers:
  - Severity.score ordering is correct (critical > high > medium > low > info)
  - Target.domain is auto-extracted from URL
  - Finding.to_dict() produces correct types and includes all required fields
  - Finding default ID is non-empty and unique across instances
  - ScanSession.duration_seconds is positive and increases over time
  - ScanSession.confirmed_findings starts empty
  - VulnType enum values match the strings expected by DB and report layers
"""
import os
import sys
import time
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.models import (
    Finding, ReconResult, ScanSession, Severity, Target, VulnType
)


def test_severity_score_ordering():
    assert Severity.CRITICAL.score > Severity.HIGH.score
    assert Severity.HIGH.score > Severity.MEDIUM.score
    assert Severity.MEDIUM.score > Severity.LOW.score
    assert Severity.LOW.score > Severity.INFO.score
    print("  PASS test_severity_score_ordering")


def test_severity_score_values():
    assert Severity.CRITICAL.score == 100
    assert Severity.HIGH.score     == 75
    assert Severity.MEDIUM.score   == 50
    assert Severity.LOW.score      == 25
    assert Severity.INFO.score     == 5
    print("  PASS test_severity_score_values")


def test_target_domain_extracted_from_url():
    t = Target(url="https://api.example.com/v1/users")
    assert t.domain == "api.example.com", \
        f"Expected 'api.example.com', got '{t.domain}'"
    print("  PASS test_target_domain_extracted_from_url")


def test_target_domain_not_overwritten_if_set():
    t = Target(url="https://example.com/path", domain="custom.domain")
    assert t.domain == "custom.domain", \
        "Explicit domain should not be overwritten by __post_init__"
    print("  PASS test_target_domain_not_overwritten_if_set")


def test_target_domain_handles_no_scheme():
    t = Target(url="example.com")
    # netloc will be empty for scheme-less URLs — domain falls back to full url
    assert t.domain  # non-empty
    print("  PASS test_target_domain_handles_no_scheme")


def test_finding_default_id_is_nonempty():
    f = Finding()
    assert f.id, "Finding.id should not be empty"
    assert len(f.id) == 8, f"Expected 8-char ID, got '{f.id}'"
    print("  PASS test_finding_default_id_is_nonempty")


def test_finding_ids_are_unique():
    ids = {Finding().id for _ in range(50)}
    assert len(ids) == 50, f"Expected 50 unique IDs, got {len(ids)}"
    print("  PASS test_finding_ids_are_unique")


def test_finding_to_dict_has_required_fields():
    f = Finding(
        title="Test XSS",
        vuln_type=VulnType.XSS_REFLECTED,
        severity=Severity.HIGH,
        url="https://example.com",
        confidence=0.8,
        confirmed=True,
    )
    d = f.to_dict()
    required = [
        "id", "title", "vuln_type", "severity", "url", "endpoint",
        "method", "parameter", "payload", "evidence",
        "steps_to_reproduce", "impact", "remediation",
        "cvss_score", "cvss_vector", "confidence",
        "confirmed", "false_positive", "tool", "discovered_at",
    ]
    for field in required:
        assert field in d, f"Missing field '{field}' in Finding.to_dict()"
    print("  PASS test_finding_to_dict_has_required_fields")


def test_finding_to_dict_types():
    f = Finding(
        title="SQLi",
        vuln_type=VulnType.SQLI,
        severity=Severity.CRITICAL,
        confidence=0.9,
        confirmed=True,
        steps_to_reproduce=["step 1", "step 2"],
    )
    d = f.to_dict()
    assert isinstance(d["severity"], str),          "severity should be str"
    assert isinstance(d["vuln_type"], str),         "vuln_type should be str"
    assert isinstance(d["confidence"], float),      "confidence should be float"
    assert isinstance(d["confirmed"], bool),        "confirmed should be bool"
    assert isinstance(d["steps_to_reproduce"], list), "steps should be list"
    assert isinstance(d["discovered_at"], str),     "discovered_at should be ISO string"
    print("  PASS test_finding_to_dict_types")


def test_finding_to_dict_enum_values_are_strings():
    f = Finding(vuln_type=VulnType.IDOR, severity=Severity.MEDIUM)
    d = f.to_dict()
    assert d["vuln_type"] == "idor", f"Expected 'idor', got {d['vuln_type']}"
    assert d["severity"] == "medium", f"Expected 'medium', got {d['severity']}"
    print("  PASS test_finding_to_dict_enum_values_are_strings")


def test_scan_session_duration_increases():
    session = ScanSession()
    t1 = session.duration_seconds
    time.sleep(0.05)
    t2 = session.duration_seconds
    assert t2 > t1, "duration_seconds should increase over time"
    print("  PASS test_scan_session_duration_increases")


def test_scan_session_duration_with_completed_at():
    session = ScanSession()
    session.completed_at = session.started_at + timedelta(seconds=42)
    assert abs(session.duration_seconds - 42.0) < 0.01, \
        f"Expected ~42s duration, got {session.duration_seconds}"
    print("  PASS test_scan_session_duration_with_completed_at")


def test_scan_session_confirmed_findings_starts_empty():
    session = ScanSession()
    assert session.confirmed_findings == [], "confirmed_findings should start empty"
    assert session.findings == [], "findings should start empty"
    print("  PASS test_scan_session_confirmed_findings_starts_empty")


def test_vuln_type_enum_values_are_lowercase_strings():
    """All VulnType values must be lowercase snake_case strings.
    This ensures DB storage and report rendering work without transformation."""
    for vt in VulnType:
        assert vt.value == vt.value.lower(), \
            f"VulnType.{vt.name} value '{vt.value}' is not lowercase"
        assert " " not in vt.value, \
            f"VulnType.{vt.name} value '{vt.value}' contains a space"
    print("  PASS test_vuln_type_enum_values_are_lowercase_strings")


def test_recon_result_defaults():
    t = Target(url="https://example.com")
    r = ReconResult(target=t)
    assert r.subdomains == []
    assert r.live_hosts == []
    assert r.endpoints == []
    assert r.crown_jewels == []
    assert r.graphql_endpoints == []
    assert r.api_endpoints == []
    assert isinstance(r.tech_stack, dict)
    print("  PASS test_recon_result_defaults")


if __name__ == "__main__":
    print("\nCore Models Tests")
    print("=" * 40)
    test_severity_score_ordering()
    test_severity_score_values()
    test_target_domain_extracted_from_url()
    test_target_domain_not_overwritten_if_set()
    test_target_domain_handles_no_scheme()
    test_finding_default_id_is_nonempty()
    test_finding_ids_are_unique()
    test_finding_to_dict_has_required_fields()
    test_finding_to_dict_types()
    test_finding_to_dict_enum_values_are_strings()
    test_scan_session_duration_increases()
    test_scan_session_duration_with_completed_at()
    test_scan_session_confirmed_findings_starts_empty()
    test_vuln_type_enum_values_are_lowercase_strings()
    test_recon_result_defaults()
    print("\nAll Models tests passed.")
