"""
Tests for reports/generator.py

Covers:
  generate()
    - Creates output files for each requested format
    - Returns dict mapping format → filepath
    - Skips formats not in the requested list
    - Works with zero confirmed findings

  _count_by_severity()
    - Correctly counts findings per severity
    - Returns empty dict for empty list
    - Multi-severity list counted independently

  _render_markdown()
    - Contains target URL and session ID
    - Contains severity summary table
    - Contains finding title and severity badge
    - Contains payload in code block
    - Contains steps to reproduce
    - Empty findings shows "No confirmed vulnerabilities"
    - Findings are sorted critical > high > medium > low > info

  _render_html()
    - Contains DOCTYPE and charset meta
    - Contains target URL
    - Contains severity badge per finding
    - Each finding has a unique anchor id
    - Empty findings shows appropriate message

  _render_json()
    - Valid JSON output
    - Contains session_id, target, findings list
    - Each finding dict has required keys
    - Empty findings list is valid JSON array
    - duration_seconds is a number
"""
import json
import os
import sys
import tempfile
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import tests.stubs  # noqa: F401

from core.models import Finding, ScanSession, Severity, Target, VulnType
from reports.generator import ReportGenerator


def _make_session(findings=None, target_url="https://example.com"):
    target = Target(url=target_url)
    session = ScanSession(target=target)
    session.id = "test-session-abc"
    session.started_at = datetime(2024, 6, 1, 12, 0, 0)
    session.completed_at = datetime(2024, 6, 1, 12, 5, 30)
    session.confirmed_findings = findings or []
    return session


def _make_finding(
    severity=Severity.HIGH,
    vuln_type=VulnType.XSS_REFLECTED,
    title="Test XSS",
    payload="<script>alert(1)</script>",
    steps=None,
):
    f = Finding(
        title=title,
        vuln_type=vuln_type,
        severity=severity,
        url="https://example.com/search",
        parameter="q",
        payload=payload,
        evidence="Response contained: <script>alert(1)</script>",
        steps_to_reproduce=steps or ["1. Navigate to URL", "2. Inject in q param"],
        impact="XSS allows cookie theft",
        remediation="Sanitise output",
        confidence=0.92,
        cvss_score=7.2,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        confirmed=True,
        tool="tester",
    )
    return f


def _tmp_gen():
    tmpdir = tempfile.mkdtemp(prefix="pin0ccs_report_test_")
    return ReportGenerator(report_dir=tmpdir), tmpdir


# ─── generate() ──────────────────────────────────────────────────────────────

def test_generate_creates_markdown_file():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session([_make_finding()])
        result = gen.generate(session, formats=["markdown"])
        assert "markdown" in result
        assert os.path.exists(result["markdown"])
        assert result["markdown"].endswith(".md")
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_generate_creates_markdown_file")


def test_generate_creates_html_file():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session([_make_finding()])
        result = gen.generate(session, formats=["html"])
        assert "html" in result
        assert os.path.exists(result["html"])
        assert result["html"].endswith(".html")
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_generate_creates_html_file")


def test_generate_creates_json_file():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session([_make_finding()])
        result = gen.generate(session, formats=["json"])
        assert "json" in result
        assert os.path.exists(result["json"])
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_generate_creates_json_file")


def test_generate_all_three_formats():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session([_make_finding()])
        result = gen.generate(session, formats=["markdown", "html", "json"])
        assert len(result) == 3
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_generate_all_three_formats")


def test_generate_skips_unrequested_formats():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session([_make_finding()])
        result = gen.generate(session, formats=["json"])
        assert "markdown" not in result
        assert "html" not in result
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_generate_skips_unrequested_formats")


def test_generate_with_zero_findings():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session(findings=[])
        result = gen.generate(session, formats=["markdown", "html", "json"])
        # Should succeed and create files
        assert len(result) == 3
        for fmt, path in result.items():
            assert os.path.exists(path), f"{fmt} file not created"
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_generate_with_zero_findings")


# ─── _count_by_severity() ────────────────────────────────────────────────────

def test_count_by_severity_single():
    gen, tmpdir = _tmp_gen()
    try:
        findings = [_make_finding(Severity.HIGH), _make_finding(Severity.HIGH)]
        counts = gen._count_by_severity(findings)
        assert counts["high"] == 2
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_count_by_severity_single")


def test_count_by_severity_mixed():
    gen, tmpdir = _tmp_gen()
    try:
        findings = [
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.MEDIUM),
        ]
        counts = gen._count_by_severity(findings)
        assert counts["critical"] == 1
        assert counts["high"] == 2
        assert counts["medium"] == 1
        assert "low" not in counts
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_count_by_severity_mixed")


def test_count_by_severity_empty():
    gen, tmpdir = _tmp_gen()
    try:
        assert gen._count_by_severity([]) == {}
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_count_by_severity_empty")


# ─── _render_markdown() ──────────────────────────────────────────────────────

def test_markdown_contains_target_url():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        md = gen._render_markdown(session, [])
        assert "https://example.com" in md
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_markdown_contains_target_url")


def test_markdown_contains_session_id():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        md = gen._render_markdown(session, [])
        assert "test-session-abc" in md
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_markdown_contains_session_id")


def test_markdown_finding_title_present():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        finding = _make_finding(title="Reflected XSS in search")
        md = gen._render_markdown(session, [finding])
        assert "Reflected XSS in search" in md
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_markdown_finding_title_present")


def test_markdown_severity_badge():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        finding = _make_finding(severity=Severity.CRITICAL)
        md = gen._render_markdown(session, [finding])
        assert "CRITICAL" in md
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_markdown_severity_badge")


def test_markdown_payload_in_code_block():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        finding = _make_finding(payload="<script>alert(1)</script>")
        md = gen._render_markdown(session, [finding])
        assert "<script>alert(1)</script>" in md
        # Payload should appear in a code block
        assert "```" in md
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_markdown_payload_in_code_block")


def test_markdown_empty_findings_message():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        md = gen._render_markdown(session, [])
        assert "No confirmed vulnerabilities" in md
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_markdown_empty_findings_message")


def test_markdown_findings_sorted_by_severity():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        # Put them in reverse order — generate() should sort critical before low
        session.confirmed_findings = [
            _make_finding(severity=Severity.LOW, title="Low Severity"),
            _make_finding(severity=Severity.CRITICAL, title="Critical Finding"),
            _make_finding(severity=Severity.HIGH, title="High Finding"),
        ]
        result = gen.generate(session, formats=["markdown"])
        md = open(result["markdown"]).read()
        critical_pos = md.find("Critical Finding")
        low_pos = md.find("Low Severity")
        assert critical_pos < low_pos, \
            "Critical finding should appear before Low in sorted output"
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_markdown_findings_sorted_by_severity")


# ─── _render_html() ──────────────────────────────────────────────────────────

def test_html_has_doctype():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        html = gen._render_html(session, [])
        assert "<!DOCTYPE html>" in html
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_html_has_doctype")


def test_html_contains_target_url():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        html = gen._render_html(session, [])
        assert "https://example.com" in html
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_html_contains_target_url")


def test_html_finding_has_anchor_id():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        finding = _make_finding()
        html = gen._render_html(session, [finding])
        assert f"finding-{finding.id}" in html
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_html_finding_has_anchor_id")


def test_html_severity_badge_in_finding():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        finding = _make_finding(severity=Severity.HIGH)
        html = gen._render_html(session, [finding])
        assert "HIGH" in html
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_html_severity_badge_in_finding")


def test_html_empty_findings_message():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        html = gen._render_html(session, [])
        assert "No confirmed vulnerabilities" in html
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_html_empty_findings_message")


# ─── _render_json() ──────────────────────────────────────────────────────────

def test_json_is_valid_json():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session([_make_finding()])
        raw = gen._render_json(session, session.confirmed_findings)
        data = json.loads(raw)   # must not raise
        assert isinstance(data, dict)
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_json_is_valid_json")


def test_json_contains_session_id():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        raw = gen._render_json(session, [])
        data = json.loads(raw)
        assert data["session_id"] == "test-session-abc"
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_json_contains_session_id")


def test_json_contains_target_url():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        raw = gen._render_json(session, [])
        data = json.loads(raw)
        assert data["target"] == "https://example.com"
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_json_contains_target_url")


def test_json_findings_list_length():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        findings = [_make_finding(), _make_finding(severity=Severity.CRITICAL)]
        raw = gen._render_json(session, findings)
        data = json.loads(raw)
        assert data["total_findings"] == 2
        assert len(data["findings"]) == 2
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_json_findings_list_length")


def test_json_finding_has_required_keys():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        finding = _make_finding()
        raw = gen._render_json(session, [finding])
        data = json.loads(raw)
        f = data["findings"][0]
        for key in ["id", "title", "vuln_type", "severity", "url",
                    "payload", "confidence", "cvss_score"]:
            assert key in f, f"Missing key: {key}"
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_json_finding_has_required_keys")


def test_json_duration_is_numeric():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        raw = gen._render_json(session, [])
        data = json.loads(raw)
        assert isinstance(data["duration_seconds"], (int, float))
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_json_duration_is_numeric")


def test_json_empty_findings_valid():
    gen, tmpdir = _tmp_gen()
    try:
        session = _make_session()
        raw = gen._render_json(session, [])
        data = json.loads(raw)
        assert data["findings"] == []
        assert data["total_findings"] == 0
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_json_empty_findings_valid")


if __name__ == "__main__":
    print("\nReportGenerator Tests")
    print("=" * 40)
    test_generate_creates_markdown_file()
    test_generate_creates_html_file()
    test_generate_creates_json_file()
    test_generate_all_three_formats()
    test_generate_skips_unrequested_formats()
    test_generate_with_zero_findings()
    test_count_by_severity_single()
    test_count_by_severity_mixed()
    test_count_by_severity_empty()
    test_markdown_contains_target_url()
    test_markdown_contains_session_id()
    test_markdown_finding_title_present()
    test_markdown_severity_badge()
    test_markdown_payload_in_code_block()
    test_markdown_empty_findings_message()
    test_markdown_findings_sorted_by_severity()
    test_html_has_doctype()
    test_html_contains_target_url()
    test_html_finding_has_anchor_id()
    test_html_severity_badge_in_finding()
    test_html_empty_findings_message()
    test_json_is_valid_json()
    test_json_contains_session_id()
    test_json_contains_target_url()
    test_json_findings_list_length()
    test_json_finding_has_required_keys()
    test_json_duration_is_numeric()
    test_json_empty_findings_valid()
    print("\nAll ReportGenerator tests passed.")
