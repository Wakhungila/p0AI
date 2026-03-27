"""
Tests for agents/tester.py — response analysis heuristics only.

These tests exercise the deterministic logic in TesterAgent without
requiring Ollama, httpx, or any external tools.
Only _analyze_response(), _is_ssrf_indicator(), _extract_params(),
and _inject_param() are tested here — they contain zero I/O.

The LLM-dependent methods (_generate_mutations, _check_business_logic,
run_attack_phase) are covered by integration tests that require Ollama.
"""
import os
import sys
import types
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.models import VulnType, Severity


def _make_mock_response(status: int = 200, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    return resp


def _make_tester() -> object:
    """Build a TesterAgent with all external dependencies mocked out."""
    from unittest.mock import MagicMock
    config = MagicMock()
    config.models.tester = "qwen2.5-coder:7b"
    config.vuln.max_payload_mutations = 10
    config.vuln.ffuf_timeout = 10
    config.vuln.nuclei_severity = ["critical", "high"]
    config.vuln.nuclei_templates = "/nonexistent"
    config.knowledge.db_path = ":memory:"
    db = MagicMock()
    db.get_payloads_for_vuln.return_value = []
    ollama = MagicMock()
    budget = MagicMock()
    budget.charge.return_value = True
    budget.record_cache_hit.return_value = None
    cache = MagicMock()
    cache.hit.return_value = None

    from agents.tester import TesterAgent
    agent = TesterAgent(config, db, ollama, budget=budget, cache=cache)
    return agent


# ─── XSS detection ────────────────────────────────────────────────────────────

def test_xss_reflected_detected_when_payload_in_body():
    agent = _make_tester()
    payload = '<script>alert(1)</script>'
    resp = _make_mock_response(200, f"<html>{payload}</html>")
    result = agent._analyze_response(resp, "https://example.com?q=", "q", payload, "xss")
    assert result is not None, "Should detect XSS when payload reflected verbatim"
    assert result.vuln_type == VulnType.XSS_REFLECTED
    assert result.severity == Severity.HIGH
    print("  PASS test_xss_reflected_detected_when_payload_in_body")


def test_xss_not_detected_when_payload_not_in_body():
    agent = _make_tester()
    payload = '<script>alert(1)</script>'
    resp = _make_mock_response(200, "<html>safe content</html>")
    result = agent._analyze_response(resp, "https://example.com", "q", payload, "xss")
    assert result is None, "Should not detect XSS when payload is not in body"
    print("  PASS test_xss_not_detected_when_payload_not_in_body")


def test_xss_not_detected_on_non_200_status():
    agent = _make_tester()
    payload = '<script>alert(1)</script>'
    resp = _make_mock_response(302, f"<html>{payload}</html>")
    result = agent._analyze_response(resp, "https://example.com", "q", payload, "xss")
    assert result is None, "Should not detect XSS on redirect response"
    print("  PASS test_xss_not_detected_on_non_200_status")


def test_xss_svg_payload_detected():
    agent = _make_tester()
    payload = '<svg onload=alert(1)>'
    resp = _make_mock_response(200, f"Result: {payload}")
    result = agent._analyze_response(resp, "https://example.com", "q", payload, "xss")
    assert result is not None
    assert result.vuln_type == VulnType.XSS_REFLECTED
    print("  PASS test_xss_svg_payload_detected")


def test_xss_benign_reflection_not_flagged():
    """A payload without execution context (just text) should not trigger."""
    agent = _make_tester()
    payload = "hello world"   # no script tag, no event handler
    resp = _make_mock_response(200, f"<html>{payload}</html>")
    result = agent._analyze_response(resp, "https://example.com", "q", payload, "xss")
    assert result is None
    print("  PASS test_xss_benign_reflection_not_flagged")


# ─── SQLi detection ───────────────────────────────────────────────────────────

def test_sqli_mysql_error_detected():
    agent = _make_tester()
    payload = "' OR '1'='1"
    resp = _make_mock_response(200, "You have an error in your SQL syntax near ''")
    result = agent._analyze_response(resp, "https://example.com", "id", payload, "sqli")
    assert result is not None, "Should detect SQLi on MySQL error string"
    assert result.vuln_type == VulnType.SQLI
    assert result.severity == Severity.CRITICAL
    print("  PASS test_sqli_mysql_error_detected")


def test_sqli_oracle_error_detected():
    agent = _make_tester()
    payload = "' OR 1=1--"
    resp = _make_mock_response(200, "ORA-01756: quoted string not properly terminated")
    result = agent._analyze_response(resp, "https://example.com", "id", payload, "sqli")
    assert result is not None, "Should detect SQLi on Oracle error string"
    print("  PASS test_sqli_oracle_error_detected")


def test_sqli_clean_response_not_flagged():
    agent = _make_tester()
    payload = "' OR '1'='1"
    resp = _make_mock_response(200, "<html>Welcome back, user!</html>")
    result = agent._analyze_response(resp, "https://example.com", "id", payload, "sqli")
    assert result is None
    print("  PASS test_sqli_clean_response_not_flagged")


# ─── SSTI detection ───────────────────────────────────────────────────────────

def test_ssti_jinja2_detected():
    agent = _make_tester()
    payload = "{{7*7}}"
    resp = _make_mock_response(200, "Result: 49")
    result = agent._analyze_response(resp, "https://example.com", "name", payload, "ssti")
    assert result is not None, "Should detect SSTI when {{7*7}} evaluates to 49"
    assert result.vuln_type == VulnType.SSTI
    assert result.severity == Severity.CRITICAL
    assert result.confidence == 0.85
    print("  PASS test_ssti_jinja2_detected")


def test_ssti_dollar_syntax_detected():
    agent = _make_tester()
    payload = "${7*7}"
    resp = _make_mock_response(200, "Hello 49!")
    result = agent._analyze_response(resp, "https://example.com", "msg", payload, "ssti")
    assert result is not None
    print("  PASS test_ssti_dollar_syntax_detected")


def test_ssti_not_detected_without_49():
    agent = _make_tester()
    payload = "{{7*7}}"
    resp = _make_mock_response(200, "Hello {{7*7}}!")  # not evaluated
    result = agent._analyze_response(resp, "https://example.com", "name", payload, "ssti")
    assert result is None, "Should not detect SSTI when expression is not evaluated"
    print("  PASS test_ssti_not_detected_without_49")


# ─── LFI detection ────────────────────────────────────────────────────────────

def test_lfi_passwd_file_detected():
    agent = _make_tester()
    payload = "../../../../etc/passwd"
    resp = _make_mock_response(200, "root:x:0:0:root:/root:/bin/bash\nnobody:x:99:99::/:")
    result = agent._analyze_response(resp, "https://example.com", "file", payload, "lfi")
    assert result is not None, "Should detect LFI when /etc/passwd content is returned"
    assert result.vuln_type == VulnType.LFI
    assert result.severity == Severity.CRITICAL
    print("  PASS test_lfi_passwd_file_detected")


def test_lfi_clean_response_not_flagged():
    agent = _make_tester()
    payload = "../../../../etc/passwd"
    resp = _make_mock_response(200, "<html>File not found</html>")
    result = agent._analyze_response(resp, "https://example.com", "file", payload, "lfi")
    assert result is None
    print("  PASS test_lfi_clean_response_not_flagged")


# ─── SSRF indicators ──────────────────────────────────────────────────────────

def test_ssrf_aws_metadata_detected():
    agent = _make_tester()
    payload = "http://169.254.169.254/latest/meta-data/"
    resp = _make_mock_response(200, "ami-id\ninstance-id\nmeta-data/")
    assert agent._is_ssrf_indicator(resp, payload) is True
    print("  PASS test_ssrf_aws_metadata_detected")


def test_ssrf_clean_response_not_flagged():
    agent = _make_tester()
    payload = "http://169.254.169.254/latest/meta-data/"
    resp = _make_mock_response(404, "Not Found")
    assert agent._is_ssrf_indicator(resp, payload) is False
    print("  PASS test_ssrf_clean_response_not_flagged")


def test_ssrf_file_protocol_detected():
    agent = _make_tester()
    payload = "file:///etc/passwd"
    resp = _make_mock_response(200, "root:x:0:0:root:/root:/bin/bash")
    assert agent._is_ssrf_indicator(resp, payload) is True
    print("  PASS test_ssrf_file_protocol_detected")


# ─── URL utilities ────────────────────────────────────────────────────────────

def test_extract_params_finds_query_params():
    agent = _make_tester()
    url = "https://example.com/search?q=hello&page=1&sort=asc"
    params = agent._extract_params(url)
    assert "q" in params
    assert "page" in params
    assert "sort" in params
    print("  PASS test_extract_params_finds_query_params")


def test_extract_params_empty_for_no_query():
    agent = _make_tester()
    url = "https://example.com/path/to/resource"
    params = agent._extract_params(url)
    assert params == [], f"Expected empty list, got {params}"
    print("  PASS test_extract_params_empty_for_no_query")


def test_inject_param_replaces_value():
    agent = _make_tester()
    url = "https://example.com/search?q=hello&page=1"
    result = agent._inject_param(url, "q", "<script>alert(1)</script>")
    assert "q=%3Cscript%3E" in result or "q=<script>" in result, \
        f"Injected value not found in URL: {result}"
    assert "page=1" in result, "Other params should be preserved"
    print("  PASS test_inject_param_replaces_value")


def test_inject_param_adds_new_param():
    agent = _make_tester()
    url = "https://example.com/page"
    result = agent._inject_param(url, "new_param", "value")
    assert "new_param=" in result
    print("  PASS test_inject_param_adds_new_param")


if __name__ == "__main__":
    print("\nTesterAgent Heuristic Tests")
    print("=" * 40)
    # XSS
    test_xss_reflected_detected_when_payload_in_body()
    test_xss_not_detected_when_payload_not_in_body()
    test_xss_not_detected_on_non_200_status()
    test_xss_svg_payload_detected()
    test_xss_benign_reflection_not_flagged()
    # SQLi
    test_sqli_mysql_error_detected()
    test_sqli_oracle_error_detected()
    test_sqli_clean_response_not_flagged()
    # SSTI
    test_ssti_jinja2_detected()
    test_ssti_dollar_syntax_detected()
    test_ssti_not_detected_without_49()
    # LFI
    test_lfi_passwd_file_detected()
    test_lfi_clean_response_not_flagged()
    # SSRF
    test_ssrf_aws_metadata_detected()
    test_ssrf_clean_response_not_flagged()
    test_ssrf_file_protocol_detected()
    # URL utils
    test_extract_params_finds_query_params()
    test_extract_params_empty_for_no_query()
    test_inject_param_replaces_value()
    test_inject_param_adds_new_param()
    print("\nAll TesterAgent heuristic tests passed.")
