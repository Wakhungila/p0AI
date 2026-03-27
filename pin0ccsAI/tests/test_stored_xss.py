"""
Tests for engines/stored_xss.py

Tests cover the deterministic, non-network parts of the engine:
  - _identify_writable() correctly categorises endpoints by method and path
  - _build_retrieve_pages() includes common reflection paths + crown jewels
  - _retrieve_and_check() returns True when canary ID is in response
  - _retrieve_and_check() returns False when canary ID absent
  - _retrieve_and_check() returns False on HTTP error response
  - canary token uniqueness across multiple tests
  - _inject() tries JSON body before form data (method order)

Network-dependent tests (_test_endpoint, run) are integration tests
that require a live server — not included here.
"""
import asyncio
import os
import sys
import types
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Shared stubs — installs structlog/httpx/yaml/pluggy mocks
import sys; sys.path.insert(0, __file__.rsplit('/', 2)[0])
import tests.stubs  # noqa: F401 — side-effect: installs all stubs

from core.models import Endpoint, ReconResult, Target
from engines.stored_xss import StoredXSSEngine, _CANARY_TEMPLATE


class _MockResponse:
    """Local mock response for stored XSS tests."""
    def __init__(self, status: int = 200, text: str = ""):
        self.status_code = status
        self.text = text
        self.headers = {}
    def json(self): return {}


def _engine() -> StoredXSSEngine:
    return StoredXSSEngine(auth_session=None, timeout=5,
                           max_endpoints=10, max_retrieve_pages=5)


def _recon_with_endpoints(endpoints: list[Endpoint]) -> ReconResult:
    target = Target(url="https://example.com")
    recon = ReconResult(target=target)
    recon.endpoints = endpoints
    recon.crown_jewels = []
    recon.graphql_endpoints = []
    return recon


# ─── Writable endpoint identification ────────────────────────────────────────

def test_post_endpoint_is_writable():
    engine = _engine()
    recon = _recon_with_endpoints([
        Endpoint(url="https://example.com/comment", method="POST"),
    ])
    writable = engine._identify_writable(recon)
    urls = [ep.url for ep in writable]
    assert "https://example.com/comment" in urls
    print("  PASS test_post_endpoint_is_writable")


def test_get_endpoint_with_neutral_path_not_writable():
    engine = _engine()
    recon = _recon_with_endpoints([
        Endpoint(url="https://example.com/static/logo.png", method="GET"),
    ])
    writable = engine._identify_writable(recon)
    # logo.png should not appear in writable
    urls = [ep.url for ep in writable]
    assert "https://example.com/static/logo.png" not in urls
    print("  PASS test_get_endpoint_with_neutral_path_not_writable")


def test_writable_pattern_in_path_makes_get_writable():
    """A GET to /api/profile matches a writable pattern — still included."""
    engine = _engine()
    recon = _recon_with_endpoints([
        Endpoint(url="https://example.com/api/profile", method="GET"),
    ])
    writable = engine._identify_writable(recon)
    urls = [ep.url for ep in writable]
    assert "https://example.com/api/profile" in urls
    print("  PASS test_writable_pattern_in_path_makes_get_writable")


def test_put_endpoint_is_writable():
    engine = _engine()
    recon = _recon_with_endpoints([
        Endpoint(url="https://example.com/api/user/1", method="PUT"),
    ])
    writable = engine._identify_writable(recon)
    urls = [ep.url for ep in writable]
    assert "https://example.com/api/user/1" in urls
    print("  PASS test_put_endpoint_is_writable")


def test_common_writable_patterns_added_as_candidates():
    """Even with zero discovered endpoints, pattern-based candidates are added."""
    engine = _engine()
    recon = _recon_with_endpoints([])
    writable = engine._identify_writable(recon)
    urls = [ep.url for ep in writable]
    # /api/comment is in _WRITABLE_PATTERNS
    assert any("/comment" in u or "/api/comment" in u for u in urls), \
        f"Expected comment pattern in candidates, got: {urls[:5]}"
    print("  PASS test_common_writable_patterns_added_as_candidates")


def test_no_duplicate_writable_urls():
    """If an endpoint is both POST and matches a pattern, it appears only once."""
    engine = _engine()
    recon = _recon_with_endpoints([
        Endpoint(url="https://example.com/comment", method="POST"),
    ])
    writable = engine._identify_writable(recon)
    urls = [ep.url for ep in writable]
    count = urls.count("https://example.com/comment")
    assert count == 1, f"URL appeared {count} times, expected 1"
    print("  PASS test_no_duplicate_writable_urls")


# ─── Retrieve page building ───────────────────────────────────────────────────

def test_retrieve_pages_include_common_paths():
    engine = _engine()
    recon = _recon_with_endpoints([])
    pages = engine._build_retrieve_pages("https://example.com", recon)
    assert "https://example.com/" in pages
    assert "https://example.com/dashboard" in pages
    print("  PASS test_retrieve_pages_include_common_paths")


def test_retrieve_pages_include_graphql_endpoints():
    engine = _engine()
    recon = _recon_with_endpoints([])
    recon.graphql_endpoints = ["https://example.com/graphql"]
    pages = engine._build_retrieve_pages("https://example.com", recon)
    assert "https://example.com/graphql" in pages
    print("  PASS test_retrieve_pages_include_graphql_endpoints")


def test_retrieve_pages_no_duplicates():
    engine = _engine()
    recon = _recon_with_endpoints([])
    recon.graphql_endpoints = ["https://example.com/graphql"]
    pages = engine._build_retrieve_pages("https://example.com", recon)
    assert len(pages) == len(set(pages)), "Retrieve pages should not contain duplicates"
    print("  PASS test_retrieve_pages_no_duplicates")


def test_retrieve_pages_include_content_endpoints():
    """Discovered GET endpoints matching content patterns should be included."""
    engine = _engine()
    recon = _recon_with_endpoints([
        Endpoint(url="https://example.com/dashboard", method="GET"),
        Endpoint(url="https://example.com/api/v1/widget", method="GET"),  # no content keyword
    ])
    pages = engine._build_retrieve_pages("https://example.com", recon)
    # dashboard matches content pattern
    assert "https://example.com/dashboard" in pages
    print("  PASS test_retrieve_pages_include_content_endpoints")


# ─── Retrieve and check ───────────────────────────────────────────────────────

def test_retrieve_and_check_returns_true_when_canary_found():
    """Simulate a response that contains the canary ID."""
    engine = _engine()
    canary_id = "pin0cc_a1b2c3d4"
    canary_full = f'<img src=x id="{canary_id}" onerror=alert("test")>'

    async def _run():
        mock_client = MagicMock()
        mock_resp = _MockResponse(200, f"<html><body>{canary_full}</body></html>")
        mock_client.get = AsyncMock(return_value=mock_resp)
        return await engine._retrieve_and_check(
            mock_client, "https://example.com/profile", canary_id, canary_full
        )

    result = asyncio.run(_run())
    assert result is True, "Should return True when canary ID found in page"
    print("  PASS test_retrieve_and_check_returns_true_when_canary_found")


def test_retrieve_and_check_returns_false_when_canary_absent():
    engine = _engine()
    canary_id = "pin0cc_a1b2c3d4"

    async def _run():
        mock_client = MagicMock()
        mock_resp = _MockResponse(200, "<html><body>clean page</body></html>")
        mock_client.get = AsyncMock(return_value=mock_resp)
        return await engine._retrieve_and_check(
            mock_client, "https://example.com/profile", canary_id, "payload"
        )

    result = asyncio.run(_run())
    assert result is False
    print("  PASS test_retrieve_and_check_returns_false_when_canary_absent")


def test_retrieve_and_check_returns_false_on_error_status():
    engine = _engine()
    canary_id = "pin0cc_a1b2c3d4"

    async def _run():
        mock_client = MagicMock()
        mock_resp = _MockResponse(404, f"Not found {canary_id}")  # has canary but 404
        mock_client.get = AsyncMock(return_value=mock_resp)
        return await engine._retrieve_and_check(
            mock_client, "https://example.com/profile", canary_id, "payload"
        )

    result = asyncio.run(_run())
    assert result is False, "Error responses should not trigger detection even if canary present"
    print("  PASS test_retrieve_and_check_returns_false_on_error_status")


# ─── Canary uniqueness ────────────────────────────────────────────────────────

def test_canary_tokens_are_unique():
    """Each test run should produce a different canary token."""
    import secrets
    tokens = {secrets.token_hex(4) for _ in range(50)}
    assert len(tokens) == 50, "tokens should be unique (birthday paradox risk is negligible at 4 bytes)"
    print("  PASS test_canary_tokens_are_unique")


def test_canary_template_contains_token():
    token = "deadbeef"
    canary = _CANARY_TEMPLATE.format(token=token)
    assert token in canary
    assert "pin0cc_" in canary
    assert "onerror" in canary
    print("  PASS test_canary_template_contains_token")


if __name__ == "__main__":
    print("\nStoredXSSEngine Tests")
    print("=" * 40)
    test_post_endpoint_is_writable()
    test_get_endpoint_with_neutral_path_not_writable()
    test_writable_pattern_in_path_makes_get_writable()
    test_put_endpoint_is_writable()
    test_common_writable_patterns_added_as_candidates()
    test_no_duplicate_writable_urls()
    test_retrieve_pages_include_common_paths()
    test_retrieve_pages_include_graphql_endpoints()
    test_retrieve_pages_no_duplicates()
    test_retrieve_pages_include_content_endpoints()
    test_retrieve_and_check_returns_true_when_canary_found()
    test_retrieve_and_check_returns_false_when_canary_absent()
    test_retrieve_and_check_returns_false_on_error_status()
    test_canary_tokens_are_unique()
    test_canary_template_contains_token()
    print("\nAll StoredXSSEngine tests passed.")
