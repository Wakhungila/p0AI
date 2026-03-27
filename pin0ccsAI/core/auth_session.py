"""
pin0ccsAI — Auth Session Manager

Provides authenticated HTTP clients to any component that needs them.
Supports cookie-based auth, Bearer tokens, API keys, and custom headers.
Sessions are loaded from a JSON file, environment variables, or CLI flags.

Design:
  - AuthSession is injected into TesterAgent and Debator via the orchestrator
  - Every httpx.AsyncClient built with .build_client() automatically carries auth
  - The session file format is intentionally simple — easy to populate from Burp
  - Auth state is NEVER stored in the database or logs (only in memory + session file)
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from core.logger import get_logger

log = get_logger(__name__)


@dataclass
class AuthSession:
    """
    Holds all authentication material for one target.

    Precedence (highest to lowest):
      1. Explicit constructor arguments
      2. Session file (--auth-file)
      3. Environment variables
      4. No auth (anonymous)
    """
    # Cookie jar — dict of {name: value}
    cookies: dict[str, str] = field(default_factory=dict)

    # Headers injected into every request
    # e.g. {"Authorization": "Bearer eyJ...", "X-API-Key": "abc123"}
    headers: dict[str, str] = field(default_factory=dict)

    # Convenience: set this to auto-build Authorization: Bearer <token>
    bearer_token: str = ""

    # Convenience: set this to auto-build X-API-Key: <key>
    api_key: str = ""
    api_key_header: str = "X-API-Key"

    # Base URL this auth applies to (optional — used for scoping)
    target_url: str = ""

    # Human label for logging (never logged to file, only to console DEBUG)
    label: str = "default"

    def __post_init__(self):
        # Materialise convenience fields into headers dict
        if self.bearer_token and "Authorization" not in self.headers:
            self.headers["Authorization"] = f"Bearer {self.bearer_token}"
        if self.api_key and self.api_key_header not in self.headers:
            self.headers[self.api_key_header] = self.api_key

    @property
    def is_authenticated(self) -> bool:
        return bool(self.cookies or self.headers)

    def build_client_kwargs(self) -> dict:
        """
        Return kwargs suitable for httpx.AsyncClient(**kwargs).
        Merges cookies and headers into the client constructor.
        """
        kwargs: dict = {"verify": False, "follow_redirects": True}
        if self.cookies:
            kwargs["cookies"] = self.cookies
        if self.headers:
            kwargs["headers"] = self.headers
        return kwargs

    # ─── Loaders ─────────────────────────────────────────────────────────────

    @classmethod
    def load(cls, path: str | Path) -> "AuthSession":
        """
        Load from a JSON session file.

        Supported formats:

        1. Flat dict (simplest):
            {
              "cookies": {"session": "abc123", "csrf_token": "xyz"},
              "headers": {"Authorization": "Bearer eyJ..."},
              "label": "admin_user"
            }

        2. Burp copy-as-curl style (just paste the Cookie header):
            {
              "cookie_header": "session=abc123; user_id=42; csrf=xyz",
              "headers": {"X-Forwarded-For": "127.0.0.1"}
            }

        3. Bearer-only shorthand:
            {
              "bearer_token": "eyJhbGciOiJIUzI1NiJ9..."
            }
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Auth session file not found: {path}")

        with open(path) as f:
            data = json.load(f)

        # Handle cookie_header string (from Burp copy-as-curl)
        cookie_header = data.pop("cookie_header", "")
        if cookie_header:
            cookies = cls._parse_cookie_header(cookie_header)
            data.setdefault("cookies", {}).update(cookies)

        session = cls(**{k: v for k, v in data.items()
                         if k in cls.__dataclass_fields__})
        log.info("auth_session.loaded",
                 label=session.label,
                 has_cookies=bool(session.cookies),
                 has_headers=bool(session.headers))
        return session

    @classmethod
    def from_env(cls) -> Optional["AuthSession"]:
        """
        Load auth from environment variables.
        Returns None if no auth env vars are set.

        Variables:
          PIN0_AUTH_COOKIE      — raw Cookie header string
          PIN0_AUTH_BEARER      — Bearer token string
          PIN0_AUTH_API_KEY     — API key value
          PIN0_AUTH_API_HEADER  — API key header name (default: X-API-Key)
          PIN0_AUTH_HEADERS     — JSON string of extra headers
        """
        cookie_str = os.environ.get("PIN0_AUTH_COOKIE", "")
        bearer    = os.environ.get("PIN0_AUTH_BEARER", "")
        api_key   = os.environ.get("PIN0_AUTH_API_KEY", "")
        api_hdr   = os.environ.get("PIN0_AUTH_API_HEADER", "X-API-Key")
        extra_hdrs_raw = os.environ.get("PIN0_AUTH_HEADERS", "")

        if not any([cookie_str, bearer, api_key, extra_hdrs_raw]):
            return None

        cookies = cls._parse_cookie_header(cookie_str) if cookie_str else {}
        extra_headers: dict[str, str] = {}
        if extra_hdrs_raw:
            try:
                extra_headers = json.loads(extra_hdrs_raw)
            except json.JSONDecodeError:
                log.warning("auth_session.env_headers_parse_error",
                            raw=extra_hdrs_raw[:100])

        session = cls(
            cookies=cookies,
            bearer_token=bearer,
            api_key=api_key,
            api_key_header=api_hdr,
            headers=extra_headers,
            label="env",
        )
        log.info("auth_session.from_env",
                 has_cookies=bool(cookies), has_bearer=bool(bearer))
        return session

    @classmethod
    def anonymous(cls) -> "AuthSession":
        """Return an unauthenticated session (no-op)."""
        return cls(label="anonymous")

    # ─── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_cookie_header(header: str) -> dict[str, str]:
        """
        Parse a raw Cookie header string into {name: value} dict.
        Handles:
          session=abc123; user_id=42; csrf_token=xyz
          session=abc123;user_id=42
        """
        cookies: dict[str, str] = {}
        for part in header.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                cookies[name.strip()] = value.strip()
        return cookies

    def to_dict_safe(self) -> dict:
        """
        Return a safe representation for logging/status display.
        Masks actual credential values.
        """
        return {
            "label": self.label,
            "cookies": [k for k in self.cookies.keys()],
            "headers": [k for k in self.headers.keys()],
            "authenticated": self.is_authenticated,
        }
