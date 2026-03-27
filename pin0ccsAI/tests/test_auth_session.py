"""
Tests for core/auth_session.py

Covers:
  - Anonymous session is_authenticated == False
  - Bearer token materialised into Authorization header
  - API key materialised into correct header name
  - Cookie-only session is_authenticated == True
  - _parse_cookie_header handles semicolons, spaces, values with equals
  - load() from JSON file — flat dict format
  - load() from JSON file — cookie_header string format
  - load() from JSON file — bearer_token shorthand format
  - load() raises FileNotFoundError for missing file
  - from_env() returns None when no env vars set
  - from_env() builds session from PIN0_AUTH_BEARER
  - from_env() builds session from PIN0_AUTH_COOKIE
  - build_client_kwargs() returns verify=False always
  - build_client_kwargs() merges cookies and headers
  - to_dict_safe() masks credential values (lists keys only)
  - Explicit headers dict not overwritten by bearer_token materialisation
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Shared stubs — installs structlog/httpx/yaml/pluggy mocks
import sys; sys.path.insert(0, __file__.rsplit('/', 2)[0])
import tests.stubs  # noqa: F401 — side-effect: installs all stubs

from core.auth_session import AuthSession


def test_anonymous_is_not_authenticated():
    auth = AuthSession.anonymous()
    assert not auth.is_authenticated
    assert auth.cookies == {}
    assert auth.headers == {}
    print("  PASS test_anonymous_is_not_authenticated")


def test_bearer_token_materialises_into_authorization_header():
    auth = AuthSession(bearer_token="eyJtoken")
    assert "Authorization" in auth.headers
    assert auth.headers["Authorization"] == "Bearer eyJtoken"
    assert auth.is_authenticated
    print("  PASS test_bearer_token_materialises_into_authorization_header")


def test_api_key_materialises_into_default_header():
    auth = AuthSession(api_key="secret123")
    assert "X-API-Key" in auth.headers
    assert auth.headers["X-API-Key"] == "secret123"
    print("  PASS test_api_key_materialises_into_default_header")


def test_api_key_uses_custom_header_name():
    auth = AuthSession(api_key="secret", api_key_header="X-Custom-Key")
    assert "X-Custom-Key" in auth.headers
    assert "X-API-Key" not in auth.headers
    print("  PASS test_api_key_uses_custom_header_name")


def test_cookie_only_session_is_authenticated():
    auth = AuthSession(cookies={"session": "abc123"})
    assert auth.is_authenticated
    assert not auth.headers  # no headers from cookies alone
    print("  PASS test_cookie_only_session_is_authenticated")


def test_parse_cookie_header_standard():
    result = AuthSession._parse_cookie_header("session=abc123; user_id=42; csrf=xyz")
    assert result == {"session": "abc123", "user_id": "42", "csrf": "xyz"}
    print("  PASS test_parse_cookie_header_standard")


def test_parse_cookie_header_no_spaces():
    result = AuthSession._parse_cookie_header("a=1;b=2;c=3")
    assert result == {"a": "1", "b": "2", "c": "3"}
    print("  PASS test_parse_cookie_header_no_spaces")


def test_parse_cookie_header_value_contains_equals():
    # Base64 encoded values often contain '='
    result = AuthSession._parse_cookie_header("token=abc=def==; other=val")
    # partition('=') means first '=' splits, rest goes to value
    assert result["token"] == "abc=def=="
    assert result["other"] == "val"
    print("  PASS test_parse_cookie_header_value_contains_equals")


def test_parse_cookie_header_empty_string():
    result = AuthSession._parse_cookie_header("")
    assert result == {}
    print("  PASS test_parse_cookie_header_empty_string")


def test_load_from_file_flat_dict():
    data = {
        "cookies": {"session": "abc123", "csrf": "xyz"},
        "headers": {"X-Custom": "value"},
        "label": "test_user",
    }
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        auth = AuthSession.load(path)
        assert auth.cookies == {"session": "abc123", "csrf": "xyz"}
        assert auth.headers.get("X-Custom") == "value"
        assert auth.label == "test_user"
        assert auth.is_authenticated
    finally:
        os.unlink(path)
    print("  PASS test_load_from_file_flat_dict")


def test_load_from_file_cookie_header_string():
    data = {"cookie_header": "session=abc123; user_id=42"}
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        auth = AuthSession.load(path)
        assert auth.cookies.get("session") == "abc123"
        assert auth.cookies.get("user_id") == "42"
    finally:
        os.unlink(path)
    print("  PASS test_load_from_file_cookie_header_string")


def test_load_from_file_bearer_shorthand():
    data = {"bearer_token": "eyJtoken123"}
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        auth = AuthSession.load(path)
        assert auth.headers.get("Authorization") == "Bearer eyJtoken123"
    finally:
        os.unlink(path)
    print("  PASS test_load_from_file_bearer_shorthand")


def test_load_raises_for_missing_file():
    try:
        AuthSession.load("/nonexistent/path/session.json")
        assert False, "Expected FileNotFoundError"
    except FileNotFoundError:
        pass
    print("  PASS test_load_raises_for_missing_file")


def test_from_env_returns_none_when_no_vars_set():
    # Clear all auth env vars
    for key in ["PIN0_AUTH_COOKIE", "PIN0_AUTH_BEARER",
                "PIN0_AUTH_API_KEY", "PIN0_AUTH_HEADERS"]:
        os.environ.pop(key, None)
    result = AuthSession.from_env()
    assert result is None
    print("  PASS test_from_env_returns_none_when_no_vars_set")


def test_from_env_builds_session_from_bearer():
    os.environ["PIN0_AUTH_BEARER"] = "envtoken123"
    for key in ["PIN0_AUTH_COOKIE", "PIN0_AUTH_API_KEY", "PIN0_AUTH_HEADERS"]:
        os.environ.pop(key, None)
    try:
        auth = AuthSession.from_env()
        assert auth is not None
        assert auth.headers.get("Authorization") == "Bearer envtoken123"
    finally:
        os.environ.pop("PIN0_AUTH_BEARER", None)
    print("  PASS test_from_env_builds_session_from_bearer")


def test_from_env_builds_session_from_cookie():
    os.environ["PIN0_AUTH_COOKIE"] = "session=envtest; csrf=abc"
    for key in ["PIN0_AUTH_BEARER", "PIN0_AUTH_API_KEY", "PIN0_AUTH_HEADERS"]:
        os.environ.pop(key, None)
    try:
        auth = AuthSession.from_env()
        assert auth is not None
        assert auth.cookies.get("session") == "envtest"
        assert auth.cookies.get("csrf") == "abc"
    finally:
        os.environ.pop("PIN0_AUTH_COOKIE", None)
    print("  PASS test_from_env_builds_session_from_cookie")


def test_build_client_kwargs_always_has_verify_false():
    auth = AuthSession(cookies={"s": "v"})
    kwargs = auth.build_client_kwargs()
    assert kwargs.get("verify") is False
    print("  PASS test_build_client_kwargs_always_has_verify_false")


def test_build_client_kwargs_includes_cookies():
    auth = AuthSession(cookies={"session": "abc", "csrf": "xyz"})
    kwargs = auth.build_client_kwargs()
    assert kwargs.get("cookies") == {"session": "abc", "csrf": "xyz"}
    print("  PASS test_build_client_kwargs_includes_cookies")


def test_build_client_kwargs_includes_headers():
    auth = AuthSession(bearer_token="tok")
    kwargs = auth.build_client_kwargs()
    assert "Authorization" in kwargs.get("headers", {})
    print("  PASS test_build_client_kwargs_includes_headers")


def test_build_client_kwargs_anonymous_has_no_cookies_or_headers():
    auth = AuthSession.anonymous()
    kwargs = auth.build_client_kwargs()
    assert "cookies" not in kwargs
    assert "headers" not in kwargs
    print("  PASS test_build_client_kwargs_anonymous_has_no_cookies_or_headers")


def test_to_dict_safe_lists_keys_not_values():
    auth = AuthSession(
        cookies={"session": "secret_value_123"},
        headers={"Authorization": "Bearer secret_token"},
        label="admin",
    )
    safe = auth.to_dict_safe()
    assert "session" in safe["cookies"]          # key present
    assert "secret_value_123" not in str(safe)   # value masked
    assert "Authorization" in safe["headers"]     # key present
    assert "Bearer secret_token" not in str(safe) # value masked
    assert safe["authenticated"] is True
    print("  PASS test_to_dict_safe_lists_keys_not_values")


def test_explicit_headers_not_overwritten_by_bearer():
    """If Authorization is already set explicitly, bearer_token should not overwrite it."""
    auth = AuthSession(
        headers={"Authorization": "CustomScheme explicit_token"},
        bearer_token="should_not_overwrite",
    )
    assert auth.headers["Authorization"] == "CustomScheme explicit_token"
    print("  PASS test_explicit_headers_not_overwritten_by_bearer")


if __name__ == "__main__":
    print("\nAuthSession Tests")
    print("=" * 40)
    test_anonymous_is_not_authenticated()
    test_bearer_token_materialises_into_authorization_header()
    test_api_key_materialises_into_default_header()
    test_api_key_uses_custom_header_name()
    test_cookie_only_session_is_authenticated()
    test_parse_cookie_header_standard()
    test_parse_cookie_header_no_spaces()
    test_parse_cookie_header_value_contains_equals()
    test_parse_cookie_header_empty_string()
    test_load_from_file_flat_dict()
    test_load_from_file_cookie_header_string()
    test_load_from_file_bearer_shorthand()
    test_load_raises_for_missing_file()
    test_from_env_returns_none_when_no_vars_set()
    test_from_env_builds_session_from_bearer()
    test_from_env_builds_session_from_cookie()
    test_build_client_kwargs_always_has_verify_false()
    test_build_client_kwargs_includes_cookies()
    test_build_client_kwargs_includes_headers()
    test_build_client_kwargs_anonymous_has_no_cookies_or_headers()
    test_to_dict_safe_lists_keys_not_values()
    test_explicit_headers_not_overwritten_by_bearer()
    print("\nAll AuthSession tests passed.")
