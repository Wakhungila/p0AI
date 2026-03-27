"""
tests/stubs.py — Shared dependency stubs for pin0ccsAI test suite.

Import this at the top of any test file BEFORE importing pin0ccsAI modules.
Idempotent: safe to call from multiple test files in the same process.

Usage:
    import tests.stubs  # or: from tests import stubs
"""
import sys
import types

_INSTALLED: set[str] = set()


def install() -> None:
    """Install all stubs. Idempotent — calling twice is safe."""
    _install_structlog()
    _install_httpx()
    _install_yaml()
    _install_aiodns()


def _install_structlog() -> None:
    if "structlog" in _INSTALLED:
        return

    # Create all submodule objects first
    _sl_stdlib = types.ModuleType("structlog.stdlib")
    _sl_ctx = types.ModuleType("structlog.contextvars")
    _sl_dev = types.ModuleType("structlog.dev")
    _sl_proc = types.ModuleType("structlog.processors")

    class _Logger:
        def bind(self, **k): return self
        def info(self, *a, **k): pass
        def debug(self, *a, **k): pass
        def warning(self, *a, **k): pass
        def error(self, *a, **k): pass

    _sl_stdlib.BoundLogger = _Logger
    _sl_stdlib.add_log_level = None
    _sl_stdlib.add_logger_name = None
    _sl_stdlib.LoggerFactory = object
    _sl_stdlib.ProcessorFormatter = type("PF", (), {"wrap_for_formatter": None})
    _sl_ctx.merge_contextvars = None
    _sl_ctx.bind_contextvars = lambda **k: None
    _sl_ctx.clear_contextvars = lambda: None
    _sl_dev.ConsoleRenderer = lambda **k: None
    _sl_proc.TimeStamper = lambda **k: None
    _sl_proc.StackInfoRenderer = lambda: None
    _sl_proc.format_exc_info = None
    _sl_proc.JSONRenderer = lambda: None

    # Build root module last, with submodule references attached
    _sl = types.ModuleType("structlog")
    _sl.get_logger = lambda *a, **k: _Logger()
    _sl.configure = lambda **k: None
    _sl.stdlib = _sl_stdlib
    _sl.contextvars = _sl_ctx
    _sl.dev = _sl_dev
    _sl.processors = _sl_proc

    sys.modules.update({
        "structlog": _sl,
        "structlog.stdlib": _sl_stdlib,
        "structlog.contextvars": _sl_ctx,
        "structlog.dev": _sl_dev,
        "structlog.processors": _sl_proc,
    })
    _INSTALLED.add("structlog")


def _install_httpx() -> None:
    if "httpx" in _INSTALLED:
        return

    from unittest.mock import AsyncMock

    class _MockResponse:
        def __init__(self, status: int = 200, text: str = ""):
            self.status_code = status
            self.text = text
            self.headers = {}
        def json(self): return {}

    class _MockAsyncClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def get(self, *a, **k): return _MockResponse()
        async def post(self, *a, **k): return _MockResponse()
        async def request(self, *a, **k): return _MockResponse()
        async def head(self, *a, **k): return _MockResponse()

    _httpx = types.ModuleType("httpx")
    _httpx.AsyncClient = _MockAsyncClient
    _httpx.Response = _MockResponse
    _httpx.Timeout = type("Timeout", (), {"__init__": lambda s, *a, **k: None})
    _httpx.ConnectError = Exception
    _httpx.HTTPStatusError = Exception
    sys.modules["httpx"] = _httpx
    _INSTALLED.add("httpx")


def _install_yaml() -> None:
    if "yaml" in _INSTALLED:
        return
    # Patch safe_load on the real yaml module rather than replacing the entire
    # module. This allows tests that need real YAML parsing (test_config.py)
    # to import yaml and get the real module, while tests that don't need it
    # get a no-op safe_load that avoids FileNotFoundError on missing config files.
    try:
        import yaml as _real_yaml
        _real_yaml._original_safe_load = _real_yaml.safe_load
        _real_yaml.safe_load = lambda f: {}
    except ImportError:
        # yaml not installed — create a minimal fake module
        _yaml = types.ModuleType("yaml")
        _yaml.safe_load = lambda f: {}
        sys.modules["yaml"] = _yaml
    _INSTALLED.add("yaml")


def _restore_yaml() -> None:
    """Restore real yaml.safe_load. Called by tests that need it."""
    try:
        import yaml as _real_yaml
        if hasattr(_real_yaml, "_original_safe_load"):
            _real_yaml.safe_load = _real_yaml._original_safe_load
    except ImportError:
        pass


def _install_aiodns() -> None:
    if "aiodns" in _INSTALLED:
        return
    sys.modules["aiodns"] = types.ModuleType("aiodns")
    _INSTALLED.add("aiodns")


# Auto-install when this module is imported
install()
