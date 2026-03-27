"""
Tests for core/config.py

Covers:
  Config.load()
    - Loads from a valid YAML file
    - Raises FileNotFoundError for missing path
    - Applies sub-section values to correct dataclass fields
    - Ignores unknown YAML keys (no KeyError)
    - _ensure_dirs creates required directories

  Config.get()
    - Single-level dotpath returns correct value
    - Two-level dotpath returns correct value
    - Missing key returns provided default
    - Missing key with no default returns None
    - Intermediate non-dict node returns default (no AttributeError)

  _from_dict()
    - Known keys are applied
    - Unknown keys are silently dropped
    - Empty dict returns defaults

  _apply_env_overrides()
    - PIN0_OLLAMA_URL overrides ollama.base_url
    - PIN0_LOG_LEVEL overrides logging.level
    - PIN0_MODEL_TESTER overrides models.tester
    - Unset env vars leave values unchanged

  Defaults
    - VulnConfig confidence_threshold default
    - OllamaConfig port default
    - VulnConfig nuclei_severity default list
"""
import functools
import os
import sys
import tempfile
import textwrap

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import tests.stubs  # noqa: F401 — installs structlog/httpx stubs, patches yaml.safe_load


def _use_real_yaml(fn):
    """Temporarily restore real yaml.safe_load for tests that call Config.load()."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        import yaml
        stub = yaml.safe_load
        real = getattr(yaml, "_original_safe_load", stub)
        yaml.safe_load = real
        try:
            return fn(*args, **kwargs)
        finally:
            yaml.safe_load = stub
    return wrapper


# ─── YAML fixtures ───────────────────────────────────────────────────────────

def _write_yaml(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        f.write(textwrap.dedent(content))
    return path


_MINIMAL = """
project:
  name: test_project
  report_dir: /tmp/pin0ccs_test_reports
  data_dir: /tmp/pin0ccs_test_data
  log_dir: /tmp/pin0ccs_test_logs
knowledge:
  db_path: /tmp/pin0ccs_test.db
"""

_FULL = """
project:
  name: full_test
  report_dir: /tmp/pin0ccs_test_reports
  data_dir: /tmp/pin0ccs_test_data
  log_dir: /tmp/pin0ccs_test_logs
ollama:
  base_url: http://custom-ollama:11434
  timeout: 240
models:
  tester: deepseek-coder:6.7b
  debator: llama3.1:8b
  strategy: mistral:7b
  knowledge: mistral:7b
tools:
  nmap: /usr/bin/nmap
recon:
  threads: 100
  timeout: 15
vuln:
  confidence_threshold: 0.80
  max_payload_mutations: 15
performance:
  max_mutation_calls: 6
  cache_ttl_hours: 48
  model_overlap_ok: true
knowledge:
  db_path: /tmp/pin0ccs_test.db
logging:
  level: DEBUG
  format: console
"""


# ─── Config.load() ────────────────────────────────────────────────────────────

@_use_real_yaml
def test_load_minimal_yaml_succeeds():
    path = _write_yaml(_MINIMAL)
    try:
        from core.config import Config
        cfg = Config.load(path)
        assert cfg is not None
        assert cfg.project.get("name") == "test_project"
    finally:
        os.unlink(path)
    print("  PASS test_load_minimal_yaml_succeeds")


def test_load_missing_file_raises():
    from core.config import Config
    try:
        Config.load("/nonexistent/path/config.yaml")
        assert False, "Should have raised FileNotFoundError"
    except FileNotFoundError:
        pass
    print("  PASS test_load_missing_file_raises")


@_use_real_yaml
def test_load_applies_ollama_section():
    path = _write_yaml(_FULL)
    try:
        from core.config import Config
        cfg = Config.load(path)
        assert cfg.ollama.base_url == "http://custom-ollama:11434"
        assert cfg.ollama.timeout == 240
    finally:
        os.unlink(path)
    print("  PASS test_load_applies_ollama_section")


@_use_real_yaml
def test_load_applies_models_section():
    path = _write_yaml(_FULL)
    try:
        from core.config import Config
        cfg = Config.load(path)
        assert cfg.models.tester == "deepseek-coder:6.7b"
        assert cfg.models.strategy == "mistral:7b"
    finally:
        os.unlink(path)
    print("  PASS test_load_applies_models_section")


@_use_real_yaml
def test_load_applies_vuln_section():
    path = _write_yaml(_FULL)
    try:
        from core.config import Config
        cfg = Config.load(path)
        assert cfg.vuln.confidence_threshold == 0.80
        assert cfg.vuln.max_payload_mutations == 15
    finally:
        os.unlink(path)
    print("  PASS test_load_applies_vuln_section")


@_use_real_yaml
def test_load_applies_logging_section():
    path = _write_yaml(_FULL)
    try:
        from core.config import Config
        cfg = Config.load(path)
        assert cfg.logging.level == "DEBUG"
        assert cfg.logging.format == "console"
    finally:
        os.unlink(path)
    print("  PASS test_load_applies_logging_section")


@_use_real_yaml
def test_load_ignores_unknown_keys():
    yaml_with_extra = _MINIMAL + "\nunknown_section:\n  unknown_key: value\n"
    path = _write_yaml(yaml_with_extra)
    try:
        from core.config import Config
        cfg = Config.load(path)
        assert cfg is not None
    finally:
        os.unlink(path)
    print("  PASS test_load_ignores_unknown_keys")


@_use_real_yaml
def test_load_creates_required_directories():
    import uuid, shutil
    tmpbase = f"/tmp/pin0ccs_dirtest_{uuid.uuid4().hex[:8]}"
    yaml_content = f"""
project:
  report_dir: {tmpbase}/reports
  data_dir: {tmpbase}/data
  log_dir: {tmpbase}/logs
knowledge:
  db_path: {tmpbase}/data/knowledge.db
"""
    path = _write_yaml(yaml_content)
    try:
        from core.config import Config
        Config.load(path)
        assert os.path.isdir(f"{tmpbase}/reports"), "reports dir not created"
        assert os.path.isdir(f"{tmpbase}/data"),    "data dir not created"
        assert os.path.isdir(f"{tmpbase}/logs"),    "logs dir not created"
    finally:
        os.unlink(path)
        shutil.rmtree(tmpbase, ignore_errors=True)
    print("  PASS test_load_creates_required_directories")


# ─── Config.get() ─────────────────────────────────────────────────────────────

@_use_real_yaml
def test_get_top_level_key():
    path = _write_yaml(_FULL)
    try:
        from core.config import Config
        cfg = Config.load(path)
        val = cfg.get("performance.max_mutation_calls")
        assert val == 6, f"Expected 6, got {val!r}"
    finally:
        os.unlink(path)
    print("  PASS test_get_top_level_key")


@_use_real_yaml
def test_get_nested_key():
    path = _write_yaml(_FULL)
    try:
        from core.config import Config
        cfg = Config.load(path)
        val = cfg.get("performance.cache_ttl_hours")
        assert val == 48, f"Expected 48, got {val!r}"
    finally:
        os.unlink(path)
    print("  PASS test_get_nested_key")


@_use_real_yaml
def test_get_missing_key_returns_default():
    path = _write_yaml(_MINIMAL)
    try:
        from core.config import Config
        cfg = Config.load(path)
        val = cfg.get("nonexistent.key", "fallback")
        assert val == "fallback"
    finally:
        os.unlink(path)
    print("  PASS test_get_missing_key_returns_default")


@_use_real_yaml
def test_get_missing_key_no_default_returns_none():
    path = _write_yaml(_MINIMAL)
    try:
        from core.config import Config
        cfg = Config.load(path)
        val = cfg.get("nonexistent.key")
        assert val is None
    finally:
        os.unlink(path)
    print("  PASS test_get_missing_key_no_default_returns_none")


@_use_real_yaml
def test_get_model_overlap_ok_boolean():
    path = _write_yaml(_FULL)
    try:
        from core.config import Config
        cfg = Config.load(path)
        val = cfg.get("performance.model_overlap_ok", False)
        assert val is True, f"Expected True, got {val!r}"
    finally:
        os.unlink(path)
    print("  PASS test_get_model_overlap_ok_boolean")


@_use_real_yaml
def test_get_intermediate_non_dict_returns_default():
    yaml_content = _MINIMAL + "\nscalar_key: hello\n"
    path = _write_yaml(yaml_content)
    try:
        from core.config import Config
        cfg = Config.load(path)
        val = cfg.get("scalar_key.subkey", "safe")
        assert val == "safe"
    finally:
        os.unlink(path)
    print("  PASS test_get_intermediate_non_dict_returns_default")


# ─── _from_dict() — no yaml needed ──────────────────────────────────────────

def test_from_dict_known_keys_applied():
    from core.config import _from_dict, OllamaConfig
    cfg = _from_dict(OllamaConfig, {"base_url": "http://test:9999", "timeout": 30})
    assert cfg.base_url == "http://test:9999"
    assert cfg.timeout == 30
    print("  PASS test_from_dict_known_keys_applied")


def test_from_dict_unknown_keys_dropped():
    from core.config import _from_dict, OllamaConfig
    cfg = _from_dict(OllamaConfig, {"base_url": "http://x:1", "ghost": "ignored"})
    assert cfg.base_url == "http://x:1"
    assert not hasattr(cfg, "ghost")
    print("  PASS test_from_dict_unknown_keys_dropped")


def test_from_dict_empty_uses_defaults():
    from core.config import _from_dict, OllamaConfig
    cfg = _from_dict(OllamaConfig, {})
    assert cfg.base_url == "http://localhost:11434"
    assert cfg.timeout == 120
    print("  PASS test_from_dict_empty_uses_defaults")


def test_from_dict_partial_overrides():
    from core.config import _from_dict, ModelsConfig
    cfg = _from_dict(ModelsConfig, {"tester": "custom:latest"})
    assert cfg.tester == "custom:latest"
    assert cfg.debator == "llama3.1:8b"   # unchanged default
    print("  PASS test_from_dict_partial_overrides")


# ─── _apply_env_overrides() — no yaml needed ─────────────────────────────────

def test_env_override_ollama_url():
    os.environ["PIN0_OLLAMA_URL"] = "http://remote:11434"
    try:
        from core.config import _apply_env_overrides
        result = _apply_env_overrides({"ollama": {"base_url": "http://localhost:11434"}})
        assert result["ollama"]["base_url"] == "http://remote:11434"
    finally:
        del os.environ["PIN0_OLLAMA_URL"]
    print("  PASS test_env_override_ollama_url")


def test_env_override_log_level():
    os.environ["PIN0_LOG_LEVEL"] = "DEBUG"
    try:
        from core.config import _apply_env_overrides
        result = _apply_env_overrides({})
        assert result["logging"]["level"] == "DEBUG"
    finally:
        del os.environ["PIN0_LOG_LEVEL"]
    print("  PASS test_env_override_log_level")


def test_env_override_model_tester():
    os.environ["PIN0_MODEL_TESTER"] = "codellama:13b"
    try:
        from core.config import _apply_env_overrides
        result = _apply_env_overrides({})
        assert result["models"]["tester"] == "codellama:13b"
    finally:
        del os.environ["PIN0_MODEL_TESTER"]
    print("  PASS test_env_override_model_tester")


def test_env_override_absent_leaves_unchanged():
    for k in ["PIN0_OLLAMA_URL", "PIN0_LOG_LEVEL", "PIN0_MODEL_TESTER", "PIN0_MODEL_DEBATOR"]:
        os.environ.pop(k, None)
    from core.config import _apply_env_overrides
    raw = {"ollama": {"base_url": "http://original:1234"}}
    result = _apply_env_overrides(raw)
    assert result["ollama"]["base_url"] == "http://original:1234"
    print("  PASS test_env_override_absent_leaves_unchanged")


# ─── Defaults — no yaml needed ───────────────────────────────────────────────

def test_default_confidence_threshold():
    from core.config import VulnConfig
    assert VulnConfig().confidence_threshold == 0.75
    print("  PASS test_default_confidence_threshold")


def test_default_ollama_port():
    from core.config import OllamaConfig
    assert "11434" in OllamaConfig().base_url
    print("  PASS test_default_ollama_port")


def test_default_nuclei_severity_list():
    from core.config import VulnConfig
    sev = VulnConfig().nuclei_severity
    assert "critical" in sev and "high" in sev
    print("  PASS test_default_nuclei_severity_list")


if __name__ == "__main__":
    print("\nConfig Tests")
    print("=" * 40)
    test_load_minimal_yaml_succeeds()
    test_load_missing_file_raises()
    test_load_applies_ollama_section()
    test_load_applies_models_section()
    test_load_applies_vuln_section()
    test_load_applies_logging_section()
    test_load_ignores_unknown_keys()
    test_load_creates_required_directories()
    test_get_top_level_key()
    test_get_nested_key()
    test_get_missing_key_returns_default()
    test_get_missing_key_no_default_returns_none()
    test_get_model_overlap_ok_boolean()
    test_get_intermediate_non_dict_returns_default()
    test_from_dict_known_keys_applied()
    test_from_dict_unknown_keys_dropped()
    test_from_dict_empty_uses_defaults()
    test_from_dict_partial_overrides()
    test_env_override_ollama_url()
    test_env_override_log_level()
    test_env_override_model_tester()
    test_env_override_absent_leaves_unchanged()
    test_default_confidence_threshold()
    test_default_ollama_port()
    test_default_nuclei_severity_list()
    print("\nAll Config tests passed.")
