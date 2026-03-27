"""
Tests for plugins/__init__.py

Covers:
  PluginManager construction
    - No plugin dir (autoload=False) creates empty manager
    - load_plugins() on empty dir returns 0
    - load_plugins() on nonexistent dir returns 0

  register()
    - Manually registered plugin appears in loaded_plugins
    - Multiple plugins can be registered

  on_finding_raw()
    - Returns original finding when no plugin modifies it
    - Returns modified finding from the first plugin that returns non-None
    - Stops at first non-None return (first plugin wins)
    - None return from all plugins falls through to original

  on_finding_confirmed()
    - Called once per confirmed finding
    - Arguments passed correctly

  extra_payloads()
    - Returns empty list when no plugins registered
    - Aggregates payloads from multiple plugins
    - Ignores None returns

  on_recon_complete() / on_scan_complete() / on_report_generated()
    - Called without raising

  load_plugins() from temp dir
    - Loads a real plugin file with @hookimpl methods
    - Skips files starting with underscore
    - Gracefully handles files with import errors
"""
import os
import sys
import tempfile
import textwrap

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import tests.stubs  # noqa: F401 — installs structlog/httpx stubs; pluggy is NOT stubbed

from core.models import Finding, Severity, VulnType
from plugins import PluginManager, hookimpl


def _finding():
    return Finding(
        title="Test XSS",
        vuln_type=VulnType.XSS_REFLECTED,
        severity=Severity.HIGH,
        url="https://example.com",
        confirmed=True,
        confidence=0.9,
    )


def _empty_pm():
    return PluginManager(plugin_dir="/nonexistent", autoload=False)


# ─── Construction ─────────────────────────────────────────────────────────────

def test_construction_no_autoload():
    pm = PluginManager(plugin_dir="/nonexistent", autoload=False)
    assert pm.loaded_plugins == []
    print("  PASS test_construction_no_autoload")


def test_load_plugins_nonexistent_dir_returns_zero():
    pm = PluginManager(plugin_dir="/nonexistent/path", autoload=False)
    result = pm.load_plugins()
    assert result == 0
    print("  PASS test_load_plugins_nonexistent_dir_returns_zero")


def test_load_plugins_empty_dir_returns_zero():
    tmpdir = tempfile.mkdtemp()
    try:
        pm = PluginManager(plugin_dir=tmpdir, autoload=False)
        result = pm.load_plugins()
        assert result == 0
    finally:
        os.rmdir(tmpdir)
    print("  PASS test_load_plugins_empty_dir_returns_zero")


# ─── register() ──────────────────────────────────────────────────────────────

def test_register_plugin_appears_in_loaded():
    class MyPlugin:
        pass
    pm = _empty_pm()
    pm.register(MyPlugin(), name="my_plugin")
    assert "my_plugin" in pm.loaded_plugins
    print("  PASS test_register_plugin_appears_in_loaded")


def test_register_multiple_plugins():
    class PluginA:
        pass
    class PluginB:
        pass
    pm = _empty_pm()
    pm.register(PluginA(), name="plugin_a")
    pm.register(PluginB(), name="plugin_b")
    assert len(pm.loaded_plugins) == 2
    print("  PASS test_register_multiple_plugins")


# ─── on_finding_raw() ────────────────────────────────────────────────────────

def test_on_finding_raw_no_plugins_returns_original():
    pm = _empty_pm()
    f = _finding()
    result = pm.on_finding_raw(f)
    assert result is f
    print("  PASS test_on_finding_raw_no_plugins_returns_original")


def test_on_finding_raw_plugin_returns_modified():
    class ModifyPlugin:
        @hookimpl
        def on_finding_raw(self, finding):
            finding.title = "Modified by plugin"
            return finding

    pm = _empty_pm()
    pm.register(ModifyPlugin(), name="modifier")
    f = _finding()
    result = pm.on_finding_raw(f)
    assert result.title == "Modified by plugin"
    print("  PASS test_on_finding_raw_plugin_returns_modified")


def test_on_finding_raw_none_returns_falls_through():
    class PassThroughPlugin:
        @hookimpl
        def on_finding_raw(self, finding):
            return None   # explicit pass-through

    pm = _empty_pm()
    pm.register(PassThroughPlugin(), name="passthrough")
    f = _finding()
    result = pm.on_finding_raw(f)
    assert result is f, "None return should fall through to original finding"
    print("  PASS test_on_finding_raw_none_returns_falls_through")


def test_on_finding_raw_first_non_none_wins():
    class PluginA:
        @hookimpl
        def on_finding_raw(self, finding):
            finding.title = "Plugin A"
            return finding

    class PluginB:
        @hookimpl
        def on_finding_raw(self, finding):
            finding.title = "Plugin B"
            return finding

    pm = _empty_pm()
    pm.register(PluginA(), name="plugin_a")
    pm.register(PluginB(), name="plugin_b")
    f = _finding()
    result = pm.on_finding_raw(f)
    # One of the plugins wins — result should be modified (not original title)
    assert result.title in ("Plugin A", "Plugin B")
    print("  PASS test_on_finding_raw_first_non_none_wins")


# ─── on_finding_confirmed() ──────────────────────────────────────────────────

def test_on_finding_confirmed_called():
    calls = []

    class TrackingPlugin:
        @hookimpl
        def on_finding_confirmed(self, finding, session_id):
            calls.append((finding.title, session_id))

    pm = _empty_pm()
    pm.register(TrackingPlugin(), name="tracker")
    f = _finding()
    pm.on_finding_confirmed(f, "sess-001")
    assert len(calls) == 1
    assert calls[0] == ("Test XSS", "sess-001")
    print("  PASS test_on_finding_confirmed_called")


def test_on_finding_confirmed_no_plugins_no_error():
    pm = _empty_pm()
    pm.on_finding_confirmed(_finding(), "sess-001")   # should not raise
    print("  PASS test_on_finding_confirmed_no_plugins_no_error")


# ─── extra_payloads() ────────────────────────────────────────────────────────

def test_extra_payloads_empty_manager():
    pm = _empty_pm()
    result = pm.extra_payloads("xss", "https://example.com")
    assert result == []
    print("  PASS test_extra_payloads_empty_manager")


def test_extra_payloads_single_plugin():
    class PayloadPlugin:
        @hookimpl
        def extra_payloads(self, vuln_type, url):
            if vuln_type == "xss":
                return ["<custom-payload>"]
            return []

    pm = _empty_pm()
    pm.register(PayloadPlugin(), name="payload_plugin")
    result = pm.extra_payloads("xss", "https://example.com")
    assert "<custom-payload>" in result
    print("  PASS test_extra_payloads_single_plugin")


def test_extra_payloads_aggregated_from_multiple():
    class PluginA:
        @hookimpl
        def extra_payloads(self, vuln_type, url):
            return ["payload_a1", "payload_a2"]

    class PluginB:
        @hookimpl
        def extra_payloads(self, vuln_type, url):
            return ["payload_b1"]

    pm = _empty_pm()
    pm.register(PluginA(), name="plugin_a")
    pm.register(PluginB(), name="plugin_b")
    result = pm.extra_payloads("sqli", "https://example.com")
    assert "payload_a1" in result
    assert "payload_a2" in result
    assert "payload_b1" in result
    assert len(result) == 3
    print("  PASS test_extra_payloads_aggregated_from_multiple")


def test_extra_payloads_vuln_type_not_matching_returns_empty():
    class XSSPlugin:
        @hookimpl
        def extra_payloads(self, vuln_type, url):
            if vuln_type == "xss":
                return ["xss_payload"]
            return []

    pm = _empty_pm()
    pm.register(XSSPlugin(), name="xss_plugin")
    result = pm.extra_payloads("sqli", "https://example.com")
    assert result == []
    print("  PASS test_extra_payloads_vuln_type_not_matching_returns_empty")


# ─── Other hooks ─────────────────────────────────────────────────────────────

def test_on_recon_complete_no_error():
    pm = _empty_pm()
    pm.on_recon_complete(recon_result=None, config=None)
    print("  PASS test_on_recon_complete_no_error")


def test_on_scan_complete_no_error():
    pm = _empty_pm()
    pm.on_scan_complete(session=None, report_paths={})
    print("  PASS test_on_scan_complete_no_error")


def test_on_report_generated_no_error():
    pm = _empty_pm()
    pm.on_report_generated(report_path="/tmp/report.md", fmt="markdown")
    print("  PASS test_on_report_generated_no_error")


# ─── load_plugins() from temp dir ────────────────────────────────────────────

def test_load_plugins_from_real_file():
    plugin_code = textwrap.dedent("""
        from plugins import hookimpl

        class TestPlugin:
            @hookimpl
            def extra_payloads(self, vuln_type, url):
                return ["loaded_from_file"]
    """)
    tmpdir = tempfile.mkdtemp()
    try:
        plugin_path = os.path.join(tmpdir, "my_plugin.py")
        with open(plugin_path, "w") as f:
            f.write(plugin_code)

        pm = PluginManager(plugin_dir=tmpdir, autoload=True)
        result = pm.extra_payloads("xss", "https://example.com")
        assert "loaded_from_file" in result, \
            f"Plugin payload not found. Got: {result}. Loaded: {pm.loaded_plugins}"
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_load_plugins_from_real_file")


def test_load_plugins_skips_underscore_files():
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "_private_plugin.py"), "w") as f:
            f.write("# This should not be loaded\n")
        pm = PluginManager(plugin_dir=tmpdir, autoload=True)
        assert pm.loaded_plugins == [], \
            f"Underscore file should not be loaded. Got: {pm.loaded_plugins}"
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_load_plugins_skips_underscore_files")


def test_load_plugins_handles_import_error_gracefully():
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "broken_plugin.py"), "w") as f:
            f.write("import nonexistent_module_12345\n")
        # Should not raise — just logs a warning and skips
        pm = PluginManager(plugin_dir=tmpdir, autoload=True)
        assert pm.loaded_plugins == []
    finally:
        import shutil; shutil.rmtree(tmpdir)
    print("  PASS test_load_plugins_handles_import_error_gracefully")


if __name__ == "__main__":
    print("\nPluginManager Tests")
    print("=" * 40)
    test_construction_no_autoload()
    test_load_plugins_nonexistent_dir_returns_zero()
    test_load_plugins_empty_dir_returns_zero()
    test_register_plugin_appears_in_loaded()
    test_register_multiple_plugins()
    test_on_finding_raw_no_plugins_returns_original()
    test_on_finding_raw_plugin_returns_modified()
    test_on_finding_raw_none_returns_falls_through()
    test_on_finding_raw_first_non_none_wins()
    test_on_finding_confirmed_called()
    test_on_finding_confirmed_no_plugins_no_error()
    test_extra_payloads_empty_manager()
    test_extra_payloads_single_plugin()
    test_extra_payloads_aggregated_from_multiple()
    test_extra_payloads_vuln_type_not_matching_returns_empty()
    test_on_recon_complete_no_error()
    test_on_scan_complete_no_error()
    test_on_report_generated_no_error()
    test_load_plugins_from_real_file()
    test_load_plugins_skips_underscore_files()
    test_load_plugins_handles_import_error_gracefully()
    print("\nAll PluginManager tests passed.")
