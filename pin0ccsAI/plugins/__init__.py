"""
pin0ccsAI — Plugin System

Zero-dependency hook registry. Drop a .py file in the plugins/ directory
and it loads automatically. Implements the same public API as the previous
pluggy-based version so all orchestrator call sites remain unchanged.

Hooks (implement any of these in your plugin class):

    on_recon_complete(recon_result, config)
    on_finding_raw(finding)            → return modified Finding or None
    on_finding_confirmed(finding, session_id)
    on_scan_complete(session, report_paths)
    extra_payloads(vuln_type, url)     → return list[str]
    on_report_generated(report_path, fmt)

Usage in a plugin file (save to plugins/my_plugin.py):

    from plugins import hookimpl

    class MyPlugin:
        @hookimpl
        def on_finding_confirmed(self, finding, session_id):
            print(f"[+] {finding.severity.value}: {finding.title}")

        @hookimpl
        def extra_payloads(self, vuln_type, url):
            if vuln_type == "xss":
                return ["<x/onpointerenter=alert(1)>"]
            return []

The @hookimpl decorator is a no-op marker — it annotates a method so the
auto-loader can identify plugin classes without importing pluggy.
"""
from __future__ import annotations

import importlib.util
import inspect
from pathlib import Path
from typing import Any, Optional

from core.logger import get_logger

log = get_logger(__name__)

# ─── Public marker decorator ─────────────────────────────────────────────────

def hookimpl(fn):
    """
    No-op decorator that marks a method as a hook implementation.
    Annotated methods are discovered by the auto-loader and called
    by PluginManager hook callers.
    """
    fn._pin0ccs_hookimpl = True
    return fn


# ─── Known hook names ─────────────────────────────────────────────────────────

_HOOKS = {
    "on_recon_complete",
    "on_finding_raw",
    "on_finding_confirmed",
    "on_scan_complete",
    "extra_payloads",
    "on_report_generated",
}


# ─── Plugin Manager ───────────────────────────────────────────────────────────

class PluginManager:
    """
    Lightweight hook registry. Replaces pluggy with a simple list of
    registered plugin instances. Each hook caller iterates the list and
    calls any method with a matching name, collecting return values.

    Public API is identical to the previous pluggy-based implementation
    so the orchestrator and CLI need no changes.
    """

    def __init__(self, plugin_dir: str = "./plugins", autoload: bool = True):
        self._plugins: list[tuple[str, object]] = []   # (name, instance)
        self._loaded: list[str] = []
        self._plugin_dir = Path(plugin_dir)

        if autoload:
            self.load_plugins()

    # ─── Registration ─────────────────────────────────────────────────────────

    def register(self, plugin: object, name: str = None) -> None:
        """Manually register a plugin instance."""
        label = name or type(plugin).__name__
        self._plugins.append((label, plugin))
        self._loaded.append(label)
        log.debug("plugin.registered", name=label)

    def load_plugins(self) -> int:
        """
        Auto-load all .py files from plugin_dir that contain classes
        with @hookimpl-decorated methods. Returns count of loaded plugins.

        Files starting with '_' are skipped (private / __init__.py etc.).
        Import errors are caught and logged — one bad plugin won't
        prevent others from loading.
        """
        if not self._plugin_dir.exists():
            return 0

        loaded = 0
        for plugin_file in sorted(self._plugin_dir.glob("*.py")):
            if plugin_file.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    f"pin0ccs_plugin_{plugin_file.stem}", plugin_file
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for class_name, cls in inspect.getmembers(module, inspect.isclass):
                    if self._has_hookimpl(cls):
                        instance = cls()
                        label = f"{plugin_file.stem}.{class_name}"
                        self.register(instance, name=label)
                        log.info("plugin.loaded", plugin=label)
                        loaded += 1

            except Exception as e:
                log.warning("plugin.load_failed",
                            file=str(plugin_file), error=str(e))
        return loaded

    @property
    def loaded_plugins(self) -> list[str]:
        return self._loaded.copy()

    # ─── Hook callers ─────────────────────────────────────────────────────────

    def on_recon_complete(self, recon_result: Any, config: Any) -> None:
        self._broadcast("on_recon_complete",
                        recon_result=recon_result, config=config)

    def on_finding_raw(self, finding: Any) -> Any:
        """
        Return the first non-None result from any plugin, or the original
        finding if no plugin modified it.
        """
        for name, plugin in self._plugins:
            method = getattr(plugin, "on_finding_raw", None)
            if method is None:
                continue
            try:
                result = method(finding=finding)
                if result is not None:
                    return result
            except Exception as e:
                log.warning("plugin.hook_error",
                            plugin=name, hook="on_finding_raw", error=str(e))
        return finding

    def on_finding_confirmed(self, finding: Any, session_id: str) -> None:
        self._broadcast("on_finding_confirmed",
                        finding=finding, session_id=session_id)

    def on_scan_complete(self, session: Any, report_paths: dict) -> None:
        self._broadcast("on_scan_complete",
                        session=session, report_paths=report_paths)

    def extra_payloads(self, vuln_type: str, url: str) -> list[str]:
        """Aggregate payloads from all plugins that implement this hook."""
        payloads: list[str] = []
        for name, plugin in self._plugins:
            method = getattr(plugin, "extra_payloads", None)
            if method is None:
                continue
            try:
                result = method(vuln_type=vuln_type, url=url)
                if isinstance(result, list):
                    payloads.extend(result)
            except Exception as e:
                log.warning("plugin.hook_error",
                            plugin=name, hook="extra_payloads", error=str(e))
        return payloads

    def on_report_generated(self, report_path: str, fmt: str) -> None:
        self._broadcast("on_report_generated",
                        report_path=report_path, fmt=fmt)

    # ─── Internal helpers ─────────────────────────────────────────────────────

    def _broadcast(self, hook: str, **kwargs) -> None:
        """Call hook on every registered plugin that implements it."""
        for name, plugin in self._plugins:
            method = getattr(plugin, hook, None)
            if method is None:
                continue
            try:
                method(**kwargs)
            except Exception as e:
                log.warning("plugin.hook_error",
                            plugin=name, hook=hook, error=str(e))

    @staticmethod
    def _has_hookimpl(cls) -> bool:
        """Return True if the class has any @hookimpl-decorated methods."""
        for attr_name in dir(cls):
            if attr_name.startswith("_"):
                continue
            attr = getattr(cls, attr_name, None)
            if callable(attr) and getattr(attr, "_pin0ccs_hookimpl", False):
                return True
        return False


# ─── Example Plugin Template ─────────────────────────────────────────────────

EXAMPLE_PLUGIN = '''"""
pin0ccsAI Plugin Example — copy this to plugins/my_plugin.py
"""
from plugins import hookimpl


class MyPlugin:
    """Example plugin — Slack notification on confirmed finding."""

    @hookimpl
    def on_finding_confirmed(self, finding, session_id):
        """Called when Debator confirms a real vulnerability."""
        print(f"[PLUGIN] Confirmed: {finding.severity.value} — {finding.title}")

    @hookimpl
    def extra_payloads(self, vuln_type, url):
        """Inject custom payloads for specific vuln types."""
        if vuln_type == "xss":
            return ["<x/onpointerenter=eval(atob(\'YWxlcnQoMSk=\'))>"]
        return []
'''
