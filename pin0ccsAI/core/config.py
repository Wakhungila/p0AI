"""
pin0ccsAI — Configuration System
Loads, validates, and provides typed access to config/config.yaml
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dataclasses import dataclass, field


_DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "config.yaml"


@dataclass
class OllamaConfig:
    base_url: str = "http://localhost:11434"
    timeout: int = 120


@dataclass
class ModelsConfig:
    tester: str = "qwen2.5-coder:7b"
    debator: str = "llama3.1:8b"
    strategy: str = "mistral:7b"
    knowledge: str = "mixtral:8x7b"


@dataclass
class ToolsConfig:
    subfinder: str = "subfinder"
    assetfinder: str = "assetfinder"
    httpx: str = "httpx"
    nuclei: str = "nuclei"
    ffuf: str = "ffuf"
    gobuster: str = "gobuster"
    nmap: str = "nmap"
    whatweb: str = "whatweb"


@dataclass
class ReconConfig:
    threads: int = 50
    timeout: int = 10
    resolve_dns: bool = True
    screenshot: bool = False
    tech_detect: bool = True
    wordlists: dict = field(default_factory=dict)


@dataclass
class VulnConfig:
    nuclei_templates: str = "~/.local/nuclei-templates"
    nuclei_severity: list = field(default_factory=lambda: ["critical", "high", "medium"])
    ffuf_rate: int = 100
    ffuf_timeout: int = 10
    max_payload_mutations: int = 25
    confidence_threshold: float = 0.75


@dataclass
class StrategyConfig:
    high_value_patterns: list = field(default_factory=list)
    crown_jewel_score_threshold: int = 60


@dataclass
class Web3Config:
    rpc_timeout: int = 30
    max_functions_to_test: int = 50
    check_signature_replay: bool = True
    check_access_control: bool = True
    check_reentrancy: bool = True


@dataclass
class KnowledgeConfig:
    db_path: str = "./data/kb/knowledge.db"
    sources: list = field(default_factory=list)
    update_interval_hours: int = 24
    max_entries: int = 10000


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "json"
    log_to_file: bool = True
    max_bytes: int = 10485760
    backup_count: int = 5


@dataclass
class Config:
    """Root configuration object. Access via Config.load()"""
    project: dict = field(default_factory=dict)
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    models: ModelsConfig = field(default_factory=ModelsConfig)
    tools: ToolsConfig = field(default_factory=ToolsConfig)
    recon: ReconConfig = field(default_factory=ReconConfig)
    vuln: VulnConfig = field(default_factory=VulnConfig)
    strategy: StrategyConfig = field(default_factory=StrategyConfig)
    web3: Web3Config = field(default_factory=Web3Config)
    knowledge: KnowledgeConfig = field(default_factory=KnowledgeConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    plugins: dict = field(default_factory=dict)
    reporting: dict = field(default_factory=dict)

    _raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        config_path = Path(path) if path else _DEFAULT_CONFIG_PATH
        if not config_path.exists():
            raise FileNotFoundError(f"Config not found: {config_path}")

        with open(config_path) as f:
            raw = yaml.safe_load(f)

        # Allow env variable overrides: PIN0_OLLAMA_URL etc.
        raw = _apply_env_overrides(raw)

        cfg = cls(_raw=raw)
        cfg.project = raw.get("project", {})
        cfg.plugins = raw.get("plugins", {})
        cfg.reporting = raw.get("reporting", {})

        cfg.ollama = _from_dict(OllamaConfig, raw.get("ollama", {}))
        cfg.models = _from_dict(ModelsConfig, raw.get("models", {}))
        cfg.tools = _from_dict(ToolsConfig, raw.get("tools", {}))
        cfg.recon = _from_dict(ReconConfig, raw.get("recon", {}))
        cfg.vuln = _from_dict(VulnConfig, raw.get("vuln", {}))
        cfg.strategy = _from_dict(StrategyConfig, raw.get("strategy", {}))
        cfg.web3 = _from_dict(Web3Config, raw.get("web3", {}))
        cfg.knowledge = _from_dict(KnowledgeConfig, raw.get("knowledge", {}))
        cfg.logging = _from_dict(LoggingConfig, raw.get("logging", {}))

        _ensure_dirs(cfg)
        return cfg

    def get(self, dotpath: str, default: Any = None) -> Any:
        """Dotted path access: cfg.get('recon.threads')"""
        keys = dotpath.split(".")
        node = self._raw
        for k in keys:
            if not isinstance(node, dict):
                return default
            node = node.get(k, default)
        return node


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _from_dict(cls, data: dict):
    """Populate a dataclass from a dict, ignoring unknown keys."""
    import dataclasses
    known = {f.name for f in dataclasses.fields(cls)}
    filtered = {k: v for k, v in data.items() if k in known}
    return cls(**filtered)


def _apply_env_overrides(raw: dict) -> dict:
    overrides = {
        "PIN0_OLLAMA_URL": ("ollama", "base_url"),
        "PIN0_LOG_LEVEL": ("logging", "level"),
        "PIN0_MODEL_TESTER": ("models", "tester"),
        "PIN0_MODEL_DEBATOR": ("models", "debator"),
    }
    for env_key, (section, field) in overrides.items():
        val = os.environ.get(env_key)
        if val:
            raw.setdefault(section, {})[field] = val
    return raw


def _ensure_dirs(cfg: Config) -> None:
    dirs = [
        cfg.project.get("data_dir", "./data"),
        cfg.project.get("log_dir", "./logs"),
        cfg.project.get("report_dir", "./reports"),
        str(Path(cfg.knowledge.db_path).parent),
    ]
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)
