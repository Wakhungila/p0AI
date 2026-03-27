"""
pin0ccsAI — Core Data Models
Shared types used across agents, engines, and reporting.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        return {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 5}[self.value]


class VulnType(str, Enum):
    IDOR = "idor"
    BROKEN_ACCESS = "broken_access_control"
    SSRF = "ssrf"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    SQLI = "sql_injection"
    FILE_UPLOAD = "file_upload"
    BUSINESS_LOGIC = "business_logic"
    AUTH_BYPASS = "auth_bypass"
    CACHE_POISON = "web_cache_poisoning"
    GRAPHQL_MISC = "graphql_misconfiguration"
    OPEN_REDIRECT = "open_redirect"
    SSTI = "ssti"
    LFI = "lfi"
    RFI = "rfi"
    RCE = "rce"
    # Web3
    SIGNATURE_REPLAY = "signature_replay"
    CONTRACT_ACCESS = "contract_access_control"
    REENTRANCY = "reentrancy"
    WALLET_AUTH = "wallet_auth_flaw"
    # Generic
    MISCONFIGURATION = "misconfiguration"
    INFORMATION_DISCLOSURE = "information_disclosure"
    OTHER = "other"


@dataclass
class Target:
    """Represents a scope item to be tested."""
    url: str
    domain: str = ""
    is_web3: bool = False
    contract_address: str = ""
    rpc_url: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.domain and self.url:
            from urllib.parse import urlparse
            parsed = urlparse(self.url)
            self.domain = parsed.netloc or self.url


@dataclass
class Endpoint:
    """A discovered endpoint with metadata."""
    url: str
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    tech_stack: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    crown_jewel_score: int = 0
    is_authenticated: bool = False
    notes: str = ""


@dataclass
class Finding:
    """A single vulnerability finding, before and after Debator validation."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    vuln_type: VulnType = VulnType.OTHER
    severity: Severity = Severity.INFO
    url: str = ""
    endpoint: str = ""
    method: str = "GET"
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    steps_to_reproduce: list[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    confidence: float = 0.0          # 0.0 - 1.0, set by Debator
    confirmed: bool = False           # True only after Debator validates
    false_positive: bool = False
    tool: str = ""                    # nuclei / ffuf / manual / ai
    raw_output: str = ""
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    validated_at: Optional[datetime] = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "vuln_type": self.vuln_type.value,
            "severity": self.severity.value,
            "url": self.url,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "steps_to_reproduce": self.steps_to_reproduce,
            "impact": self.impact,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "confidence": self.confidence,
            "confirmed": self.confirmed,
            "false_positive": self.false_positive,
            "tool": self.tool,
            "discovered_at": self.discovered_at.isoformat(),
            "validated_at": self.validated_at.isoformat() if self.validated_at else None,
        }


@dataclass
class ReconResult:
    """Aggregated output of the recon engine for a single target."""
    target: Target
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[str] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    tech_stack: dict[str, list[str]] = field(default_factory=dict)  # host -> techs
    open_ports: dict[str, list[int]] = field(default_factory=dict)  # host -> ports
    graphql_endpoints: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    crown_jewels: list[Endpoint] = field(default_factory=list)
    scanned_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ScanSession:
    """Top-level session tracking an entire scan lifecycle."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: Optional[Target] = None
    recon: Optional[ReconResult] = None
    findings: list[Finding] = field(default_factory=list)
    confirmed_findings: list[Finding] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    status: str = "running"   # running | complete | failed
    notes: str = ""

    @property
    def duration_seconds(self) -> float:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return (datetime.utcnow() - self.started_at).total_seconds()
