"""
pin0ccsAI — Debator Agent (llama3.1:8b)
Critical thinker. Independently reproduces vulnerabilities.
Challenges assumptions and eliminates false positives.
Mode 2: Validation — llama3.1:8b
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Optional

import httpx

from agents.base import BaseAgent
from core.config import Config
from core.database import Database
from core.models import Finding, Severity
from core.ollama_client import OllamaClient

_SYSTEM_PROMPT = """You are a skeptical senior security researcher.
Your job is to DISPROVE vulnerabilities, not confirm them.
You challenge every assumption. You only confirm a finding if the evidence is irrefutable.
You think about false positive causes: WAF, caching, coincidental reflection, benign SQL messages.
Output JSON only when asked for structured data."""

_VALIDATION_PROMPT = """Analyze this security finding and determine if it is a TRUE POSITIVE or FALSE POSITIVE.

Finding:
- Title: {title}
- Type: {vuln_type}
- URL: {url}
- Parameter: {parameter}
- Payload: {payload}
- Evidence: {evidence}
- HTTP Status: {status}
- Steps: {steps}

Think through:
1. Is this evidence conclusive? Could it be a coincidence?
2. Common false positive causes for this vuln type?
3. Does the evidence actually demonstrate exploitability?

Output JSON:
{{
  "verdict": "true_positive" | "false_positive" | "needs_more_testing",
  "confidence": 0.0-1.0,
  "reasoning": "detailed explanation",
  "suggested_validation_steps": ["step1", "step2"],
  "adjusted_severity": "critical|high|medium|low|info"
}}"""


class DebatorAgent(BaseAgent):
    name = "debator"

    def __init__(self, config: Config, db: Database, ollama: OllamaClient):
        super().__init__(config, db, ollama)
        self._threshold = config.vuln.confidence_threshold

    @property
    def model(self) -> str:
        return self.config.models.debator  # llama3.1:8b

    # ─── Main Entry Point ────────────────────────────────────────────────────

    async def validate_findings(
        self, findings: list[Finding], session_id: str
    ) -> tuple[list[Finding], list[Finding]]:
        """
        Validate a list of findings.
        Returns (confirmed_findings, false_positives).
        """
        self.log.info("debator.start", total_findings=len(findings))

        confirmed = []
        false_positives = []

        # Process in batches to avoid overwhelming the LLM
        sem = asyncio.Semaphore(3)

        async def validate_one(finding: Finding):
            async with sem:
                return await self._validate_single(finding, session_id)

        results = await asyncio.gather(
            *[validate_one(f) for f in findings],
            return_exceptions=True,
        )

        for finding, result in zip(findings, results):
            if isinstance(result, Exception):
                self.log.warning("debator.validation_error",
                                 finding_id=finding.id, error=str(result))
                # On error, keep finding but mark as unvalidated
                finding.confidence = 0.5
                confirmed.append(finding)
                continue

            validated_finding = result
            if validated_finding.confirmed:
                confirmed.append(validated_finding)
            else:
                false_positives.append(validated_finding)

        self.log.info("debator.complete",
                      confirmed=len(confirmed),
                      false_positives=len(false_positives))
        return confirmed, false_positives

    # ─── Single Finding Validation ────────────────────────────────────────────

    async def _validate_single(self, finding: Finding, session_id: str) -> Finding:
        self.log.debug("debator.validating", finding_id=finding.id,
                       title=finding.title, vuln_type=finding.vuln_type.value)

        # Step 1: Independent reproduction
        reproduced, repro_evidence = await self._reproduce_finding(finding)

        # Step 2: LLM critical analysis
        verdict = await self._llm_analyze(finding, reproduced, repro_evidence)

        # Step 3: Update finding based on verdict
        finding.validated_at = datetime.utcnow()

        v = verdict.get("verdict", "needs_more_testing")
        confidence = float(verdict.get("confidence", 0.5))
        reasoning = verdict.get("reasoning", "")

        # Upgrade confidence if we reproduced it
        if reproduced:
            confidence = min(1.0, confidence + 0.15)

        # Update severity if LLM suggests adjustment
        adjusted_sev = verdict.get("adjusted_severity", "")
        if adjusted_sev:
            sev_map = {
                "critical": Severity.CRITICAL, "high": Severity.HIGH,
                "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
            }
            if adjusted_sev in sev_map:
                finding.severity = sev_map[adjusted_sev]

        finding.confidence = confidence

        if v == "true_positive" and confidence >= self._threshold:
            finding.confirmed = True
            finding.false_positive = False
            finding.extra["debator_reasoning"] = reasoning
            self.log.info("debator.confirmed",
                          finding_id=finding.id,
                          confidence=confidence,
                          severity=finding.severity.value)
        elif v == "false_positive" or confidence < (self._threshold - 0.2):
            finding.confirmed = False
            finding.false_positive = True
            finding.extra["debator_reasoning"] = reasoning
            self.log.info("debator.rejected",
                          finding_id=finding.id,
                          reason=reasoning[:100])
        else:
            # Needs more testing — keep but mark as unconfirmed
            finding.confirmed = False
            finding.false_positive = False
            finding.extra["debator_reasoning"] = f"Inconclusive: {reasoning}"

        # Save to DB
        self.db.save_finding(finding, session_id)
        return finding

    # ─── Independent Reproduction ─────────────────────────────────────────────

    async def _reproduce_finding(self, finding: Finding) -> tuple[bool, str]:
        """
        Attempt to independently reproduce the finding by replaying the request.
        Returns (reproduced: bool, evidence: str)
        """
        url = finding.endpoint or finding.url
        if not url or not finding.payload:
            return False, ""

        try:
            async with httpx.AsyncClient(
                timeout=15, verify=False, follow_redirects=True
            ) as client:
                # Replay with the same payload
                if finding.parameter:
                    from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    qs[finding.parameter] = [finding.payload]
                    new_query = urlencode(qs, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                else:
                    test_url = url

                resp = await client.get(test_url)
                evidence = resp.text[:500]

                # Check if the original evidence pattern still holds
                if finding.evidence and len(finding.evidence) > 20:
                    # Key fragment from original evidence
                    key_fragment = finding.evidence[:50].strip()
                    if key_fragment.lower() in evidence.lower():
                        return True, evidence

                # Check vuln-specific reproduction conditions
                return self._check_reproduction(finding, resp, evidence)

        except Exception as e:
            self.log.debug("debator.reproduce_failed", error=str(e))
            return False, ""

    def _check_reproduction(
        self, finding: Finding, resp: httpx.Response, body: str
    ) -> tuple[bool, str]:
        vuln_type = finding.vuln_type.value

        if "xss" in vuln_type:
            if finding.payload in body:
                return True, body[:300]
        elif "sqli" in vuln_type:
            sql_errors = ["sql syntax", "mysql_fetch", "ora-01", "sqlite_"]
            if any(err in body.lower() for err in sql_errors):
                return True, body[:300]
        elif "ssti" in vuln_type:
            if "49" in body:
                return True, body[:300]
        elif "ssrf" in vuln_type:
            if resp.status_code == 200 and len(body) > 100:
                return True, body[:300]
        elif "idor" in vuln_type:
            if resp.status_code == 200 and len(body) > 100:
                return True, body[:300]

        return False, body[:300]

    # ─── LLM Critical Analysis ────────────────────────────────────────────────

    async def _llm_analyze(
        self, finding: Finding, reproduced: bool, repro_evidence: str
    ) -> dict:
        evidence = finding.evidence
        if reproduced and repro_evidence:
            evidence = f"[ORIGINAL]: {finding.evidence}\n[REPRODUCED]: {repro_evidence}"

        prompt = _VALIDATION_PROMPT.format(
            title=finding.title,
            vuln_type=finding.vuln_type.value,
            url=finding.url,
            parameter=finding.parameter,
            payload=finding.payload,
            evidence=evidence[:600] if evidence else "None provided",
            status="reproduced=True" if reproduced else "reproduced=False",
            steps="\n".join(finding.steps_to_reproduce),
        )

        if reproduced:
            prompt += "\n\nNOTE: This finding was independently reproduced — weight this heavily."

        try:
            result = await self.think_json(prompt, system=_SYSTEM_PROMPT, temperature=0.2)
            if isinstance(result, dict):
                return result
        except Exception as e:
            self.log.warning("debator.llm_failed", error=str(e))

        # Fallback: use reproduction result alone
        return {
            "verdict": "true_positive" if reproduced else "needs_more_testing",
            "confidence": 0.65 if reproduced else 0.4,
            "reasoning": "LLM analysis unavailable. Based on reproduction result only.",
            "adjusted_severity": finding.severity.value,
        }

    # ─── CVSS Scoring ─────────────────────────────────────────────────────────

    async def assign_cvss(self, finding: Finding) -> Finding:
        """Use LLM to assign a CVSS 3.1 score to a confirmed finding."""
        prompt = f"""Assign a CVSS 3.1 score to this vulnerability:

Title: {finding.title}
Type: {finding.vuln_type.value}
URL: {finding.url}
Impact: {finding.impact}
Evidence: {finding.evidence[:300]}

Output JSON:
{{
  "cvss_score": 0.0-10.0,
  "cvss_vector": "CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...",
  "reasoning": "brief explanation"
}}"""

        try:
            result = await self.think_json(prompt, system=_SYSTEM_PROMPT)
            if isinstance(result, dict):
                finding.cvss_score = float(result.get("cvss_score", 0.0))
                finding.cvss_vector = result.get("cvss_vector", "")
        except Exception as e:
            self.log.debug("debator.cvss_failed", error=str(e))

        return finding
