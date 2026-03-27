"""
pin0ccsAI — Strategy Agent (mistral:7b)
Analyzes recon output, scores endpoints, and decides what to attack first.
"""
from __future__ import annotations

from typing import Any

from agents.base import BaseAgent
from core.config import Config
from core.database import Database
from core.logger import get_logger
from core.models import Endpoint, ReconResult
from core.ollama_client import OllamaClient

log = get_logger(__name__)

_SYSTEM_PROMPT = """You are an elite offensive security strategist.
Given a list of discovered endpoints, you score each one for attack value.
You prioritize: auth flows, payment systems, admin panels, APIs, file uploads.
You output structured JSON only — never prose."""


class StrategyAgent(BaseAgent):
    name = "strategy"

    def __init__(self, config: Config, db: Database, ollama: OllamaClient):
        super().__init__(config, db, ollama)
        self._patterns = config.strategy.high_value_patterns
        self._threshold = config.strategy.crown_jewel_score_threshold

    @property
    def model(self) -> str:
        return self.config.models.strategy  # mistral:7b

    # ─── Main Entry Point ────────────────────────────────────────────────────

    async def prioritize(self, recon: ReconResult) -> ReconResult:
        """
        Score all endpoints, select crown jewels, return updated ReconResult.
        """
        log.info("strategy.start", endpoints=len(recon.endpoints))

        # Step 1: Rule-based quick scoring
        for ep in recon.endpoints:
            ep.crown_jewel_score = self._rule_based_score(ep)

        # Step 2: AI-assisted scoring for interesting endpoints
        interesting = [ep for ep in recon.endpoints if ep.crown_jewel_score >= 20]
        if interesting:
            ai_scores = await self._ai_score_endpoints(interesting)
            for ep in interesting:
                if ep.url in ai_scores:
                    # Blend rule score + AI score
                    ep.crown_jewel_score = int(
                        (ep.crown_jewel_score + ai_scores[ep.url]) / 2
                    )

        # Step 3: Mark crown jewels
        recon.crown_jewels = [
            ep for ep in recon.endpoints
            if ep.crown_jewel_score >= self._threshold
        ]
        recon.crown_jewels.sort(key=lambda e: e.crown_jewel_score, reverse=True)

        log.info("strategy.crown_jewels", count=len(recon.crown_jewels))
        for cj in recon.crown_jewels[:10]:
            log.info("crown_jewel", url=cj.url, score=cj.crown_jewel_score)

        return recon

    async def plan_attack_sequence(self, recon: ReconResult) -> list[dict[str, Any]]:
        """
        Ask the LLM to produce an ordered attack plan given the recon summary.
        Returns list of {phase, targets, techniques, priority}.
        """
        summary = self._build_recon_summary(recon)

        prompt = f"""Recon summary for target:
{summary}

Based on this, produce an ordered attack plan.
For each phase, specify:
- phase name
- target URLs (subset of the above)
- vulnerability types to test
- reasoning

Output JSON array: [
  {{
    "phase": "string",
    "targets": ["url1", "url2"],
    "vuln_types": ["idor", "ssrf", ...],
    "reasoning": "string",
    "priority": 1
  }},
  ...
]"""
        try:
            plan = await self.think_json(prompt, system=_SYSTEM_PROMPT, temperature=0.2)
            if isinstance(plan, list):
                log.info("strategy.attack_plan", phases=len(plan))
                return plan
        except Exception as e:
            log.warning("strategy.plan_failed", error=str(e))

        # Fallback: deterministic plan
        return self._deterministic_plan(recon)

    # ─── Scoring Logic ───────────────────────────────────────────────────────

    def _rule_based_score(self, endpoint: Endpoint) -> int:
        score = 0
        url_lower = endpoint.url.lower()

        # Pattern matching
        pattern_scores = {
            "/admin": 90, "/panel": 85, "/dashboard": 80,
            "/api/": 70, "/v1/": 65, "/v2/": 65, "/v3/": 65,
            "/graphql": 80, "/graphiql": 85,
            "/checkout": 90, "/payment": 95, "/billing": 90,
            "/auth": 85, "/login": 75, "/register": 65,
            "/reset": 80, "/forgot": 75,
            "/upload": 85, "/file": 70, "/attach": 70,
            "/internal": 90, "/debug": 85, "/_debug": 85,
            "/actuator": 90, "/health": 40, "/metrics": 50,
            "/swagger": 70, "/openapi": 70, "/docs": 50,
            "/.git": 95, "/.env": 95, "/config": 85,
            "/user": 60, "/account": 65, "/profile": 60,
            "/order": 75, "/cart": 70, "/invoice": 80,
            "/webhook": 70, "/callback": 65,
            "/rpc": 75, "/soap": 65, "/wsdl": 65,
        }

        for pattern, pts in pattern_scores.items():
            if pattern in url_lower:
                score = max(score, pts)

        # HTTP method bonuses
        if endpoint.method in ("POST", "PUT", "PATCH", "DELETE"):
            score += 10

        # Auth indicators
        if endpoint.is_authenticated:
            score += 15

        # Tech stack bonuses
        for tech in endpoint.tech_stack:
            t = tech.lower()
            if "graphql" in t:
                score += 20
            if "wordpress" in t:
                score += 15

        # Status code: 401/403 means there's something gated worth poking
        if endpoint.status_code in (401, 403):
            score += 20
        elif endpoint.status_code == 200:
            score += 5

        return min(score, 100)

    async def _ai_score_endpoints(self, endpoints: list[Endpoint]) -> dict[str, int]:
        """Use LLM to score a batch of interesting endpoints."""
        endpoint_list = "\n".join(
            f"- {ep.url} [status:{ep.status_code}] [method:{ep.method}]"
            for ep in endpoints[:30]  # Cap at 30 to manage token count
        )

        prompt = f"""Score each endpoint for bug bounty attack value (0-100).
Higher = more likely to contain critical/high severity vulnerabilities.

Endpoints:
{endpoint_list}

Output JSON object: {{"url": score, ...}}
Example: {{"/api/v1/user/id": 85, "/static/logo.png": 5}}"""

        try:
            scores = await self.think_json(prompt, system=_SYSTEM_PROMPT)
            if isinstance(scores, dict):
                return {url: int(s) for url, s in scores.items() if isinstance(s, (int, float))}
        except Exception as e:
            log.warning("strategy.ai_score_failed", error=str(e))

        return {}

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _build_recon_summary(self, recon: ReconResult) -> str:
        lines = [f"Target: {recon.target.url}"]
        lines.append(f"Live hosts: {len(recon.live_hosts)}")
        if recon.tech_stack:
            all_techs = set()
            for techs in recon.tech_stack.values():
                all_techs.update(techs)
            lines.append(f"Tech stack: {', '.join(all_techs)}")
        if recon.graphql_endpoints:
            lines.append(f"GraphQL endpoints: {', '.join(recon.graphql_endpoints)}")
        if recon.api_endpoints:
            lines.append(f"API endpoints ({len(recon.api_endpoints)}): " +
                         ", ".join(recon.api_endpoints[:10]))
        if recon.crown_jewels:
            lines.append("Crown jewels:")
            for cj in recon.crown_jewels[:15]:
                lines.append(f"  [{cj.crown_jewel_score}] {cj.url}")
        return "\n".join(lines)

    def _deterministic_plan(self, recon: ReconResult) -> list[dict[str, Any]]:
        plan = []
        if recon.graphql_endpoints:
            plan.append({
                "phase": "GraphQL exploration",
                "targets": recon.graphql_endpoints,
                "vuln_types": ["graphql_misconfiguration", "idor", "broken_access_control"],
                "reasoning": "GraphQL often exposes introspection and authorization flaws",
                "priority": 1,
            })
        auth_targets = [cj.url for cj in recon.crown_jewels if
                        any(x in cj.url.lower() for x in ["/auth", "/login", "/reset", "/admin"])]
        if auth_targets:
            plan.append({
                "phase": "Authentication testing",
                "targets": auth_targets[:10],
                "vuln_types": ["auth_bypass", "broken_access_control", "idor"],
                "reasoning": "Auth endpoints are highest-priority for critical findings",
                "priority": 2,
            })
        api_targets = [cj.url for cj in recon.crown_jewels if "/api/" in cj.url.lower()]
        if api_targets:
            plan.append({
                "phase": "API fuzzing",
                "targets": api_targets[:10],
                "vuln_types": ["idor", "ssrf", "sql_injection", "broken_access_control"],
                "reasoning": "APIs frequently contain IDOR and access control issues",
                "priority": 3,
            })
        plan.append({
            "phase": "Broad vulnerability scan",
            "targets": [cj.url for cj in recon.crown_jewels[:20]],
            "vuln_types": ["xss_reflected", "xss_stored", "open_redirect",
                           "information_disclosure"],
            "reasoning": "Nuclei sweep of all high-value endpoints",
            "priority": 4,
        })
        return plan
