"""
pin0ccsAI — Scan Orchestrator  [v0.4 — model lifecycle optimised]

Model swap contract (≤ 2 swaps per scan):

  Phase 0  Health check    → NO LLM
  Phase 1  Recon           → NO LLM
  Phase 2  Strategy        → mistral:7b      [LOAD #1]
  ──────── SWAP 1 ─────────────────────────────────────────── ~8-15s
  Phase 3  Tester          → qwen2.5-coder:7b [LOAD #2]
  Phase 3b Stored XSS      → NO LLM  ← begin_preload(llama3.1) here
  Phase 4  Web3            → NO LLM  ← finish_preload() here
  ──────── SWAP 2 ─────────────────────────────────────────── ~1-3s (hot)
  Phase 5  Debator         → llama3.1:8b     [LOAD #3 — prewarmed]
  Phase 6  Learning Loop   → NO LLM
  Phase 7  Report          → NO LLM
  ──────── deactivate current model ─────────────────────────────────

The background preload of llama3.1 during Stored XSS + Web3 means
Swap 2 completes in 1-3s instead of 10-45s because the model is
already resident in RAM by the time Debator needs it.

New in v0.4:
  - ModelLifecycleManager: explicit model load/unload with timing
  - begin_preload() during HTTP-only phases (no-LLM overlap)
  - model_lifecycle.summary logged at scan end
  - max 2 swaps enforced with budget warning on violation
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Optional

from agents.debator import DebatorAgent
from agents.knowledge import KnowledgeAgent
from agents.strategy import StrategyAgent
from agents.tester import TesterAgent
from core.auth_session import AuthSession
from core.checkpoint import (
    CheckpointManager,
    PHASE_RECON, PHASE_STRATEGY, PHASE_TESTER,
    PHASE_WEB3, PHASE_DEBATOR, PHASE_REPORT,
)
from core.config import Config
from core.database import Database
from core.exploit_memory import ExploitMemory
from core.learning_loop import LearningLoop
from core.llm_budget import LLMBudget
from core.logger import bind_scan_context, clear_scan_context, get_logger
from core.model_lifecycle import ModelLifecycleManager
from core.models import Finding, ReconResult, ScanSession, Target
from core.ollama_client import OllamaClient
from core.payload_cache import PayloadCache
from engines.recon import ReconEngine
from engines.stored_xss import StoredXSSEngine
from plugins import PluginManager
from reports.generator import ReportGenerator

log = get_logger(__name__)


class ScanOrchestrator:
    def __init__(self, config: Config):
        self.config = config
        self.db = Database(config.knowledge.db_path)
        self.cache = PayloadCache(
            db_path=config.knowledge.db_path,
            ttl_hours=config.get("performance.cache_ttl_hours", 72),
        )
        self.exploit_memory = ExploitMemory(
            db_path=config.knowledge.db_path,
            min_success_rate=config.get("performance.memory_min_success_rate", 0.10),
            max_results=config.get("performance.memory_max_results", 20),
        )
        self.plugin_mgr = PluginManager(
            plugin_dir=config.plugins.get("plugin_dir", "./plugins"),
            autoload=config.plugins.get("autoload", True),
        )
        self.report_gen = ReportGenerator(
            config.project.get("report_dir", "./reports")
        )

    async def run(
        self,
        target: Target,
        skip_recon: bool = False,
        phases: Optional[list[str]] = None,
        web3_contract: Optional[str] = None,
        web3_rpc: Optional[str] = None,
        auth: Optional[AuthSession] = None,
        resume: bool = False,
    ) -> ScanSession:
        """
        Full scan pipeline with optimised model lifecycle.

        Model swap schedule (maximum 2 swaps):

          Window A  Recon (subprocesses, no LLM, 20-120 s)
                    → preload mistral:7b in background

          Swap 1    Strategy starts — mistral already warm
                    (Strategy finishes) → begin sequential transition:
                    unload mistral, then preload qwen2.5-coder

          (No swap) Tester starts — qwen2.5 already warm
                    (Tester + StoredXSS + Web3 finish) → transition to llama3.1

          Swap 2    Debator starts — llama3.1 already warm

        auth   — optional AuthSession injected into all HTTP requests
        resume — skip completed phases using SQLite checkpoints
        """
        if resume:
            session = self._find_resumable_session(target) or ScanSession(target=target)
        else:
            session = ScanSession(target=target)

        self.db.create_session(session)
        bind_scan_context(target=target.url, scan_id=session.id)

        ckpt = CheckpointManager(self.config.knowledge.db_path, session.id)
        budget = LLMBudget(
            ceilings={
                "tester_mutation":  self.config.get("performance.max_mutation_calls", 8),
                "tester_business":  self.config.get("performance.max_business_calls", 1),
                "strategy_score":   1,
                "strategy_plan":    1,
                "debator_validate": 9999,
                "debator_cvss":     self.config.get("performance.max_cvss_calls", 10),
            }
        )

        if resume and ckpt.completed_phases():
            log.info("scan.resuming",
                     session_id=session.id,
                     completed=ckpt.completed_phases(),
                     resume_from=ckpt.resume_from_phase())
        else:
            log.info("scan.start", target=target.url, session_id=session.id)

        try:
            async with OllamaClient(
                base_url=self.config.ollama.base_url,
                timeout=self.config.ollama.timeout,
            ) as ollama:

                health = await ollama.health_check()
                if health["status"] != "ok":
                    raise RuntimeError(
                        f"Ollama unreachable at {self.config.ollama.base_url}. "
                        "Run: ollama serve"
                    )
                log.info("ollama.ready", models=health.get("models", []))

                if auth and auth.is_authenticated:
                    log.info("scan.authenticated",
                             label=auth.label,
                             cookies=list(auth.cookies.keys()),
                             headers=list(auth.headers.keys()))

                # ── Model lifecycle manager ───────────────────────────────
                # Single instance for the whole scan. All model transitions
                # are coordinated here — the pipeline never calls preload
                # or unload directly.
                overlap_ok = self.config.get("performance.model_overlap_ok", False)
                lifecycle = ModelLifecycleManager(
                    ollama=ollama,
                    model_strategy=self.config.models.strategy,
                    model_tester=self.config.models.tester,
                    model_debator=self.config.models.debator,
                    max_swaps=2,
                    overlap_ok=overlap_ok,
                )

                # ── Phase 1: Recon — NO LLM ──────────────────────────────
                # Fire mistral preload immediately so it loads during
                # the 20-120 s of subprocess calls in recon.
                if not ckpt.is_done(PHASE_RECON):
                    lifecycle.start_preload(self.config.models.strategy)

                if ckpt.is_done(PHASE_RECON):
                    log.info("phase.recon.restored")
                    recon = ckpt.load_recon(target)
                else:
                    log.info("phase.recon")
                    recon = await self._run_recon(target, skip_recon)
                    session.recon = recon
                    ckpt.save_recon(recon)
                    self.plugin_mgr.on_recon_complete(
                        recon_result=recon, config=self.config
                    )
                    log.info("phase.recon.done",
                             subdomains=len(recon.subdomains),
                             live_hosts=len(recon.live_hosts),
                             endpoints=len(recon.endpoints))
                session.recon = recon

                # ── Phase 2: Strategy — mistral:7b ───────────────────────
                # SWAP 1: await mistral (should already be warm from recon window)
                if not ckpt.is_done(PHASE_STRATEGY):
                    wait = await lifecycle.wait_for_model(self.config.models.strategy)
                    if wait > 1.0:
                        log.warning("model_lifecycle.strategy_wait_nonzero",
                                    wait_s=round(wait, 2),
                                    hint="Recon was too short to fully load mistral. "
                                         "Consider --skip-recon on fast targets.")

                if ckpt.is_done(PHASE_STRATEGY):
                    log.info("phase.strategy.restored")
                    attack_plan = ckpt.load_attack_plan()
                else:
                    log.info("phase.strategy", model=self.config.models.strategy)
                    strategy = StrategyAgent(self.config, self.db, ollama)
                    recon, attack_plan = await self._run_strategy(
                        strategy, recon, budget
                    )
                    ckpt.save_attack_plan(attack_plan)
                    del strategy

                    # Strategy done — begin transition to qwen2.5-coder.
                    # On 8GB: unload mistral first, then preload qwen2.5 (sequential).
                    # This fires in the background; the Tester awaits the result
                    # via wait_for_model before its first LLM call.
                    log.info("model_lifecycle.begin_strategy_to_tester_transition")
                    await lifecycle.transition(
                        from_model=self.config.models.strategy,
                        to_model=self.config.models.tester,
                    )

                log.info("phase.strategy.done",
                         crown_jewels=len(recon.crown_jewels),
                         phases=len(attack_plan))

                # ── Phase 3: Tester — qwen2.5-coder:7b ──────────────────
                # SWAP 2 (internal): await qwen2.5 (loading since end of Strategy)
                if not ckpt.is_done(PHASE_TESTER):
                    wait = await lifecycle.wait_for_model(self.config.models.tester)
                    if wait > 1.0:
                        log.warning("model_lifecycle.tester_wait_nonzero",
                                    wait_s=round(wait, 2))

                if ckpt.is_done(PHASE_TESTER):
                    log.info("phase.tester.restored")
                    raw_dicts = ckpt.load_raw_findings() or []
                    all_raw_findings = self._dicts_to_findings(raw_dicts)
                else:
                    log.info("phase.tester", model=self.config.models.tester)
                    tester = TesterAgent(
                        self.config, self.db, ollama,
                        budget=budget, cache=self.cache,
                        auth=auth,
                        exploit_memory=self.exploit_memory,
                    )
                    all_raw_findings = await self._run_tester(
                        tester, attack_plan, recon, session.id, phases
                    )
                    session.findings = all_raw_findings
                    del tester

                    # Phase 3b: Stored XSS — NO LLM
                    # We have free CPU time here while waiting for nothing.
                    # Begin transitioning to llama3.1 NOW so it loads during
                    # the HTTP-bound Stored XSS + Web3 phases.
                    log.info("model_lifecycle.begin_tester_to_debator_transition")
                    await lifecycle.transition(
                        from_model=self.config.models.tester,
                        to_model=self.config.models.debator,
                    )

                    log.info("phase.stored_xss")
                    stored_engine = StoredXSSEngine(
                        auth_session=auth,
                        timeout=self.config.vuln.ffuf_timeout,
                        max_endpoints=10,
                        max_retrieve_pages=5,
                    )
                    stored_findings = await stored_engine.run(recon, session.id)
                    all_raw_findings.extend(stored_findings)
                    log.info("phase.stored_xss.done",
                             new_findings=len(stored_findings))

                    ckpt.save_raw_findings(all_raw_findings)

                session.findings = all_raw_findings
                log.info("phase.tester.done",
                         raw_findings=len(all_raw_findings),
                         llm_calls=budget.total_calls(),
                         cache_hits=budget.total_cache_hits())

                # ── Phase 4: Web3 — NO LLM ───────────────────────────────
                # llama3.1 continues loading in the background during this.
                if (target.is_web3 or web3_contract) and not ckpt.is_done(PHASE_WEB3):
                    log.info("phase.web3")
                    web3_findings = await self._run_web3(
                        target, web3_contract, web3_rpc
                    )
                    all_raw_findings.extend(web3_findings)
                    session.findings = all_raw_findings
                    log.info("phase.web3.done", findings=len(web3_findings))

                # Plugin hook — all findings accumulated, none validated yet
                processed = [
                    self.plugin_mgr.on_finding_raw(f)
                    for f in all_raw_findings
                ]

                # ── Phase 5: Debator — llama3.1:8b ──────────────────────
                # SWAP 3 (final): await llama3.1 — should be warm from
                # the Stored XSS + Web3 window. If those phases were very
                # short, we block here for the remainder of the load.
                if not ckpt.is_done(PHASE_DEBATOR):
                    wait = await lifecycle.wait_for_model(self.config.models.debator)
                    if wait > 1.0:
                        log.warning("model_lifecycle.debator_wait_nonzero",
                                    wait_s=round(wait, 2),
                                    hint="Stored XSS + Web3 phases were too short "
                                         "to fully load llama3.1. Consider adding "
                                         "more target URLs to extend these phases.")

                if ckpt.is_done(PHASE_DEBATOR):
                    log.info("phase.debator.restored")
                    confirmed = [
                        f for f in processed if f.confirmed and not f.false_positive
                    ]
                else:
                    log.info("phase.debator",
                             total=len(processed),
                             model=self.config.models.debator)
                    debator = DebatorAgent(self.config, self.db, ollama)
                    debator._budget = budget
                    confirmed, false_positives = await debator.validate_findings(
                        processed, session.id
                    )
                    confirmed = await self._run_cvss(debator, confirmed, budget)
                    ckpt.save(PHASE_DEBATOR, {"confirmed_count": len(confirmed)})
                    del debator

                session.confirmed_findings = confirmed
                for f in confirmed:
                    self.plugin_mgr.on_finding_confirmed(
                        finding=f, session_id=session.id
                    )
                log.info("phase.debator.done", confirmed=len(confirmed))

                # ── Phase 6: Learning Loop — NO LLM ─────────────────────
                if confirmed:
                    log.info("phase.learning_loop")
                    loop = LearningLoop(self.db, self.cache, self.exploit_memory)
                    loop_stats = loop.ingest_findings(
                        confirmed, session.id, target.url
                    )
                    log.info("phase.learning_loop.done", **loop_stats)

                # ── Phase 7: Report — NO LLM ─────────────────────────────
                log.info("phase.report")
                session.completed_at = datetime.utcnow()
                session.status = "complete"
                self.db.update_session_status(
                    session.id, "complete", session.completed_at
                )
                formats = self.config.reporting.get(
                    "formats", ["markdown", "html", "json"]
                )
                report_paths = self.report_gen.generate(session, formats=formats)
                ckpt.save(PHASE_REPORT, {"paths": report_paths})

                for fmt, path in report_paths.items():
                    self.plugin_mgr.on_report_generated(report_path=path, fmt=fmt)
                self.plugin_mgr.on_scan_complete(
                    session=session, report_paths=report_paths
                )

                ckpt.clear()

                # Log full lifecycle summary alongside existing budget summary
                lifecycle.log_summary()
                budget.log_summary()

                log.info("scan.complete",
                         session_id=session.id,
                         confirmed=len(confirmed),
                         model_swaps=lifecycle.summary()["swap_count"],
                         llm_calls_total=budget.total_calls(),
                         cache_hits_total=budget.total_cache_hits(),
                         reports=report_paths)

                return session

        except Exception as e:
            log.error("scan.failed", error=str(e), session_id=session.id)
            session.status = "failed"
            session.completed_at = datetime.utcnow()
            self.db.update_session_status(
                session.id, "failed", session.completed_at
            )
            log.info("scan.resumable",
                     session_id=session.id,
                     completed_phases=ckpt.completed_phases(),
                     hint="Resume with: python cli.py scan <url> --resume")
            raise
        finally:
            clear_scan_context()

    # ─── Phase Helpers ────────────────────────────────────────────────────────

    async def _run_recon(self, target: Target, skip_recon: bool) -> ReconResult:
        if skip_recon:
            recon = ReconResult(target=target)
            recon.live_hosts = [target.url]
            log.info("phase.recon.skipped")
            return recon
        engine = ReconEngine(self.config)
        recon = await engine.run(target)
        log.info("phase.recon.done",
                 subdomains=len(recon.subdomains),
                 live_hosts=len(recon.live_hosts),
                 endpoints=len(recon.endpoints),
                 open_ports_hosts=len(recon.open_ports))
        return recon

    async def _run_strategy(
        self, strategy: StrategyAgent, recon: ReconResult, budget: LLMBudget
    ) -> tuple[ReconResult, list[dict]]:
        if budget.charge("strategy_score"):
            recon = await strategy.prioritize(recon)
        else:
            for ep in recon.endpoints:
                ep.crown_jewel_score = strategy._rule_based_score(ep)
            recon.crown_jewels = sorted(
                [ep for ep in recon.endpoints
                 if ep.crown_jewel_score >= strategy._threshold],
                key=lambda e: e.crown_jewel_score, reverse=True,
            )

        if budget.charge("strategy_plan"):
            attack_plan = await strategy.plan_attack_sequence(recon)
        else:
            attack_plan = strategy._deterministic_plan(recon)

        return recon, attack_plan

    async def _run_tester(
        self,
        tester: TesterAgent,
        attack_plan: list[dict],
        recon: ReconResult,
        session_id: str,
        phase_filter: Optional[list[str]],
    ) -> list[Finding]:
        all_findings: list[Finding] = []
        for phase in attack_plan:
            phase_name = phase.get("phase", "unnamed")
            if phase_filter and not any(
                p.lower() in phase_name.lower() for p in phase_filter
            ):
                log.debug("tester.phase_skipped", phase=phase_name)
                continue
            log.info("tester.running_phase", phase=phase_name)
            raw = await tester.run_attack_phase(phase, recon, session_id)
            all_findings.extend(raw)
        return all_findings

    async def _run_web3(
        self,
        target: Target,
        web3_contract: Optional[str],
        web3_rpc: Optional[str],
    ) -> list[Finding]:
        from modules.web3.analyzer import Web3Module
        web3 = Web3Module(self.config)
        findings: list[Finding] = []
        contract = web3_contract or target.contract_address
        rpc = web3_rpc or target.rpc_url
        if contract and rpc:
            findings.extend(await web3.analyze_contract(contract, rpc))
        findings.extend(await web3.check_wallet_auth(target.url))
        return findings

    async def _run_cvss(
        self,
        debator: DebatorAgent,
        confirmed: list[Finding],
        budget: LLMBudget,
    ) -> list[Finding]:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_confirmed = sorted(
            confirmed, key=lambda f: severity_order.get(f.severity.value, 5)
        )
        results: list[Finding] = []
        cap = budget._ceilings.get("debator_cvss", 10)
        for f in sorted_confirmed:
            if budget.charge("debator_cvss"):
                scored = await debator.assign_cvss(f)
                results.append(scored if isinstance(scored, Finding) else f)
            else:
                if len(results) == cap:
                    log.info("cvss.budget_exhausted",
                             remaining=len(sorted_confirmed) - len(results))
                results.append(f)
        return results

    # ─── Resume Support ───────────────────────────────────────────────────────

    def _find_resumable_session(self, target: Target) -> Optional[ScanSession]:
        sessions = self.db.list_sessions(limit=20)
        for s in sessions:
            if (s["target_url"] == target.url
                    and s["status"] in ("failed", "running")
                    and not s.get("completed_at")):
                ckpt = CheckpointManager(self.config.knowledge.db_path, s["id"])
                if ckpt.completed_phases():
                    from datetime import datetime
                    session = ScanSession(id=s["id"], target=target)
                    session.started_at = datetime.fromisoformat(s["started_at"])
                    session.status = "running"
                    log.info("scan.resume_candidate",
                             session_id=s["id"],
                             completed=ckpt.completed_phases())
                    return session
        return None

    # ─── Utilities ────────────────────────────────────────────────────────────

    def _dicts_to_findings(self, raw_dicts: list[dict]) -> list[Finding]:
        from core.models import Severity, VulnType
        findings = []
        for d in raw_dicts:
            try:
                f = Finding(
                    id=d.get("id", ""),
                    title=d.get("title", ""),
                    vuln_type=VulnType(d.get("vuln_type", "other")),
                    severity=Severity(d.get("severity", "info")),
                    url=d.get("url", ""),
                    endpoint=d.get("endpoint", ""),
                    method=d.get("method", "GET"),
                    parameter=d.get("parameter", ""),
                    payload=d.get("payload", ""),
                    evidence=d.get("evidence", ""),
                    steps_to_reproduce=d.get("steps_to_reproduce", []),
                    impact=d.get("impact", ""),
                    remediation=d.get("remediation", ""),
                    cvss_score=float(d.get("cvss_score") or 0),
                    cvss_vector=d.get("cvss_vector", ""),
                    confidence=float(d.get("confidence") or 0),
                    confirmed=bool(d.get("confirmed", False)),
                    false_positive=bool(d.get("false_positive", False)),
                    tool=d.get("tool", ""),
                )
                findings.append(f)
            except Exception as e:
                log.warning("checkpoint.finding_deserialise_failed", error=str(e))
        return findings

    # ─── Knowledge Update ─────────────────────────────────────────────────────

    async def update_knowledge(self, url: Optional[str] = None) -> dict:
        async with OllamaClient(
            base_url=self.config.ollama.base_url,
            timeout=self.config.ollama.timeout,
        ) as ollama:
            agent = KnowledgeAgent(self.config, self.db, ollama)
            log.info("knowledge.update_start", model=agent.model,
                     mode="single_url" if url else "all_sources")
            if url:
                return await agent.ingest_url(url)
            return await agent.ingest_all()

    def invalidate_payload_cache(self, vuln_type: Optional[str] = None) -> int:
        deleted = self.cache.invalidate(vuln_type=vuln_type)
        log.info("cache.invalidated", deleted=deleted, vuln_type=vuln_type)
        return deleted

    def cache_stats(self) -> dict:
        return self.cache.stats()
