#!/usr/bin/env python3
"""
pin0ccsAI — CLI Interface
Usage: python cli.py [COMMAND] [OPTIONS]
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent))

from core.config import Config
from core.logger import setup_logging, get_logger
from core.models import Target

BANNER = r"""
 ██████╗ ██╗███╗   ██╗ ██████╗  ██████╗ ██████╗███████╗ █████╗ ██╗
 ██╔══██╗██║████╗  ██║██╔═████╗██╔════╝██╔════╝██╔════╝██╔══██╗██║
 ██████╔╝██║██╔██╗ ██║██║██╔██║██║     ╚█████╗ ███████╗███████║██║
 ██╔═══╝ ██║██║╚██╗██║████╔╝██║██║      ╚═══██╗╚════██║██╔══██║██║
 ██║     ██║██║ ╚████║╚██████╔╝╚██████╗██████╔╝███████║██║  ██║██║
 ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝
  Autonomous AI Pentest Framework  |  BladHound  |  Local • Kali • Offline
"""


def _load_config(config_path: str) -> Config:
    try:
        return Config.load(config_path)
    except FileNotFoundError as e:
        click.secho(f"[ERROR] {e}", fg="red")
        sys.exit(1)


def _setup(config: Config) -> None:
    setup_logging(
        level=config.logging.level,
        fmt=config.logging.format,
        log_to_file=config.logging.log_to_file,
        log_dir=config.project.get("log_dir", "./logs"),
        max_bytes=config.logging.max_bytes,
        backup_count=config.logging.backup_count,
    )


# ─── CLI Root ─────────────────────────────────────────────────────────────────

@click.group()
@click.version_option("0.1.0", prog_name="pin0ccsAI")
def cli():
    """pin0ccsAI — Autonomous AI-powered pentest framework."""
    pass


# ─── scan ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target_url")
@click.option("--config", "-c", default="config/config.yaml",
              help="Path to config file", show_default=True)
@click.option("--skip-recon", is_flag=True, help="Skip subdomain enumeration and host discovery")
@click.option("--phase", "-p", multiple=True,
              help="Run specific attack phases only (can repeat). e.g. -p graphql -p auth")
@click.option("--web3-contract", default=None, help="Smart contract address to analyze")
@click.option("--web3-rpc", default=None, help="RPC endpoint URL for Web3 analysis")
@click.option("--scope-file", default=None,
              help="Path to scope file (one URL per line)")
@click.option("--output-dir", default=None, help="Override report output directory")
@click.option("--format", "fmt", multiple=True,
              type=click.Choice(["markdown", "html", "json"]),
              default=["markdown", "html", "json"],
              help="Report formats to generate")
@click.option("--auth-file", default=None,
              help="Path to JSON auth session file (cookies, headers, bearer token)")
@click.option("--auth-cookie", default=None,
              help="Raw Cookie header string for authenticated scanning. "
                   "Example: 'session=abc123; csrf=xyz'")
@click.option("--auth-bearer", default=None,
              help="Bearer token for Authorization header. "
                   "Example: 'eyJhbGciOiJIUzI1NiJ9...'")
@click.option("--resume", is_flag=True,
              help="Resume a previously interrupted scan for this target. "
                   "Skips completed phases (recon, strategy, etc.).")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def scan(
    target_url, config, skip_recon, phase, web3_contract,
    web3_rpc, scope_file, output_dir, fmt,
    auth_file, auth_cookie, auth_bearer, resume, verbose
):
    """
    Run a full pentest scan against TARGET_URL.

    Examples:\n
      python cli.py scan https://example.com\n
      python cli.py scan https://example.com --auth-cookie 'session=abc; csrf=xyz'\n
      python cli.py scan https://example.com --auth-bearer eyJ...\n
      python cli.py scan https://example.com --auth-file ./session.json\n
      python cli.py scan https://example.com --resume\n
      python cli.py scan https://example.com --skip-recon -p graphql -p auth
    """
    click.echo(BANNER)
    cfg = _load_config(config)

    if verbose:
        cfg.logging.level = "DEBUG"
    if output_dir:
        cfg.project["report_dir"] = output_dir
    if fmt:
        cfg.reporting["formats"] = list(fmt)

    _setup(cfg)
    log = get_logger("cli")

    # Build auth session
    from core.auth_session import AuthSession
    auth = None
    if auth_file:
        try:
            auth = AuthSession.load(auth_file)
            click.secho(f"[+] Auth loaded from file: {auth.label}", fg="green")
        except FileNotFoundError as e:
            click.secho(f"[ERROR] {e}", fg="red")
            sys.exit(1)
    elif auth_cookie or auth_bearer:
        auth = AuthSession(
            cookies=AuthSession._parse_cookie_header(auth_cookie) if auth_cookie else {},
            bearer_token=auth_bearer or "",
            label="cli",
        )
        click.secho(
            f"[+] Auth: {'cookie' if auth_cookie else ''}"
            f"{'bearer' if auth_bearer else ''} session active",
            fg="green"
        )
    else:
        # Try environment variables
        auth = AuthSession.from_env()
        if auth:
            click.secho(f"[+] Auth loaded from environment variables", fg="green")

    # Build targets
    targets = []
    if scope_file:
        scope = Path(scope_file)
        if not scope.exists():
            click.secho(f"[ERROR] Scope file not found: {scope_file}", fg="red")
            sys.exit(1)
        urls = [u.strip() for u in scope.read_text().splitlines() if u.strip()]
        targets = [Target(url=u) for u in urls]
        click.echo(f"[*] Loaded {len(targets)} targets from scope file")
    else:
        targets = [Target(
            url=target_url,
            is_web3=bool(web3_contract),
            contract_address=web3_contract or "",
            rpc_url=web3_rpc or "",
        )]

    from core.orchestrator import ScanOrchestrator
    orchestrator = ScanOrchestrator(cfg)

    for target in targets:
        click.secho(f"\n[*] Starting scan: {target.url}", fg="cyan", bold=True)
        if resume:
            click.secho("[*] Resume mode: skipping completed phases", fg="yellow")
        try:
            session = asyncio.run(orchestrator.run(
                target=target,
                skip_recon=skip_recon,
                phases=list(phase) if phase else None,
                web3_contract=web3_contract,
                web3_rpc=web3_rpc,
                auth=auth,
                resume=resume,
            ))
            _print_scan_summary(session)

        except KeyboardInterrupt:
            click.secho("\n[!] Scan interrupted. Resume with --resume flag.", fg="yellow")
            sys.exit(130)
        except Exception as e:
            click.secho(f"\n[ERROR] Scan failed: {e}", fg="red")
            click.secho("[*] Scan state saved. Resume with: "
                        f"python cli.py scan {target_url} --resume", fg="yellow")
            if verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)


# ─── recon ────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target_url")
@click.option("--config", "-c", default="config/config.yaml", show_default=True)
@click.option("--verbose", "-v", is_flag=True)
def recon(target_url, config, verbose):
    """
    Run reconnaissance only — no active exploitation.

    Performs subdomain enumeration, live host detection,
    tech fingerprinting, and API/GraphQL discovery.
    """
    cfg = _load_config(config)
    if verbose:
        cfg.logging.level = "DEBUG"
    _setup(cfg)

    click.secho(f"\n[*] Recon: {target_url}", fg="cyan")

    from engines.recon import ReconEngine
    from agents.strategy import StrategyAgent
    from core.database import Database
    from core.ollama_client import OllamaClient

    async def _run():
        db = Database(cfg.knowledge.db_path)
        engine = ReconEngine(cfg)
        target = Target(url=target_url)
        result = await engine.run(target)

        async with OllamaClient(cfg.ollama.base_url, cfg.ollama.timeout) as ollama:
            strategy = StrategyAgent(cfg, db, ollama)
            result = await strategy.prioritize(result)

        return result

    result = asyncio.run(_run())
    _print_recon_summary(result)


# ─── update-kb ────────────────────────────────────────────────────────────────

@cli.command("update-kb")
@click.option("--config", "-c", default="config/config.yaml", show_default=True)
@click.option("--url", default=None,
              help="Ingest a specific URL (blog post, CVE page, writeup)")
@click.option("--verbose", "-v", is_flag=True)
def update_kb(config, url, verbose):
    """
    Update the knowledge base from security sources.

    Ingests bug bounty writeups, CVEs, and research blogs.
    Extracts payloads and exploitation techniques.
    """
    cfg = _load_config(config)
    if verbose:
        cfg.logging.level = "DEBUG"
    _setup(cfg)

    from core.orchestrator import ScanOrchestrator
    orchestrator = ScanOrchestrator(cfg)

    if url:
        click.secho(f"[*] Ingesting: {url}", fg="cyan")
    else:
        click.secho("[*] Running full knowledge base update...", fg="cyan")

    stats = asyncio.run(orchestrator.update_knowledge(url=url))
    click.secho("\n[+] Knowledge Base Update Complete", fg="green", bold=True)
    click.echo(f"    New entries  : {stats.get('new', stats.get('status', 0))}")
    click.echo(f"    Duplicates   : {stats.get('duplicate', 0)}")
    click.echo(f"    Total in KB  : {stats.get('total_kb_entries', '?')}")
    if "sources" in stats:
        click.echo("    By source:")
        for src, info in stats["sources"].items():
            click.echo(f"      {src}: {info}")


# ─── report ───────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("session_id")
@click.option("--config", "-c", default="config/config.yaml", show_default=True)
@click.option("--format", "fmt", multiple=True,
              type=click.Choice(["markdown", "html", "json"]),
              default=["markdown", "html", "json"])
@click.option("--output-dir", default=None)
def report(session_id, config, fmt, output_dir):
    """
    (Re)generate a report for a past scan session.

    SESSION_ID is the UUID shown after a scan completes.
    """
    cfg = _load_config(config)
    _setup(cfg)

    if output_dir:
        cfg.project["report_dir"] = output_dir

    from core.database import Database
    from core.models import ScanSession
    from reports.generator import ReportGenerator

    db = Database(cfg.knowledge.db_path)
    session_data = db.get_session(session_id)
    if not session_data:
        click.secho(f"[ERROR] Session not found: {session_id}", fg="red")
        sys.exit(1)

    confirmed = db.get_confirmed_findings(session_id)
    click.echo(f"[*] Found {len(confirmed)} confirmed findings for session {session_id}")

    from core.models import Finding, Severity, VulnType
    from datetime import datetime

    # Reconstruct minimal session object
    session = ScanSession(id=session_id)
    session.target = Target(url=session_data["target_url"])
    session.started_at = datetime.fromisoformat(session_data["started_at"])
    if session_data.get("completed_at"):
        session.completed_at = datetime.fromisoformat(session_data["completed_at"])

    findings = []
    for fd in confirmed:
        f = Finding(
            id=fd["id"], title=fd["title"],
            severity=Severity(fd["severity"]),
            vuln_type=VulnType(fd["vuln_type"]),
            url=fd["url"], endpoint=fd["endpoint"],
            parameter=fd.get("parameter", ""),
            payload=fd.get("payload", ""),
            evidence=fd.get("evidence", ""),
            steps_to_reproduce=fd.get("steps_to_reproduce", []),
            impact=fd.get("impact", ""),
            remediation=fd.get("remediation", ""),
            cvss_score=fd.get("cvss_score", 0.0),
            cvss_vector=fd.get("cvss_vector", ""),
            confidence=fd.get("confidence", 0.0),
            confirmed=True,
            tool=fd.get("tool", ""),
        )
        findings.append(f)

    session.confirmed_findings = findings
    gen = ReportGenerator(cfg.project.get("report_dir", "./reports"))
    paths = gen.generate(session, formats=list(fmt))

    click.secho("\n[+] Reports generated:", fg="green", bold=True)
    for f_, p in paths.items():
        click.echo(f"    {f_:10} → {p}")


# ─── status ───────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--config", "-c", default="config/config.yaml", show_default=True)
@click.option("--limit", default=10, show_default=True)
def status(config, limit):
    """
    Show system status: sessions, KB, payload cache, Ollama health,
    and active resource configuration.
    """
    cfg = _load_config(config)
    _setup(cfg)

    from core.database import Database
    from core.payload_cache import PayloadCache
    db = Database(cfg.knowledge.db_path)

    # Sessions
    sessions = db.list_sessions(limit=limit)
    click.secho("\n Recent Scan Sessions", fg="cyan", bold=True)
    click.echo(f"  {'ID':10} {'TARGET':38} {'STATUS':10} {'STARTED':20} {'FINDINGS':8}")
    click.echo("  " + "─" * 92)
    for s in sessions:
        color = {"complete": "green", "failed": "red", "running": "yellow"}.get(s["status"], "white")
        confirmed_cnt = len(db.get_confirmed_findings(s["id"]))
        click.echo(
            f"  {s['id'][:8]:10} {s['target_url'][:38]:38} "
            + click.style(f"{s['status']:10}", fg=color)
            + f" {s['started_at'][:19]:20} {confirmed_cnt:>5} confirmed"
        )

    # Knowledge base
    kb = db.kb_stats()
    click.secho(f"\n Knowledge Base", fg="cyan", bold=True)
    click.echo(f"  Total entries  : {kb.get('total', 0)}")
    for src, cnt in sorted(kb.get("by_source", {}).items()):
        click.echo(f"  {src:25} {cnt:>5} entries")

    # Payload cache
    cache = PayloadCache(cfg.knowledge.db_path)
    cs = cache.stats()
    ttl_h = cfg.get("performance.cache_ttl_hours", 72)
    click.secho(f"\n Payload Cache  (TTL: {ttl_h}h)", fg="cyan", bold=True)
    if cs["total"] == 0:
        click.echo("  Empty — will populate on first scan")
    else:
        fresh = cs["total"] - cs["stale"]
        click.secho(f"  ✓ {fresh:>3} fresh entries", fg="green")
        if cs["stale"]:
            click.secho(f"  ~ {cs['stale']:>3} stale  (run: python cli.py clear-cache)", fg="yellow")
        for vt, cnt in sorted(cs["by_type"].items()):
            click.echo(f"    ✓ {vt:30} {cnt} variant set(s)")

    # Resource config
    click.secho(f"\n Resource Configuration", fg="cyan", bold=True)
    click.echo(f"  Tester model      : {cfg.models.tester}")
    click.echo(f"  Debator model     : {cfg.models.debator}")
    click.echo(f"  Strategy model    : {cfg.models.strategy}")
    click.echo(f"  Knowledge model   : {cfg.models.knowledge}")
    click.echo(f"  Max mutations     : {cfg.vuln.max_payload_mutations}")
    click.echo(f"  Mutation budget   : {cfg.get('performance.max_mutation_calls', 8)} calls/scan")
    click.echo(f"  CVSS budget       : {cfg.get('performance.max_cvss_calls', 10)} calls/scan")
    all_models = [cfg.models.tester, cfg.models.debator, cfg.models.strategy, cfg.models.knowledge]
    if any("mixtral" in m for m in all_models):
        click.secho("  [WARNING] mixtral detected — requires ~26GB RAM. Replace with mistral:7b.", fg="red", bold=True)

    # Ollama health
    async def _check_ollama():
        from core.ollama_client import OllamaClient
        async with OllamaClient(cfg.ollama.base_url) as c:
            return await c.health_check()

    health = asyncio.run(_check_ollama())
    click.secho(f"\n Ollama  ({cfg.ollama.base_url})", fg="cyan", bold=True)
    if health["status"] == "ok":
        click.secho(f"  ✓ Reachable", fg="green")
        loaded = health.get("models", [])
        required = set(all_models)
        for m in loaded:
            tag = " ← loaded" if any(r.split(":")[0] in m for r in required) else ""
            click.echo(f"    {m}{tag}")
        for req in sorted(required):
            base = req.split(":")[0]
            if not any(base in m for m in loaded):
                click.secho(f"  ✗ {req} not pulled  →  ollama pull {req}", fg="yellow")
    else:
        click.secho(f"  ✗ Unreachable: {health.get('error', 'unknown')}", fg="red")
        click.echo("    Start with: ollama serve")


# ─── memory ───────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--config", "-c", default="config/config.yaml", show_default=True)
@click.option("--clear", is_flag=True,
              help="Clear all exploit memory entries.")
@click.option("--vuln-type", default=None,
              help="Limit display or clear to one vuln type (e.g. xss, sqli).")
@click.option("--top", default=10, show_default=True,
              help="Number of top payloads to display.")
def memory(config, clear, vuln_type, top):
    """
    Inspect and manage the Exploit Memory — payloads proven to work.

    Shows success rates, hit counts, and top-performing payloads.
    Use --clear to reset entries (e.g. after a large batch of false positives).
    """
    cfg = _load_config(config)
    _setup(cfg)

    from core.exploit_memory import ExploitMemory
    mem = ExploitMemory(cfg.knowledge.db_path)

    if clear:
        if vuln_type:
            click.confirm(
                f"Delete all exploit memory entries for '{vuln_type}'?",
                abort=True,
            )
        else:
            click.confirm("Delete ALL exploit memory entries?", abort=True)
        deleted = mem.clear(vuln_type=vuln_type)
        click.secho(f"[+] Cleared {deleted} entries.", fg="green")
        return

    stats = mem.stats()

    click.secho("\n Exploit Memory", fg="cyan", bold=True)
    click.echo(f"  Total entries : {stats['total_entries']}")

    if not stats['total_entries']:
        click.echo("  Empty — memory populates as confirmed findings accumulate.")
        return

    click.secho("\n By vulnerability type:", bold=True)
    click.echo(f"  {'Type':30} {'Entries':>8} {'Avg rate':>10} {'Total hits':>12}")
    click.echo("  " + "─" * 64)
    for row in stats["by_vuln_type"]:
        if vuln_type and row["vuln_type"] != vuln_type:
            continue
        rate_pct = f"{row['avg_success_rate']*100:.0f}%"
        click.echo(
            f"  {row['vuln_type']:30} {row['count']:>8} "
            f"{rate_pct:>10} {row['total_hits']:>12}"
        )

    click.secho(f"\n Top {top} payloads by success rate:", bold=True)
    click.echo(
        f"  {'Type':18} {'Rate':>6} {'S':>4} {'F':>4} "
        f"{'Sev':>8}  {'Payload'}"
    )
    click.echo("  " + "─" * 80)
    shown = 0
    for row in stats["top_payloads"]:
        if vuln_type and row["vuln_type"] != vuln_type:
            continue
        rate_pct = f"{row['success_rate']*100:.0f}%"
        sev_color = {
            "critical": "bright_red", "high": "red",
            "medium": "yellow", "low": "green",
        }.get(row["severity"], "white")
        click.echo(
            f"  {row['vuln_type']:18} {rate_pct:>6} "
            f"{row['success_count']:>4} {row['failure_count']:>4} "
            + click.style(f"{row['severity']:>8}", fg=sev_color)
            + f"  {row['payload']}"
        )
        shown += 1
        if shown >= top:
            break

    click.echo()


# ─── cache-stats ─────────────────────────────────────────────────────────────

@cli.command("cache-stats")
@click.option("--config", "-c", default="config/config.yaml", show_default=True)
def cache_stats(config):
    """Show payload cache statistics — entries, TTL status, by vuln type."""
    cfg = _load_config(config)
    _setup(cfg)
    from core.payload_cache import PayloadCache
    cache = PayloadCache(cfg.knowledge.db_path)
    stats = cache.stats()
    click.secho("\n Payload Cache", fg="cyan", bold=True)
    click.echo(f"  Total entries : {stats['total']}")
    click.echo(f"  Stale entries : {stats['stale']} (will regenerate on next scan)")
    if stats["by_type"]:
        click.echo("  By vuln type  :")
        for vt, count in sorted(stats["by_type"].items()):
            click.echo(f"    {vt:30} {count}")
    else:
        click.echo("  Cache is empty — will populate on first scan")


@cli.command("clear-cache")
@click.option("--config", "-c", default="config/config.yaml", show_default=True)
@click.option("--vuln-type", default=None,
              help="Clear only a specific vuln type (e.g. xss, sqli). "
                   "Omit to evict all stale entries.")
@click.confirmation_option(prompt="This will delete cached mutations. Continue?")
def clear_cache(config, vuln_type):
    """
    Evict payload cache entries.

    Without --vuln-type: evicts only stale entries (older than TTL).\n
    With --vuln-type: evicts all entries for that type, forcing regeneration.
    """
    cfg = _load_config(config)
    _setup(cfg)
    from core.payload_cache import PayloadCache
    cache = PayloadCache(cfg.knowledge.db_path)
    deleted = cache.invalidate(vuln_type=vuln_type)
    if deleted:
        click.secho(f"[+] Evicted {deleted} cache entries", fg="green")
    else:
        click.echo("[*] Nothing to evict")


# ─── check-tools ──────────────────────────────────────────────────────────────

@cli.command("check-tools")
@click.option("--config", "-c", default="config/config.yaml", show_default=True)
def check_tools(config):
    """Verify all required tools are installed and reachable."""
    import shutil
    cfg = _load_config(config)
    _setup(cfg)

    click.secho("\n Tool Check", fg="cyan", bold=True)
    tools = {
        "subfinder": cfg.tools.subfinder,
        "assetfinder": cfg.tools.assetfinder,
        "httpx": cfg.tools.httpx,
        "nuclei": cfg.tools.nuclei,
        "ffuf": cfg.tools.ffuf,
        "gobuster": cfg.tools.gobuster,
        "nmap": cfg.tools.nmap,
    }

    all_ok = True
    for name, cmd in tools.items():
        found = shutil.which(cmd)
        if found:
            click.secho(f"  ✓ {name:15} {found}", fg="green")
        else:
            click.secho(f"  ✗ {name:15} NOT FOUND (install: apt install {cmd})", fg="red")
            all_ok = False

    click.secho("\n Model Check (requires Ollama running)", fg="cyan", bold=True)
    required_models = {
        "tester   (qwen2.5-coder:7b)": cfg.models.tester,
        "debator  (llama3.1:8b)":      cfg.models.debator,
        "strategy (mistral:7b)":       cfg.models.strategy,
        "knowledge(mistral:7b)":       cfg.models.knowledge,
    }
    click.echo("  NOTE: mixtral:8x7b removed. Knowledge agent now uses mistral:7b.")

    async def _check_models():
        from core.ollama_client import OllamaClient
        async with OllamaClient(cfg.ollama.base_url) as c:
            health = await c.health_check()
            if health["status"] != "ok":
                return health
            results = {}
            for role, model in required_models.items():
                ok = await c.ensure_model(model)
                results[role] = (model, ok)
            return results

    model_results = asyncio.run(_check_models())
    if isinstance(model_results, dict) and "error" not in model_results:
        for role, (model, ok) in model_results.items():
            if ok:
                click.secho(f"  ✓ {role:15} {model}", fg="green")
            else:
                click.secho(
                    f"  ✗ {role:15} {model} — pull with: ollama pull {model}", fg="yellow"
                )
    else:
        click.secho(f"  Ollama not reachable: {model_results.get('error', '?')}", fg="red")

    if all_ok:
        click.secho("\n[+] All tools present", fg="green", bold=True)
    else:
        click.secho("\n[!] Some tools missing — install them for full functionality", fg="yellow")


# ─── Output Helpers ───────────────────────────────────────────────────────────

def _print_scan_summary(session):
    from core.models import Severity
    confirmed = session.confirmed_findings

    click.secho("\n" + "═" * 60, fg="cyan")
    click.secho(" SCAN COMPLETE", fg="cyan", bold=True)
    click.secho("═" * 60, fg="cyan")
    click.echo(f" Target    : {session.target.url}")
    click.echo(f" Session   : {session.id}")
    click.echo(f" Duration  : {session.duration_seconds:.0f}s")
    click.echo(f" Status    : {session.status}")
    click.secho("\n Confirmed Findings:", bold=True)

    colors = {
        "critical": "bright_red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "info": "white",
    }

    counts: dict[str, int] = {}
    for f in confirmed:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    for sev in ["critical", "high", "medium", "low", "info"]:
        count = counts.get(sev, 0)
        if count > 0:
            click.secho(f"   {sev.upper():10} {count}", fg=colors[sev])

    if confirmed:
        click.secho("\n Top Findings:", bold=True)
        for f in confirmed[:5]:
            sev_color = colors.get(f.severity.value, "white")
            click.echo(
                "  " + click.style(f"[{f.severity.value.upper()}]", fg=sev_color)
                + f" {f.title[:60]}"
            )
    else:
        click.secho("\n No confirmed vulnerabilities found.", fg="green")

    click.secho("═" * 60 + "\n", fg="cyan")


def _print_recon_summary(result):
    click.secho("\n Recon Results:", fg="cyan", bold=True)
    click.echo(f"  Subdomains  : {len(result.subdomains)}")
    click.echo(f"  Live hosts  : {len(result.live_hosts)}")
    click.echo(f"  Endpoints   : {len(result.endpoints)}")
    click.echo(f"  GraphQL     : {len(result.graphql_endpoints)}")
    click.echo(f"  API paths   : {len(result.api_endpoints)}")

    if result.crown_jewels:
        click.secho("\n  Crown Jewels (high-value targets):", bold=True)
        for cj in result.crown_jewels[:15]:
            click.secho(f"    [{cj.crown_jewel_score:3}] {cj.url}", fg="yellow")

    if result.tech_stack:
        click.secho("\n  Tech Stack:", bold=True)
        for host, techs in list(result.tech_stack.items())[:5]:
            if techs:
                click.echo(f"    {host}: {', '.join(techs[:5])}")


if __name__ == "__main__":
    cli()
