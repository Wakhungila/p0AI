"""
pin0ccsAI — Report Generator
Generates Markdown, HTML, and JSON reports from confirmed findings.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.logger import get_logger
from core.models import Finding, ScanSession, Severity

log = get_logger(__name__)

_SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
]

_SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#16a34a",
    "info": "#6b7280",
}


class ReportGenerator:
    def __init__(self, report_dir: str = "./reports"):
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, session: ScanSession, formats: list[str] = None) -> dict[str, str]:
        """Generate reports in all requested formats. Returns {format: filepath}."""
        formats = formats or ["markdown", "html", "json"]
        outputs = {}

        findings = sorted(
            session.confirmed_findings,
            key=lambda f: _SEVERITY_ORDER.index(f.severity)
        )

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        target_slug = session.target.domain.replace(".", "_") if session.target else "unknown"
        base_name = f"{target_slug}_{timestamp}"

        if "markdown" in formats:
            path = self.report_dir / f"{base_name}.md"
            content = self._render_markdown(session, findings)
            path.write_text(content, encoding="utf-8")
            outputs["markdown"] = str(path)
            log.info("report.generated", format="markdown", path=str(path))

        if "html" in formats:
            path = self.report_dir / f"{base_name}.html"
            content = self._render_html(session, findings)
            path.write_text(content, encoding="utf-8")
            outputs["html"] = str(path)
            log.info("report.generated", format="html", path=str(path))

        if "json" in formats:
            path = self.report_dir / f"{base_name}.json"
            content = self._render_json(session, findings)
            path.write_text(content, encoding="utf-8")
            outputs["json"] = str(path)
            log.info("report.generated", format="json", path=str(path))

        return outputs

    # ─── Markdown Renderer ───────────────────────────────────────────────────

    def _render_markdown(self, session: ScanSession, findings: list[Finding]) -> str:
        lines = []
        target_url = session.target.url if session.target else "Unknown"
        scan_date = session.started_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        duration = f"{session.duration_seconds:.0f}s"

        lines.append(f"# Security Assessment Report")
        lines.append(f"")
        lines.append(f"**Target:** `{target_url}`  ")
        lines.append(f"**Date:** {scan_date}  ")
        lines.append(f"**Duration:** {duration}  ")
        lines.append(f"**Session ID:** `{session.id}`  ")
        lines.append(f"")

        # Summary stats
        counts = self._count_by_severity(findings)
        lines.append(f"## Executive Summary")
        lines.append(f"")
        lines.append(f"| Severity | Count |")
        lines.append(f"|----------|-------|")
        for sev in _SEVERITY_ORDER:
            count = counts.get(sev.value, 0)
            if count > 0:
                lines.append(f"| **{sev.value.upper()}** | {count} |")
        lines.append(f"")

        if not findings:
            lines.append(f"No confirmed vulnerabilities found.")
            return "\n".join(lines)

        lines.append(f"## Findings ({len(findings)} total)")
        lines.append(f"")

        for i, f in enumerate(findings, 1):
            sev_badge = f"[{f.severity.value.upper()}]"
            lines.append(f"---")
            lines.append(f"")
            lines.append(f"### {i}. {f.title} {sev_badge}")
            lines.append(f"")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| **ID** | `{f.id}` |")
            lines.append(f"| **Type** | `{f.vuln_type.value}` |")
            lines.append(f"| **Severity** | **{f.severity.value.upper()}** |")
            if f.cvss_score:
                lines.append(f"| **CVSS Score** | {f.cvss_score:.1f} |")
            if f.cvss_vector:
                lines.append(f"| **CVSS Vector** | `{f.cvss_vector}` |")
            lines.append(f"| **URL** | `{f.url}` |")
            if f.parameter:
                lines.append(f"| **Parameter** | `{f.parameter}` |")
            lines.append(f"| **Confidence** | {f.confidence:.0%} |")
            lines.append(f"| **Tool** | `{f.tool}` |")
            lines.append(f"")

            if f.steps_to_reproduce:
                lines.append(f"#### Steps to Reproduce")
                lines.append(f"")
                for step in f.steps_to_reproduce:
                    lines.append(f"{step}")
                lines.append(f"")

            if f.payload:
                lines.append(f"#### Payload")
                lines.append(f"```")
                lines.append(f.payload)
                lines.append(f"```")
                lines.append(f"")

            if f.evidence:
                lines.append(f"#### Evidence")
                lines.append(f"```")
                lines.append(f.evidence[:500])
                lines.append(f"```")
                lines.append(f"")

            if f.impact:
                lines.append(f"#### Impact")
                lines.append(f"")
                lines.append(f.impact)
                lines.append(f"")

            if f.remediation:
                lines.append(f"#### Remediation")
                lines.append(f"")
                lines.append(f.remediation)
                lines.append(f"")

            debator_note = f.extra.get("debator_reasoning", "")
            if debator_note:
                lines.append(f"> **Debator note:** {debator_note[:200]}")
                lines.append(f"")

        lines.append(f"---")
        lines.append(f"")
        lines.append(f"*Generated by pin0ccsAI — {scan_date}*")
        return "\n".join(lines)

    # ─── HTML Renderer ────────────────────────────────────────────────────────

    def _render_html(self, session: ScanSession, findings: list[Finding]) -> str:
        target_url = session.target.url if session.target else "Unknown"
        scan_date = session.started_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        counts = self._count_by_severity(findings)

        finding_cards = ""
        for i, f in enumerate(findings, 1):
            color = _SEVERITY_COLORS.get(f.severity.value, "#6b7280")
            steps_html = "".join(
                f"<li><code>{s}</code></li>" for s in f.steps_to_reproduce
            )
            finding_cards += f"""
<div class="finding" id="finding-{f.id}">
  <div class="finding-header" style="border-left: 4px solid {color}">
    <span class="badge" style="background:{color}">{f.severity.value.upper()}</span>
    <h3>{i}. {f.title}</h3>
    <small>ID: {f.id} | Type: {f.vuln_type.value} | Confidence: {f.confidence:.0%}</small>
  </div>
  <div class="finding-body">
    <table>
      <tr><td><b>URL</b></td><td><code>{f.url}</code></td></tr>
      {"<tr><td><b>Parameter</b></td><td><code>" + f.parameter + "</code></td></tr>" if f.parameter else ""}
      {"<tr><td><b>CVSS</b></td><td>" + str(f.cvss_score) + " — <code>" + f.cvss_vector + "</code></td></tr>" if f.cvss_score else ""}
      <tr><td><b>Tool</b></td><td>{f.tool}</td></tr>
    </table>
    {"<h4>Steps to Reproduce</h4><ol>" + steps_html + "</ol>" if f.steps_to_reproduce else ""}
    {"<h4>Payload</h4><pre><code>" + f.payload + "</code></pre>" if f.payload else ""}
    {"<h4>Evidence</h4><pre><code>" + f.evidence[:400] + "</code></pre>" if f.evidence else ""}
    {"<h4>Impact</h4><p>" + f.impact + "</p>" if f.impact else ""}
    {"<h4>Remediation</h4><p>" + f.remediation + "</p>" if f.remediation else ""}
  </div>
</div>"""

        summary_rows = "".join(
            f'<tr><td style="color:{_SEVERITY_COLORS[s.value]}"><b>{s.value.upper()}</b></td>'
            f'<td>{counts.get(s.value, 0)}</td></tr>'
            for s in _SEVERITY_ORDER if counts.get(s.value, 0) > 0
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Report — {target_url}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         max-width: 1000px; margin: 0 auto; padding: 2rem; background: #f8fafc; }}
  h1 {{ color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 1rem; }}
  h2 {{ color: #1e293b; margin-top: 2rem; }}
  .meta {{ background: #1e293b; color: #cbd5e1; padding: 1rem 1.5rem;
           border-radius: 8px; font-family: monospace; }}
  .summary table {{ border-collapse: collapse; }}
  .summary td {{ padding: 0.4rem 1rem; border: 1px solid #e2e8f0; }}
  .finding {{ background: white; border-radius: 8px; margin: 1.5rem 0;
              box-shadow: 0 1px 3px rgba(0,0,0,.1); overflow: hidden; }}
  .finding-header {{ padding: 1rem 1.5rem; background: #f8fafc; }}
  .finding-header h3 {{ margin: 0.25rem 0; }}
  .finding-body {{ padding: 1rem 1.5rem; }}
  .badge {{ padding: 2px 8px; border-radius: 4px; color: white;
            font-size: 11px; font-weight: 700; letter-spacing: 0.5px; margin-right: 8px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 0.5rem 0; }}
  td {{ padding: 0.35rem 0.75rem; border: 1px solid #e2e8f0; vertical-align: top; }}
  td:first-child {{ width: 120px; white-space: nowrap; color: #64748b; }}
  pre {{ background: #0f172a; color: #e2e8f0; padding: 1rem; border-radius: 6px;
         overflow-x: auto; font-size: 13px; }}
  code {{ font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 13px; }}
  h4 {{ margin: 1rem 0 0.5rem; color: #475569; }}
  footer {{ text-align: center; color: #94a3b8; margin-top: 3rem; font-size: 13px; }}
</style>
</head>
<body>
<h1>Security Assessment Report</h1>
<div class="meta">
  <b>Target:</b> {target_url}<br>
  <b>Date:</b> {scan_date}<br>
  <b>Session:</b> {session.id}<br>
  <b>Duration:</b> {session.duration_seconds:.0f}s
</div>

<h2>Executive Summary</h2>
<div class="summary">
<table>
<tr><th>Severity</th><th>Count</th></tr>
{summary_rows}
<tr><td><b>TOTAL</b></td><td><b>{len(findings)}</b></td></tr>
</table>
</div>

<h2>Findings ({len(findings)})</h2>
{finding_cards if finding_cards else "<p>No confirmed vulnerabilities found.</p>"}

<footer>Generated by pin0ccsAI &mdash; {scan_date}</footer>
</body>
</html>"""

    # ─── JSON Renderer ────────────────────────────────────────────────────────

    def _render_json(self, session: ScanSession, findings: list[Finding]) -> str:
        data = {
            "session_id": session.id,
            "target": session.target.url if session.target else "",
            "started_at": session.started_at.isoformat(),
            "completed_at": session.completed_at.isoformat() if session.completed_at else None,
            "duration_seconds": session.duration_seconds,
            "summary": self._count_by_severity(findings),
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
        return json.dumps(data, indent=2, default=str)

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _count_by_severity(self, findings: list[Finding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts
