"""
pin0ccsAI — Knowledge Agent  [8GB-optimised: mistral:7b]

mixtral:8x7b removed — requires 26GB RAM minimum.
Replaced with mistral:7b for extraction. Quality trade-off is acceptable:
mistral:7b reliably extracts vuln types, payloads, and CVE IDs from
structured security content. It is NOT called during scans — only during
`update-kb` which runs standalone, so the full 4GB headroom is available.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
from datetime import datetime
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from agents.base import BaseAgent
from core.config import Config
from core.database import Database
from core.logger import get_logger
from core.ollama_client import OllamaClient

log = get_logger(__name__)

_SYSTEM_PROMPT = """You are a security knowledge extraction engine.
Given security research content, you extract:
- Vulnerability types present
- Specific payloads that were used
- Exploitation techniques
- CVE identifiers
Output ONLY structured JSON."""

_EXTRACTION_PROMPT = """Extract security knowledge from this content.

Source: {source}
Title: {title}
Content: {content}

Extract:
1. Vulnerability types (use these exact values where applicable):
   idor, broken_access_control, ssrf, xss_reflected, xss_stored, xss_dom,
   sql_injection, file_upload, business_logic, auth_bypass, web_cache_poisoning,
   graphql_misconfiguration, open_redirect, ssti, lfi, rfi, rce,
   signature_replay, contract_access_control, reentrancy, wallet_auth_flaw,
   misconfiguration, information_disclosure

2. Specific payloads that were used (extract verbatim where possible)
3. Step-by-step exploitation techniques
4. Any CVE identifiers mentioned

Output JSON:
{{
  "vuln_types": ["type1", "type2"],
  "payloads": ["payload1", "payload2"],
  "techniques": ["technique description 1", "technique description 2"],
  "cve": "CVE-XXXX-XXXXX or empty string",
  "summary": "one sentence summary"
}}"""


# Curated sources for security knowledge ingestion
_SOURCES = [
    {
        "type": "rss",
        "url": "https://portswigger.net/research/rss",
        "name": "portswigger",
    },
    {
        "type": "rss",
        "url": "https://feeds.feedburner.com/hackerone/blogs",
        "name": "hackerone_blog",
    },
    {
        "type": "api",
        "url": "https://cve.circl.lu/api/last/20",
        "name": "cve_circl",
        "format": "json",
    },
    {
        "type": "scrape",
        "url": "https://hackerone.com/hacktivity?sort_type=popular",
        "name": "h1_hacktivity",
    },
]


class KnowledgeAgent(BaseAgent):
    name = "knowledge"

    def __init__(self, config: Config, db: Database, ollama: OllamaClient):
        super().__init__(config, db, ollama)
        self._sources = config.knowledge.sources or _SOURCES

    @property
    def model(self) -> str:
        # mixtral:8x7b replaced — uses mistral:7b (fits 8GB RAM)
        # KnowledgeAgent only runs during update-kb, never during scans.
        return self.config.models.knowledge or self.config.models.strategy

    # ─── Main Entry Point ────────────────────────────────────────────────────

    async def ingest_all(self, max_entries: int = 50) -> dict:
        """Run full knowledge ingestion cycle. Returns stats."""
        stats = {"new": 0, "duplicate": 0, "failed": 0, "sources": {}}

        log.info("knowledge.ingest_start", sources=len(self._sources))

        for source in self._sources:
            source_name = source.get("name", "unknown")
            try:
                entries = await self._fetch_source(source)
                new, dupe = await self._process_entries(entries[:max_entries], source_name)
                stats["new"] += new
                stats["duplicate"] += dupe
                stats["sources"][source_name] = {"new": new, "duplicate": dupe}
                log.info("knowledge.source_done", source=source_name, new=new, dupe=dupe)
            except Exception as e:
                log.warning("knowledge.source_failed", source=source_name, error=str(e))
                stats["failed"] += 1
                stats["sources"][source_name] = {"error": str(e)}

        db_stats = self.db.kb_stats()
        stats["total_kb_entries"] = db_stats.get("total", 0)
        log.info("knowledge.ingest_complete", **stats)
        return stats

    async def ingest_url(self, url: str, source_name: str = "manual") -> dict:
        """Ingest a single URL (blog post, writeup, CVE page)."""
        content = await self._fetch_url_content(url)
        if not content:
            return {"status": "error", "reason": "could not fetch content"}

        title = self._extract_title(content, url)
        extracted = await self._extract_knowledge(
            content=content[:3000],
            title=title,
            source=source_name,
        )
        if not extracted:
            return {"status": "error", "reason": "extraction failed"}

        entry = {
            "source": source_name,
            "title": title,
            "url": url,
            "content": content[:5000],
            "vuln_types": extracted.get("vuln_types", []),
            "payloads": extracted.get("payloads", []),
            "techniques": extracted.get("techniques", []),
            "cve": extracted.get("cve", ""),
            "hash": hashlib.sha256(content[:2000].encode()).hexdigest(),
        }

        is_new = self.db.save_kb_entry(entry)
        return {
            "status": "new" if is_new else "duplicate",
            "title": title,
            "vuln_types": extracted.get("vuln_types", []),
            "payloads_found": len(extracted.get("payloads", [])),
        }

    # ─── Source Fetching ─────────────────────────────────────────────────────

    async def _fetch_source(self, source: dict) -> list[dict]:
        source_type = source.get("type", "rss")
        if source_type == "rss":
            return await self._fetch_rss(source["url"], source["name"])
        elif source_type == "api":
            return await self._fetch_api(source["url"], source["name"],
                                          source.get("format", "json"))
        elif source_type == "scrape":
            return await self._fetch_scrape(source["url"], source["name"])
        return []

    async def _fetch_rss(self, url: str, name: str) -> list[dict]:
        entries = []
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code != 200:
                    return entries

                content = resp.text
                # Simple RSS/Atom parser (no dependencies)
                items = re.findall(
                    r'<item[^>]*>(.*?)</item>',
                    content, re.DOTALL
                ) or re.findall(
                    r'<entry[^>]*>(.*?)</entry>',
                    content, re.DOTALL
                )

                for item in items[:20]:
                    title_m = re.search(r'<title[^>]*>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>',
                                        item, re.DOTALL)
                    link_m = re.search(r'<link[^>]*>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</link>',
                                       item, re.DOTALL) or re.search(
                        r'<link[^>]*href="([^"]+)"', item)
                    desc_m = re.search(
                        r'<description[^>]*>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</description>',
                        item, re.DOTALL
                    ) or re.search(
                        r'<content[^>]*>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</content>',
                        item, re.DOTALL
                    )

                    if title_m and link_m:
                        entries.append({
                            "title": self._strip_html(title_m.group(1).strip()),
                            "url": link_m.group(1).strip(),
                            "content": self._strip_html(desc_m.group(1).strip())
                            if desc_m else "",
                            "source": name,
                        })
        except Exception as e:
            log.debug("knowledge.rss_failed", url=url, error=str(e))
        return entries

    async def _fetch_api(self, url: str, name: str, fmt: str) -> list[dict]:
        entries = []
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url)
                if fmt == "json":
                    data = resp.json()
                    # Handle CVE API format
                    if isinstance(data, list):
                        for item in data[:20]:
                            cve_id = item.get("id", "")
                            summary = item.get("summary", "")
                            entries.append({
                                "title": cve_id,
                                "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
                                "content": summary,
                                "source": name,
                                "cve_hint": cve_id,
                            })
        except Exception as e:
            log.debug("knowledge.api_failed", url=url, error=str(e))
        return entries

    async def _fetch_scrape(self, url: str, name: str) -> list[dict]:
        # Minimal scrape — fetch page, extract links to reports
        entries = []
        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
                resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                links = re.findall(r'href="(/reports/\d+[^"]*)"', resp.text)
                base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                for link in links[:10]:
                    full_url = urljoin(base, link)
                    entries.append({
                        "title": f"HackerOne report {link}",
                        "url": full_url,
                        "content": "",
                        "source": name,
                    })
        except Exception as e:
            log.debug("knowledge.scrape_failed", url=url, error=str(e))
        return entries

    # ─── Processing ──────────────────────────────────────────────────────────

    async def _process_entries(
        self, entries: list[dict], source_name: str
    ) -> tuple[int, int]:
        new_count = 0
        dupe_count = 0

        sem = asyncio.Semaphore(5)

        async def process_one(entry: dict):
            async with sem:
                return await self._process_entry(entry, source_name)

        results = await asyncio.gather(*[process_one(e) for e in entries],
                                        return_exceptions=True)
        for r in results:
            if isinstance(r, bool):
                if r:
                    new_count += 1
                else:
                    dupe_count += 1

        return new_count, dupe_count

    async def _process_entry(self, entry: dict, source_name: str) -> bool:
        url = entry.get("url", "")
        content = entry.get("content", "")
        title = entry.get("title", "")

        # Fetch full content if we only have a summary
        if len(content) < 200 and url:
            full = await self._fetch_url_content(url)
            if full:
                content = full[:4000]

        if not content:
            return False

        content_hash = hashlib.sha256(content[:2000].encode()).hexdigest()

        # Extract knowledge via LLM
        extracted = await self._extract_knowledge(
            content=content[:3000],
            title=title,
            source=source_name,
        )
        if not extracted:
            return False

        kb_entry = {
            "source": source_name,
            "title": title,
            "url": url,
            "content": content[:5000],
            "vuln_types": extracted.get("vuln_types", []),
            "payloads": extracted.get("payloads", []),
            "techniques": extracted.get("techniques", []),
            "cve": entry.get("cve_hint", extracted.get("cve", "")),
            "hash": content_hash,
        }

        return self.db.save_kb_entry(kb_entry)

    async def _extract_knowledge(
        self, content: str, title: str, source: str
    ) -> Optional[dict]:
        prompt = _EXTRACTION_PROMPT.format(
            source=source,
            title=title,
            content=content,
        )
        try:
            result = await self.think_json(prompt, system=_SYSTEM_PROMPT, temperature=0.1)
            if isinstance(result, dict):
                return result
        except Exception as e:
            log.debug("knowledge.extract_failed", error=str(e))
        return None

    # ─── Utilities ───────────────────────────────────────────────────────────

    async def _fetch_url_content(self, url: str) -> str:
        try:
            async with httpx.AsyncClient(
                timeout=20, follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"}
            ) as client:
                resp = await client.get(url)
                return self._strip_html(resp.text)
        except Exception:
            return ""

    def _strip_html(self, text: str) -> str:
        clean = re.sub(r'<[^>]+>', ' ', text)
        clean = re.sub(r'&[a-z]+;', ' ', clean)
        clean = re.sub(r'\s+', ' ', clean)
        return clean.strip()

    def _extract_title(self, content: str, url: str) -> str:
        m = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        if m:
            return self._strip_html(m.group(1)).strip()[:200]
        return urlparse(url).path.split("/")[-1] or url
