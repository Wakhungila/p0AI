"""
pin0ccsAI — Recon Engine
Subdomain enumeration, live host detection, tech fingerprinting,
API discovery, and GraphQL endpoint detection.
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx

from core.config import Config
from core.logger import get_logger
from core.models import Endpoint, ReconResult, Target

log = get_logger(__name__)

# GraphQL introspection query — minimal version
_GQL_INTROSPECTION = '{"query":"{__schema{types{name}}}"}'

# Common GraphQL endpoint paths
_GQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
    "/query", "/gql", "/graph", "/playground",
]

# Common API path indicators
_API_INDICATORS = [
    "/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/service/",
    "/swagger", "/openapi", "/docs/api",
]


class ReconEngine:
    def __init__(self, config: Config):
        self.cfg = config
        self.recon_cfg = config.recon
        self.tools_cfg = config.tools

    # ─── Main Entry Point ────────────────────────────────────────────────────

    async def run(self, target: Target) -> ReconResult:
        log.info("recon.start", target=target.url)
        result = ReconResult(target=target)

        domain = target.domain
        if not domain:
            domain = urlparse(target.url).netloc

        # 1. Subdomain enumeration
        result.subdomains = await self._enumerate_subdomains(domain)
        log.info("recon.subdomains", count=len(result.subdomains))

        # 2. Live host detection
        all_hosts = list(set([target.url] + result.subdomains))
        result.live_hosts = await self._filter_live_hosts(all_hosts)
        log.info("recon.live_hosts", count=len(result.live_hosts))

        # 3a. Port scanning with nmap (top 1000 ports, parallel per host)
        if shutil.which(self.tools_cfg.nmap):
            nmap_tasks = [
                self._run_nmap(host) for host in result.live_hosts[:10]
            ]
            nmap_results = await asyncio.gather(*nmap_tasks, return_exceptions=True)
            for host, ports in zip(result.live_hosts[:10], nmap_results):
                if isinstance(ports, list) and ports:
                    result.open_ports[host] = ports
            log.info("recon.nmap_done",
                     hosts_scanned=len(result.open_ports),
                     total_open_ports=sum(len(p) for p in result.open_ports.values()))
        else:
            log.info("recon.nmap_skip", reason="nmap not found in PATH")

        # 3b. Tech detection: whatweb first (richer), regex fallback for each host
        tech_tasks = [
            self._detect_tech_full(host) for host in result.live_hosts[:20]
        ]
        tech_results = await asyncio.gather(*tech_tasks, return_exceptions=True)
        for host, tech in zip(result.live_hosts[:20], tech_results):
            if isinstance(tech, list) and tech:
                result.tech_stack[host] = tech
        log.info("recon.tech_done", hosts_fingerprinted=len(result.tech_stack))

        # 4. Endpoint / directory discovery (on root domain + key subdomains)
        discovery_targets = result.live_hosts[:5]
        discovery_tasks = [self._discover_endpoints(host) for host in discovery_targets]
        all_endpoints = await asyncio.gather(*discovery_tasks, return_exceptions=True)
        for endpoints in all_endpoints:
            if isinstance(endpoints, list):
                result.endpoints.extend(endpoints)

        # 5. GraphQL detection
        gql_tasks = [self._detect_graphql(host) for host in result.live_hosts[:10]]
        gql_results = await asyncio.gather(*gql_tasks, return_exceptions=True)
        for gql in gql_results:
            if isinstance(gql, list):
                result.graphql_endpoints.extend(gql)

        # 6. API endpoint markers
        result.api_endpoints = [
            e.url for e in result.endpoints
            if any(ind in e.url for ind in _API_INDICATORS)
        ]

        log.info("recon.complete",
                 endpoints=len(result.endpoints),
                 graphql=len(result.graphql_endpoints),
                 apis=len(result.api_endpoints),
                 open_ports_hosts=len(result.open_ports))
        return result

    # ─── Subdomain Enumeration ───────────────────────────────────────────────

    async def _enumerate_subdomains(self, domain: str) -> list[str]:
        subdomains: set[str] = set()

        # Run subfinder
        if shutil.which(self.tools_cfg.subfinder):
            subs = await self._run_subfinder(domain)
            subdomains.update(subs)
        else:
            log.warning("tool.missing", tool="subfinder")

        # Run assetfinder
        if shutil.which(self.tools_cfg.assetfinder):
            subs = await self._run_assetfinder(domain)
            subdomains.update(subs)
        else:
            log.warning("tool.missing", tool="assetfinder")

        # Normalize — prepend https:// if missing
        normalized = []
        for s in subdomains:
            if not s.startswith("http"):
                normalized.append(f"https://{s}")
            else:
                normalized.append(s)

        return normalized

    async def _run_subfinder(self, domain: str) -> list[str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                self.tools_cfg.subfinder, "-d", domain, "-silent",
                "-t", str(self.recon_cfg.threads),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            return [line.strip() for line in stdout.decode().splitlines() if line.strip()]
        except (asyncio.TimeoutError, FileNotFoundError) as e:
            log.warning("subfinder.failed", error=str(e))
            return []

    async def _run_assetfinder(self, domain: str) -> list[str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                self.tools_cfg.assetfinder, "--subs-only", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            return [line.strip() for line in stdout.decode().splitlines()
                    if line.strip() and domain in line]
        except (asyncio.TimeoutError, FileNotFoundError) as e:
            log.warning("assetfinder.failed", error=str(e))
            return []

    # ─── Live Host Detection ─────────────────────────────────────────────────

    async def _filter_live_hosts(self, urls: list[str]) -> list[str]:
        """Use httpx to filter only responding hosts."""
        if not shutil.which(self.tools_cfg.httpx):
            log.warning("tool.missing", tool="httpx — falling back to async HTTP probe")
            return await self._async_probe_hosts(urls)

        # Write URL list to temp file
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("\n".join(urls))
            tmp = f.name

        try:
            proc = await asyncio.create_subprocess_exec(
                self.tools_cfg.httpx,
                "-l", tmp,
                "-silent",
                "-threads", str(self.recon_cfg.threads),
                "-timeout", str(self.recon_cfg.timeout),
                "-status-code",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            live = []
            for line in stdout.decode().splitlines():
                # httpx -status-code output: url [status_code]
                parts = line.strip().split()
                if parts:
                    live.append(parts[0])
            return live
        except Exception as e:
            log.warning("httpx.failed", error=str(e))
            return await self._async_probe_hosts(urls)
        finally:
            os.unlink(tmp)

    async def _async_probe_hosts(self, urls: list[str]) -> list[str]:
        """Fallback: direct async HTTP probing."""
        live = []
        async with httpx.AsyncClient(timeout=self.recon_cfg.timeout,
                                      verify=False, follow_redirects=True) as client:
            sem = asyncio.Semaphore(self.recon_cfg.threads)
            async def probe(url: str):
                async with sem:
                    try:
                        resp = await client.head(url)
                        if resp.status_code < 500:
                            return url
                    except Exception:
                        pass
                    return None

            results = await asyncio.gather(*[probe(u) for u in urls])
            live = [r for r in results if r]
        return live

    # ─── Port Scanning (nmap) ────────────────────────────────────────────────

    async def _run_nmap(self, url: str) -> list[int]:
        """
        Run nmap top-1000 port scan against a host.
        Parses output for open port numbers.
        Returns list of open port integers.
        """
        from urllib.parse import urlparse
        host = urlparse(url).hostname or url
        try:
            proc = await asyncio.create_subprocess_exec(
                self.tools_cfg.nmap,
                "-sV",           # service version detection
                "--top-ports", "1000",
                "-T4",           # aggressive timing (fast on LAN)
                "-oG", "-",      # grepable output to stdout
                "--open",        # only show open ports
                host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
            output = stdout.decode()
            # Grepable format: Ports: 22/open/tcp//ssh//OpenSSH 8.9/,
            # also: 80/open/tcp//http//nginx 1.18/
            ports: list[int] = []
            for line in output.splitlines():
                if "Ports:" in line:
                    for segment in line.split(","):
                        m = re.match(r"\s*(\d+)/open", segment.strip())
                        if m:
                            ports.append(int(m.group(1)))
            log.info("nmap.done", host=host, open_ports=ports)
            return ports
        except asyncio.TimeoutError:
            log.warning("nmap.timeout", host=host)
        except Exception as e:
            log.warning("nmap.failed", host=host, error=str(e))
        return []

    # ─── Tech Detection ──────────────────────────────────────────────────────

    async def _detect_tech_full(self, url: str) -> list[str]:
        """
        Combined tech detection:
          1. whatweb (richer signatures, 1800+ plugins)
          2. Inline regex patterns (fallback / augmentation)
        Results are merged and deduplicated.
        """
        techs: set[str] = set()

        # whatweb (structured JSON output)
        if shutil.which(self.tools_cfg.whatweb):
            ww_techs = await self._run_whatweb(url)
            techs.update(ww_techs)

        # Regex-based fallback always runs — adds context whatweb may miss
        re_techs = await self._detect_tech(url)
        techs.update(re_techs)

        return sorted(techs)

    async def _run_whatweb(self, url: str) -> list[str]:
        """
        Run whatweb with JSON output and extract technology names.
        whatweb --log-json=- <url> writes JSON to stdout.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                self.tools_cfg.whatweb,
                "--log-json=-",   # JSON output to stdout
                "--quiet",
                "--no-errors",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            raw = stdout.decode().strip()
            if not raw:
                return []

            # whatweb JSON: list of result objects, each has a plugins dict
            # [{"target": "...", "plugins": {"nginx": {...}, "PHP": {...}}}]
            try:
                results = json.loads(raw)
            except json.JSONDecodeError:
                # Some versions output one JSON obj per line
                techs: list[str] = []
                for line in raw.splitlines():
                    try:
                        obj = json.loads(line)
                        techs.extend(self._extract_whatweb_techs(obj))
                    except json.JSONDecodeError:
                        pass
                return techs

            techs = []
            if isinstance(results, list):
                for obj in results:
                    techs.extend(self._extract_whatweb_techs(obj))
            elif isinstance(results, dict):
                techs.extend(self._extract_whatweb_techs(results))
            return techs

        except asyncio.TimeoutError:
            log.warning("whatweb.timeout", url=url)
        except Exception as e:
            log.warning("whatweb.failed", url=url, error=str(e))
        return []

    def _extract_whatweb_techs(self, obj: dict) -> list[str]:
        """
        Extract technology names from one whatweb JSON result object.
        Each plugin name is a technology. Version strings are appended when present.
        """
        techs: list[str] = []
        plugins = obj.get("plugins", {})
        for plugin_name, plugin_data in plugins.items():
            # Skip meta-plugins that aren't real tech identifiers
            if plugin_name.lower() in {"title", "status", "html", "country",
                                        "ip", "httpserver", "redirectlocation",
                                        "uncommonheaders", "via-proxy",
                                        "cookies", "email"}:
                continue
            version = ""
            if isinstance(plugin_data, dict):
                versions = plugin_data.get("version", [])
                if versions and isinstance(versions, list):
                    version = versions[0]
            tech = f"{plugin_name}/{version}" if version else plugin_name
            techs.append(tech)
        return techs

    async def _detect_tech(self, url: str) -> list[str]:
        techs = []
        try:
            async with httpx.AsyncClient(timeout=10, verify=False,
                                          follow_redirects=True) as client:
                resp = await client.get(url)
                headers = dict(resp.headers)
                body = resp.text[:5000]

                if server := headers.get("server", ""):
                    techs.append(server)
                if powered := headers.get("x-powered-by", ""):
                    techs.append(powered)
                patterns = {
                    "WordPress": r'wp-content|wp-includes',
                    "React": r'react\.js|__react|data-reactroot',
                    "Angular": r'ng-version|angular',
                    "Vue.js": r'vue\.js|__vue',
                    "Laravel": r'laravel_session|Laravel',
                    "Django": r'csrfmiddlewaretoken|django',
                    "Rails": r'_rails|authenticity_token',
                    "Express": r'x-powered-by.*Express',
                    "Next.js": r'__NEXT_DATA__|_next/static',
                    "Nuxt.js": r'__nuxt|_nuxt/',
                    "GraphQL": r'graphql|__schema',
                    "Spring": r'JSESSIONID|spring',
                    "ASP.NET": r'__VIEWSTATE|ASP\.NET',
                    "Symfony": r'symfony|sf_redirect',
                    "Flask": r'Werkzeug|flask',
                }
                combined = body + str(headers)
                for tech, pattern in patterns.items():
                    if re.search(pattern, combined, re.IGNORECASE):
                        techs.append(tech)

        except Exception as e:
            log.debug("tech_detect.failed", url=url, error=str(e))

        return list(set(techs))

    # ─── GraphQL Detection ───────────────────────────────────────────────────

    async def _discover_endpoints(self, base_url: str) -> list[Endpoint]:
        """Run gobuster/ffuf against a host, return list of discovered endpoints."""
        endpoints: list[Endpoint] = []

        wordlist = self.recon_cfg.wordlists.get("dirs", "")
        if not Path(wordlist).exists():
            # Try alternate common wordlist locations
            for alt in ["/usr/share/wordlists/dirb/common.txt",
                        "/usr/share/dirb/wordlists/common.txt"]:
                if Path(alt).exists():
                    wordlist = alt
                    break

        if not wordlist or not Path(wordlist).exists():
            log.warning("recon.no_wordlist", tried=wordlist)
            return endpoints

        if shutil.which(self.tools_cfg.gobuster):
            endpoints = await self._run_gobuster(base_url, wordlist)
        elif shutil.which(self.tools_cfg.ffuf):
            endpoints = await self._run_ffuf(base_url, wordlist)
        else:
            log.warning("tool.missing", tool="gobuster and ffuf — skipping dir discovery")

        return endpoints

    async def _run_gobuster(self, url: str, wordlist: str) -> list[Endpoint]:
        endpoints = []
        try:
            proc = await asyncio.create_subprocess_exec(
                self.tools_cfg.gobuster, "dir",
                "-u", url,
                "-w", wordlist,
                "-q",               # quiet
                "-t", "30",
                "--timeout", f"{self.recon_cfg.timeout}s",
                "-o", "/dev/stdout",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            for line in stdout.decode().splitlines():
                # gobuster output: /path (Status: 200) [Size: 1234]
                m = re.match(r'^(/\S+)\s+\(Status:\s*(\d+)\)', line.strip())
                if m:
                    path, status = m.group(1), int(m.group(2))
                    if status not in (404, 400):
                        endpoints.append(Endpoint(
                            url=url.rstrip("/") + path,
                            status_code=status,
                        ))
        except Exception as e:
            log.warning("gobuster.failed", url=url, error=str(e))
        return endpoints

    async def _run_ffuf(self, url: str, wordlist: str) -> list[Endpoint]:
        endpoints = []
        try:
            proc = await asyncio.create_subprocess_exec(
                self.tools_cfg.ffuf,
                "-u", url.rstrip("/") + "/FUZZ",
                "-w", wordlist,
                "-t", "30",
                "-rate", str(self.cfg.vuln.ffuf_rate),
                "-timeout", str(self.cfg.vuln.ffuf_timeout),
                "-mc", "200,201,301,302,401,403",
                "-of", "csv",
                "-o", "/dev/stdout",
                "-s",   # silent
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            for line in stdout.decode().splitlines():
                if "," in line and not line.startswith("FUZZ"):
                    parts = line.split(",")
                    if len(parts) >= 4:
                        word, status = parts[0], parts[3]
                        try:
                            endpoints.append(Endpoint(
                                url=url.rstrip("/") + "/" + word,
                                status_code=int(status),
                            ))
                        except ValueError:
                            pass
        except Exception as e:
            log.warning("ffuf.failed", url=url, error=str(e))
        return endpoints

    # ─── GraphQL Detection ───────────────────────────────────────────────────

    async def _detect_graphql(self, base_url: str) -> list[str]:
        found = []
        async with httpx.AsyncClient(timeout=10, verify=False,
                                      follow_redirects=True) as client:
            for path in _GQL_PATHS:
                url = base_url.rstrip("/") + path
                try:
                    # POST introspection
                    resp = await client.post(
                        url,
                        content=_GQL_INTROSPECTION,
                        headers={"Content-Type": "application/json"},
                    )
                    body = resp.text
                    if ("__schema" in body or "__types" in body or
                            "data" in body and resp.status_code == 200):
                        found.append(url)
                        log.info("recon.graphql_found", url=url)
                    # GET probe for GraphiQL UI
                    resp2 = await client.get(url)
                    if "graphiql" in resp2.text.lower() or "graphql" in resp2.text.lower():
                        if url not in found:
                            found.append(url)
                except Exception:
                    pass
        return found
