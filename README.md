# pin0ccsAI

**Autonomous AI-powered web application and Web3 penetration testing framework.**

Built for Kali Linux. Fully local. Multi-agent. Zero hallucinated vulnerabilities.  
Optimised for 8GB RAM, CPU-only systems.

---

## Architecture

```
Target → Recon Engine → Strategy Agent → Tester Agent → Debator Agent → Report
                                              ↓                               ↓
                                     Stored XSS Engine          Learning Loop → KB
                                              ↑
                                      Knowledge Agent ← External Sources
```

### Model routing (8GB-safe)

| Agent | Model | Phase | Role |
|-------|-------|-------|------|
| Strategy | mistral:7b | Phase 2 | Crown jewel scoring, attack plan |
| Tester | qwen2.5-coder:7b | Phase 3 | Batched payload mutation, fuzzing |
| Debator | llama3.1:8b | Phase 5 | Validation, false-positive elimination |
| Knowledge | mistral:7b | `update-kb` only | CVE/writeup ingestion |

Only one model is active at any time. mixtral:8x7b has been removed.

---

## Setup

### 1. Install system tools

```bash
sudo apt update
sudo apt install -y subfinder assetfinder httpx-toolkit nuclei ffuf gobuster nmap whatweb
```

### 2. Install Ollama and pull models

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &

# Required models (3 x ~4GB each — pull before first scan)
ollama pull qwen2.5-coder:7b
ollama pull llama3.1:8b
ollama pull mistral:7b
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt --break-system-packages
```

### 4. Verify everything

```bash
python cli.py check-tools
```

---

## Usage

### Basic scan

```bash
python cli.py scan https://target.example.com
```

### Authenticated scan

```bash
# From a session file (recommended — see config/session.*.example.json)
python cli.py scan https://target.example.com --auth-file config/session.json

# Cookie string (paste from Burp)
python cli.py scan https://target.example.com \
  --auth-cookie 'session=abc123; csrf_token=xyz'

# Bearer / JWT token
python cli.py scan https://target.example.com \
  --auth-bearer 'eyJhbGciOiJIUzI1NiJ9...'

# Environment variables (no CLI flags needed)
export PIN0_AUTH_COOKIE='session=abc; csrf=xyz'
python cli.py scan https://target.example.com
```

### Resume an interrupted scan

If a scan crashes or is interrupted with Ctrl-C, resume it from the last completed phase:

```bash
python cli.py scan https://target.example.com --resume
```

Phase outputs (recon, strategy, tester) are checkpointed to SQLite automatically.
Completed phases are skipped on resume. Checkpoints are cleared after a clean run.

### Recon only (safe — no exploitation)

```bash
python cli.py recon https://target.example.com
```

### Targeted scan — specific phases only

```bash
python cli.py scan https://target.example.com \
  --skip-recon \
  --phase graphql \
  --phase auth
```

### Web3 / smart contract scan

```bash
python cli.py scan https://dapp.example.com \
  --web3-contract 0xContractAddress \
  --web3-rpc https://mainnet.infura.io/v3/YOUR_KEY
```

### Multiple targets from scope file

```bash
# scope.txt — one URL per line
python cli.py scan https://placeholder.com --scope-file scope.txt
```

### Update knowledge base

```bash
# Pull from PortSwigger, HackerOne blog, CVE feeds
python cli.py update-kb

# Ingest a specific writeup or CVE page
python cli.py update-kb --url https://hackerone.com/reports/1234567
python cli.py update-kb --url https://portswigger.net/research/some-writeup
```

### Payload cache management

```bash
# Show cache state and hit rates
python cli.py cache-stats

# Evict stale entries (older than TTL)
python cli.py clear-cache

# Force regeneration for a specific vuln type
python cli.py clear-cache --vuln-type xss
```

### System status

```bash
# Sessions, KB stats, cache state, resource config, Ollama health
python cli.py status
```

### Regenerate a report

```bash
python cli.py report <SESSION_ID> --format html --format json
```

---

## Authentication — Session File Format

Create a JSON file and pass it with `--auth-file`. Three formats supported:

**Flat dict** (most flexible):
```json
{
  "label": "admin_user",
  "cookies": {
    "session": "abc123",
    "csrf_token": "xyz789"
  },
  "headers": {
    "X-Custom-Header": "value"
  }
}
```

**Burp copy-as-curl** (paste Cookie header directly):
```json
{
  "label": "burp_session",
  "cookie_header": "session=abc123; user_id=42; csrf=xyz",
  "headers": {
    "User-Agent": "Mozilla/5.0"
  }
}
```

**Bearer / JWT shorthand**:
```json
{
  "label": "api_user",
  "bearer_token": "eyJhbGciOiJIUzI1NiJ9..."
}
```

See `config/session.*.example.json` for ready-to-fill templates.

Auth credentials are **never stored in the database or logs** — only held in memory during the scan.

---

## Configuration

All settings live in `config/config.yaml`. Key tuning options:

```yaml
# Model assignments
models:
  tester:    qwen2.5-coder:7b   # payload mutation, fuzzing
  debator:   llama3.1:8b        # validation, CVSS
  strategy:  mistral:7b         # scoring, planning
  knowledge: mistral:7b         # KB ingestion (update-kb only)

# Vulnerability detection
vuln:
  confidence_threshold: 0.75    # raise for fewer FPs, lower for more coverage
  max_payload_mutations: 10     # max AI mutations per vuln type per phase
  nuclei_severity: [critical, high, medium]

# 8GB RAM resource ceilings (LLM calls per scan)
performance:
  max_mutation_calls: 8         # mutation LLM calls (batched per vuln type)
  max_business_calls: 1         # business logic reasoning (per phase)
  max_cvss_calls: 10            # CVSS scoring (critical/high prioritised first)
  cache_ttl_hours: 72           # payload cache TTL
```

---

## How the Learning Loop Works

Confirmed findings feed back into the knowledge base automatically after each scan:

```
Scan → Debator confirms finding → LearningLoop.ingest_findings()
     → Payload stored in kb_entries (deduplicated by SHA-256)
     → PayloadCache invalidated for affected vuln types
     → Next scan's Tester Agent picks up the new payload from KB
```

What gets stored: exact payloads and technique descriptions from confirmed findings.  
What gets rejected: JWTs, session IDs (32+ hex chars), UUIDs — per-session material that would not be reusable.

---

## Scan Resume

Every phase output is checkpointed to SQLite before the next phase begins:

```
Phase 1 completes → checkpoint saved → Phase 2 starts
Phase 2 completes → checkpoint saved → Phase 3 starts
...crash or Ctrl-C...
python cli.py scan <url> --resume
→ Loads Phase 1 + 2 from checkpoint → skips directly to Phase 3
```

The resume flag finds the most recent incomplete session for the target URL. Checkpoints are deleted automatically after a clean run.

---

## Plugin System

Drop a `.py` file in `plugins/` to hook into any phase:

```python
from plugins import hookimpl

class MyPlugin:
    @hookimpl
    def on_finding_confirmed(self, finding, session_id):
        # Send Slack notification, create Jira ticket, webhook, etc.
        print(f"[+] {finding.severity.value}: {finding.title}")

    @hookimpl
    def extra_payloads(self, vuln_type, url):
        # Inject custom payloads for specific vuln types
        if vuln_type == "xss":
            return ["<x/onpointerenter=alert(1)>"]
        return []

    @hookimpl
    def on_recon_complete(self, recon_result, config):
        # Post-process recon data, add custom endpoints, etc.
        pass
```

Available hooks: `on_recon_complete`, `on_finding_raw`, `on_finding_confirmed`,
`on_scan_complete`, `extra_payloads`, `on_report_generated`.

---

## Vulnerability Coverage

| Category | Types |
|----------|-------|
| XSS | Reflected, Stored (two-request canary), DOM |
| Injection | SQLi (error-based), SSTI, LFI, SSRF, RCE |
| Access Control | IDOR (path enumeration), Broken Access Control, Auth Bypass |
| Web | Web Cache Poisoning, Business Logic, File Upload |
| API | GraphQL introspection, REST API issues, Open Redirect |
| Web3 | Signature Replay, Contract Access Control, Reentrancy, Wallet Auth Flaws |

---

## Report Output

Reports are written to `./reports/` in three formats after each scan:

- `target_TIMESTAMP.md` — Markdown (for sharing/archiving)
- `target_TIMESTAMP.html` — HTML with severity colouring (for client delivery)
- `target_TIMESTAMP.json` — Machine-readable (for pipeline integration)

Each confirmed finding contains:

| Field | Description |
|-------|-------------|
| Title | Concise vulnerability name |
| Severity | critical / high / medium / low / info |
| CVSS 3.1 | AI-assigned score and vector string |
| URL + Parameter | Exact location |
| Payload | Exact string that triggered the finding |
| Evidence | Response snippet |
| Steps to reproduce | Numbered, copy-paste ready |
| Impact | What an attacker gains |
| Remediation | Concrete fix guidance |
| Confidence | 0–100% from Debator Agent |

---

## Project Structure

```
pin0ccsAI/
├── cli.py                        ← Entry point (Click CLI)
├── requirements.txt
├── config/
│   ├── config.yaml               ← Main configuration
│   ├── session.example.json      ← Auth session template (flat dict)
│   ├── session.bearer.example.json
│   └── session.burp.example.json
├── core/
│   ├── auth_session.py           ← Auth: cookies, bearer, API keys
│   ├── checkpoint.py             ← Scan resume / phase checkpointing
│   ├── config.py                 ← YAML config loader
│   ├── database.py               ← SQLite persistence
│   ├── learning_loop.py          ← Confirmed findings → KB feedback
│   ├── llm_budget.py             ← Per-scan LLM call ceilings
│   ├── logger.py                 ← Structured logging (structlog)
│   ├── models.py                 ← Shared dataclasses
│   ├── ollama_client.py          ← Async Ollama HTTP wrapper
│   ├── orchestrator.py           ← Main scan pipeline
│   └── payload_cache.py          ← SQLite-backed mutation cache
├── agents/
│   ├── base.py                   ← BaseAgent (shared deps)
│   ├── strategy.py               ← Strategy Agent — mistral:7b
│   ├── tester.py                 ← Tester Agent — qwen2.5-coder:7b
│   ├── debator.py                ← Debator Agent — llama3.1:8b
│   └── knowledge.py              ← Knowledge Agent — mistral:7b
├── engines/
│   ├── recon.py                  ← Subfinder, httpx, nmap, whatweb
│   └── stored_xss.py             ← Two-request stored XSS canary engine
├── modules/
│   └── web3/
│       └── analyzer.py           ← Smart contract + wallet auth analysis
├── plugins/
│   └── __init__.py               ← pluggy hook system
├── reports/
│   └── generator.py              ← Markdown / HTML / JSON renderer
├── tests/
│   ├── stubs.py                  ← Shared dependency stubs
│   ├── run_tests.py              ← Test runner (no pytest needed)
│   ├── test_models.py            ← 15 tests
│   ├── test_payload_cache.py     ← 13 tests
│   ├── test_llm_budget.py        ← 12 tests
│   ├── test_database.py          ← 16 tests
│   ├── test_tester_heuristics.py ← 20 tests
│   ├── test_auth_session.py      ← 22 tests
│   ├── test_checkpoint.py        ← 18 tests
│   ├── test_learning_loop.py     ← 19 tests
│   └── test_stored_xss.py        ← 15 tests
└── data/
    └── kb/
        └── knowledge.db          ← SQLite: sessions, findings, KB, cache, checkpoints
```

---

## Running Tests

```bash
# All 150 tests
pip install -r requirements.txt --break-system-packages
python tests/run_tests.py

# Verbose output
python tests/run_tests.py --verbose

# Single suite
python tests/run_tests.py --suite auth_session
python tests/run_tests.py --suite checkpoint
python tests/run_tests.py --suite learning_loop
```

---

## Performance — 8GB RAM Notes

| Model | RAM (4-bit quant) | When active |
|-------|-------------------|-------------|
| mistral:7b | ~4.1 GB | Strategy phase + update-kb |
| qwen2.5-coder:7b | ~4.1 GB | Tester phase |
| llama3.1:8b | ~4.7 GB | Debator phase |

Only one model loads at a time. Ollama manages unloading automatically between phases. On SSD, model swap takes ~5–15s. On spinning disk, ~20–45s.

Key reductions vs naive implementation:
- Payload mutation: **one batched LLM call per vuln type** (not per URL) = ~93% fewer calls
- Payload cache: **zero LLM calls on repeat scans** for same tech stack
- Business logic: **one call per phase** (not per URL)
- CVSS scoring: **capped at 10** (critical/high prioritised)

---

## BladHound Team Notes

- All LLM inference is local via Ollama — **no data leaves the machine**
- Every finding goes through independent reproduction + LLM critique before confirmation
- Confirmed finding payloads automatically feed back to the KB for future scans
- Use `--resume` after any crash — phase outputs are checkpointed to SQLite
- Auth sessions are memory-only — never written to disk by the framework
- Web3 module covers EVM contracts (reentrancy, access control, signature replay) + wallet auth

---

*pin0ccsAI v0.3 — BladHound | Kali Linux | Fully Offline*
