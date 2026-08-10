<p align="center">
  <h1 align="center">🔍 ReconForge</h1>
  <p align="center">
    <b>Local, free, professional-grade attack-surface recon platform for bug bounty hunters.</b><br/>
    Your targets and findings never leave your machine.
  </p>
  <p align="center">
    <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
    <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blue">
    <img alt="Platform" src="https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey">
    <img alt="PRs" src="https://img.shields.io/badge/PRs-welcome-brightgreen">
  </p>
</p>

---

## Why ReconForge?

SaaS recon platforms charge $22+/month for what is, at its core, an orchestrator around free
open-source tools. ReconForge gives you **the same pipeline, locally, for free** — plus things
paid platforms don't: diff-based monitoring alerts, standalone HTML reports, Excel exports,
and principled pure-Python fallbacks so no stage ever hard-fails when a binary is missing.

**Verified real run** (owasp.org, `basic` profile, no bruteforce):

```
✓ subdomains module: 269 unique hosts found
✓ dns: 45 resolved, 26 records
✓ http probe: 44/45 alive
✓ urls: 2097 unique collected
Done in 523s
```

## Feature Matrix

| Area | Module | Technique / Engine |
|------|--------|--------------------|
| Subdomains | `subdomains` | subfinder, amass, crt.sh, wordlist bruteforce (dnsx), permutation scan |
| DNS | `dns` | dnsx + dnspython — A/AAAA/CNAME/MX/TXT/NS/SOA, wildcard filtering, NXDOMAIN pruning |
| HTTP probe | `http_probe` | httpx — status / title / tech-detect / webserver / CDN |
| Ports | `ports` | naabu → nmap → pure-Python connect scan (auto-fallback chain) |
| URLs | `urls` | gau + waybackurls + katana crawl (time-capped) |
| JS analysis | `js_secrets` | endpoint extraction + 15 secret regex classes (AWS, GCP, Stripe, JWT, private keys…) |
| Parameters | `params` | param mining from URL corpus + arjun when installed |
| XSS | `xss` | dalfox `--only-discovery` / Python reflection-probe fallback |
| Takeover | `takeover` | subzy + 12-service fingerprint fallback |
| Cloud enum | `cloud_enum` | S3 / Azure Blob / GCP / Firebase discovery & public/protected probing |
| Dir scan | `dirscan` | ffuf (autocalibration, JSON output) or Python fallback |
| Vulns/CVEs | `vulnerabilities` | nuclei (exposure, misconfig, cve, takeover, sqli, lfi, ssrf, redirect…) |
| Monitoring | `monitor` | snapshot diffing → Discord/Slack/Telegram alerts on *added/removed* assets |
| Reports | `report` | single-file standalone HTML — sortable + filterable tables, no CDN |
| Exports | `export` | JSON / CSV / TXT / XLSX per category |

## Install

```bash
git clone https://github.com/viveksec/reconforge.git
cd reconforge
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
./.venv/bin/pip install -e .
cp .env.example .env        # optional: notifications

# install external tools (optional — fallbacks exist for most stages)
bash scripts/install_tools.sh
```

Check what was detected:

```bash
reconforge tools
```

## Usage

### Scanning

```bash
# full pipeline (all modules)
reconforge scan target.com -p full

# fast presets
reconforge scan target.com -p sub       # subs + probe + takeover
reconforge scan target.com -p basic     # + ports + urls
reconforge scan target.com -p vuln      # urls→js→params→vulns only
reconforge scan target.com -p monitor   # diff-focused light run

# noisy optional modules
reconforge scan target.com -p full --xss --dirscan

# bulk mode
reconforge scan --domains watchlist.txt --threads 30

# performance knobs
reconforge scan target.com --nuclei-rl 100 --max-hosts 500 \
    --wl-subs wordlists/subdomains-top1million-5000.txt --timeout 900
```

### Results

```bash
# browse (rich tables)
reconforge show target.com --table hosts --alive -n 20
reconforge show target.com --table vulnerabilities -n 50

# plain output for scripts
reconforge show target.com --table hosts --alive --plain > alive.txt

# exports (like the paid tools)
reconforge export target.com -f all            # json+csv+txt+xlsx
reconforge export target.com -c vulnerabilities -f csv

# standalone HTML report
reconforge report target.com
# → output/target.com/reconforge_report.html
```

### Monitoring with alerts

```bash
# .env
RECONF_WEBHOOK=https://discord.com/api/webhooks/...
RECONF_TELEGRAM_TOKEN=123:abc
RECONF_TELEGRAM_CHAT=123456

# continuous loop (hourly), alert only on changes
reconforge monitor --domains watchlist.txt --interval 3600

# one round — cron-friendly
reconforge monitor --domains watchlist.txt --once
```

Example scan output:

```
→ subfinder (passive sources)
  87 results
→ permutation scan
  permutation added 174 hosts
✓ subdomains module: 261 unique hosts found
→ dnsx resolution (A/AAAA/CNAME)
✓ dns: 45 resolved, 21 records
→ httpx probing (status/title/tech/cdn)
✓ http probe: 44/45 alive
...
╭────────── Changes since last scan ──────────╮
│ hosts: +45 / -0                             │
│ urls: +2097 / -0                            │
╰──────────────────────────────────────────────╯
```

## Output layout

```
output/target.com/
├── reconforge.db                  # SQLite — everything is queryable
├── reconforge_report.html         # standalone report
├── exports/
│   ├── subdomains.json/.csv/.txt/.xlsx
│   ├── urls.*  ports.*  vulnerabilities.*  secrets.*  takeovers.*  …
│   └── reconforge_report.xlsx     # one workbook, sheet per category
├── .snapshots*/                   # diff state for monitoring
└── *.jsonl, *.txt                 # raw tool output (kept for audit)
```

## Architecture

```
reconforge CLI (Typer)
  └── Pipeline (profile-ordered stages, per-module error isolation)
      ├── modules/            one file per capability
      ├── core/runner.py      subprocess engine: timeouts, streaming, ANSI-safe JSONL parsing
      ├── core/tool_flags.py  runtime flag detection (works across tool versions)
      ├── core/store.py       SQLite upsert layer
      ├── core/diff.py        snapshot diffing (monitoring)
      └── core/notify.py      Discord/Slack/Telegram
```

Design notes:

- **Fault isolation** — every module runs behind a guard; a crashed tool never kills the scan.
- **Version-tolerant** — flag spellings (`-json` vs `-jsonl`, etc.) are auto-detected from
  `-h` output, so old/new builds of subfinder/dnsx/httpx/nuclei all work.
- **No fake "resolved" rows** — NXDOMAIN and wildcard responses are filtered in Python
  (dnsx's `-wd` is known to swallow output on some versions).
- **Bounded runtime** — nuclei targets, katana crawl and JS fetches are all hard-capped so
  big surfaces finish in minutes instead of hours. Tunable via CLI flags.

## Why local beats SaaS recon

| Capability | SaaS Platforms | ReconForge |
|---|---|---|
| 30+ recon modules | ✅ cloud | ✅ local |
| Price | $22+/mo | **free / open source** |
| Data privacy | stored on vendor servers | **100% local SQLite** |
| CSV/TXT/Excel export | ✅ | ✅ |
| Diff monitoring alerts | ✅ webhook | ✅ webhook + Telegram |
| Standalone HTML report | ❌ | ✅ |
| Wildcard/NXDOMAIN cleanup | partial | ✅ |
| Works offline for triage | ❌ | ✅ |

## Roadmap

- [ ] Screenshot module (gowitness) once installed
- [ ] Per-technology nuclei profile routing
- [ ] REST API + minimal web dashboard (opt-in)
- [ ] GitHub Action for scheduled scans in CI
- [ ] Subdomain→ASN mapping

## Contributing

PRs welcome. Please run `python -m compileall src` before committing and keep
modules single-responsibility (one file = one capability).

## Legal

Use only on assets you are authorized to test. This tool performs real scanning traffic
(port scans, HTTP probes, path fuzzing). The authors are not responsible for misuse.

## Author

Built with ☕ by [@viveksec](https://github.com/viveksec) — bug bounty hunter.
If this saved you time, consider giving it a ⭐.
