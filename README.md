# ReconForge

Local, free, PrettyRecon-style attack-surface recon platform for bug bounty hunters.
Runs entirely on your machine (or VPS) — your targets and findings never leave your control.

## Features (all PrettyRecon modules + extras)

| Area | Module | Technique |
|------|--------|-----------|
| **Subdomains** | `subdomains` | subfinder, amass, crt.sh, wordlist bruteforce (dnsx), permutation |
| **DNS** | `dns` | dnsx + dnspython (A/AAAA/CNAME/MX/TXT/NS/SOA records) |
| **HTTP probe** | `http_probe` | httpx (status/title/tech/webserver/CDN) |
| **Ports** | `ports` | naabu top-1000 → nmap → pure-python connect-scan fallback |
| **URLs** | `urls` | gau + waybackurls + katana crawl |
| **JS Endpoints & Secrets** | `js_secrets` | JS download + regex extraction (endpoints/URLs) + 15 secret patterns + nuclei exposure templates |
| **Parameters** | `params` | param mining + arjun when installed |
| **XSS** | `xss` | dalfox, or reflection-probe fallback |
| **Takeover** | `takeover` | subzy + fingerprint fallback (20+ services) |
| **Cloud enum** | `cloud_enum` | S3/Azure/GCP/Firebase discovery & probing |
| **Dir scan** | `dirscan` | ffuf (or python fallback) |
| **Vuln scan** | `vulnerabilities` | nuclei (exposure/misconfig/CVE/takeover/sqli/lfi/ssrf/redirect…) |

**Extras PrettyRecon doesn't have in the same form:**

- 🔁 **Diff-based monitoring** — re-run a scan and be alerted only about *new* / *removed* assets (hosts, ports, urls, vulns, secrets) via Discord/Slack/Telegram webhook.
- 📄 **Standalone HTML report** with sortable, filterable tables (no JS CDN required).
- 🗂️ **Bulk scanning** from a file (`--domains`).
- 🛠 **Python fallbacks** for nearly every stage — works even when external tools are missing.
- 🧰 **Exports** in JSON / CSV / TXT / Excel per category.

## Install

```bash
git clone <this-repo> && cd reconforge
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
./.venv/bin/pip install -e .        # provides `reconforge` command

# (optional) install all recon tools at once
bash scripts/install_tools.sh
```

Minimum wordlists live in `wordlists/` (subs / dirs / params / resolvers).

## Usage

### Main scan
```bash
# full pipeline
reconforge scan example.com -p full

# individual profiles (subset of modules)
reconforge scan example.com -p sub        # subs + probe + takeover only
reconforge scan example.com -p basic      # + ports + urls
reconforge scan example.com -p vuln       # subs→urls→js→params→vulns
reconforge scan example.com -p monitor    # diff-focused, runs

# enable noisy optional stages
reconforge scan example.com -p full --xss --dirscan

# knobs
reconforge scan example.com -t 60 --timeout 1200 \
    --wl-subs wordlists/subdomains-top1million-5000.txt
```

### Batch scan many domains
```bash
reconforge scan --domains targets.txt -p full -t 30
```

### Browse results
```bash
reconforge show example.com --table hosts
reconforge show example.com --table vulnerabilities -n 50
reconforge show example.com --table secrets
```

### Export (PrettyRecon parity)
```bash
reconforge export example.com                     # json+csv+txt (default)
reconforge export example.com -f xlsx             # excel workbook
reconforge export example.com -f all              # everything
reconforge export example.com -c vulnerabilities -f csv
```

### HTML report
```bash
reconforge report example.com
# → output/example.com/reconforge_report.html  (sortable, filterable)
```

### 24/7 monitoring with alerts
```bash
# set a webhook (Discord/Slack/etc.) or telegram creds in .env
echo 'RECONF_WEBHOOK=https://discord.com/api/webhooks/…' >> .env

# watch several domains every hour, alert only on diffs
reconforge monitor --domains watchlist.txt --interval 3600

# one round (for cron/systemd)
reconforge monitor --domains watchlist.txt --once
```

### Check which binaries are detected
```bash
reconforge tools
```

Example `.env`:
```
RECONF_WEBHOOK=https://discord.com/api/webhooks/xxxx/yyyy
RECONF_TELEGRAM_TOKEN=123:abc
RECONF_TELEGRAM_CHAT=123456
```

## Output layout

```
output/example.com/
├── reconforge.db                # sqlite with everything
├── reconforge_report.html       # standalone report
├── exports/
│   ├── hosts.json/.csv/.txt
│   ├── urls.*  ports.*  vulnerabilities.*  secrets.*  …
│   └── reconforge_report.xlsx
└── .snapshots*/                 # diff state for monitoring
```

## Architecture at a glance

```
reconforge scan → CLI (Typer)
                └── Pipeline (orchestrator, per-profile)
                    ├── modules/*        — one file per capability
                    ├── core/runner.py   — safe subprocess wrapper
                    ├── core/store.py    — SQLite + upserts
                    ├── core/diff.py     — snapshot diffing
                    └── core/notify.py   — webhooks / telegram
```

External-tool wrappers are streaming, timeout-guarded, and fall back to
optimized pure-python implementations where feasible.

## Legal

Use only on assets you are authorized to test. ReconForge runs real traffic,
scans ports and probes endpoints — do not aim it at third parties without
explicit permission.
