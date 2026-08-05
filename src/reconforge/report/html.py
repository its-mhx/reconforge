"""Standalone HTML report generator — single self-contained file."""
from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from ..core.store import Store

CSS = """
:root{--bg:#0b0f17;--card:#131a26;--fg:#dfe6f0;--muted:#8a97a8;--accent:#4fd1c5;
--crit:#ff5277;--high:#ff9f43;--med:#feca57;--low:#54a0ff;--info:#8395a7;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 'Segoe UI',system-ui,monospace}
header{background:linear-gradient(135deg,#0d1321,#16213a);padding:28px 34px;
border-bottom:1px solid #1f2b40}
h1{margin:0;font-size:26px}h1 span{color:var(--accent)}
.meta{color:var(--muted);margin-top:6px}
.wrap{padding:24px 34px;max-width:1500px;margin:0 auto}
.card{background:var(--card);border:1px solid #1f2b40;border-radius:12px;
padding:18px;margin-bottom:22px}
.card h2{margin:0 0 12px;font-size:17px;color:var(--accent);letter-spacing:.5px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #1c2636;
vertical-align:top;word-break:break-all}
th{color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:1px;
cursor:pointer}
tr:hover td{background:#0f1622}
.sev{padding:2px 10px;border-radius:99px;font-weight:600;font-size:11px}
.critical{background:var(--crit)}.high{background:var(--high);color:#000}
.medium{background:var(--med);color:#000}.low{background:var(--low);color:#000}
.info{background:var(--info);color:#000}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}
.stat{background:#0e1524;border:1px solid #1f2b40;border-radius:10px;padding:16px}
.stat b{font-size:26px;display:block;color:var(--accent)}
.stat span{color:var(--muted);font-size:12px;text-transform:uppercase}
input[type=search]{width:100%;padding:8px 12px;margin-bottom:10px;border-radius:8px;
border:1px solid #1f2b40;background:#0e1524;color:var(--fg)}
details{margin:4px 0}summary{cursor:pointer;color:var(--accent)}
code{background:#0e1524;padding:1px 6px;border-radius:6px;font-size:12px}
footer{color:var(--muted);text-align:center;padding:30px;font-size:12px}
"""

JS = """
function filterTable(input,table){
 const q=input.value.toLowerCase();
 table.querySelectorAll("tbody tr").forEach(r=>
   r.style.display=r.textContent.toLowerCase().includes(q)?"":"none");}
function sortTable(th){
 const t=th.closest("table"),i=[...th.parentNode.children].indexOf(th),tb=t.tBodies[0];
 const rows=[...tb.rows];
 rows.sort((a,b)=>a.cells[i].textContent.localeCompare(b.cells[i].textContent,
   undefined,{numeric:true}));
 rows.forEach(r=>tb.appendChild(r));}
"""


def _esc(v) -> str:
    return html.escape("" if v is None else str(v))


def _sev(s: str) -> str:
    s = (s or "info").lower()
    return f'<span class="sev {s}">{s.upper()}</span>'


def _section(title: str, table_id: str, cols: list[str],
             rows: list[dict], cols_map: dict[str, str] | None = None,
             sev_col: str | None = None, limit: int = 300) -> str:
    body = []
    for r in rows[:limit]:
        tds = []
        for c in cols:
            v = r.get(c)
            if isinstance(v, (list, tuple)):
                v = ", ".join(str(x) for x in v)
            if c == sev_col:
                tds.append(f"<td>{_sev(v)}</td>")
            else:
                tds.append(f"<td>{_esc(v)}</td>")
        body.append(f"<tr>{''.join(tds)}</tr>")
    more = f"<p style='color:var(--muted)'>… showing {limit} of {len(rows)}</p>" if len(rows) > limit else ""
    return f"""<div class="card"><h2>{title}</h2>
<input type="search" placeholder="filter…" onkeyup="filterTable(this,document.getElementById('{table_id}'))">
<div style="max-height:520px;overflow:auto">
<table id="{table_id}"><thead><tr>{''.join(f'<th onclick="sortTable(this)">{c}</th>' for c in cols)}</tr></thead>
<tbody>{''.join(body)}</tbody></table></div>{more}</div>"""


def generate(store: Store, target: str, out_path: Path,
             stats: dict[str, int]) -> Path:
    hosts = store.table("hosts")
    vulns = sorted(store.table("vulnerabilities"),
                   key=lambda v: _rank(v.get("severity")), reverse=True)
    secrets = sorted(store.table("secrets"),
                     key=lambda v: _rank(v.get("severity")), reverse=True)
    ports = store.table("ports")
    urls = store.table("urls")
    takeovers = store.table("takeovers")
    dirs = store.table("directories")
    cloud = store.table("cloud_assets")
    dnsr = store.table("dns_records")
    js_eps = store.table("js_endpoints")

    stat_cards = "".join(
        f'<div class="stat"><b>{_esc(v)}</b><span>{_esc(k)}</span></div>'
        for k, v in stats.items() if v)

    sections = [
        _section("Vulnerabilities", "t_vulns",
                 ["severity", "name", "host", "matched_at", "description"],
                 vulns, sev_col="severity"),
        _section("Exposed Secrets", "t_secrets",
                 ["severity", "secret_type", "source_url", "value"],
                 secrets, sev_col="severity"),
        _section("Takeover", "t_to",
                 ["subdomain", "cname", "service", "reference"], takeovers),
        _section("Hosts (subdomains)", "t_hosts",
                 ["host", "ips", "alive", "status_code", "title", "tech", "cdn"], hosts),
        _section("Open Ports", "t_ports", ["host", "port", "service"], ports),
        _section("Directories", "t_dirs", ["url", "status_code", "content_length"], dirs),
        _section("URLs", "t_urls", ["url", "source", "status_code"], urls),
        _section("JS Endpoints", "t_js", ["js_url", "endpoint", "kind"], js_eps),
        _section("Cloud Assets", "t_cloud", ["kind", "url", "status"], cloud),
        _section("DNS Records", "t_dns", ["host", "record_type", "value"], dnsr),
    ]

    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>ReconForge · {html.escape(target)}</title>
<style>{CSS}</style><script>{JS}</script></head><body>
<header><h1>Recon<span>Forge</span></h1>
<div class="meta">target <code>{html.escape(target)}</code> ·
{datetime.now().strftime('%Y-%m-%d %H:%M')}</div></header>
<div class="wrap"><div class="grid">{stat_cards}</div><br>
{''.join(sections)}</div>
<footer>generated by reconforge · offline report · {len(hosts)} hosts</footer>
</body></html>"""
    out_path.write_text(doc)
    return out_path


def _rank(sev: str | None) -> int:
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return order.get((sev or "info").lower(), 0)
