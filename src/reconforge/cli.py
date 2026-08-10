"""ReconForge — command-line interface."""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from .core.config import EngineConfig
from .core.store import Store
from .core.utils import valid_domain
from .pipeline import Pipeline, PROFILES

app = typer.Typer(
    name="reconforge",
    help="Local attack-surface recon platform — OSINT-grade features, local & free.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    pretty_exceptions_show_locals=False,
)
console = Console()


def _clean_target(raw: str) -> str:
    """Accept https?://host, host/path, host,, strip scheme+path+port."""
    import re as _re
    raw = raw.strip().lower()
    raw = _re.sub(r"^https?://", "", raw)
    raw = raw.split("/", 1)[0]
    raw = raw.rstrip(".")
    # strip port if present
    if ":" in raw and not raw.count(":") > 1:
        raw = raw.split(":")[0]
    return raw


def _cfg(target: str, profile: str, **kw) -> EngineConfig:
    cfg = EngineConfig(target=target, profile=profile, **kw)
    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    return cfg


# ------------------------------------------------------------------ scan
@app.command()
def scan(
    target: Optional[str] = typer.Argument(None, help="Target domain (example.com)"),
    domains: Optional[Path] = typer.Option(None, "--domains", "-D", exists=True,
                                           help="File with one domain per line (batch mode)"),
    profile: str = typer.Option("full", "--profile", "-p",
                                help=f"Profile: {'|'.join(PROFILES)}"),
    output: Path = typer.Option(Path("output"), "--output", "-o"),
    threads: int = typer.Option(40, "--threads", "-t"),
    timeout: int = typer.Option(900, "--timeout"),
    wordlist_subs: Optional[Path] = typer.Option(None, "--wl-subs", help="Subdomain wordlist"),
    wordlist_dirs: Optional[Path] = typer.Option(None, "--wl-dirs", help="Dir wordlist"),
    resolvers: Optional[Path] = typer.Option(None, "--resolvers"),
    proxy: Optional[str] = typer.Option(None, "--proxy"),
    no_bruteforce: bool = typer.Option(False, "--no-bruteforce"),
    run_xss: bool = typer.Option(False, "--xss", help="Enable XSS scanning (noisy)"),
    nuclei_rl: int = typer.Option(100, "--nuclei-rl", help="Nuclei req/sec rate limit"),
    max_hosts: int = typer.Option(500, "--max-hosts", help="Cap alive hosts for probing/vuln scan"),
    run_dirscan: bool = typer.Option(False, "--dirscan", help="Enable dir bruteforce"),
    no_nuclei: bool = typer.Option(False, "--no-nuclei"),
    no_katana: bool = typer.Option(False, "--no-katana", help="Disable katana crawl"),
    katana_max_hosts: int = typer.Option(20, "--katana-max-hosts"),
    katana_depth: Optional[int] = typer.Option(None, "--katana-depth"),
    webhook: Optional[str] = typer.Option(None, "--webhook", help="Discord/Slack webhook URL"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Run a recon scan against one domain, or many via --domains."""
    if profile not in PROFILES:
        raise typer.BadParameter(f"choose from: {', '.join(PROFILES)}")
    if webhook:
        os.environ["RECONF_WEBHOOK"] = webhook

    def _mk(t: str) -> EngineConfig:
        cfg = _cfg(t, profile, output_root=output, threads=threads, timeout=timeout,
                    wordlist_subs=wordlist_subs, wordlist_dirs=wordlist_dirs,
                    resolvers=resolvers, proxy=proxy,
                    active_bruteforce=not no_bruteforce, run_xss=run_xss,
                    run_dirscan=run_dirscan, run_nuclei=not no_nuclei,
                    run_katana=not no_katana,
                    katana_max_hosts=katana_max_hosts,
                    katana_depth=katana_depth)
        cfg.extra["nuclei_rl"] = nuclei_rl
        cfg.extra["max_hosts_probe"] = max_hosts
        return cfg

    if domains:
        lines = [_clean_target(l) for l in domains.read_text().splitlines()
                 if l.strip()]
        console.print(f"[bold]{len(lines)} targets queued[/]")
        for t in lines:
            if valid_domain(t):
                stats = Pipeline(_mk(t), verbose=verbose).run()
                console.print(f"[green]✓ {t}: {stats.get('subdomains', 0)} subs[/]\n")
            else:
                console.print(f"[red]skip invalid domain {t}[/]")
        return

    if not target:
        raise typer.BadParameter("provide a TARGET or --domains file")
    target = _clean_target(target)
    if not valid_domain(target):
        raise typer.BadParameter(f"'{target}' is not a valid domain")
    Pipeline(_mk(target), verbose=verbose).run()


# ------------------------------------------------------------------ show
@app.command()
def show(
    target: str,
    output: Path = typer.Option(Path("output"), "--output", "-o"),
    table: str = typer.Option("hosts", "--table", "-t",
                              help="hosts|urls|ports|vulnerabilities|secrets|takeovers|directories|cloud_assets|dns_records|js_endpoints"),
    limit: int = typer.Option(30, "--limit", "-n"),
    alive_only: bool = typer.Option(False, "--alive", help="For hosts table, only alive ones"),
    plain: bool = typer.Option(False, "--plain", help="Just print key column (scripting)"),
):
    """Browse stored results of a previous scan."""
    import json as _json
    db = output / target / "reconforge.db"
    if not db.exists():
        console.print(f"[red]No database at {db}[/]")
        raise typer.Exit(1)
    store = Store(db)
    rows = store.table(table)
    if alive_only and table == "hosts":
        rows = [r for r in rows if r.get("alive")]

    # friendly per-table layouts
    LAYOUT = {
        "hosts": ["host", "alive", "status_code", "title"],
        "urls": ["url", "source", "status_code"],
        "ports": ["host", "port", "service"],
        "vulnerabilities": ["severity", "name", "host", "matched_at"],
        "secrets": ["severity", "secret_type", "source_url", "value"],
        "takeovers": ["subdomain", "cname", "service"],
        "directories": ["url", "status_code", "content_length"],
        "cloud_assets": ["kind", "url", "status"],
        "dns_records": ["host", "record_type", "value"],
        "js_endpoints": ["js_url", "endpoint", "kind"],
    }

    def _fmt(v):
        if v is None or v == "":
            return ""
        if isinstance(v, str) and v.startswith("[") and v.endswith("]"):
            try:
                arr = _json.loads(v)
                if isinstance(arr, list):
                    return ", ".join(str(x) for x in arr[:2]) + (f"+{len(arr)-2}" if len(arr) > 2 else "")
                return str(v)[:60]
            except Exception:
                return str(v)[:60]
        s = str(v)
        return s[:80] + ("…" if len(s) > 80 else "")

    if plain:
        key = LAYOUT.get(table, ["host"])[0]
        for r in rows[:limit]:
            console.print(r.get(key, ""))
        return

    cols = LAYOUT.get(table)
    if not cols or not rows:
        cols = [c for c in rows[0].keys() if c not in ("hash", "extra", "description")] if rows else []
    t = Table(title=f"{table} ({len(rows)}{' — alive only' if alive_only else ''})",
              highlight=True, expand=True)
    for c in cols:
        # give fewer columns more room
        t.add_column(c, overflow="ellipsis", ratio=1, max_width=60)
    for r in rows[:limit]:
        t.add_row(*[_fmt(r.get(c)) for c in cols])
    console.print(t)
    if len(rows) > limit:
        console.print(f"[dim]… and {len(rows)-limit} more (raise --limit)[/]")


# ------------------------------------------------------------------ export
@app.command()
def export(
    target: str = typer.Argument(...),
    fmt: str = typer.Option("json,csv,txt", "--fmt", "-f",
                            help="comma list: json,csv,txt,xlsx or 'all'"),
    category: str = typer.Option("all", "--category", "-c"),
    output: Path = typer.Option(Path("output"), "--output", "-o"),
):
    """Export results to json/csv/txt/xlsx per category."""
    from .exporters import CATEGORY_FILES, export_all, export_category
    db = output / target / "reconforge.db"
    store = Store(db)
    out_dir = output / target
    fmts = ["json", "csv", "txt", "xlsx"] if fmt == "all" else [f.strip() for f in fmt.split(",")]
    paths = []
    if category == "all":
        paths = export_all(store, out_dir, fmts)
    else:
        for f in fmts:
            p = export_category(store, out_dir, f, category)
            if p:
                paths.append(p)
    for p in paths:
        console.print(f"[green]✓ {p}[/]")


# ------------------------------------------------------------------ report
@app.command()
def report(
    target: str,
    output: Path = typer.Option(Path("output"), "--output", "-o"),
):
    """Generate a standalone HTML report."""
    from .report.html import generate
    db = output / target / "reconforge.db"
    store = Store(db)
    path = out_dir = output / target
    stats = {k: store.count(k) for k in ("hosts", "ports", "urls", "vulnerabilities",
                                         "secrets", "takeovers", "directories", "cloud_assets")}
    p = generate(store, target, path / "reconforge_report.html", stats)
    console.print(f"[green]✓ report → {p}[/]")


# ------------------------------------------------------------------ monitor
@app.command()
def monitor(
    domains: Path = typer.Option(..., "--domains", "-D", exists=True,
                                 help="File with one domain per line"),
    interval: int = typer.Option(3600, "--interval", "-i", help="Seconds between rounds"),
    profile: str = typer.Option("monitor", "--profile", "-p"),
    output: Path = typer.Option(Path("output"), "--output", "-o"),
    webhook: Optional[str] = typer.Option(None, "--webhook"),
    once: bool = typer.Option(False, "--once", help="Run one round and exit"),
):
    """Continuous monitoring loop with diff-based alerts."""
    import time
    if webhook:
        os.environ["RECONF_WEBHOOK"] = webhook
    lines = [l.strip() for l in domains.read_text().splitlines() if l.strip()]
    console.print(f"[bold]Monitoring {len(lines)} domain(s) every {interval}s[/]")
    while True:
        for t in lines:
            if valid_domain(t):
                Pipeline(_cfg(t, profile, output_root=output)).run()
        if once:
            break
        console.print(f"[dim]sleeping {interval}s…[/]")
        time.sleep(interval)


# ------------------------------------------------------------------ tools
@app.command()
def tools():
    """Show which external tools are detected."""
    from .core.tools import TOOLS
    from .core.config import which
    t = Table(title="External tools")
    t.add_column("tool"); t.add_column("status"); t.add_column("path")
    for name, spec in TOOLS.items():
        p = which(spec.binary)
        t.add_row(name,
                  "[green]OK[/]" if p else "[red]missing[/]",
                  p or ("python fallback" if spec.has_py_fallback else "—"))
    console.print(t)


if __name__ == "__main__":
    app()
