"""Subdomain takeover detection — subzy primary, fingerprint fallback."""
from __future__ import annotations

import re
from rich.console import Console

from ..core.config import EngineConfig
from ..core.models import TakeoverFinding
from ..core.runner import ToolRunner
from ..tools import python_fallbacks as fb

console = Console(stderr=True)


def run(cfg: EngineConfig, runner: ToolRunner,
        subdomains: list[str],
        cnames: dict[str, str]) -> list[TakeoverFinding]:
    if not subdomains:
        return []
    out = runner.workdir
    subs_file = out / "takeover_subs.txt"
    subs_file.write_text("\n".join(sorted(set(subdomains))))

    findings: list[TakeoverFinding] = []

    subzy = cfg.tool("subzy")
    if subzy:
        console.print(f"[cyan]→ subzy on {len(subdomains)} subdomains[/]")
        runner.run(
            "subzy",
            [subzy, "run", "--targets", str(subs_file),
             "--concurrency", str(cfg.threads), "--timeout", "8",
             "--hide_fails"],
            out_file=out / "takeover_subzy.txt",
            timeout=cfg.timeout,
        )
        text = (out / "takeover_subzy.txt").read_text(errors="replace") \
            if (out / "takeover_subzy.txt").exists() else ""
        for line in text.splitlines():
            if "VULNERABLE" in line.upper():
                m = re.search(r"((?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})", line)
                sub = m.group(1) if m else line.strip()
                sub = sub.replace("https://", "").replace("http://", "").strip("/")
                svc_match = re.search(r"\[([A-Za-z0-9\-\s]+)\]", line)
                svc = svc_match.group(1) if svc_match else ""
                findings.append(TakeoverFinding(
                    subdomain=sub, cname=cnames.get(sub, ""), service=svc,
                    vulnerable=True, reference=line.strip()))
    else:
        console.print("[yellow]⚠ subzy missing — fingerprint fallback[/]")
        for r in fb.takeover_check(cnames or {s: "" for s in subdomains},
                                   threads=cfg.threads):
            findings.append(TakeoverFinding(**r))

    console.print(f"[green]✓ takeover: {len(findings)} candidates[/]")
    return findings
