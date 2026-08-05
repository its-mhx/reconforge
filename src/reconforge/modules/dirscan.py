"""Directory bruteforce with ffuf (fallback pure-python)."""
from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from ..core.config import EngineConfig
from ..core.models import DirectoryFinding
from ..core.runner import ToolRunner
from ..tools import python_fallbacks as fb

console = Console(stderr=True)

INTERESTING_CODES = "200,201,204,301,302,307,401,403,405"


def run(cfg: EngineConfig, runner: ToolRunner,
        alive_hosts: list[str]) -> list[DirectoryFinding]:
    if not alive_hosts or not cfg.run_dirscan:
        if not cfg.run_dirscan:
            console.print("[dim]• dirscan disabled (enable with --dirscan)[/]")
        return []

    out = runner.workdir
    findings: list[DirectoryFinding] = []

    wl: Path | None = cfg.wordlist_dirs
    if wl is None or not Path(wl).exists():
        console.print("[yellow]⚠ dir wordlist missing — skipping dirscan[/]")
        return []

    ffuf = cfg.tool("ffuf")
    targets = [f"https://{h}" for h in alive_hosts[:15]]     # cap for sanity
    for base in targets:
        if ffuf:
            console.print(f"[cyan]→ ffuf on {base}[/]")
            jout = out / f"ffuf_{base.split('//')[1].replace('.','_')}.json"
            runner.run(
                "ffuf",
                [ffuf, "-u", f"{base}/FUZZ", "-w", str(wl),
                 "-mc", INTERESTING_CODES, "-t", str(cfg.threads),
                 "-timeout", "8", "-ac", "-s", "-of", "json", "-o", str(jout)],
                timeout=cfg.timeout,
            )
            if jout.exists():
                try:
                    data = json.loads(jout.read_text())
                    for res in data.get("results", []):
                        findings.append(DirectoryFinding(
                            url=res.get("url", ""), status_code=res.get("status", 0),
                            content_length=res.get("length", 0),
                            words=res.get("words", 0), lines=res.get("lines", 0),
                            redirect=res.get("redirectlocation", "") or None,
                        ))
                except Exception:
                    pass
        else:
            console.print(f"[yellow]⚠ ffuf missing — python dirscan on {base}[/]")
            words = runner.read_lines(wl)
            for f in fb.dir_scan(base, words, threads=cfg.threads):
                findings.append(DirectoryFinding(
                    url=f["url"], status_code=f["status_code"],
                    content_length=f["content_length"], words=f["words"],
                    lines=f["lines"], redirect=f.get("redirect"),
                ))

    console.print(f"[green]✓ dirscan: {len(findings)} hits[/]")
    return findings
