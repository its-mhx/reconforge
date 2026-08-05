"""Vulnerability scanning with nuclei + CVE correlation via cvemap/vulnx when present."""
from __future__ import annotations

from rich.console import Console

from ..core.config import EngineConfig
from ..core.models import Vulnerability
from ..core.runner import ToolRunner

console = Console(stderr=True)


def run_nuclei(cfg: EngineConfig, runner: ToolRunner,
               targets: list[str], tags: str = "",
               severity: str = "info,low,medium,high,critical") -> list[Vulnerability]:
    out = runner.workdir
    nuclei = cfg.tool("nuclei")
    if not nuclei or not targets:
        console.print("[yellow]⚠ nuclei missing — skipping template vuln scan[/]")
        return []

    tfile = out / "nuclei_targets.txt"
    tfile.write_text("\n".join(sorted(set(targets))))

    console.print(f"[cyan]→ nuclei on {len(targets)} targets[/]")
    # standard template classes (broad coverage like prettyrecon 'common vulns')
    base_tags = tags or ("exposure,misconfig,cve,default-login,tech,takeover,sqli,"
                         "lfi,rce,ssrf,redirect,iot")
    runner.run(
        "nuclei",
        [nuclei, "-silent", "-jsonl", "-tags", base_tags,
         "-severity", severity, "-rl", "150", "-c", str(cfg.threads),
         "-timeout", "10", "-retries", "1", "-no-color"],
        input_file=tfile,
        out_file=out / "nuclei.jsonl",
        timeout=cfg.timeout * 3,    # long-running phase
    )

    vulns: list[Vulnerability] = []
    seen = set()
    for obj in runner.iter_json_lines(out / "nuclei.jsonl"):
        info = obj.get("info", {})
        key = (obj.get("template-id"), obj.get("host"), obj.get("matched-at"))
        if key in seen:
            continue
        seen.add(key)
        vulns.append(Vulnerability(
            template_id=obj.get("template-id", ""),
            name=info.get("name", ""),
            severity=info.get("severity", "info"),
            host=obj.get("host", ""),
            matched_at=obj.get("matched-at"),
            description=(info.get("description") or "")[:500],
            reference=info.get("reference") or [],
            tags=info.get("tags") or [],
            extra={"matcher_name": obj.get("matcher-name", ""),
                   "extracted": str(obj.get("extracted-results", ""))[:300]},
        ))
    console.print(f"[green]✓ nuclei: {len(vulns)} findings[/]")
    return vulns


def run_cvemap(cfg: EngineConfig, runner: ToolRunner) -> list[dict]:
    """Optional: pull fresh trending CVEs for situational awareness."""
    cvemap = cfg.tool("cvemap")
    if not cvemap:
        return []
    out = runner.workdir / "cvemap.jsonl"
    runner.run("cvemap", [cvemap, "-silent", "-json", "-limit", "50"],
               out_file=out, timeout=120)
    return list(runner.iter_json_lines(out))
