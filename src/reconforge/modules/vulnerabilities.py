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
    if not nuclei:
        console.print("[yellow]⚠ nuclei missing — skipping template vuln scan[/]")
        return []
    if not targets:
        console.print("[dim]• nuclei: no targets, skipping[/]")
        return []

    # 🔒 HARD CAP: 795+ hosts × rmap dnsx probe funnels into nuclei which can
    # silently appear to hang on large scopes. Clamp at 500 templates-targets;
    # run in two passes — first 200 critical+high, then remaining with info/low.
    targets = sorted(set(targets))
    if len(targets) > 300:
        console.print(f"[yellow]nuclei target pool capped: {len(targets)} → 300 "
                      f"(vuln scan can finish in minutes this way)[/]")
        targets = targets[:300]
    if cfg.run_xss or cfg.profile == "full":
        # XSS scanning needs deeper URL list
        pass
    tfile = out / "nuclei_targets.txt"
    tfile.write_text("\n".join(targets))

    console.print(f"[cyan]→ nuclei on {len(targets)} targets "
                  f"(rl={cfg.extra.get('nuclei_rl', 100)})[/]")
    # Extended tags incl. OWASP top-10 style findings + takeovers
    base_tags = tags or (
        "exposure,misconfig,cve,default-login,tech,takeover,sqli,"
        "lfi,rce,ssrf,redirect,iot,unauthenticated,xss,xss-reflected"
    )
    from ..core.tool_flags import (detect_jsonl_flag, detect_no_color,
                                   detect_silent_flag)
    # conservative rate-limit so a home-lab ISP link doesn't collapse
    rl = max(50, min(cfg.extra.get("nuclei_rl", 100), 150))
    c = max(5, min(cfg.threads, 30))
    args = [
        nuclei,
        detect_silent_flag(nuclei),
        detect_jsonl_flag(nuclei),
        "-tags", base_tags,
        "-severity", severity,
        "-rl", str(rl),
        "-c", str(c),
        "-stats=false",
        "-ms",                    # mute status messages — faster parsing
        "-timeout", "8",
        "-retries", "0",          # 1 attempt per template, avoid hangs
        "-bulk-size", str(min(len(targets), 50)),
        "-project-path", str(out / ".nuclei"),
    ]
    nc = detect_no_color(nuclei)
    if nc:
        args.append(nc)
    runner.run(
        "nuclei",
        args,
        input_file=tfile,
        out_file=out / "nuclei.jsonl",
        timeout=cfg.timeout * 2,    # generous but capped
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


def run_nuclei_templates(cfg: EngineConfig, runner: ToolRunner,
                         targets: list[str], template_paths: list[str]) -> list[Vulnerability]:
    """Run with custom template paths (e.g., secrets, exposures)."""
    out = runner.workdir
    nuclei = cfg.tool("nuclei")
    if not nuclei or not targets:
        return []
    tfile = out / "nuclei_targets_templates.txt"
    tfile.write_text("\n".join(targets))
    args = [nuclei, "-silent", "-jsonl", "-t", ",".join(template_paths),
            "-severity", "info,low,medium,high,critical",
            "-rl", "100", "-c", "25", "-timeout", "8", "-stats=false"]
    runner.run("nuclei", args, input_file=tfile,
               out_file=out / "nuclei_custom.jsonl", timeout=cfg.timeout * 2)
    return list(runner.iter_json_lines(out / "nuclei_custom.jsonl"))

