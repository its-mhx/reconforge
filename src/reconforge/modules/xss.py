"""XSS scanning — dalfox if available, else reflection probe fallback."""
from __future__ import annotations

from rich.console import Console

from ..core.config import EngineConfig
from ..core.models import Vulnerability
from ..core.runner import ToolRunner
from ..tools import python_fallbacks as fb

console = Console(stderr=True)


def run(cfg: EngineConfig, runner: ToolRunner, param_urls: list[str]) -> list[Vulnerability]:
    if not param_urls:
        return []
    out = runner.workdir
    findings: list[Vulnerability] = []

    dalfox = cfg.tool("dalfox")
    if dalfox:
        console.print(f"[cyan]→ dalfox on {len(param_urls)} parameterized urls[/]")
        urls_file = out / "dalfox_targets.txt"
        urls_file.write_text("\n".join(sorted(set(param_urls))[:2000]))
        runner.run(
            "dalfox",
            [dalfox, "file", str(urls_file), "--silence-force", "--format", "json",
             "--mass-worker", str(cfg.threads), "--timeout", "8",
             "--only-discovery", "--skip-bav", "--no-spinner"],
            out_file=out / "dalfox.json",
            timeout=cfg.timeout * 2,
        )
        data = (out / "dalfox.json")
        if data.exists():
            try:
                import json
                raw = json.loads(data.read_text() or "[]")
                for item in raw if isinstance(raw, list) else [raw]:
                    findings.append(Vulnerability(
                        template_id="dalfox",
                        name="Reflected/Stored XSS (dalfox)",
                        severity=item.get("severity", "medium"),
                        host=item.get("data", "").split("?")[0],
                        matched_at=item.get("data", ""),
                        description=f"type={item.get('type','R')} param={item.get('param','')}",
                        tags=["xss", "dalfox"],
                    ))
            except Exception:
                pass
    else:
        console.print("[yellow]⚠ dalfox missing — python reflection probe[/]")
        for h in fb.xss_reflection(param_urls, threads=cfg.threads):
            findings.append(Vulnerability(
                template_id="reflection_xss",
                name="Reflected XSS (probe)",
                severity="medium",
                host=h["url"].split("?")[0], matched_at=h["url"],
                description=f"param={h['param']} payload={h['payload']}",
                tags=["xss", "reflection"],
            ))

    console.print(f"[green]✓ xss: {len(findings)} potential reflections[/]")
    return findings
