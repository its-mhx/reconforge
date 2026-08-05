"""URL collection from archives (wayback/gau) + live crawling (katana)."""
from __future__ import annotations

from rich.console import Console

from ..core.config import EngineConfig
from ..core.models import URL
from ..core.runner import ToolRunner
from ..core.utils import apex, url_params
from ..tools import python_fallbacks as fb

console = Console(stderr=True)


def run(cfg: EngineConfig, runner: ToolRunner,
        alive_hosts: list[str]) -> list[URL]:
    target = apex(cfg.target)
    out = runner.workdir
    urls: dict[str, URL] = {}

    def _add(u: str, source: str):
        u = u.strip()
        if not u or not u.startswith(("http://", "https://")):
            return
        if target not in u:
            return
        if u in urls:
            # merge source labels
            if source not in urls[u].source:
                urls[u].source += f",{source}"
        else:
            urls[u] = URL(url=u, source=source, params=url_params(u))

    # ---- gau
    gau = cfg.tool("gau")
    if gau:
        console.print("[cyan]→ gau (wayback/commoncrawl/otx/alienvault)[/]")
        r = runner.run("gau", [gau, "--threads", "5", target],
                       out_file=out / "urls_gau.txt", timeout=cfg.timeout)
        for line in runner.read_lines(out / "urls_gau.txt"):
            _add(line, "gau")
        console.print(f"  [dim]{r.lines} lines[/]")
    else:
        console.print("[yellow]⚠ gau missing — python wayback fallback[/]")
        for u in fb.wayback_urls(target):
            _add(u, "wayback_py")

    # ---- waybackurls (fast, single-source but deep)
    wb = cfg.tool("waybackurls")
    if wb:
        console.print("[cyan]→ waybackurls[/]")
        (out / "urls_wayback.txt").unlink(missing_ok=True)
        runner.run("waybackurls", [wb], input_text=target,
                   out_file=out / "urls_wayback.txt", timeout=180)
        for line in runner.read_lines(out / "urls_wayback.txt"):
            _add(line, "wayback")

    # ---- katana crawl on alive hosts (depth 2)
    katana = cfg.tool("katana")
    if katana and alive_hosts:
        console.print(f"[cyan]→ katana crawl on {len(alive_hosts)} alive hosts (d=2)[/]")
        targets_file = out / "katana_targets.txt"
        targets_file.write_text("\n".join(f"https://{h}" for h in alive_hosts[:200]))
        runner.run(
            "katana",
            [katana, "-silent", "-d", "2", "-jc", "-kf", "all",
             "-timeout", "10", "-c", str(cfg.threads)],
            input_file=targets_file,
            out_file=out / "urls_katana.txt",
        )
        for line in runner.read_lines(out / "urls_katana.txt"):
            _add(line, "katana")

    console.print(f"[green]✓ urls: {len(urls)} unique collected[/]")
    return list(urls.values())
