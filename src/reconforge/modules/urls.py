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

    # ---- katana crawl on alive hosts (bounded by max-duration so crawl phase
    # is provably bounded; katana can hang for hours on third-party targets).
    katana = cfg.tool("katana")
    if katana and alive_hosts and cfg.run_katana:
        # cap hosts and depth so vuln profile phases stay snappy
        cap_hosts = min(len(alive_hosts), cfg.katana_max_hosts)
        depth = cfg.katana_depth or (2 if cfg.profile == "full" else 1)
        console.print(f"[cyan]→ katana crawl on {cap_hosts} alive hosts (d={depth}, max 4min)[/]")
        targets_file = out / "katana_targets.txt"
        targets_file.write_text("\n".join(f"https://{h}" for h in alive_hosts[:cap_hosts]))
        runner.run(
            "katana",
            [katana, "-silent", "-d", str(depth), "-jc", "-kf", "all",
             "-timeout", "10", "-c", str(min(cfg.threads, 15)),
             "-max-duration", "240"],      # hard cutoff: 4 min total
            input_file=targets_file,
            out_file=out / "urls_katana.txt",
            timeout=300,
        )
        for line in runner.read_lines(out / "urls_katana.txt"):
            _add(line, "katana")
    elif katana and alive_hosts and not cfg.run_katana:
        console.print("[dim]• katana crawl disabled (--no-katana)[/]")

    console.print(f"[green]✓ urls: {len(urls)} unique collected[/]")
    return list(urls.values())
