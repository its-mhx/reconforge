"""HTTP probing: status, title, tech stack, web server, CDN, alive hosts."""
from __future__ import annotations

import json
from rich.console import Console

from ..core.config import EngineConfig
from ..core.models import Host
from ..core.runner import ToolRunner
from ..tools import python_fallbacks as fb

console = Console(stderr=True)


def run(cfg: EngineConfig, runner: ToolRunner, hosts: list[Host]) -> list[Host]:
    if not hosts:
        return hosts
    out = runner.workdir
    hosts_file = out / "probe_input.txt"
    hosts_file.write_text("\n".join(h.host for h in hosts))

    alive: dict[str, dict] = {}
    httpx_bin = cfg.tool("httpx")
    if httpx_bin:
        console.print("[cyan]→ httpx probing (status/title/tech/cdn)[/]")
        out_file = out / "probe_httpx.jsonl"
        out_file.unlink(missing_ok=True)
        # httpx prints JSONL to stdout when -jsonl is given and no -o; writing
        # to stdout keeps compatibility across httpx versions.
        r = runner.run(
            "httpx",
            [httpx_bin, "-silent", "-jsonl", "-title", "-tech-detect", "-status-code",
             "-content-length", "-web-server", "-cdn", "-ip", "-cname",
             "-follow-redirects", "-no-color", "-random-agent",
             "-threads", str(cfg.threads), "-timeout", "8"],
            input_file=hosts_file,
            out_file=out_file,
        )
        for obj in runner.iter_json_lines(out_file):
            host = (obj.get("host") or obj.get("input", "").split(":")[0]).lower()
            url = obj.get("url", "")
            if not host and url:
                host = url.split("://", 1)[1].split("/")[0].lower()
            tech = obj.get("tech") or []
            alive[host] = {
                "alive": obj.get("status_code") is not None,
                "status_code": obj.get("status_code"),
                "title": obj.get("title") or "",
                "tech": tech,
                "webserver": obj.get("webserver") or "",
                "content_length": obj.get("content_length"),
                "cdn": obj.get("cdn_name") or obj.get("cdn") or "",
                "url": url,
            }
        console.print(f"  [dim]{len(alive)} alive[/]")
    else:
        console.print("[yellow]⚠ httpx missing — python probe fallback[/]")
        for r in fb.probe_bulk([h.host for h in hosts], threads=cfg.threads,
                               max_hosts=cfg.max_hosts_probe):
            host = r["url"].split("://", 1)[1]
            alive[host] = {
                "alive": True, "status_code": r["status_code"],
                "title": r.get("title") or "", "tech": [],
                "webserver": r.get("webserver") or "",
                "content_length": r.get("content_length"),
                "cdn": "", "url": r["url"],
            }

    # attach to hosts
    for h in hosts:
        if h.host in alive:
            meta = alive[h.host]
            h.alive = bool(meta["alive"])
            h.status_code = meta["status_code"]
            h.title = meta["title"]
            h.tech = meta["tech"]
            h.webserver = meta["webserver"]
            h.content_length = meta["content_length"]
            h.cdn = meta["cdn"]
            h.url = meta["url"]

    n_alive = sum(1 for h in hosts if h.alive)
    console.print(f"[green]✓ http probe: {n_alive}/{len(hosts)} alive[/]")
    return hosts
