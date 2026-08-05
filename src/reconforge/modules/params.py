"""Parameter discovery — arjun/paramspider if present, else mine URLs."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

from rich.console import Console

from ..core.config import EngineConfig
from ..core.models import URL
from ..core.runner import ToolRunner

console = Console(stderr=True)

COMMON_PARAMS = ["id", "page", "file", "path", "url", "redirect", "next", "return",
                 "q", "query", "search", "keyword", "name", "user", "username",
                 "email", "token", "key", "api_key", "auth", "callback", "ref",
                 "mode", "action", "cmd", "exec", "download", "document", "img",
                 "image", "view", "edit", "delete", "admin", "debug", "test",
                 "offset", "limit", "sort", "order", "filter", "category", "lang"]


def mine_params(urls: list[URL]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for u in urls:
        p = urlparse(u.url)
        base = f"{p.scheme}://{p.netloc}{p.path}"
        names = [k for k, _ in parse_qsl(p.query)]
        out.setdefault(base, [])
        for n in names:
            if n not in out[base]:
                out[base].append(n)
    return out


def run(cfg: EngineConfig, runner: ToolRunner, urls: list[URL]) -> list[URL]:
    """Return the list of URLs that actually carry parameters (gFUZZ targets)."""
    console.print("[cyan]→ parameter discovery[/]")
    endpoints_with_params = [u for u in urls if u.params]

    arjun = cfg.tool("arjun")  # almost never preinstalled; soft path
    out = runner.workdir
    if arjun and urls:
        endpoints = sorted({u.url.split("?")[0] for u in urls})[:200]
        base_file = out / "arjun_bases.txt"
        base_file.write_text("\n".join(endpoints))
        runner.run(
            "arjun",
            [arjun, "-i", str(base_file), "-oJ", str(out / "arjun.json"),
             "-t", "15", "--stable"],
            timeout=cfg.timeout,
        )
        # parsing arjun output is best-effort; we mainly rely on mined params

    console.print(f"[green]✓ params: {len(endpoints_with_params)} parameterized urls[/]")
    return endpoints_with_params
