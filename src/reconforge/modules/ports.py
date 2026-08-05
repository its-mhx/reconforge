"""Port scanning using naabu (preferred) with nmap/Python fallbacks."""
from __future__ import annotations

import re

from rich.console import Console

from ..core.config import EngineConfig
from ..core.models import Port
from ..core.runner import ToolRunner
from ..tools import python_fallbacks as fb

console = Console(stderr=True)


def run(cfg: EngineConfig, runner: ToolRunner, ips_and_hosts: list[str]) -> list[Port]:
    if not ips_and_hosts:
        return []
    out = runner.workdir
    targets = out / "port_targets.txt"
    targets.write_text("\n".join(sorted(set(ips_and_hosts))))

    naabu = cfg.tool("naabu")
    ports: dict[tuple[str, int, str], Port] = {}

    if naabu:
        console.print(f"[cyan]→ naabu top-1000 on {len(ips_and_hosts)} targets[/]")
        runner.run(
            "naabu",
            [naabu, "-silent", "-top-ports", "1000", "-rate", "3000",
             "-c", str(cfg.threads), "-scan-type", "c",  # CONNECT scan (no root)
             "-timeout", "1500"],
            input_file=targets,
            out_file=out / "ports_naabu.txt",
            timeout=cfg.timeout,
        )
        for line in runner.read_lines(out / "ports_naabu.txt"):
            # format: host:port
            m = re.match(r"^(.+?):(\d+)$", line)
            if not m:
                continue
            host, port = m.group(1), int(m.group(2))
            ports[(host, port, "tcp")] = Port(host=host, port=port)
    else:
        nmap = cfg.tool("nmap")
        if nmap:
            console.print("[yellow]⚠ naabu missing — nmap fallback (slower)[/]")
            xml = out / "ports_nmap.xml"
            runner.run(
                "nmap",
                [nmap, "-sT", "--top-ports", "300", "-T4", "-oX", str(xml),
                 "-iL", str(targets)],
                timeout=cfg.timeout,
            )
            for m in re.finditer(
                r'<address addr="([^"]+)"[^>]*/>.*?<port protocol="(\w+)" portid="(\d+)">\s*<state state="open"',
                xml.read_text(errors="replace") if xml.exists() else "",
                re.S,
            ):
                ip, proto, port = m.group(1), m.group(2), int(m.group(3))
                ports[(ip, port, proto)] = Port(host=ip, ip=ip, port=port, protocol=proto)
        else:
            console.print("[yellow]⚠ no naabu/nmap — python connect scan (top-100)[/]")
            for r in fb.scan_ports(ips_and_hosts, top=100):
                ports[(r["host"], r["port"], "tcp")] = Port(
                    host=r["host"], ip=r.get("ip"), port=r["port"], service=r.get("service"))

    console.print(f"[green]✓ ports: {len(ports)} open[/]")
    return list(ports.values())
