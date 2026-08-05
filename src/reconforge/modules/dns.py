"""DNS resolution & record harvesting (A/AAAA/CNAME/MX/TXT/NS/SOA)."""
from __future__ import annotations

import dns.resolver
from rich.console import Console

from ..core.config import EngineConfig
from ..core.models import DNSRecord, Host
from ..core.runner import ToolRunner
from ..core.utils import apex, normalize_host
from ..tools import python_fallbacks as fb

console = Console(stderr=True)
RTYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]


def _query(name: str, rtype: str) -> list[str]:
    try:
        ans = dns.resolver.resolve(name, rtype, lifetime=6)
        return [str(r).strip('"') for r in ans]
    except Exception:
        return []


def run(cfg: EngineConfig, runner: ToolRunner,
        subdomain_sources: dict[str, list[str]]) -> tuple[list[Host], list[DNSRecord]]:
    """Resolve all subdomains; enrich with IPs + all record types."""
    target = apex(cfg.target)
    out = runner.workdir
    hosts: dict[str, Host] = {}
    records: list[DNSRecord] = []

    subs_file = out / "all_subdomains.txt"
    subs_file.write_text("\n".join(sorted(subdomain_sources)))

    dnsx = cfg.tool("dnsx")
    resolved: dict[str, dict] = {}
    if dnsx:
        console.print("[cyan]→ dnsx resolution (A/AAAA/CNAME + wildcard filter)[/]")
        jfile = out / "resolved.jsonl"
        jfile.unlink(missing_ok=True)
        runner.run(
            "dnsx",
            [dnsx, "-silent", "-jsonl", "-a", "-aaaa", "-cname", "-resp", "-retry", "1",
             "-wd", target, "-rl", "300", "-t", str(cfg.threads)],
            input_file=subs_file,
            out_file=jfile,
        )
        for obj in runner.iter_json_lines(jfile):
            host = normalize_host(obj.get("host", ""))
            if not host:
                continue
            ips = sorted(set((obj.get("a") or []) + (obj.get("aaaa") or [])))
            cnames = obj.get("cname") or []
            resolved[host] = {"ips": ips, "cname": cnames[0] if cnames else None}
    else:
        console.print("[yellow]⚠ dnsx missing — python resolver fallback[/]")
        res = fb.resolve_bulk(subdomain_sources.keys(), threads=cfg.threads * 4)
        for h, ips in res.items():
            resolved[h] = {"ips": ips, "cname": None}

    # build Host models
    for h, meta in resolved.items():
        hosts[h] = Host(
            host=h, ips=meta["ips"], cname=meta["cname"],
            sources=subdomain_sources.get(h, ["unknown"]),
        )

    # full record set for the apex + interesting subs (mail/NS context)
    console.print("[cyan]→ harvesting DNS records (A/AAAA/MX/TXT/NS/SOA/CNAME)[/]")
    interesting = {target}
    interesting.update(h for h in resolved if any(
        kw in h for kw in ("mail", "mx", "vpn", "remote", "webmail")))  # noqa: E501
    for name in sorted(interesting)[:200]:
        for rt in RTYPES:
            for val in _query(name, rt):
                records.append(DNSRecord(host=name, record_type=rt, value=val))

    console.print(f"[green]✓ dns: {len(hosts)} resolved, {len(records)} records[/]")
    return list(hosts.values()), records
