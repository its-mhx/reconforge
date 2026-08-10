"""DNS resolution & record harvesting (A/AAAA/CNAME/MX/TXT/NS/SOA).

Key behaviors:
 * Wildcard domains: subfinder-amassed garbage (random-suffix subs on a
   wildcard zone) is filtered out by querying a known-random subdomain.
 * NXDOMAIN rows are NOT inserted.
 * Pur python fallback when dnsx is missing/broken.
"""
from __future__ import annotations

import re

import dns.resolver
from rich.console import Console

from ..core.config import EngineConfig
from ..core.models import DNSRecord, Host
from ..core.runner import ToolRunner
from ..core.utils import apex, normalize_host
from ..tools import python_fallbacks as fb

console = Console(stderr=True)
RTYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
IPV6 = re.compile(r"^[0-9a-fA-F:]+$")


def _query(name: str, rtype: str) -> list[str]:
    try:
        ans = dns.resolver.resolve(name, rtype, lifetime=6)
        return [str(r).strip('"') for r in ans]
    except Exception:
        return []


def _extract_ips(obj: dict) -> set[str]:
    """Pull IPv4/IPv6 out of dnsx JSONL row, whatever schema variant."""
    ips: set[str] = set()
    for k in ("a", "aaaa"):
        for v in obj.get(k) or []:
            if isinstance(v, str) and (IPV4.match(v) or IPV6.match(v)):
                ips.add(v.lower())
    resp = obj.get("resp") or {}
    if isinstance(resp, dict):
        for k in ("a", "aaaa"):
            for v in resp.get(k) or []:
                if isinstance(v, str):
                    ips.add(v.lower())
    return ips


def _collapse_wildcards(hosts: dict[str, dict], apex_domain: str,
                        threads: int) -> int:
    """Remove hosts that only exist because of a *.apex wildcard entry."""
    probe = f"rforge-wc-{__import__('random').randint(10**8, 10**9 - 1)}.{apex_domain}"
    wildcard_ips = set(fb.resolve_bulk([probe], threads=1).get(probe, []))
    if not wildcard_ips:
        return 0
    removed = 0
    for h in list(hosts):
        ips = set(hosts[h]["ips"])
        if ips and ips.issubset(wildcard_ips):
            del hosts[h]
            removed += 1
    if removed:
        console.print(f"  [dim]wildcard filter: removed {removed} noise hosts[/]")
    return removed


def run(cfg: EngineConfig, runner: ToolRunner,
        subdomain_sources: dict[str, list[str]]) -> tuple[list[Host], list[DNSRecord]]:
    """Resolve all subdomains; enrich with IPs + all record types."""
    target = apex(cfg.target)
    out = runner.workdir
    hosts: dict[str, Host] = {}
    records: list[DNSRecord] = []

    subs_file = out / "all_subdomains.txt"
    subs_file.write_text("\n".join(sorted(subdomain_sources)))

    resolved: dict[str, dict] = {}
    dnsx = cfg.tool("dnsx")
    if dnsx:
        console.print("[cyan]→ dnsx resolution (A/AAAA/CNAME)[/]")
        jfile = out / "resolved.jsonl"
        jfile.unlink(missing_ok=True)
        from ..core.tool_flags import detect_jsonl_flag, detect_silent_flag
        runner.run(
            "dnsx",
            [dnsx, detect_silent_flag(dnsx), detect_jsonl_flag(dnsx),
             "-a", "-aaaa", "-cname", "-resp", "-retry", "1",
             "-rl", "300", "-t", str(cfg.threads)],
            input_file=subs_file,
            out_file=jfile,
        )
        for obj in runner.iter_json_lines(jfile):
            host = normalize_host(obj.get("host") or obj.get("input") or
                                  obj.get("name") or "")
            if not host:
                continue
            status = str(obj.get("status_code", "")).upper()
            ips = _extract_ips(obj)
            cname_primary = None
            for c in [obj.get("cname"), (obj.get("resp") or {}).get("cname")
                      if isinstance(obj.get("resp"), dict) else None]:
                if isinstance(c, list) and c:
                    cname_primary = c[0].rstrip(".")
                elif isinstance(c, str):
                    cname_primary = c.rstrip(".")
                if cname_primary:
                    break
            # Keep NXDOMAIN rows only when we have a cname (used by takeover)
            if status == "NXDOMAIN" and not cname_primary:
                continue
            if not ips and not cname_primary:
                continue
            resolved[host] = {"ips": sorted(ips), "cname": cname_primary}

        # if dnsx produced very few valid rows, try python fallback too
        if len(resolved) < max(1, len(subdomain_sources) // 50):
            console.print(f"  [yellow]dnsx gave {len(resolved)} rows — using "
                          f"python resolver as well[/]")
            fallback = fb.resolve_bulk(subdomain_sources.keys(),
                                       threads=cfg.threads * 4)
            for h, ips in fallback.items():
                if h not in resolved:
                    resolved[h] = {"ips": ips, "cname": None}
    else:
        console.print("[yellow]⚠ dnsx missing — python resolver fallback[/]")
        fallback = fb.resolve_bulk(subdomain_sources.keys(),
                                   threads=cfg.threads * 4)
        for h, ips in fallback.items():
            resolved[h] = {"ips": ips, "cname": None}

    # wildcard filtering (cheap and important for clean output)
    _collapse_wildcards(resolved, target, cfg.threads)

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
        kw in h for kw in ("mail", "mx", "vpn", "remote", "webmail")))
    for name in sorted(interesting)[:200]:
        for rt in RTYPES:
            for val in _query(name, rt):
                records.append(DNSRecord(host=name, record_type=rt, value=val))

    console.print(f"[green]✓ dns: {len(hosts)} resolved, {len(records)} records[/]")
    return list(hosts.values()), records
