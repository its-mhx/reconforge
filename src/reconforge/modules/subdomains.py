"""Subdomain enumeration: passive sources (subfinder/amass/crt.sh),
active wordlist bruteforce (puredns-style via dnsx/massdns) + permutation."""
from __future__ import annotations

from pathlib import Path

from rich.console import Console

from ..core.config import EngineConfig
from ..core.runner import ToolRunner
from ..core.utils import apex, in_scope, normalize_host
from ..tools import python_fallbacks as fb

console = Console(stderr=True)


def run(cfg: EngineConfig, runner: ToolRunner) -> dict[str, list[str]]:
    """Returns {subdomain: [sources]} — resolution happens in dns module."""
    target = apex(cfg.target)
    out = runner.workdir

    sources: dict[str, list[str]] = {}     # host -> [tool names]

    def _add(hosts, src):
        for h in hosts:
            h = normalize_host(h)
            if in_scope(h, target):
                sources.setdefault(h, [])
                if src not in sources[h]:
                    sources[h].append(src)

    # ---- passive: subfinder
    subfinder = cfg.tool("subfinder")
    if subfinder:
        console.print("[cyan]→ subfinder (passive sources)[/]")
        r = runner.run("subfinder", [subfinder, "-d", target, "-all", "-silent",
                                     "-timeout", "20"],
                       out_file=out / "subs_subfinder.txt")
        _add(runner.read_lines(out / "subs_subfinder.txt", lower=True), "subfinder")
        console.print(f"  [dim]{r.lines} results[/]")
    else:
        console.print("[yellow]⚠ subfinder missing — skipping passive API enum[/]")

    # ---- passive: amass (intel/enum passive only). Cap runtime hard —
    # amass can hang on slow upstream APIs even with -timeout.
    amass = cfg.tool("amass")
    if amass:
        console.print("[cyan]→ amass (passive)[/]")
        r = runner.run("amass", [amass, "enum", "-passive", "-d", target,
                                 "-timeout", "3", "-nocolor", "-silent"],
                       out_file=out / "subs_amass.txt",
                       timeout=120, ok_codes=(0, 1, 2, 124, 137, -9, -15))
        _add(runner.read_lines(out / "subs_amass.txt", lower=True), "amass")
        console.print(f"  [dim]{r.lines} results (rc={r.returncode})[/]")
    else:
        console.print("[yellow]⚠ amass missing — using crt.sh fallback[/]")
        _add(fb.crtsh_subdomains(target), "crtsh_py")

    # ---- crt.sh fallback always on (cheap, finds extra certs)
    console.print("[cyan]→ crt.sh (certificate transparency)[/]")
    crt = fb.crtsh_subdomains(target)
    _add(crt, "crtsh")
    console.print(f"  [dim]{len(crt)} results[/]")

    # ---- active bruteforce with wordlist (dnsx)
    if cfg.active_bruteforce and cfg.wordlist_subs:
        wl = Path(cfg.wordlist_subs)
        if wl.exists():
            console.print(f"[cyan]→ active bruteforce ({wl.name})[/]")
            words = runner.read_lines(wl, lower=True)
            candidates = [f"{w}.{target}" for w in words]
            cand_file = out / "bruteforce_candidates.txt"
            cand_file.write_text("\n".join(candidates))

            dnsx = cfg.tool("dnsx")
            if dnsx:
                from ..core.tool_flags import detect_jsonl_flag, detect_silent_flag
                jfile = out / "subs_bruteforce.jsonl"
                jfile.unlink(missing_ok=True)
                args = [dnsx,
                        detect_silent_flag(dnsx),
                        detect_jsonl_flag(dnsx),
                        "-a", "-aaaa", "-cname", "-resp", "-retry", "1",
                        "-rl", "200", "-t", str(cfg.threads)]
                r = runner.run(
                    "dnsx",
                    args,
                    input_file=cand_file,
                    out_file=jfile,
                    timeout=cfg.timeout,
                )
                for obj in runner.iter_json_lines(out / "subs_bruteforce.jsonl"):
                    host = normalize_host(obj.get("host", ""))
                    if host and in_scope(host, target):
                        _add([host], "bruteforce")
                console.print(f"  [dim]done[/]")
            else:
                # python brute resolve fallback
                console.print("  [dim]dnsx missing — python resolver fallback (slower)[/]")
                hits = fb.resolve_bulk(candidates, threads=cfg.threads * 4)
                _add(list(hits.keys()), "bruteforce_py")

    # ---- permutation (simple join of discovered tokens)
    console.print("[cyan]→ permutation scan[/]")
    before = len(sources)
    tokens: set[str] = set()
    for h in list(sources)[:2000]:
        for part in h.replace(f".{target}", "").split("."):
            if 2 <= len(part) <= 24 and part.isalnum():
                tokens.add(part)
    perm_candidates = [f"{t}.{target}" for t in sorted(tokens)]
    perm_candidates += [f"{a}-{b}.{target}" for a in sorted(tokens)[:30]
                        for b in ("dev", "stage", "stg", "test", "api", "uat")
                        if a != b]
    if perm_candidates:
        dnsx = cfg.tool("dnsx")
        perm_file = out / "perm_candidates.txt"
        perm_file.write_text("\n".join(perm_candidates))
        if dnsx:
            from ..core.tool_flags import detect_jsonl_flag, detect_silent_flag
            jfile = out / "subs_perm.jsonl"
            jfile.unlink(missing_ok=True)
            runner.run("dnsx", [dnsx, detect_silent_flag(dnsx),
                                detect_jsonl_flag(dnsx), "-a", "-resp",
                                "-rl", "200", "-t", str(cfg.threads)],
                       input_file=perm_file,
                       out_file=jfile)
            for obj in runner.iter_json_lines(jfile):
                host = normalize_host(obj.get("host", ""))
                if host and in_scope(host, target):
                    _add([host], "permutation")
        else:
            hits = fb.resolve_bulk(perm_candidates, threads=cfg.threads * 4)
            _add(list(hits.keys()), "permutation_py")
        console.print(f"  [dim]permutation added {len(sources) - before} hosts[/]")

    console.print(f"[green]✓ subdomains module: {len(sources)} unique hosts found[/]")
    return sources
