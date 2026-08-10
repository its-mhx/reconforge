"""Pipeline orchestrator — maps profile presets to ordered module execution.

Every module runs inside a `_safe_step()` wrapper: failures are reported but
never crash the whole pipeline (full fault-tolerant resilience)."""
from __future__ import annotations

import time
from typing import Any, Callable

from rich.console import Console
from rich.panel import Panel

from .core.config import EngineConfig
from .core.diff import diff_with_previous, rotate_snapshots, take_snapshot
from .core.models import Host
from .core.notify import Notifier
from .core.runner import ToolRunner
from .core.store import Store
from .core.utils import apex
from .modules import cloud_enum, dirscan, dns, http_probe, js_secrets, params
from .modules import ports, subdomains, takeover, urls as urls_mod
from .modules import vulnerabilities, xss

console = Console(stderr=True)

PROFILES: dict[str, list[str]] = {
    "sub":     ["subdomains", "dns", "http_probe", "takeover"],
    "basic":   ["subdomains", "dns", "http_probe", "ports", "urls", "takeover"],
    "vuln":    ["subdomains", "dns", "http_probe", "urls", "js_secrets",
                "params", "xss", "takeover", "vulnerabilities"],
    "full":    ["subdomains", "dns", "http_probe", "ports", "urls",
                "js_secrets", "params", "xss", "takeover", "cloud_enum",
                "dirscan", "vulnerabilities"],
    "monitor": ["subdomains", "dns", "http_probe", "urls", "js_secrets",
                "takeover", "vulnerabilities"],
}


class Pipeline:
    def __init__(self, cfg: EngineConfig, verbose: bool = False):
        self.cfg = cfg
        self.out_dir = cfg.out_dir
        self.runner = ToolRunner(self.out_dir, timeout=cfg.timeout, verbose=verbose)
        self.store = Store(cfg.db_path)
        self.notifier = Notifier(cfg.notify_webhook,
                                 cfg.telegram_token, cfg.telegram_chat)
        self.errors: list[tuple[str, str]] = []      # (step, message)

    # ------------------------------------------------------------------
    def _safe_step(self, name: str, fn: Callable[..., Any], *args, **kwargs) -> Any:
        """Run a module; on exception record it and return None."""
        try:
            return fn(*args, **kwargs)
        except KeyboardInterrupt:
            raise
        except Exception as e:  # noqa: BLE001
            self.errors.append((name, str(e)))
            console.print(f"[red]✗ {name} failed: {e}[/]")
            if self.runner.verbose:
                console.print_exception()
            return None

    # ------------------------------------------------------------------
    def run(self) -> dict[str, int]:
        cfg = self.cfg
        cfg.target = apex(cfg.target)
        steps = PROFILES[cfg.profile]

        console.print(Panel.fit(
            f"[bold]Target:[/] {cfg.target}\n[bold]Profile:[/] {cfg.profile}\n"
            f"[bold]Modules:[/] {' → '.join(steps)}",
            title="ReconForge", border_style="green"))

        self.store.start_scan(cfg.target, cfg.profile)
        self.notifier.send_scan_start(cfg.target, cfg.profile)
        started = time.time()

        hosts: list[Host] = []
        alive_hosts: list[str] = []
        cnames: dict[str, str] = {}
        url_objs = []
        all_vulns = []

        try:
            # ---------------- subdomains
            sub_sources = {}
            if "subdomains" in steps:
                sub_sources = self._safe_step(
                    "subdomains", subdomains.run, cfg, self.runner) or {}

            # ---------------- dns
            if "dns" in steps:
                res = self._safe_step("dns", dns.run, cfg, self.runner, sub_sources)
                if res:
                    hosts, records = res
                    self.store.add_hosts(hosts)
                    self.store.add_dns_records(records)
                    cnames = {h.host: h.cname for h in hosts if h.cname}

            # ---------------- http probe
            if "http_probe" in steps and hosts:
                probed = self._safe_step("http_probe", http_probe.run,
                                         cfg, self.runner, hosts)
                if probed:
                    hosts = probed
                    self.store.add_hosts(hosts)     # upsert with alive info
                    alive_hosts = [h.host for h in hosts if h.alive]

            # ---------------- ports
            if "ports" in steps:
                targets = [h.host for h in hosts if h.ips] or [cfg.target]
                port_objs = self._safe_step("ports", ports.run, cfg, self.runner,
                                            targets) or []
                self.store.add_ports(port_objs)

            # ---------------- urls
            if "urls" in steps:
                url_objs = self._safe_step(
                    "urls", urls_mod.run, cfg, self.runner,
                    alive_hosts or [cfg.target]) or []
                self.store.add_urls(url_objs)

            # ---------------- js + secrets
            if "js_secrets" in steps and url_objs:
                res = self._safe_step("js_secrets", js_secrets.run,
                                      cfg, self.runner, [u.url for u in url_objs])
                if res:
                    eps, secrets = res
                    self.store.add_js_endpoints(eps)
                    self.store.add_secrets(secrets)

            # ---------------- params / xss
            if "params" in steps and url_objs:
                param_objs = self._safe_step("params", params.run,
                                             cfg, self.runner, url_objs) or []
                param_urls = [u.url for u in param_objs]

                if "xss" in steps and param_urls and cfg.run_xss:
                    found = self._safe_step("xss", xss.run, cfg, self.runner,
                                            param_urls) or []
                    all_vulns += found
                elif "xss" in steps and not cfg.run_xss:
                    console.print("[dim]• xss module skipped (enable with --xss)[/]")

            # ---------------- takeover
            if "takeover" in steps:
                subs_for_to = [h.host for h in hosts] if hosts else [cfg.target]
                takeovers = self._safe_step("takeover", takeover.run, cfg,
                                            self.runner, subs_for_to, cnames) or []
                self.store.add_takeovers(takeovers)
                for t in takeovers:
                    if t.vulnerable:
                        self.notifier.send_takeover(t.subdomain, t.service)

            # ---------------- cloud enum
            if "cloud_enum" in steps:
                assets = self._safe_step(
                    "cloud_enum", cloud_enum.run, cfg, self.runner,
                    [u.url for u in url_objs],
                    [h.host for h in hosts] if hosts else []) or []
                self.store.add_cloud(assets)

            # ---------------- dirscan
            if "dirscan" in steps:
                dirs = self._safe_step("dirscan", dirscan.run, cfg, self.runner,
                                       alive_hosts) or []
                self.store.add_directories(dirs)

            # ---------------- vulnerabilities (nuclei on urls + hosts)
            if "vulnerabilities" in steps:
                targets = sorted(set(
                    [h.url for h in hosts if h.alive and h.url]
                    + [u.url.split("?")[0] for u in url_objs][:800]
                    + ([f"https://{cfg.target}"] if not hosts else [])
                ))
                found = self._safe_step("vulnerabilities", vulnerabilities.run_nuclei,
                                        cfg, self.runner, targets) or []
                all_vulns += found
                self.store.add_vulns(all_vulns)

        except KeyboardInterrupt:
            console.print("\n[red]Interrupted — saving partial state…[/]")

        # ---------------- monitor diff + notifications
        diff = None
        try:
            diff = diff_with_previous(self.store, self.out_dir)
            if diff.has_changes:
                console.print(Panel(
                    "\n".join(diff.summary_lines()),
                    title="[bold yellow]Changes since last scan[/]",
                    border_style="yellow"))
                self.notifier.send_changes(cfg.target, diff)
            rotate_snapshots(self.out_dir)
            take_snapshot(self.store, self.out_dir)
        except Exception as e:  # noqa: BLE001
            console.print(f"[yellow]snapshot/diff step skipped: {e}[/]")

        # ---------------- final stats
        elapsed = time.time() - started
        stats = {
            "subdomains": len(hosts) or self.store.count("hosts"),
            "alive_hosts": sum(1 for h in hosts if h.alive) or
                           self.store.conn.execute(
                               "SELECT COUNT(*) FROM hosts WHERE alive=1").fetchone()[0],
            "ports": self.store.count("ports"),
            "urls": self.store.count("urls"),
            "js_endpoints": self.store.count("js_endpoints"),
            "secrets": self.store.count("secrets"),
            "takeovers": self.store.count("takeovers"),
            "vulnerabilities": self.store.count("vulnerabilities"),
            "directories": self.store.count("directories"),
            "cloud_assets": self.store.count("cloud_assets"),
        }
        self.notifier.send_scan_done(cfg.target, stats)

        title = f"[bold green]Done in {int(elapsed)}s"
        if self.errors:
            title += f" ({len(self.errors)} steps had errors)"
        console.print(Panel(
            "\n".join(f"[bold]{k}[/]: {v}" for k, v in stats.items() if v)
            + (f"\n[yellow]errors: {', '.join(e for e, _ in self.errors)}[/]"
               if self.errors else ""),
            title=title, border_style="green"))
        return stats
