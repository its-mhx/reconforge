"""Pipeline orchestrator — maps profile presets to ordered module execution."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from .core.config import EngineConfig
from .core.diff import DiffResult, diff_with_previous, rotate_snapshots, take_snapshot
from .core.models import Host
from .core.notify import Notifier
from .core.runner import ToolRunner
from .core.store import Store
from .core.utils import apex
from .modules import (
    cloud_enum, dirscan, dns, js_secrets, params, ports,
    subdomains, takeover, urls as urls_mod, vulnerabilities, xss,
)

console = Console(stderr=True)

PROFILES = {
    "sub":     ["subdomains", "dns", "http_probe", "takeover"],
    "basic":   ["subdomains", "dns", "http_probe", "ports", "urls", "takeover"],
    "vuln":    ["subdomains", "dns", "http_probe", "urls",
                "js_secrets", "params", "xss", "takeover", "vulnerabilities"],
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
        self.notifier = Notifier(cfg.notify_webhook, cfg.telegram_token, cfg.telegram_chat)

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

        hosts: list[Host] = []
        alive_hosts: list[str] = []
        cnames: dict[str, str] = {}
        url_objs = []
        param_urls: list[str] = []
        all_vulns = []

        try:
            # ---------------- subdomains
            if "subdomains" in steps:
                sub_sources = subdomains.run(cfg, self.runner)
            else:
                sub_sources = {}

            # ---------------- dns
            if "dns" in steps:
                hosts, records = dns.run(cfg, self.runner, sub_sources)
                self.store.add_hosts(hosts)
                self.store.add_dns_records(records)
                cnames = {h.host: h.cname for h in hosts if h.cname}

            # ---------------- http probe
            if "http_probe" in steps and hosts:
                hosts = __import__(
                    "reconforge.modules.http_probe", fromlist=["run"]
                ).run(cfg, self.runner, hosts)
                self.store.add_hosts(hosts)     # upsert with alive info
                alive_hosts = [h.host for h in hosts if h.alive]

            # ---------------- ports
            if "ports" in steps:
                targets = [h.host for h in hosts if h.ips] or [cfg.target]
                port_objs = ports.run(cfg, self.runner, targets)
                self.store.add_ports(port_objs)

            # ---------------- urls
            if "urls" in steps:
                url_objs = urls_mod.run(cfg, self.runner, alive_hosts or [cfg.target])
                self.store.add_urls(url_objs)

            # ---------------- js + secrets
            if "js_secrets" in steps and url_objs:
                eps, secrets = js_secrets.run(cfg, self.runner,
                                              [u.url for u in url_objs])
                self.store.add_js_endpoints(eps)
                self.store.add_secrets(secrets)

            # ---------------- params
            if "params" in steps and url_objs:
                param_url_objs = params.run(cfg, self.runner, url_objs)
                param_urls = [u.url for u in param_url_objs]

            # ---------------- xss
            if "xss" in steps and param_urls and cfg.run_xss:
                all_vulns += xss.run(cfg, self.runner, param_urls)
            elif "xss" in steps and not cfg.run_xss:
                console.print("[dim]• xss module skipped (enable with --xss)[/]")

            # ---------------- takeover
            if "takeover" in steps:
                to = takeover.run(cfg, self.runner,
                                  [h.host for h in hosts] if hosts else [cfg.target],
                                  cnames)
                self.store.add_takeovers(to)
                for t in to:
                    if t.vulnerable:
                        self.notifier.send_takeover(t.subdomain, t.service)

            # ---------------- cloud enum
            if "cloud_enum" in steps:
                assets = cloud_enum.run(cfg, self.runner,
                                        [u.url for u in url_objs],
                                        [h.host for h in hosts] if hosts else [])
                self.store.add_cloud(assets)

            # ---------------- dirscan
            if "dirscan" in steps:
                dirs = dirscan.run(cfg, self.runner, alive_hosts)
                self.store.add_directories(dirs)

            # ---------------- vulnerabilities (nuclei on urls + hosts)
            if "vulnerabilities" in steps:
                targets = sorted(set(
                    [h.url for h in hosts if h.alive and h.url] +
                    [u.url.split("?")[0] for u in url_objs][:800] +
                    ([f"https://{cfg.target}"] if not hosts else [])
                ))
                all_vulns += vulnerabilities.run_nuclei(cfg, self.runner, targets)
                self.store.add_vulns(all_vulns)

        except KeyboardInterrupt:
            console.print("\n[red]Interrupted — saving partial state…[/]")
        finally:
            pass

        # ---------------- monitor diff + notifications
        if cfg.profile in {"monitor", "full", "vuln", "basic", "sub"}:
            diff = diff_with_previous(self.store, self.out_dir)
            if diff.has_changes:
                console.print(Panel(
                    "\n".join(diff.summary_lines()),
                    title="[bold yellow]Changes since last scan[/]",
                    border_style="yellow"))
                self.notifier.send_changes(cfg.target, diff)
            rotate_snapshots(self.out_dir)
            take_snapshot(self.store, self.out_dir)

        # ---------------- final stats
        stats = {
            "subdomains": len([h for h in hosts] or self.store.count("hosts")),
            "alive_hosts": len(alive_hosts),
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
        console.print(Panel(
            "\n".join(f"[bold]{k}[/]: {v}" for k, v in stats.items() if v),
            title="[bold green]Done", border_style="green"))
        return stats
