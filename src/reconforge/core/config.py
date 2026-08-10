"""Runtime configuration."""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

APP_NAME = "reconforge"
TOOLS_SETUP_HINT = "Run: bash scripts/install_tools.sh  (installs via go install / apt)"


def which(binary: str) -> str | None:
    """Return full path of a binary, falling back to ~/go/bin."""
    p = shutil.which(binary)
    if p:
        return p
    gobin = Path.home() / "go" / "bin" / binary
    return str(gobin) if gobin.exists() else None


@dataclass
class EngineConfig:
    """All knobs for a scan run."""
    target: str
    profile: str = "full"                     # sub/basic/vuln/full/monitor
    output_root: Path = Path("output")
    threads: int = 40
    timeout: int = 900                        # per tool, seconds
    wordlist_subs: Path | None = None
    wordlist_dirs: Path | None = None
    resolvers: Path | None = None
    proxy: str | None = None
    notify_webhook: str | None = os.getenv("RECONF_WEBHOOK")          # discord/slack generic
    telegram_token: str | None = os.getenv("RECONF_TELEGRAM_TOKEN")
    telegram_chat: str | None = os.getenv("RECONF_TELEGRAM_CHAT")
    # feature toggles (modules can check these)
    active_bruteforce: bool = True
    run_nuclei: bool = True
    run_xss: bool = False                     # dalfox is noisy; off unless asked
    run_dirscan: bool = False
    run_katana: bool = True                   # disable to skip crawling entirely
    katana_max_hosts: int = 20
    katana_depth: int | None = None           # auto: 2 for full, 1 otherwise
    max_hosts_probe: int = 5000
    extra: dict = field(default_factory=dict)

    @property
    def out_dir(self) -> Path:
        d = self.output_root / self.target
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def db_path(self) -> Path:
        return self.out_dir / "reconforge.db"

    def tool(self, name: str) -> str | None:
        return which(name)


DEFAULT_WORDLISTS = {
    "subs_small": "wordlists/subdomains-top1million-5000.txt",
    "dirs_common": "wordlists/common.txt",
    "params": "wordlists/params.txt",
    "resolvers": "wordlists/resolvers.txt",
}
