"""Compare the state of a scan with a previous snapshot (monitoring)."""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .store import KEY_FUNCS, Store

SNAPSHOT_TABLES = ["hosts", "ports", "urls", "vulnerabilities", "secrets"]


@dataclass
class DiffResult:
    added: dict[str, list[str]] = field(default_factory=dict)
    removed: dict[str, list[str]] = field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        return any(self.added.values()) or any(self.removed.values())

    def summary_lines(self) -> list[str]:
        lines = []
        for t in self.added:
            a, r = len(self.added[t]), len(self.removed.get(t, []))
            if a or r:
                lines.append(f"{t}: +{a} / -{r}")
        return lines or ["no changes"]


def snapshot_dir(out_dir: Path) -> Path:
    d = out_dir / ".snapshots"
    d.mkdir(parents=True, exist_ok=True)
    return d


def take_snapshot(store: Store, out_dir: Path) -> None:
    """Save current table keys as <table>.json into the snapshot dir."""
    sdir = snapshot_dir(out_dir)
    for t in SNAPSHOT_TABLES:
        keys = sorted(store.export_keys(t))
        (sdir / f"{t}.json").write_text(json.dumps(keys))


def diff_with_previous(store: Store, out_dir: Path) -> DiffResult:
    sdir = snapshot_dir(out_dir)
    res = DiffResult()
    for t in SNAPSHOT_TABLES:
        snap = sdir / f"{t}.json"
        prev_keys = set(json.loads(snap.read_text())) if snap.exists() else set()
        now_keys = store.export_keys(t)
        res.added[t] = sorted(now_keys - prev_keys)
        res.removed[t] = sorted(prev_keys - now_keys)
    return res


def rotate_snapshots(out_dir: Path, keep: int = 2) -> None:
    """Keep a short history of snapshots for potential forensics."""
    sdir = snapshot_dir(out_dir)
    hist = sdir.parent / ".snapshots_history"
    hist.mkdir(exist_ok=True)
    import time
    ts = int(time.time())
    target = hist / str(ts)
    shutil.copytree(sdir, target, dirs_exist_ok=True)
    histories = sorted(hist.iterdir(), key=lambda p: p.name)
    while len(histories) > keep:
        shutil.rmtree(histories.pop(0), ignore_errors=True)
