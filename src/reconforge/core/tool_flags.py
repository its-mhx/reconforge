"""Auto-detect correct CLI flag spellings per installed binary version
(e.g. dnsx variants use -jsonl / --jsonl / -json depending on version)."""
from __future__ import annotations

import re
import subprocess
from functools import lru_cache

JSONL_CANDIDATES = ["-jsonl", "--jsonl", "-jl", "-json", "--json", "-j"]
SILENT_CANDIDATES = ["-silent", "--silent", "-s", "--quiet"]
NO_COLOR = ["-no-color", "--no-color", "-nc", "--nc", "--no-colorize"]


@lru_cache(maxsize=128)
def _help_text(binary: str) -> str:
    try:
        proc = subprocess.run([binary, "-h"], capture_output=True, text=True,
                              timeout=8)
        return (proc.stdout or "") + (proc.stderr or "")
    except Exception:
        return ""


def _pick(binary: str, candidates: list[str]) -> str | None:
    txt = _help_text(binary)
    for cand in candidates:
        # match at start-of-token (space, newline or beginning)
        if re.search(rf"(?:^|[\s]){re.escape(cand)}(?:[\s=,]|$)", txt):
            return cand
    return None


def detect_jsonl_flag(binary: str) -> str:
    return _pick(binary, JSONL_CANDIDATES) or "-jsonl"


def detect_silent_flag(binary: str) -> str:
    return _pick(binary, SILENT_CANDIDATES) or "-silent"


def detect_no_color(binary: str) -> str | None:
    return _pick(binary, NO_COLOR)


# convenience alias used across modules
def flags_for(binary: str) -> dict[str, str]:
    return {
        "jsonl": detect_jsonl_flag(binary),
        "silent": detect_silent_flag(binary),
        "no_color": detect_no_color(binary) or "",
    }
