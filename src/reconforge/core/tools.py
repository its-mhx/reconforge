"""Concrete adapter layer mapping logical capabilities to external binaries."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ToolSpec:
    name: str
    binary: str
    has_py_fallback: bool = False


TOOLS: dict[str, ToolSpec] = {
    "subfinder":   ToolSpec("subfinder", "subfinder"),
    "amass":       ToolSpec("amass", "amass"),
    "dnsx":        ToolSpec("dnsx", "dnsx"),
    "naabu":       ToolSpec("naabu", "naabu"),
    "httpx":       ToolSpec("httpx", "httpx"),
    "gau":         ToolSpec("gau", "gau"),
    "waybackurls": ToolSpec("waybackurls", "waybackurls"),
    "katana":      ToolSpec("katana", "katana"),
    "nuclei":      ToolSpec("nuclei", "nuclei"),
    "ffuf":        ToolSpec("ffuf", "ffuf", has_py_fallback=True),
    "feroxbuster": ToolSpec("feroxbuster", "feroxbuster", has_py_fallback=True),
    "dalfox":      ToolSpec("dalfox", "dalfox"),
    "subzy":       ToolSpec("subzy", "subzy", has_py_fallback=True),
    "gowitness":   ToolSpec("gowitness", "gowitness"),
    "nmap":        ToolSpec("nmap", "nmap"),
}


def build_cmd(tool: str, *args: str, config_tool_path: str | None = None) -> list[str]:
    base = config_tool_path or tool
    return [base, *args]


def available(config, tool: str) -> bool:
    """config is EngineConfig; checks binary presence."""
    return config.tool(TOOLS[tool].binary if tool in TOOLS else tool) is not None


def missing_tools(config, needed: list[str]) -> list[str]:
    return [t for t in needed if not available(config, t)]


def wordlist_dir() -> Path:
    here = Path(__file__).resolve()
    return here.parent.parent.parent.parent / "wordlists"
