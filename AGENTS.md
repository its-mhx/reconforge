# AGENTS.md — coding guidance for contributors and AI agents

## Project
ReconForge: local, free attack-surface reconnaissance tool for bug bounty hunting.
Python 3.10+, modular pipeline orchestrating well-known open-source scanners
(subfinder, dnsx, httpx, nuclei, gau, katana, subzy, dalfox, ffuf).

## Layout
- `src/reconforge/cli.py` — Typer entry point (`scan`, `show`, `export`, `report`, `monitor`, `tools`)
- `src/reconforge/pipeline.py` — profile runner with per-module error isolation
- `src/reconforge/modules/*` — one file per capability (add NEW modules here)
- `src/reconforge/core/*` — runner (subprocess), store (SQLite), diff, notify, config, tool_flags
- `src/reconforge/tools/python_fallbacks.py` — pure-Python fallbacks so nothing hard-fails
- `scripts/install_tools.sh` — go-installable recon tool bootstrap

## Conventions
- Modules return typed Pydantic models from `core/models.py`; never raw dicts.
- Packages **must** declare fallbacks for missing binaries via `python_fallbacks.py`.
- Never raise from a module — the pipeline guards with `_safe_step`, return empty results instead.
- Always stream subprocess stdout to a file (see `runner.run(..., out_file=...)`) — never hold
  big outputs in memory.
- Use `runtime flag adaptation` (`core/tool_flags.py`) for external-binary ARG spellings
  (e.g. dnsx v1 vs v2).
- Threading limits come from `EngineConfig.threads`; respect them everywhere.
- Add new Pydantic models in `core/models.py`, add a corresponding SQLite table in
  `core/store.py` schema.
- Exports: `exporters.CATEGORY_FILES` drives JSON/CSV/TXT/XLSX & HTML report sections.

## Code style
- No f-strings in logging calls (use `console.print` from rich).
- Type hints required for new public functions.
- No external network calls in modules other than the designated fetcher (crt.sh / wayback).
- Keep wordlists under `wordlists/`; do not commit scan outputs (`output/` is ignored).
- User data (webhooks, tokens) **only** comes from `.env` — never hard-code credentials.

## Testing a change
```bash
python3 -m compileall -q src && ./.venv/bin/reconforge tools
./.venv/bin/reconforge scan owasp.org -p sub --no-bruteforce --timeout 300   # smoke test
```

## Publishing
Tag a release after: `git tag v0.x.y && git push origin v0.x.y` then `gh release create`.
Keep CHANGELOG.md honest — no fake features, no vaporware.
