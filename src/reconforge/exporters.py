"""Export scan data to txt/csv/json/excel (PrettyRecon parity)."""
from __future__ import annotations

import csv
import json
from pathlib import Path

from openpyxl import Workbook

from .core.store import Store

CATEGORY_FILES = {
    "subdomains": ("hosts", ["host", "ips", "sources", "cname", "alive",
                             "status_code", "title", "tech", "webserver", "cdn", "url"]),
    "ports": ("ports", ["host", "ip", "port", "protocol", "service"]),
    "urls": ("urls", ["url", "source", "status_code", "content_type", "params"]),
    "js_endpoints": ("js_endpoints", ["js_url", "endpoint", "kind"]),
    "secrets": ("secrets", ["source_url", "secret_type", "value", "severity"]),
    "vulnerabilities": ("vulnerabilities", ["severity", "name", "template_id",
                                            "host", "matched_at", "description", "tags"]),
    "takeovers": ("takeovers", ["subdomain", "cname", "service", "vulnerable", "reference"]),
    "directories": ("directories", ["url", "status_code", "content_length", "redirect"]),
    "cloud_assets": ("cloud_assets", ["kind", "url", "status", "region"]),
    "dns_records": ("dns_records", ["host", "record_type", "value"]),
}


def _cell(v):
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False)
    return v


def export_category(store: Store, out_dir: Path, fmt: str, category: str) -> Path | None:
    """Export one category. Returns the written path (or None if no rows)."""
    if category not in CATEGORY_FILES:
        return None
    table, cols = CATEGORY_FILES[category]
    rows = store.table(table)
    if not rows:
        return None
    out_dir.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        path = out_dir / f"{category}.json"
        path.write_text(json.dumps(rows, indent=2, default=str))
        return path
    if fmt == "csv":
        path = out_dir / f"{category}.csv"
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow({c: _cell(r.get(c)) for c in cols})
        return path
    if fmt == "txt":
        path = out_dir / f"{category}.txt"
        key_col = cols[0]
        # prefer "alive" hosts first for subdomains txt
        if category == "subdomains":
            rows = sorted(rows, key=lambda r: 0 if r.get("alive") else 1)
        path.write_text("\n".join(str(r.get(key_col, "")) for r in rows))
        return path
    if fmt in ("xlsx", "excel"):
        path = out_dir / f"{category}.xlsx"
        wb = Workbook()
        ws = wb.active
        ws.title = category[:31]
        ws.append(cols)
        for r in rows:
            ws.append([_cell(r.get(c)) for c in cols])
        _autowidth(ws)
        wb.save(path)
        return path
    return None


def export_excel(store: Store, out_dir: Path) -> Path:
    """One workbook with a sheet per category."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "reconforge_report.xlsx"
    wb = Workbook()
    written = 0
    for i, (category, (table, cols)) in enumerate(CATEGORY_FILES.items()):
        rows = store.table(table)
        if not rows:
            continue
        ws = wb.active if wb.active.max_row == 1 and written == 0 else wb.create_sheet()
        ws.title = category[:31]
        written += 1
        ws.append(cols)
        for r in rows:
            ws.append([_cell(r.get(c)) for c in cols])
        _autowidth(ws)
    if written == 0:                              # workbook with zero sheets
        ws = wb.active
        ws.title = "empty"
        ws.append(["no data"])
    wb.save(path)
    return path


def _autowidth(ws) -> None:
    for col in ws.columns:
        try:
            width = min(max((len(str(c.value or "")) for c in col), default=8) + 2, 80)
            ws.column_dimensions[col[0].column_letter].width = width
        except Exception:
            pass


def export_all(store: Store, out_dir: Path, fmts: list[str]) -> list[Path]:
    paths: list[Path] = []
    exp_dir = out_dir / "exports"
    for category in CATEGORY_FILES:
        for fmt in fmts:
            p = export_category(store, exp_dir, fmt, category)
            if p:
                paths.append(p)
    return paths
