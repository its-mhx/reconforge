"""Export scan data to txt/csv/json/excel (PrettyRecon parity)."""
from __future__ import annotations

import csv
import io
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


def export_category(store: Store, out_dir: Path, fmt: str, category: str) -> Path | None:
    if category not in CATEGORY_FILES:
        return None
    table, cols = CATEGORY_FILES[category]
    rows = store.table(table)
    if not rows:
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{category}.{fmt if fmt != 'xlsx' else 'csv'}"
    if fmt == "json":
        path = out_dir / f"{category}.json"
        path.write_text(json.dumps(rows, indent=2, default=str))
    elif fmt == "csv":
        path = out_dir / f"{category}.csv"
        with open(path, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader(); w.writerows(rows)
    elif fmt == "txt":
        path = out_dir / f"{category}.txt"
        key_col = cols[0]
        path.write_text("\n".join(str(r.get(key_col, "")) for r in rows))
    return path


def export_excel(store: Store, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "reconforge_report.xlsx"
    wb = Workbook()
    wb.remove(wb.active)
    for category, (table, cols) in CATEGORY_FILES.items():
        rows = store.table(table)
        if not rows:
            continue
        ws = wb.create_sheet(title=category[:31])
        ws.append(cols)
        for r in rows:
            ws.append([_cell(r.get(c)) for c in cols])
        for col in ws.columns:
            ws.column_dimensions[col[0].column_letter].width = min(
                max((len(str(c.value or "")) for c in col), default=10) + 2, 80)
    wb.save(path)
    return path


def _cell(v):
    if isinstance(v, (list, dict)):
        return json.dumps(v)
    return v


def export_all(store: Store, out_dir: Path, fmts: list[str]) -> list[Path]:
    paths: list[Path] = []
    for category in CATEGORY_FILES:
        for fmt in fmts:
            p = export_category(store, out_dir / "exports", fmt, category)
            if p:
                paths.append(p)
    if "xlsx" in fmts or "excel" in fmts:
        paths.append(export_excel(store, out_dir / "exports"))
    return paths
