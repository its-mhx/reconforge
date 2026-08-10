"""SQLite storage layer — every finding type gets a table."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from ..core.models import (
    CloudAsset, DirectoryFinding, DNSRecord, Host, JSEndpoint,
    Port, Secret, TakeoverFinding, URL, Vulnerability,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts(
    host TEXT PRIMARY KEY, ips TEXT, sources TEXT, cname TEXT,
    alive INTEGER DEFAULT 0, status_code INTEGER, title TEXT,
    tech TEXT, webserver TEXT, content_length INTEGER, cdn TEXT, url TEXT
);
CREATE TABLE IF NOT EXISTS dns_records(
    host TEXT, record_type TEXT, value TEXT,
    PRIMARY KEY(host, record_type, value)
);
CREATE TABLE IF NOT EXISTS ports(
    host TEXT, ip TEXT, port INTEGER, protocol TEXT, service TEXT,
    PRIMARY KEY(host, port, protocol)
);
CREATE TABLE IF NOT EXISTS urls(
    url TEXT PRIMARY KEY, source TEXT, status_code INTEGER,
    content_type TEXT, params TEXT
);
CREATE TABLE IF NOT EXISTS js_endpoints(
    js_url TEXT, endpoint TEXT, kind TEXT,
    PRIMARY KEY(js_url, endpoint)
);
CREATE TABLE IF NOT EXISTS secrets(
    hash TEXT PRIMARY KEY, source_url TEXT, secret_type TEXT,
    value TEXT, severity TEXT
);
CREATE TABLE IF NOT EXISTS vulnerabilities(
    hash TEXT PRIMARY KEY, template_id TEXT, name TEXT, severity TEXT,
    host TEXT, matched_at TEXT, description TEXT, reference TEXT,
    tags TEXT, extra TEXT
);
CREATE TABLE IF NOT EXISTS directories(
    url TEXT PRIMARY KEY, status_code INTEGER, content_length INTEGER,
    words INTEGER, lines INTEGER, redirect TEXT
);
CREATE TABLE IF NOT EXISTS takeovers(
    subdomain TEXT PRIMARY KEY, cname TEXT, service TEXT,
    vulnerable INTEGER, reference TEXT
);
CREATE TABLE IF NOT EXISTS cloud_assets(
    url TEXT PRIMARY KEY, kind TEXT, status TEXT, region TEXT
);
CREATE TABLE IF NOT EXISTS scans(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started TEXT DEFAULT (datetime('now')), profile TEXT, target TEXT
);
"""

KEY_FUNCS = {
    "hosts": lambda d: d["host"],
    "ports": lambda d: f'{d["host"]}:{d["port"]}',
    "urls": lambda d: d["url"],
    # severity first so diff alerts can rank without a DB lookup
    "vulnerabilities": lambda d: (
        f'{d.get("severity", "info")}|{d.get("template_id", "")}:'
        f'{d["host"]}:{d.get("matched_at") or ""}'
    ),
    "secrets": lambda d: (
        f'{d.get("severity", "info")}|'
        + (d.get("hash") or f'{d["source_url"]}:{d["secret_type"]}')
    ),
}


class Store:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---------------- writes ----------------
    def _execute(self, sql: str, rows: Iterable[tuple]) -> None:
        self.conn.executemany(sql, rows)
        self.conn.commit()

    def add_hosts(self, hosts: Iterable[Host]) -> None:
        rows = [
            (
                h.host, json.dumps(h.ips), json.dumps(h.sources), h.cname,
                int(h.alive), h.status_code, h.title, json.dumps(h.tech),
                h.webserver, h.content_length, h.cdn, h.url,
            )
            for h in hosts
        ]
        self._execute(
            """INSERT INTO hosts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(host) DO UPDATE SET
                 ips=excluded.ips, sources=excluded.sources, cname=excluded.cname,
                 alive=excluded.alive, status_code=excluded.status_code,
                 title=excluded.title, tech=excluded.tech,
                 webserver=excluded.webserver, content_length=excluded.content_length,
                 cdn=excluded.cdn, url=excluded.url""",
            rows,
        )

    def add_dns_records(self, recs: Iterable[DNSRecord]) -> None:
        self._execute(
            "INSERT OR IGNORE INTO dns_records VALUES(?,?,?)",
            [(r.host, r.record_type, r.value) for r in recs],
        )

    def add_ports(self, ports: Iterable[Port]) -> None:
        self._execute(
            "INSERT OR IGNORE INTO ports VALUES(?,?,?,?,?)",
            [(p.host, p.ip, p.port, p.protocol, p.service) for p in ports],
        )

    def add_urls(self, urls: Iterable[URL]) -> None:
        self._execute(
            """INSERT INTO urls VALUES(?,?,?,?,?)
               ON CONFLICT(url) DO UPDATE SET
                 source=excluded.source, status_code=excluded.status_code,
                 content_type=excluded.content_type, params=excluded.params""",
            [(u.url, u.source, u.status_code, u.content_type, json.dumps(u.params)) for u in urls],
        )

    def add_js_endpoints(self, eps: Iterable[JSEndpoint]) -> None:
        self._execute(
            "INSERT OR IGNORE INTO js_endpoints VALUES(?,?,?)",
            [(e.js_url, e.endpoint, e.kind) for e in eps],
        )

    def add_secrets(self, secs: Iterable[Secret]) -> None:
        import hashlib
        rows = []
        for s in secs:
            h = hashlib.sha1(f"{s.source_url}|{s.secret_type}|{s.value}".encode()).hexdigest()
            rows.append((h, s.source_url, s.secret_type, s.value, s.severity))
        self._execute("INSERT OR IGNORE INTO secrets VALUES(?,?,?,?,?)", rows)

    def add_vulns(self, vulns: Iterable[Vulnerability]) -> None:
        import hashlib
        rows = []
        for v in vulns:
            h = hashlib.sha1(
                f"{v.template_id}|{v.host}|{v.matched_at}".encode()
            ).hexdigest()
            rows.append(
                (
                    h, v.template_id, v.name, v.severity, v.host,
                    v.matched_at, v.description, json.dumps(v.reference),
                    json.dumps(v.tags), json.dumps(v.extra),
                )
            )
        self._execute("INSERT OR REPLACE INTO vulnerabilities VALUES(?,?,?,?,?,?,?,?,?,?)", rows)

    def add_directories(self, dirs: Iterable[DirectoryFinding]) -> None:
        self._execute(
            "INSERT OR REPLACE INTO directories VALUES(?,?,?,?,?,?)",
            [(d.url, d.status_code, d.content_length, d.words, d.lines, d.redirect) for d in dirs],
        )

    def add_takeovers(self, items: Iterable[TakeoverFinding]) -> None:
        self._execute(
            "INSERT OR REPLACE INTO takeovers VALUES(?,?,?,?,?)",
            [(t.subdomain, t.cname, t.service, int(t.vulnerable), t.reference) for t in items],
        )

    def add_cloud(self, items: Iterable[CloudAsset]) -> None:
        self._execute(
            "INSERT OR REPLACE INTO cloud_assets VALUES(?,?,?,?)",
            [(c.url, c.kind, c.status, c.region) for c in items],
        )

    def start_scan(self, target: str, profile: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans(profile, target) VALUES(?,?)", (profile, target)
        )
        self.conn.commit()
        return int(cur.lastrowid)

    # ---------------- reads ----------------
    def table(self, name: str) -> list[dict[str, Any]]:
        cur = self.conn.execute(f"SELECT * FROM {name}")
        return [dict(r) for r in cur.fetchall()]

    def column(self, table: str, column: str) -> list[str]:
        cur = self.conn.execute(f"SELECT {column} FROM {table}")
        return [r[0] for r in cur.fetchall()]

    def count(self, table: str) -> int:
        return int(self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    def export_keys(self, table: str) -> set[str]:
        keyfn = KEY_FUNCS.get(table, lambda d: json.dumps(d, sort_keys=True))
        return {keyfn(r) for r in self.table(table)}

    def close(self) -> None:
        self.conn.close()
