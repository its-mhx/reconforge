"""Small shared helpers."""
from __future__ import annotations

import hashlib
import re
import socket
from urllib.parse import urlparse, parse_qsl

import tldextract

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\.?$"
)


def valid_domain(domain: str) -> bool:
    return bool(_DOMAIN_RE.match(domain.strip().rstrip(".")))


def apex(domain: str) -> str:
    e = tldextract.extract(domain)
    return f"{e.domain}.{e.suffix}" if e.suffix else domain


def normalize_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if ":" in host and not host.count(":") > 1:      # strip single tcp port
        host = host.split(":")[0]
    if host.startswith("*."):
        host = host[2:]
    return host


def in_scope(host: str, apex_domain: str) -> bool:
    host = normalize_host(host)
    return host == apex_domain or host.endswith("." + apex_domain)


def resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return sorted({i[4][0] for i in infos})
    except socket.gaierror:
        return []


def sha1(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()


def url_host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def url_params(url: str) -> list[str]:
    try:
        q = urlparse(url).query
        return sorted({k for k, _ in parse_qsl(q)})
    except Exception:
        return []


def dedupe_keep_order(items):
    seen = set()
    out = []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def batched(items, n):
    for i in range(0, len(items), n):
        yield items[i : i + n]
