"""Dependency-free Python fallbacks for key capabilities, used when the
preferred external binary is missing so the pipeline never hard-fails."""
from __future__ import annotations

import concurrent.futures as cf
import json
import re
import socket
import ssl
import warnings
from pathlib import Path
from typing import Iterable
from urllib.parse import urljoin

import requests

# disable InsecureRequestWarning spam — recon normally hits broken TLS setups
warnings.filterwarnings("ignore", "Unverified HTTPS request")
try:
    from urllib3 import disable_warnings
    from urllib3.exceptions import InsecureRequestWarning
    disable_warnings(InsecureRequestWarning)
except ImportError:
    pass  # urllib3 not present

# Shared session with warnings disabled (reused across fallbacks)
_SESSION = requests.Session()

UA = {"User-Agent": "ReconForge/0.1 (+https://github.com)"}
TIMEOUT = 8
# populated post-init below
_SESSION.headers.update(UA)

# ---------------------------------------------------------------- crt.sh subs
def crtsh_subdomains(domain: str) -> list[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, headers=UA, timeout=25)
        out: set[str] = set()
        for row in r.json():
            for n in str(row.get("name_value", "")).split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n.endswith(domain):
                    out.add(n)
        return sorted(out)
    except Exception:
        return []


# ------------------------------------------------------------------ resolver
def resolve_bulk(hosts: Iterable[str], threads: int = 64) -> dict[str, list[str]]:
    """Return {host: [ips]} for hosts that resolve."""
    out: dict[str, list[str]] = {}
    hs = list(set(hosts))

    def _res(h: str):
        try:
            infos = socket.getaddrinfo(h, None, proto=socket.IPPROTO_TCP)
            return h, sorted({i[4][0] for i in infos})
        except socket.gaierror:
            return h, []

    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        for host, ips in ex.map(_res, hs):
            if ips:
                out[host] = ips
    return out


# ------------------------------------------------------------------ http probe
def probe(url: str) -> dict | None:
    try:
        r = requests.get(url, headers=UA, timeout=TIMEOUT, allow_redirects=True, verify=False)
        title = ""
        m = re.search(r"<title>(.*?)</title>", r.text, re.I | re.S)
        if m:
            title = m.group(1).strip()[:120]
        server = r.headers.get("Server", "")
        return {
            "url": url, "status_code": r.status_code, "title": title,
            "webserver": server, "content_length": len(r.content),
            "final_url": r.url,
        }
    except Exception:
        return None


def probe_bulk(hosts: Iterable[str], threads: int = 40, max_hosts: int = 2000) -> list[dict]:
    targets: list[str] = []
    for h in list(hosts)[:max_hosts]:
        targets += [f"https://{h}", f"http://{h}"]
    results: list[dict] = []
    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        for r in ex.map(probe, targets):
            if r and r["status_code"]:
                results.append(r)
    # keep https pref
    best: dict[str, dict] = {}
    for r in results:
        host = r["url"].split("://", 1)[1]
        if host not in best or (r["url"].startswith("https") and not best[host]["url"].startswith("https")):
            best[host] = r
    return list(best.values())


# ------------------------------------------------------------------ ports
def scan_ports(hosts: Iterable[str], top: int = 100, threads: int = 200) -> list[dict]:
    ports = _top_ports(top)
    out: list[dict] = []

    def _scan(host: str):
        hits = []
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return hits
        for p in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            try:
                if s.connect_ex((ip, p)) == 0:
                    try:
                        svc = socket.getservbyport(p)
                    except Exception:
                        svc = ""
                    hits.append({"host": host, "ip": ip, "port": p,
                                 "protocol": "tcp", "service": svc})
            finally:
                s.close()
        return hits

    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        for r in ex.map(_scan, list(hosts)):
            out.extend(r)
    return out


def _top_ports(n: int) -> list[int]:
    base = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,
            3389,5900,6379,8080,8443,8000,8888,9200,9300,27017,1433,1521,
            5432,5984,11211,6379,8009,8081,8090,9000,9090,15672,5601,5044]
    tcp = base + list(range(1, 1025))
    seen, out = set(), []
    for p in tcp:
        if p not in seen:
            seen.add(p)
            out.append(p)
        if len(out) >= n:
            break
    return out


# ------------------------------------------------------------------ wayback
def wayback_urls(domain: str, limit: int = 5000) -> list[str]:
    url = ("http://web.archive.org/cdx/search/cdx?url="
           f"*.{domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}")
    try:
        r = requests.get(url, headers=UA, timeout=30)
        data = r.json()
        return sorted({row[0] for row in data[1:] if row})
    except Exception:
        return []


# ------------------------------------------------------------------ takeover
TAKEOVER_FINGERPRINTS = {
    "AWS S3": ["NoSuchBucket"],
    "GitHub Pages": ["There isn't a GitHub Pages site here"],
    "Heroku": ["No such app", "herokucdn.com/error-pages"],
    "Shopify": ["Sorry, this shop is currently unavailable"],
    "Fastly": ["Fastly error: unknown domain"],
    "Pantheon": ["The gods are wise"],
    "Tumblr": ["Whatever you were looking for doesn't currently exist"],
    "WordPress.com": ["Do you want to register"],
    "Zendesk": ["Help Center Closed"],
    "Unbounce": ["The requested URL was not found on this server"],
    "Surge": ["project not found"],
    "Bitbucket": ["Repository not found"],
    "Netlify": ["Not Found - Request ID:"],
}


def takeover_check(cnames: dict[str, str], threads: int = 32) -> list[dict]:
    """cnames: {subdomain: cname}. HTTP-fetch and fingerprint services."""
    out: list[dict] = []

    def _check(sub_cname):
        sub, cname = sub_cname
        for scheme in ("https", "http"):
            try:
                r = requests.get(f"{scheme}://{sub}", headers=UA, timeout=TIMEOUT, allow_redirects=True, verify=False)
                body = r.text
                for svc, marks in TAKEOVER_FINGERPRINTS.items():
                    for mark in marks:
                        if mark.lower() in body.lower():
                            return {"subdomain": sub, "cname": cname,
                                    "service": svc, "vulnerable": True,
                                    "reference": f"https://{sub}"}
            except Exception:
                continue
        return {"subdomain": sub, "cname": cname, "service": "", "vulnerable": False, "reference": ""}

    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        out = [r for r in ex.map(_check, cnames.items()) if r and r.get("vulnerable")]
    return out


# ------------------------------------------------------------------ crawler (small)
def crawl(seed: str, depth: int = 2, max_pages: int = 300, threads: int = 20) -> dict:
    """Very small breadth-first crawler (fallback for katana)."""
    from urllib.parse import urldefrag, urlparse
    seen: set[str] = set()
    urls: set[str] = set()
    js: set[str] = set()
    endpoints: set[str] = set()
    base_host = urlparse(seed).netloc
    frontier = [seed]

    for _ in range(depth + 1):
        if not frontier or len(seen) >= max_pages:
            break
        new_frontier: list[str] = []
        def _fetch(u):
            try:
                return u, requests.get(u, headers=UA, timeout=TIMEOUT, verify=False)
            except Exception:
                return u, None
        with cf.ThreadPoolExecutor(max_workers=threads) as ex:
            for u, r in ex.map(_fetch, frontier):
                if not r or u in seen:
                    continue
                seen.add(u)
                urls.add(u)
                body = r.text or ""
                ct = r.headers.get("Content-Type", "")
                for link in re.findall(r'(?:href|src)\s*=\s*"([^"]+)"', body):
                    absu = urljoin(u, link)
                    absu = urldefrag(absu)[0]          # strip fragment
                    pu = urlparse(absu)
                    if pu.netloc != base_host:
                        continue
                    path = absu.lower()
                    if re.search(r"\.js($|\?)", path):
                        js.add(absu)
                    elif re.search(r"\.(png|jpe?g|gif|svg|css|ico|woff2?)($|\?)", path):
                        continue
                    elif pu.path not in ("", "/") or pu.query:
                        endpoints.add(absu)
                        new_frontier.append(absu)
                    else:
                        new_frontier.append(absu)
                if "text/html" in ct:
                    for m in re.findall(r"['\"](/[a-zA-Z0-9_\-/\.]{2,120})['\"]", body):
                        endpoints.add(urljoin(u, m))
        frontier = [x for x in new_frontier if x not in seen]
    return {"urls": sorted(urls), "js": sorted(js), "endpoints": sorted(endpoints)}


# ------------------------------------------------------------------ dir scan fallback
def dir_scan(base: str, wordlist: list[str], threads: int = 30) -> list[dict]:
    findings: list[dict] = []
    base = base.rstrip("/")

    def _hit(path: str):
        url = f"{base}/{path.lstrip('/')}"
        try:
            r = requests.get(url, headers=UA, timeout=TIMEOUT, allow_redirects=False, verify=False)
            if r.status_code in (200, 201, 204, 301, 302, 307, 401, 403):
                return {"url": url, "status_code": r.status_code,
                        "content_length": len(r.content),
                        "words": len(r.text.split()), "lines": r.text.count("\n"),
                        "redirect": r.headers.get("Location", "")}
        except Exception:
            pass
        return None

    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        for r in ex.map(_hit, wordlist):
            if r:
                findings.append(r)
    return findings


# ------------------------------------------------------------------ xss reflection probe (fallback)
XSS_PROBES = [
    '"<script>alert(1)</script>', "'\"><img src=x onerror=alert(1)>",
    "javascript:alert(1)", "\"><svg onload=alert(1)>",
]


def xss_reflection(urls_with_params: list[str], threads: int = 20) -> list[dict]:
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
    out: list[dict] = []

    def _one(u: str):
        p = urlparse(u)
        qs = parse_qsl(p.query)
        hits = []
        for name, _ in qs:
            for payload in XSS_PROBES:
                new_qs = [(n, payload if n == name else v) for n, v in qs]
                test = urlunparse(p._replace(query=urlencode(new_qs)))
                try:
                    r = requests.get(test, headers=UA, timeout=TIMEOUT, verify=False)
                    if payload in r.text:
                        hits.append({"url": test, "param": name, "payload": payload,
                                     "context": "reflected"})
                        break
                except Exception:
                    continue
        return hits

    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        for r in ex.map(_one, urls_with_params):
            out.extend(r)
    return out


def jdump(obj) -> str:
    return json.dumps(obj, ensure_ascii=False)
