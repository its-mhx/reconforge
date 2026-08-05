"""JS file analysis: endpoint extraction + secret/token detection."""
from __future__ import annotations

import re
import concurrent.futures as cf
from pathlib import Path
from urllib.parse import urljoin

import requests
from rich.console import Console

from ..core.config import EngineConfig
from ..core.models import JSEndpoint, Secret
from ..core.runner import ToolRunner

console = Console(stderr=True)
UA = {"User-Agent": "ReconForge/0.1"}

JS_URL_RE = re.compile(r"https?://[^\s\"'<>]+\.js(?:\?[^\s\"'<>]*)?", re.I)
ENDPOINT_RE = re.compile(r"""["'`](\/[a-zA-Z0-9_\-\./~%]{2,200})["'`]""")
ABS_URL_RE = re.compile(r"""["'`](https?://[a-zA-Z0-9_\-\.]+[a-zA-Z0-9_\-\./~%]*)["'`]""")

SECRET_PATTERNS: dict[str, tuple[str, str]] = {
    # name: (regex, severity)
    "AWS Access Key":        (r"AKIA[0-9A-Z]{16}", "critical"),
    "AWS Secret Key":        (r"(?:aws.{0,20})?(?:secret|private).{0,10}['\"]([0-9a-zA-Z/+]{40})['\"]", "critical"),
    "Google API Key":        (r"AIza[0-9A-Za-z_\-]{35}", "high"),
    "Google OAuth":          (r"ya29\.[0-9A-Za-z_\-]+", "high"),
    "GitHub Token":          (r"(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,255}", "high"),
    "GitLab Token":          (r"glpat-[0-9A-Za-z_\-]{20}", "high"),
    "Slack Token":           (r"xox[baprs]-[0-9A-Za-z\-]+", "high"),
    "Stripe Live Key":       (r"(?:sk|pk)_live_[0-9a-zA-Z]{24,99}", "critical"),
    "Stripe Test Key":       (r"(?:sk|pk)_test_[0-9a-zA-Z]{24,99}", "medium"),
    "Twilio":                (r"SK[0-9a-fA-F]{32}", "high"),
    "SendGrid":              (r"SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}", "high"),
    "Mailgun":               (r"key-[0-9a-zA-Z]{32}", "high"),
    "Firebase":              (r"[0-9a-z\-]+\.firebaseio\.com", "medium"),
    "JWT":                   (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}", "low"),
    "Private Key":           (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "critical"),
    "Bearer Token":          (r"Bearer\s+[A-Za-z0-9_\-\.=]{20,200}", "medium"),
    "Basic Auth in URL":     (r"[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@", "medium"),
    "IP Address (internal)": (r"\b(?:10|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}\b", "info"),
}

_JS_BODY_CACHE: dict[str, str] = {}


def _fetch(url: str, timeout: int = 10) -> str:
    if url in _JS_BODY_CACHE:
        return _JS_BODY_CACHE[url]
    try:
        r = requests.get(url, headers=UA, timeout=timeout, verify=False)
        body = r.text if r.ok else ""
    except Exception:
        body = ""
    _JS_BODY_CACHE[url] = body
    return body


def discover_js_from_urls(urls: list[str]) -> list[str]:
    js = sorted({u for u in urls if re.search(r"\.js(\?|$)", u, re.I)})
    # common bundle guesses on roots
    roots = {re.match(r"(https?://[^/]+)", u).group(1) for u in urls
             if re.match(r"https?://", u)}
    for root in roots:
        for guess in ("/main.js", "/app.js", "/bundle.js", "/static/js/main.js"):
            js.append(urljoin(root, guess))
    return sorted(set(js))


def run(cfg: EngineConfig, runner: ToolRunner, urls: list[str]) -> tuple[list[JSEndpoint], list[Secret]]:
    out = runner.workdir
    console.print(f"[cyan]→ js analysis on {len(urls)} urls[/]")
    js_urls = discover_js_from_urls(urls)
    endpoints: list[JSEndpoint] = []
    secrets: list[Secret] = []

    def _analyze(js_url: str):
        body = _fetch(js_url)
        if not body:
            return [], []
        eps: list[JSEndpoint] = []
        secs: list[Secret] = []
        for m in ENDPOINT_RE.findall(body):
            if not any(skip in m.lower() for skip in
                       (".png", ".jpg", ".css", ".svg", ".ico", ".woff", "node_modules")):
                eps.append(JSEndpoint(js_url=js_url, endpoint=m, kind="path"))
        for m in ABS_URL_RE.findall(body):
            eps.append(JSEndpoint(js_url=js_url, endpoint=m, kind="url"))
        for stype, (pat, sev) in SECRET_PATTERNS.items():
            for m in re.findall(pat, body, flags=re.I | re.M):
                val = m if isinstance(m, str) else m[0]
                # skip placeholders
                if any(x in val.lower() for x in ("example", "xxxx", "your_", "<", "dummy")):
                    continue
                secs.append(Secret(source_url=js_url, secret_type=stype,
                                   value=str(val)[:300], severity=sev))
        return eps, secs

    with cf.ThreadPoolExecutor(max_workers=cfg.threads) as ex:
        for eps, secs in ex.map(_analyze, js_urls):
            endpoints.extend(eps)
            secrets.extend(secs)

    # ---- optional nuclei token templates over harvested urls (best-effort)
    nuclei = cfg.tool("nuclei")
    if nuclei and cfg.run_nuclei and urls:
        urls_file = out / "urls_for_secrets.txt"
        urls_file.write_text("\n".join(sorted(set(urls))[:3000]))
        runner.run(
            "nuclei",
            [nuclei, "-silent", "-jsonl", "-tags", "token,exposure,config",
             "-severity", "low,medium,high,critical", "-rl", "150"],
            input_file=urls_file,
            out_file=out / "secrets_nuclei.jsonl",
        )
        for obj in runner.iter_json_lines(out / "secrets_nuclei.jsonl"):
            info = obj.get("info", {})
            matched = obj.get("matched-at") or obj.get("host")
            name = info.get("name", "exposure")
            sev = info.get("severity", "low")
            secrets.append(Secret(source_url=matched or "", secret_type=name,
                                  value=obj.get("extracted-results", "")
                                  if isinstance(obj.get("extracted-results"), str)
                                  else str(obj.get("extracted-results", "")[:200]),
                                  severity=sev))

    console.print(f"[green]✓ js/secrets: {len(endpoints)} endpoints, {len(secrets)} potential secrets[/]")
    return endpoints, secrets
