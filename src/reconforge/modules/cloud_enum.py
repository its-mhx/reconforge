"""Cloud asset discovery — S3/Azure/GCP/Firebase from names+URL content."""
from __future__ import annotations

import re
import concurrent.futures as cf

from rich.console import Console

from ..tools.python_fallbacks import _SESSION

from ..core.config import EngineConfig
from ..core.models import CloudAsset
from ..core.runner import ToolRunner
from ..core.utils import apex

console = Console(stderr=True)
UA = {"User-Agent": "ReconForge/0.1"}
BUCKET_RE = re.compile(
    r"(?:[a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])\.(s3[\.-][a-z0-9-]+\.amazonaws\.com|"
    r"s3\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com|"
    r"firebaseio\.com|web\.app|appspot\.com)", re.I)


def _probe_bucket(url: str) -> CloudAsset | None:
    try:
        r = _SESSION.get(url, timeout=8, verify=False)
        status = {200: "open", 403: "protected", 404: "notfound"}.get(r.status_code, str(r.status_code))
        kind = ("s3" if "amazonaws" in url else
                "azure_blob" if "windows.net" in url else
                "gcp_bucket" if "googleapis" in url else
                "firebase" if "firebaseio" in url else "other")
        if status in ("open", "protected"):
            return CloudAsset(kind=kind, url=url, status=status)
    except Exception:
        return None
    return None


def run(cfg: EngineConfig, runner: ToolRunner, urls: list[str],
        subdomains: list[str]) -> list[CloudAsset]:
    target = apex(cfg.target)
    console.print("[cyan]→ cloud enumeration[/]")
    found: dict[str, CloudAsset] = {}

    # harvest bucket URLs from url corpus
    candidates: set[str] = set()
    for u in urls:
        for m in BUCKET_RE.finditer(u):
            candidates.add(f"https://{m.group(0)}")

    # brute common bucket names off the org name
    org = re.sub(r"[^a-z0-9]", "", target.split(".")[0])
    if org:
        for name in {org, f"{org}-assets", f"{org}-static", f"{org}-backup",
                     f"{org}-dev", f"{org}-prod", f"{org}app"}:
            candidates.add(f"https://{name}.s3.amazonaws.com")
            candidates.add(f"https://{name}.blob.core.windows.net")
            candidates.add(f"https://{name}.storage.googleapis.com")

    with cf.ThreadPoolExecutor(max_workers=cfg.threads) as ex:
        for r in ex.map(_probe_bucket, sorted(candidates)):
            if r:
                found[r.url] = r

    console.print(f"[green]✓ cloud: {len(found)} assets[/]")
    return list(found.values())
