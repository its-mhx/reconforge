"""Pydantic datamodels used across the whole pipeline."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class Host(BaseModel):
    """A discovered subdomain/host."""
    host: str
    ips: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    is_wildcard: bool = False
    cname: Optional[str] = None
    alive: bool = False
    status_code: Optional[int] = None
    title: Optional[str] = None
    tech: list[str] = Field(default_factory=list)
    webserver: Optional[str] = None
    content_length: Optional[int] = None
    cdn: Optional[str] = None
    url: Optional[str] = None


class DNSRecord(BaseModel):
    host: str
    record_type: str
    value: str


class Port(BaseModel):
    host: str
    ip: Optional[str] = None
    port: int
    protocol: str = "tcp"
    service: Optional[str] = None


class URL(BaseModel):
    url: str
    source: str = ""          # gau / waybackurls / katana / crawl
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    params: list[str] = Field(default_factory=list)


class JSEndpoint(BaseModel):
    js_url: str
    endpoint: str
    kind: str = "path"        # path | url | api


class Secret(BaseModel):
    source_url: str
    secret_type: str
    value: str
    severity: str = "medium"


class Vulnerability(BaseModel):
    template_id: str
    name: str
    severity: str            # info low medium high critical
    host: str
    matched_at: Optional[str] = None
    description: Optional[str] = None
    reference: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class DirectoryFinding(BaseModel):
    url: str
    status_code: int
    content_length: int = 0
    words: int = 0
    lines: int = 0
    redirect: Optional[str] = None


class TakeoverFinding(BaseModel):
    subdomain: str
    cname: str
    service: str = ""
    vulnerable: bool = False
    reference: str = ""


class CloudAsset(BaseModel):
    kind: str                 # s3 | azure_blob | gcp_bucket | firebase | other
    url: str
    status: str = ""
    region: str = ""
