"""Webhook / Telegram notifications for monitoring alerts."""
from __future__ import annotations

import json
from dataclasses import dataclass

import requests

from .diff import DiffResult

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


@dataclass
class Notifier:
    webhook: str | None = None
    telegram_token: str | None = None
    telegram_chat: str | None = None
    timeout: int = 15

    # ------------------------------------------------------------------
    def _post_webhook(self, payload: dict) -> bool:
        if not self.webhook:
            return False
        # try discord format first, fall back to generic json
        try:
            requests.post(self.webhook, json=payload, timeout=self.timeout)
            return True
        except Exception:
            return False

    def _post_telegram(self, text: str) -> bool:
        if not (self.telegram_token and self.telegram_chat):
            return False
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        try:
            requests.post(
                url,
                json={"chat_id": self.telegram_chat, "text": text},
                timeout=self.timeout,
            )
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    def send_text(self, text: str) -> None:
        self._post_webhook({"content": text, "text": text})
        self._post_telegram(text)

    def send_scan_start(self, target: str, profile: str) -> None:
        self.send_text(f"🛰️ ReconForge scan started → `{target}` (profile={profile})")

    def send_scan_done(self, target: str, stats: dict[str, int]) -> None:
        lines = [f"✅ ReconForge scan finished → `{target}`"]
        for k, v in stats.items():
            lines.append(f"  • {k}: {v}")
        self.send_text("\n".join(lines))

    def send_changes(self, target: str, diff: DiffResult) -> None:
        parts = [f"🔄 ReconForge changes detected on `{target}`"]
        for table, items in diff.added.items():
            if not items:
                continue
            parts.append(f"\n➕ {table} (+{len(items)}):")
            parts.extend(f"  {i}" for i in items[:25])
            if len(items) > 25:
                parts.append(f"  … and {len(items)-25} more")
        for table, items in diff.removed.items():
            if not items:
                continue
            parts.append(f"\n➖ {table} (-{len(items)}):")
            parts.extend(f"  {i}" for i in items[:25])
        self.send_text("\n".join(parts))

        # vulnerability-heavy alert
        sev = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        juicy = [
            v for v in diff.added.get("vulnerabilities", [])
            if sev.get(v.split("|")[0].split(":")[0], 0) >= 2
        ]
        if juicy:
            self.send_text("🚨 New potentially serious findings:\n" + "\n".join(juicy))

        # secret leaks
        leaks = diff.added.get("secrets", [])
        if leaks:
            self.send_text("🔑 New exposed secrets:\n" + "\n".join(leaks[:20]))

    def send_takeover(self, subdomain: str, service: str) -> None:
        self.send_text(f"⚠️ Subdomain takeover candidate: `{subdomain}` ({service})")

    # ------------------------------------------------------------------
    def is_configured(self) -> bool:
        return bool(self.webhook or (self.telegram_token and self.telegram_chat))

    def debug_payload(self) -> str:  # for tests
        return json.dumps(
            {"webhook": bool(self.webhook), "telegram": bool(self.telegram_token)}
        )
