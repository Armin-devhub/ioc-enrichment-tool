"""Threat-intel enrichment clients.

Two free providers are supported:
  * AbuseIPDB  — reputation for IPv4 addresses.
  * VirusTotal — reputation for IPs, domains, URLs and file hashes.

Each client degrades gracefully: with no API key it returns a ``skipped``
verdict instead of raising, so the tool still runs as a pure extractor.
Results are normalised into a common :class:`Enrichment` shape so the report
layer doesn't care which provider produced them.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field

import requests

# Verdict severity ordering, low -> high, used to pick an overall verdict.
_SEVERITY = {"unknown": 0, "clean": 1, "skipped": 0, "suspicious": 2, "malicious": 3}


@dataclass
class Enrichment:
    provider: str
    verdict: str = "unknown"            # clean | suspicious | malicious | unknown | skipped
    score: str = ""                     # short human-readable score
    detail: str = ""                    # extra context / link / error
    raw: dict = field(default_factory=dict)
    signals: dict = field(default_factory=dict)  # structured numbers for explanations

    def as_dict(self) -> dict:
        return {
            "provider": self.provider,
            "verdict": self.verdict,
            "score": self.score,
            "detail": self.detail,
        }


def worst_verdict(enrichments: list[Enrichment]) -> str:
    """Return the highest-severity verdict across providers."""
    worst = "unknown"
    for e in enrichments:
        if _SEVERITY.get(e.verdict, 0) > _SEVERITY.get(worst, 0):
            worst = e.verdict
    return worst


class AbuseIPDBClient:
    BASE = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str | None, timeout: int = 15):
        self.api_key = api_key
        self.timeout = timeout
        # Daily rate-limit, read from response headers on each call.
        self.rl_limit: int | None = None
        self.rl_remaining: int | None = None

    def supports(self, ioc_type: str) -> bool:
        return ioc_type == "ipv4"

    def _capture_limits(self, resp: requests.Response) -> None:
        try:
            if "X-RateLimit-Limit" in resp.headers:
                self.rl_limit = int(resp.headers["X-RateLimit-Limit"])
            if "X-RateLimit-Remaining" in resp.headers:
                self.rl_remaining = int(resp.headers["X-RateLimit-Remaining"])
        except (ValueError, TypeError):
            pass

    def quota(self) -> dict | None:
        """Latest known daily usage, or None if no call has been made yet."""
        if self.rl_limit is None or self.rl_remaining is None:
            return None
        used = max(0, self.rl_limit - self.rl_remaining)
        return {
            "provider": "AbuseIPDB", "period": "day",
            "used": used, "limit": self.rl_limit, "remaining": self.rl_remaining,
        }

    def fetch_quota(self) -> dict | None:
        """Prime the quota by making one lightweight check (costs 1 request)."""
        if not self.api_key:
            return None
        self.check("1.1.1.1")
        return self.quota()

    def check(self, value: str) -> Enrichment:
        if not self.api_key:
            return Enrichment("AbuseIPDB", verdict="skipped", detail="no API key")
        try:
            resp = requests.get(
                self.BASE,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": value, "maxAgeInDays": 90},
                timeout=self.timeout,
            )
            self._capture_limits(resp)
            if resp.status_code == 429:
                return Enrichment("AbuseIPDB", verdict="unknown", detail="rate limited (429)")
            resp.raise_for_status()
            data = resp.json().get("data", {})
        except requests.RequestException as exc:
            return Enrichment("AbuseIPDB", verdict="unknown", detail=f"error: {exc}")

        confidence = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        country = data.get("countryCode") or "?"
        if confidence >= 50:
            verdict = "malicious"
        elif confidence > 0 or reports > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"
        return Enrichment(
            "AbuseIPDB",
            verdict=verdict,
            score=f"{confidence}% / {reports} reports",
            detail=f"country={country}",
            raw=data,
            signals={
                "confidence": confidence,
                "reports": reports,
                "is_tor": bool(data.get("isTor")),
                "usage_type": data.get("usageType") or "",
            },
        )


class VirusTotalClient:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str | None, timeout: int = 20):
        self.api_key = api_key
        self.timeout = timeout

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in {"ipv4", "domain", "url", "md5", "sha1", "sha256"}

    def quota(self) -> dict | None:
        """Daily API usage from the VT user object (costs 1 request)."""
        if not self.api_key:
            return None
        try:
            resp = requests.get(
                f"{self.BASE}/users/{self.api_key}",
                headers={"x-apikey": self.api_key},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            daily = (
                resp.json()
                .get("data", {})
                .get("attributes", {})
                .get("quotas", {})
                .get("api_requests_daily", {})
            )
        except (requests.RequestException, ValueError):
            return None
        allowed = daily.get("allowed")
        used = daily.get("used")
        if allowed is None or used is None:
            return None
        return {
            "provider": "VirusTotal", "period": "day",
            "used": used, "limit": allowed, "remaining": max(0, allowed - used),
        }

    def _endpoint(self, value: str, ioc_type: str) -> str:
        if ioc_type == "ipv4":
            return f"/ip_addresses/{value}"
        if ioc_type == "domain":
            return f"/domains/{value}"
        if ioc_type == "url":
            # VT identifies URLs by their unpadded base64-url id.
            url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            return f"/urls/{url_id}"
        return f"/files/{value}"  # any hash type

    def check(self, value: str, ioc_type: str) -> Enrichment:
        if not self.api_key:
            return Enrichment("VirusTotal", verdict="skipped", detail="no API key")
        try:
            resp = requests.get(
                self.BASE + self._endpoint(value, ioc_type),
                headers={"x-apikey": self.api_key},
                timeout=self.timeout,
            )
            if resp.status_code == 404:
                return Enrichment("VirusTotal", verdict="unknown", detail="not found in VT")
            if resp.status_code == 429:
                return Enrichment("VirusTotal", verdict="unknown", detail="rate limited (429)")
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
        except requests.RequestException as exc:
            return Enrichment("VirusTotal", verdict="unknown", detail=f"error: {exc}")

        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected
        if malicious >= 1:
            verdict = "malicious"
        elif suspicious >= 1:
            verdict = "suspicious"
        elif total > 0:
            verdict = "clean"
        else:
            verdict = "unknown"
        signals = {"malicious": malicious, "suspicious": suspicious, "total": total}
        if ioc_type == "domain":
            # epoch seconds; lets us flag newly-registered domains downstream.
            signals["creation_date"] = attrs.get("creation_date")
        return Enrichment(
            "VirusTotal",
            verdict=verdict,
            score=f"{malicious}/{total} engines" if total else "no data",
            detail=attrs.get("meaningful_name", "") or "",
            raw=stats,
            signals=signals,
        )


class Enricher:
    """Routes each IOC to whichever providers support its type."""

    def __init__(self, vt_key: str | None, abuseipdb_key: str | None, pause: float = 0.0):
        self.vt = VirusTotalClient(vt_key)
        self.abuse = AbuseIPDBClient(abuseipdb_key)
        self.pause = pause  # seconds between API calls (free-tier rate limits)

    def enrich(self, value: str, ioc_type: str) -> list[Enrichment]:
        results: list[Enrichment] = []
        if self.abuse.supports(ioc_type):
            results.append(self.abuse.check(value))
            self._sleep()
        if self.vt.supports(ioc_type):
            results.append(self.vt.check(value, ioc_type))
            self._sleep()
        return results

    def _sleep(self) -> None:
        if self.pause > 0:
            time.sleep(self.pause)

    def usage(self, refresh_vt: bool = True) -> dict[str, dict | None]:
        """Current quota for each provider.

        AbuseIPDB usage is read from headers captured during this run (free);
        VirusTotal usage requires one extra call, done only when ``refresh_vt``.
        """
        return {
            "AbuseIPDB": self.abuse.quota(),
            "VirusTotal": self.vt.quota() if refresh_vt else None,
        }


def fetch_quotas(
    vt_key: str | None, abuse_key: str | None, probe_abuse: bool = True
) -> dict[str, dict | None]:
    """Stand-alone quota lookup (used by the GUI on startup / Refresh).

    ``probe_abuse`` makes one throwaway AbuseIPDB check so its headers are
    available even before a real scan (costs 1 request).
    """
    abuse = AbuseIPDBClient(abuse_key)
    vt = VirusTotalClient(vt_key)
    return {
        "AbuseIPDB": abuse.fetch_quota() if probe_abuse else abuse.quota(),
        "VirusTotal": vt.quota(),
    }
