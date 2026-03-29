"""Threat intelligence: checks IPs against AbuseIPDB or a local blocklist."""

import logging
import os
from dataclasses import dataclass
from typing import Optional

import requests

from ._cache import _BoundedCache
from .geo import is_private

logger = logging.getLogger(__name__)

# In-memory cache: ip → ThreatInfo
_THREAT_CACHE: _BoundedCache = _BoundedCache()

# Built-in blocklist (well-known scanners / honeypot sources) used when no API key is configured
_LOCAL_BLOCKLIST: frozenset[str] = frozenset({
    "198.20.69.74",    # Shodan scanner
    "198.20.69.98",    # Shodan scanner
    "198.20.70.114",   # Shodan scanner
    "198.20.71.98",    # Shodan scanner
    "198.20.87.98",    # Shodan scanner
    "198.20.99.130",   # Shodan scanner
    "209.126.136.4",   # known mass scanner
    "89.248.167.131",  # Shadowserver scanner
    "89.248.172.16",   # Shadowserver scanner
    "94.102.49.190",   # known scanner
})

# Minimum AbuseIPDB confidence score to flag an IP as malicious
_SCORE_THRESHOLD = 25


@dataclass
class ThreatInfo:
    ip: str
    score: int       # 0–100 abuse confidence score
    reports: int     # total abuse reports (0 for local blocklist entries)
    is_flagged: bool
    source: str      # "abuseipdb", "local", or "clean"

    def as_dict(self) -> dict:
        return {
            "ip": self.ip,
            "score": self.score,
            "reports": self.reports,
            "is_flagged": self.is_flagged,
            "source": self.source,
        }


def check(ip: str, timeout: int = 3) -> Optional[ThreatInfo]:
    """Return ThreatInfo for a public IP, using a local cache. Returns None for private IPs."""
    if is_private(ip):
        return None

    if ip in _THREAT_CACHE:
        return _THREAT_CACHE[ip]

    info = _check_abuseipdb(ip, timeout) or _check_local(ip)
    _THREAT_CACHE[ip] = info
    return info


def _check_abuseipdb(ip: str, timeout: int) -> Optional[ThreatInfo]:
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return None

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 30},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=timeout,
        )
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        return ThreatInfo(
            ip=ip,
            score=score,
            reports=reports,
            is_flagged=score >= _SCORE_THRESHOLD,
            source="abuseipdb",
        )
    except Exception as exc:
        logger.debug("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return None


def _check_local(ip: str) -> ThreatInfo:
    if ip in _LOCAL_BLOCKLIST:
        return ThreatInfo(ip=ip, score=100, reports=0, is_flagged=True, source="local")
    return ThreatInfo(ip=ip, score=0, reports=0, is_flagged=False, source="clean")
