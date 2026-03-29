"""Tests for threat.py — no network calls."""

import os
from unittest.mock import patch

import pytest

from packet_mapper.threat import ThreatInfo, _LOCAL_BLOCKLIST, check


def _clear_cache(ip: str):
    from packet_mapper import threat
    threat._THREAT_CACHE.pop(ip, None)


def test_private_ip_returns_none():
    assert check("192.168.1.1") is None
    assert check("127.0.0.1") is None


def test_local_blocklist_ip_is_flagged():
    ip = next(iter(_LOCAL_BLOCKLIST))
    _clear_cache(ip)
    info = check(ip)
    assert info is not None
    assert info.is_flagged
    assert info.score == 100
    assert info.source == "local"


def test_clean_ip_is_not_flagged():
    ip = "8.8.8.8"
    _clear_cache(ip)
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("ABUSEIPDB_API_KEY", None)
        info = check(ip)
    assert info is not None
    assert not info.is_flagged
    assert info.score == 0
    assert info.source == "clean"


def test_abuseipdb_flagged_when_high_score():
    ip = "1.2.3.4"
    _clear_cache(ip)
    mock_response = {
        "data": {
            "abuseConfidenceScore": 85,
            "totalReports": 42,
        }
    }
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
        with patch("packet_mapper.threat.requests.get") as mock_get:
            mock_get.return_value.json.return_value = mock_response
            info = check(ip)

    assert info is not None
    assert info.is_flagged
    assert info.score == 85
    assert info.reports == 42
    assert info.source == "abuseipdb"


def test_abuseipdb_clean_when_low_score():
    ip = "5.6.7.8"
    _clear_cache(ip)
    mock_response = {
        "data": {
            "abuseConfidenceScore": 10,
            "totalReports": 1,
        }
    }
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
        with patch("packet_mapper.threat.requests.get") as mock_get:
            mock_get.return_value.json.return_value = mock_response
            info = check(ip)

    assert info is not None
    assert not info.is_flagged
    assert info.score == 10
    assert info.source == "abuseipdb"


def test_abuseipdb_failure_falls_back_to_local():
    ip = "9.9.9.9"
    _clear_cache(ip)
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}):
        with patch("packet_mapper.threat.requests.get", side_effect=Exception("timeout")):
            info = check(ip)

    assert info is not None
    assert info.source == "clean"
    assert not info.is_flagged


def test_result_is_cached():
    ip = "10.0.0.1"  # private — returns None, not cached
    # Use a public IP
    ip = "8.8.4.4"
    _clear_cache(ip)
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("ABUSEIPDB_API_KEY", None)
        info1 = check(ip)
        info2 = check(ip)

    assert info1 is info2  # same object from cache


def test_threat_cache_ttl_expiry():
    """Cached threat entries are evicted after TTL expires."""
    from packet_mapper import threat
    from packet_mapper._cache import TTL

    ip = "11.22.33.44"
    _clear_cache(ip)
    with patch("packet_mapper._cache.time.monotonic") as mock_mono:
        mock_mono.return_value = 0.0
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            info = check(ip)
        assert info is not None

        mock_mono.return_value = TTL - 1  # still within TTL
        assert ip in threat._THREAT_CACHE

        mock_mono.return_value = TTL + 1  # past TTL
        assert ip not in threat._THREAT_CACHE


def test_threat_cache_max_size():
    """Cache evicts the oldest entry when max_size is exceeded."""
    from packet_mapper._cache import _BoundedCache

    cache = _BoundedCache(max_size=3)
    cache["a"] = "val_a"
    cache["b"] = "val_b"
    cache["c"] = "val_c"
    cache["d"] = "val_d"  # should evict "a"

    assert len(cache._store) == 3
    assert "a" not in cache._store
    assert cache["d"] == "val_d"


def test_threat_info_as_dict():
    info = ThreatInfo(ip="1.2.3.4", score=75, reports=10, is_flagged=True, source="abuseipdb")
    d = info.as_dict()
    assert d["ip"] == "1.2.3.4"
    assert d["score"] == 75
    assert d["reports"] == 10
    assert d["is_flagged"] is True
    assert d["source"] == "abuseipdb"
