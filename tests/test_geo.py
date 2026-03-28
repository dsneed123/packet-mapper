"""Tests for geo.py — no network calls."""

from unittest.mock import patch

from packet_mapper.geo import GeoLocation, is_private, lookup


def test_is_private_loopback():
    assert is_private("127.0.0.1")


def test_is_private_rfc1918():
    assert is_private("192.168.1.1")
    assert is_private("10.0.0.1")
    assert is_private("172.16.0.1")


def test_is_public():
    assert not is_private("8.8.8.8")


def test_lookup_private_returns_private_geo():
    loc = lookup("192.168.1.1")
    assert loc is not None
    assert loc.is_private
    assert loc.ip == "192.168.1.1"


def test_lookup_public_success():
    mock_response = {
        "status": "success",
        "lat": 37.4,
        "lon": -122.1,
        "city": "Mountain View",
        "country": "United States",
        "isp": "Google LLC",
    }
    with patch("packet_mapper.geo.requests.get") as mock_get:
        mock_get.return_value.json.return_value = mock_response
        loc = lookup("8.8.8.8")

    assert loc is not None
    assert loc.lat == 37.4
    assert loc.country == "United States"
    assert not loc.is_private


def test_lookup_public_failure_returns_none():
    with patch("packet_mapper.geo.requests.get", side_effect=Exception("timeout")):
        # Clear cache first
        from packet_mapper import geo
        geo._GEO_CACHE.pop("1.2.3.4", None)
        loc = lookup("1.2.3.4")

    assert loc is None


def test_geo_location_as_dict():
    loc = GeoLocation(ip="8.8.8.8", lat=37.4, lon=-122.1, city="MV", country="US", isp="Google")
    d = loc.as_dict()
    assert d["ip"] == "8.8.8.8"
    assert d["lat"] == 37.4
    assert "is_private" in d
