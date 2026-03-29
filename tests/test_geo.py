"""Tests for geo.py — no network calls, no filesystem access."""

from unittest.mock import MagicMock, patch

from packet_mapper import geo
from packet_mapper.geo import GeoLocation, is_private, lookup


def setup_function():
    """Reset shared state between tests."""
    geo._GEO_CACHE.clear()
    geo._db_reader = None
    geo._db_attempted = False


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


def test_lookup_public_geoip2_success():
    mock_reader = MagicMock()
    mock_record = MagicMock()
    mock_record.location.latitude = 37.4
    mock_record.location.longitude = -122.1
    mock_record.city.name = "Mountain View"
    mock_record.country.name = "United States"
    mock_reader.city.return_value = mock_record

    with patch("packet_mapper.geo._get_db_reader", return_value=mock_reader):
        loc = lookup("8.8.8.8")

    assert loc is not None
    assert loc.lat == 37.4
    assert loc.lon == -122.1
    assert loc.city == "Mountain View"
    assert loc.country == "United States"
    assert not loc.is_private


def test_lookup_public_success():
    """ip-api.com fallback is used when GeoLite2 DB is unavailable."""
    mock_response = {
        "status": "success",
        "lat": 37.4,
        "lon": -122.1,
        "city": "Mountain View",
        "country": "United States",
        "isp": "Google LLC",
    }
    with patch("packet_mapper.geo._get_db_reader", return_value=None):
        with patch("packet_mapper.geo.requests.get") as mock_get:
            mock_get.return_value.json.return_value = mock_response
            loc = lookup("8.8.8.8")

    assert loc is not None
    assert loc.lat == 37.4
    assert loc.country == "United States"
    assert loc.isp == "Google LLC"
    assert not loc.is_private


def test_lookup_public_failure_returns_none():
    with patch("packet_mapper.geo._get_db_reader", return_value=None):
        with patch("packet_mapper.geo.requests.get", side_effect=Exception("timeout")):
            loc = lookup("1.2.3.4")

    assert loc is None


def test_geo_location_as_dict():
    loc = GeoLocation(ip="8.8.8.8", lat=37.4, lon=-122.1, city="MV", country="US", isp="Google")
    d = loc.as_dict()
    assert d["ip"] == "8.8.8.8"
    assert d["lat"] == 37.4
    assert "is_private" in d


def test_lookup_geoip2_falls_back_on_exception():
    """If GeoLite2 raises, lookup falls back to ip-api.com."""
    mock_reader = MagicMock()
    mock_reader.city.side_effect = Exception("record not found")

    mock_response = {
        "status": "success",
        "lat": 1.0,
        "lon": 2.0,
        "city": "Somewhere",
        "country": "Testland",
        "isp": "TestISP",
    }
    with patch("packet_mapper.geo._get_db_reader", return_value=mock_reader):
        with patch("packet_mapper.geo.requests.get") as mock_get:
            mock_get.return_value.json.return_value = mock_response
            loc = lookup("1.2.3.4")

    assert loc is not None
    assert loc.city == "Somewhere"
    assert loc.isp == "TestISP"
