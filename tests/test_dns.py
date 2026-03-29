"""Tests for dns.py — no real network calls."""

import socket
from unittest.mock import patch

import pytest


def _clear(ip):
    from packet_mapper import dns
    dns._DNS_CACHE.pop(ip, None)


def test_reverse_lookup_success():
    _clear("8.8.8.8")
    with patch("socket.gethostbyaddr", return_value=("dns.google", [], ["8.8.8.8"])):
        from packet_mapper.dns import reverse_lookup
        result = reverse_lookup("8.8.8.8")
    assert result == "dns.google"


def test_reverse_lookup_caches_result():
    _clear("1.1.1.1")
    with patch("socket.gethostbyaddr", return_value=("one.one.one.one", [], ["1.1.1.1"])) as mock:
        from packet_mapper.dns import reverse_lookup
        reverse_lookup("1.1.1.1")
        reverse_lookup("1.1.1.1")
    mock.assert_called_once()


def test_reverse_lookup_failure_returns_none():
    _clear("192.0.2.1")
    with patch("socket.gethostbyaddr", side_effect=socket.herror("no PTR record")):
        from packet_mapper.dns import reverse_lookup
        result = reverse_lookup("192.0.2.1")
    assert result is None


def test_reverse_lookup_same_as_ip_returns_none():
    """PTR that resolves to the IP itself is treated as no hostname."""
    _clear("10.0.0.1")
    with patch("socket.gethostbyaddr", return_value=("10.0.0.1", [], ["10.0.0.1"])):
        from packet_mapper.dns import reverse_lookup
        result = reverse_lookup("10.0.0.1")
    assert result is None


def test_reverse_lookup_caches_none_on_failure():
    _clear("203.0.113.1")
    with patch("socket.gethostbyaddr", side_effect=socket.gaierror("not found")):
        from packet_mapper.dns import reverse_lookup
        result = reverse_lookup("203.0.113.1")
    assert result is None

    # Second call should not hit socket again (cached None)
    with patch("socket.gethostbyaddr", side_effect=Exception("should not be called")) as mock:
        reverse_lookup("203.0.113.1")
    mock.assert_not_called()
