"""Basic API smoke tests using httpx."""

import time
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from packet_mapper.capture import Connection
from packet_mapper.geo import GeoLocation


@pytest.fixture
def client():
    # Prevent real packet capture from starting
    with patch("packet_mapper.api.PacketCapture") as MockCapture:
        instance = MagicMock()
        instance.get_packets.return_value = []
        MockCapture.return_value = instance

        from packet_mapper.api import app
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c


@pytest.fixture
def client_with_data():
    """Client with pre-populated connection and packet data."""
    with patch("packet_mapper.api.PacketCapture") as MockCapture:
        mock_pkt = MagicMock()
        instance = MagicMock()
        instance.get_packets.return_value = [mock_pkt]
        MockCapture.return_value = instance

        import packet_mapper.api as api_mod
        api_mod._connections.clear()
        conn = Connection(src_ip="1.2.3.4", dst_ip="5.6.7.8", protocol="TCP", src_port=12345, dst_port=443)
        dst_geo = GeoLocation(ip="5.6.7.8", lat=51.5, lon=-0.1, city="London", country="GB")
        api_mod._connections.append({
            "timestamp": time.time(),
            "connection": conn,
            "src_geo": None,
            "dst_geo": dst_geo,
        })

        from packet_mapper.api import app
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c

        api_mod._connections.clear()


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_index_returns_html(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_export_pcap_no_packets(client):
    resp = client.get("/api/export/pcap")
    assert resp.status_code == 404


def test_export_csv_empty(client):
    import packet_mapper.api as api_mod
    api_mod._connections.clear()
    resp = client.get("/api/export/csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    lines = resp.text.strip().splitlines()
    assert lines[0] == "timestamp,src_ip,dst_ip,protocol,src_port,dst_port,country,city,hostname"
    assert len(lines) == 1  # header only


def test_timeline_empty(client):
    import packet_mapper.api as api_mod
    api_mod._connections.clear()
    resp = client.get("/api/timeline")
    assert resp.status_code == 200
    assert resp.json() == []


def test_timeline_with_data(client_with_data):
    resp = client_with_data.get("/api/timeline")
    assert resp.status_code == 200
    records = resp.json()
    assert len(records) == 1
    assert "timestamp" in records[0]
    assert records[0]["type"] == "connection"
    assert records[0]["connection"]["src_ip"] == "1.2.3.4"
    assert records[0]["connection"]["dst_ip"] == "5.6.7.8"
    assert records[0]["dst_geo"]["city"] == "London"
    assert records[0]["src_threat"] is None
    assert records[0]["dst_threat"] is None


def test_export_csv_with_data(client_with_data):
    resp = client_with_data.get("/api/export/csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "attachment" in resp.headers["content-disposition"]
    lines = resp.text.strip().splitlines()
    assert len(lines) == 2  # header + one row
    assert "TCP" in lines[1]
    assert "5.6.7.8" in lines[1]
    assert "London" in lines[1]
    assert "GB" in lines[1]
