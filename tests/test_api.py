"""Basic API smoke tests using httpx."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock


@pytest.fixture
def client():
    # Prevent real packet capture from starting
    with patch("packet_mapper.api.PacketCapture") as MockCapture:
        instance = MagicMock()
        MockCapture.return_value = instance

        from packet_mapper.api import app
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_index_returns_html(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
