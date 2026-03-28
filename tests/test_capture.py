"""Tests for capture.py — no real packet capture."""

from packet_mapper.capture import Connection, PacketCapture


def test_connection_as_dict():
    conn = Connection(src_ip="1.2.3.4", dst_ip="5.6.7.8", protocol="TCP", src_port=12345, dst_port=443)
    d = conn.as_dict()
    assert d["src_ip"] == "1.2.3.4"
    assert d["protocol"] == "TCP"
    assert d["dst_port"] == 443


def test_capture_callback_registration():
    cap = PacketCapture()
    events = []
    cap.add_callback(lambda c: events.append(c))
    assert len(cap._callbacks) == 1


def test_capture_handle_packet_no_crash():
    """Ensure _handle_packet silently handles malformed/non-IP packets."""
    cap = PacketCapture()
    events = []
    cap.add_callback(lambda c: events.append(c))

    # Pass a plain bytes object — should not raise
    cap._handle_packet(b"garbage")
    assert events == []
