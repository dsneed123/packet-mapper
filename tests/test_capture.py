"""Tests for capture.py — no real packet capture."""

from packet_mapper.capture import Connection, PacketCapture, _extract_http_host


def test_connection_as_dict():
    conn = Connection(src_ip="1.2.3.4", dst_ip="5.6.7.8", protocol="TCP", src_port=12345, dst_port=443)
    d = conn.as_dict()
    assert d["src_ip"] == "1.2.3.4"
    assert d["protocol"] == "TCP"
    assert d["dst_port"] == 443
    assert d["dns_query"] is None
    assert d["http_host"] is None


def test_connection_as_dict_with_extras():
    conn = Connection(
        src_ip="1.2.3.4",
        dst_ip="5.6.7.8",
        protocol="DNS",
        src_port=54321,
        dst_port=53,
        dns_query="example.com",
    )
    d = conn.as_dict()
    assert d["protocol"] == "DNS"
    assert d["dns_query"] == "example.com"


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


def test_handle_packet_icmp():
    """ICMP packets should produce protocol='ICMP'."""
    from scapy.layers.inet import ICMP, IP

    cap = PacketCapture()
    events = []
    cap.add_callback(lambda c: events.append(c))

    pkt = IP(src="1.2.3.4", dst="5.6.7.8") / ICMP()
    cap._handle_packet(pkt)
    assert len(events) == 1
    assert events[0].protocol == "ICMP"


def test_handle_packet_dns():
    """UDP port-53 DNS packets should produce protocol='DNS' with dns_query set."""
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, UDP

    cap = PacketCapture()
    events = []
    cap.add_callback(lambda c: events.append(c))

    pkt = IP(src="1.2.3.4", dst="8.8.8.8") / UDP(sport=12345, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="example.com")
    )
    cap._handle_packet(pkt)
    assert len(events) == 1
    assert events[0].protocol == "DNS"
    assert events[0].dns_query == "example.com"


def test_handle_packet_http():
    """TCP port-80 packets with HTTP payload should produce protocol='HTTP' and http_host."""
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw

    cap = PacketCapture()
    events = []
    cap.add_callback(lambda c: events.append(c))

    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
    pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=54321, dport=80) / Raw(load=payload)
    cap._handle_packet(pkt)
    assert len(events) == 1
    assert events[0].protocol == "HTTP"
    assert events[0].http_host == "example.com"


def test_handle_packet_https():
    """TCP port-443 packets should produce protocol='HTTPS'."""
    from scapy.layers.inet import IP, TCP

    cap = PacketCapture()
    events = []
    cap.add_callback(lambda c: events.append(c))

    pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=54321, dport=443)
    cap._handle_packet(pkt)
    assert len(events) == 1
    assert events[0].protocol == "HTTPS"
