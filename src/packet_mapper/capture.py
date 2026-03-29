"""Packet capture using scapy, emitting connection events."""

import collections
import logging
import threading
from dataclasses import dataclass
from typing import Callable, Optional

_MAX_STORED_PACKETS = 10_000

logger = logging.getLogger(__name__)

_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")


def _extract_http_host(pkt) -> Optional[str]:
    """Parse the HTTP Host header from a raw TCP payload, if present."""
    try:
        from scapy.packet import Raw

        if Raw not in pkt:
            return None
        payload = pkt[Raw].load
        if not payload.startswith(_HTTP_METHODS):
            return None
        for line in payload.split(b"\r\n"):
            if line.lower().startswith(b"host:"):
                return line[5:].strip().decode("ascii", errors="replace")
    except Exception:
        pass
    return None


def _parse_dns_query(pkt) -> Optional[str]:
    """Extract the first question name from a DNS query packet, or None."""
    try:
        from scapy.layers.dns import DNS

        dns = pkt[DNS]
        if dns.qr == 0 and dns.qd is not None:  # qr=0 → query
            return dns.qd.qname.decode("ascii", errors="replace").rstrip(".")
    except Exception:
        pass
    return None


@dataclass
class Connection:
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    dns_query: Optional[str] = None
    http_host: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "dns_query": self.dns_query,
            "http_host": self.http_host,
        }


ConnectionCallback = Callable[[Connection], None]


class PacketCapture:
    """Captures packets on a network interface and calls a callback per connection."""

    def __init__(self, interface: Optional[str] = None, bpf_filter: str = "ip or ip6"):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._callbacks: list[ConnectionCallback] = []
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._packets: collections.deque = collections.deque(maxlen=_MAX_STORED_PACKETS)

    def add_callback(self, cb: ConnectionCallback) -> None:
        self._callbacks.append(cb)

    def get_packets(self) -> list:
        """Return a snapshot of stored raw packets for export."""
        return list(self._packets)

    def _handle_packet(self, pkt) -> None:
        self._packets.append(pkt)
        try:
            from scapy.layers.dns import DNS
            from scapy.layers.inet import ICMP, IP, TCP, UDP
            from scapy.layers.inet6 import IPv6

            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
            elif IPv6 in pkt:
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst
            else:
                return

            if ICMP in pkt:
                conn = Connection(src_ip=src, dst_ip=dst, protocol="ICMP")
            elif DNS in pkt:
                sport = pkt[UDP].sport if UDP in pkt else (pkt[TCP].sport if TCP in pkt else None)
                dport = pkt[UDP].dport if UDP in pkt else (pkt[TCP].dport if TCP in pkt else None)
                conn = Connection(
                    src_ip=src,
                    dst_ip=dst,
                    protocol="DNS",
                    src_port=sport,
                    dst_port=dport,
                    dns_query=_parse_dns_query(pkt),
                )
            elif TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                if dport in (80, 8080) or sport in (80, 8080):
                    conn = Connection(
                        src_ip=src,
                        dst_ip=dst,
                        protocol="HTTP",
                        src_port=sport,
                        dst_port=dport,
                        http_host=_extract_http_host(pkt),
                    )
                elif dport == 443 or sport == 443:
                    conn = Connection(
                        src_ip=src, dst_ip=dst, protocol="HTTPS", src_port=sport, dst_port=dport
                    )
                else:
                    conn = Connection(
                        src_ip=src, dst_ip=dst, protocol="TCP", src_port=sport, dst_port=dport
                    )
            elif UDP in pkt:
                conn = Connection(
                    src_ip=src,
                    dst_ip=dst,
                    protocol="UDP",
                    src_port=pkt[UDP].sport,
                    dst_port=pkt[UDP].dport,
                )
            else:
                conn = Connection(src_ip=src, dst_ip=dst, protocol="IP")

            for cb in self._callbacks:
                cb(conn)
        except Exception as exc:
            logger.debug("Packet parse error: %s", exc)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        logger.info("Capture started on interface=%s filter='%s'", self.interface, self.bpf_filter)

    def stop(self) -> None:
        self._running = False
        logger.info("Capture stopped.")

    def _sniff_loop(self) -> None:
        from scapy.sendrecv import sniff

        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda _: not self._running,
        )
