"""Packet capture using scapy, emitting connection events."""

import asyncio
import logging
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

logger = logging.getLogger(__name__)


@dataclass
class Connection:
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    def as_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
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

    def add_callback(self, cb: ConnectionCallback) -> None:
        self._callbacks.append(cb)

    def _handle_packet(self, pkt) -> None:
        try:
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.inet6 import IPv6

            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
            elif IPv6 in pkt:
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst
            else:
                return

            if TCP in pkt:
                conn = Connection(
                    src_ip=src,
                    dst_ip=dst,
                    protocol="TCP",
                    src_port=pkt[TCP].sport,
                    dst_port=pkt[TCP].dport,
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
