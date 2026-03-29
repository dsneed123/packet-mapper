"""FastAPI application: serves the UI and broadcasts connections via WebSocket."""

import asyncio
import json
import logging
import os
import threading
import time
from collections import Counter, deque
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from .capture import Connection, PacketCapture
from .geo import lookup

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent.parent.parent / "static"

app = FastAPI(title="packet-mapper", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

_clients: set[WebSocket] = set()
_capture: PacketCapture | None = None

# --- Live stats (updated from capture thread, read from event loop) ---
_stats_lock = threading.Lock()
_stats_total: int = 0
_stats_bytes: int = 0
_stats_timestamps: deque = deque(maxlen=1000)
_stats_protocols: Counter = Counter()
_stats_countries: Counter = Counter()
_stats_ips: Counter = Counter()
_start_time: float = 0.0

# Rough average payload bytes per protocol for bandwidth estimation
_PROTO_BYTES: dict[str, int] = {
    "HTTP": 800,
    "HTTPS": 1200,
    "DNS": 64,
    "ICMP": 84,
    "TCP": 500,
    "UDP": 200,
    "IP": 100,
}


@app.get("/", response_class=HTMLResponse)
async def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/health")
async def health():
    return {"status": "ok", "clients": len(_clients)}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    _clients.add(ws)
    logger.info("WS client connected (%d total)", len(_clients))
    try:
        while True:
            # Keep alive — client doesn't send data
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        _clients.discard(ws)
        logger.info("WS client disconnected (%d total)", len(_clients))


async def _broadcast(data: dict) -> None:
    dead: set[WebSocket] = set()
    for ws in list(_clients):
        try:
            await ws.send_text(json.dumps(data))
        except Exception:
            dead.add(ws)
    _clients -= dead


def _on_connection(conn: Connection) -> None:
    """Called from the capture thread; schedule a broadcast on the event loop."""
    global _stats_total, _stats_bytes

    src_geo = lookup(conn.src_ip)
    dst_geo = lookup(conn.dst_ip)

    # Update live stats for every packet (before private-only skip)
    with _stats_lock:
        _stats_total += 1
        _stats_timestamps.append(time.monotonic())
        _stats_protocols[conn.protocol] += 1
        _stats_bytes += _PROTO_BYTES.get(conn.protocol, 300)
        if dst_geo and not dst_geo.is_private and dst_geo.country:
            _stats_countries[dst_geo.country] += 1
        if dst_geo and not dst_geo.is_private:
            _stats_ips[dst_geo.ip] += 1

    # Skip map broadcast if both endpoints are private/unresolvable
    if (src_geo is None or src_geo.is_private) and (dst_geo is None or dst_geo.is_private):
        return

    payload = {
        "type": "connection",
        "connection": conn.as_dict(),
        "src_geo": src_geo.as_dict() if src_geo else None,
        "dst_geo": dst_geo.as_dict() if dst_geo else None,
    }

    loop = asyncio.get_event_loop()
    if loop.is_running():
        asyncio.run_coroutine_threadsafe(_broadcast(payload), loop)


async def _stats_loop() -> None:
    """Broadcast a stats snapshot to all clients every 2 seconds."""
    while True:
        await asyncio.sleep(2)
        if not _clients:
            continue

        now = time.monotonic()
        with _stats_lock:
            total = _stats_total
            total_bytes = _stats_bytes
            # Count packets in the last 5 s for rate
            cutoff = now - 5.0
            recent = sum(1 for t in _stats_timestamps if t >= cutoff)
            rate = round(recent / 5.0, 1)
            protocols = dict(_stats_protocols.most_common())
            top_countries = _stats_countries.most_common(10)
            top_ips = _stats_ips.most_common(10)

        uptime_s = max(1, int(now - _start_time))
        bandwidth_bps = total_bytes // uptime_s

        payload = {
            "type": "stats",
            "total": total,
            "rate": rate,
            "protocols": protocols,
            "top_countries": [{"name": c, "count": n} for c, n in top_countries],
            "top_ips": [{"ip": ip, "count": n} for ip, n in top_ips],
            "bandwidth_bps": bandwidth_bps,
            "uptime_s": uptime_s,
        }
        await _broadcast(payload)


@app.on_event("startup")
async def startup():
    global _capture, _start_time, _stats_total, _stats_bytes
    _start_time = time.monotonic()
    _stats_total = 0
    _stats_bytes = 0
    _stats_timestamps.clear()
    _stats_protocols.clear()
    _stats_countries.clear()
    _stats_ips.clear()

    interface = os.environ.get("PACKET_MAPPER_IFACE")  # None = default interface
    _capture = PacketCapture(interface=interface)
    _capture.add_callback(_on_connection)
    _capture.start()
    asyncio.create_task(_stats_loop())


@app.on_event("shutdown")
async def shutdown():
    if _capture:
        _capture.stop()
