"""FastAPI application: serves the UI and broadcasts connections via WebSocket."""

import asyncio
import collections
import csv
import io
import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .capture import Connection, PacketCapture
from .geo import lookup
from .threat import check as threat_check

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent.parent.parent / "static"

app = FastAPI(title="packet-mapper", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

_clients: set[WebSocket] = set()
_clients_lock: asyncio.Lock = asyncio.Lock()
# Key: interface name, or "" for the default/all-interface capture
_captures: dict[str, PacketCapture] = {}
_connections: collections.deque = collections.deque(maxlen=10_000)
_connections_lock: threading.Lock = threading.Lock()


def _iface_key(interface: str | None) -> str:
    return interface or ""


def _list_interfaces() -> list[dict]:
    """Return available system network interfaces with capture status."""
    try:
        from scapy.interfaces import get_if_list
        names = get_if_list()
    except Exception:
        import socket
        names = [name for _, name in socket.if_nameindex()]

    default_capturing = "" in _captures and _captures[""]._running
    result = []
    for name in names:
        ip = None
        try:
            from scapy.interfaces import get_if_addr
            addr = get_if_addr(name)
            if addr and addr != "0.0.0.0":
                ip = addr
        except Exception:
            pass
        specific_capturing = name in _captures and _captures[name]._running
        result.append({
            "name": name,
            "ip": ip,
            "capturing": specific_capturing or default_capturing,
        })
    return result


@app.get("/", response_class=HTMLResponse)
async def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/health")
async def health():
    with _connections_lock:
        connections_snapshot = list(_connections)
    flagged = sum(1 for r in connections_snapshot if r.get("is_flagged"))
    active = [k if k else "default" for k, v in _captures.items() if v._running]
    return {"status": "ok", "clients": len(_clients), "flagged_connections": flagged, "active_interfaces": active}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    async with _clients_lock:
        _clients.add(ws)
    logger.info("WS client connected (%d total)", len(_clients))
    try:
        while True:
            # Keep alive — client doesn't send data
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        async with _clients_lock:
            _clients.discard(ws)
        logger.info("WS client disconnected (%d total)", len(_clients))


async def _broadcast(data: dict) -> None:
    async with _clients_lock:
        clients = set(_clients)
    dead: set[WebSocket] = set()
    for ws in clients:
        try:
            await ws.send_text(json.dumps(data))
        except Exception:
            dead.add(ws)
    if dead:
        async with _clients_lock:
            _clients -= dead


def _make_on_connection(interface: str | None):
    """Return a connection callback bound to a specific interface."""
    iface_name = interface or "default"

    def _on_connection(conn: Connection) -> None:
        """Called from the capture thread; schedule a broadcast on the event loop."""
        src_geo = lookup(conn.src_ip)
        dst_geo = lookup(conn.dst_ip)

        # Skip if both endpoints are private/unresolvable
        if (src_geo is None or src_geo.is_private) and (dst_geo is None or dst_geo.is_private):
            return

        src_threat = threat_check(conn.src_ip)
        dst_threat = threat_check(conn.dst_ip)
        is_flagged = bool(
            (src_threat and src_threat.is_flagged) or (dst_threat and dst_threat.is_flagged)
        )

        ts = time.time()
        payload = {
            "type": "connection",
            "timestamp": ts,
            "interface": iface_name,
            "connection": conn.as_dict(),
            "src_geo": src_geo.as_dict() if src_geo else None,
            "dst_geo": dst_geo.as_dict() if dst_geo else None,
            "src_threat": src_threat.as_dict() if src_threat else None,
            "dst_threat": dst_threat.as_dict() if dst_threat else None,
        }

        with _connections_lock:
            _connections.append({
                "timestamp": ts,
                "interface": iface_name,
                "connection": conn,
                "src_geo": src_geo,
                "dst_geo": dst_geo,
                "src_threat": src_threat,
                "dst_threat": dst_threat,
                "is_flagged": is_flagged,
            })

        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(_broadcast(payload), loop)

    return _on_connection


@app.get("/api/interfaces")
async def get_interfaces():
    return JSONResponse(_list_interfaces())


@app.post("/api/capture/start")
async def start_capture(request: Request):
    data = await request.json()
    interface = data.get("interface") or None
    key = _iface_key(interface)

    if key in _captures and _captures[key]._running:
        return JSONResponse({"status": "already_running", "interface": interface})

    capture = PacketCapture(interface=interface)
    capture.add_callback(_make_on_connection(interface))
    capture.start()
    _captures[key] = capture
    logger.info("Capture started via API on interface: %s", interface or "default")
    return JSONResponse({"status": "started", "interface": interface})


@app.post("/api/capture/stop")
async def stop_capture(request: Request):
    data = await request.json()
    interface = data.get("interface") or None
    key = _iface_key(interface)

    capture = _captures.pop(key, None)
    if not capture:
        return JSONResponse({"status": "not_running", "interface": interface})

    capture.stop()
    logger.info("Capture stopped via API on interface: %s", interface or "default")
    return JSONResponse({"status": "stopped", "interface": interface})


@app.get("/api/timeline")
async def get_timeline():
    with _connections_lock:
        connections_snapshot = list(_connections)
    records = []
    for record in connections_snapshot:
        conn = record["connection"]
        src_geo = record["src_geo"]
        dst_geo = record["dst_geo"]
        src_threat = record.get("src_threat")
        dst_threat = record.get("dst_threat")
        records.append({
            "timestamp": record["timestamp"],
            "type": "connection",
            "interface": record.get("interface", "default"),
            "connection": conn.as_dict(),
            "src_geo": src_geo.as_dict() if src_geo else None,
            "dst_geo": dst_geo.as_dict() if dst_geo else None,
            "src_threat": src_threat.as_dict() if src_threat else None,
            "dst_threat": dst_threat.as_dict() if dst_threat else None,
        })
    return JSONResponse(records)


@app.get("/api/export/pcap")
async def export_pcap(background_tasks: BackgroundTasks):
    if not _captures:
        return JSONResponse({"error": "capture not started"}, status_code=503)
    all_packets = []
    for capture in _captures.values():
        all_packets.extend(capture.get_packets())
    if not all_packets:
        return JSONResponse({"error": "no packets captured yet"}, status_code=404)

    from scapy.utils import wrpcap

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        tmp_path = f.name
    wrpcap(tmp_path, all_packets)
    background_tasks.add_task(os.unlink, tmp_path)
    return FileResponse(
        tmp_path,
        media_type="application/vnd.tcpdump.pcap",
        filename="capture.pcap",
    )


@app.get("/api/export/csv")
async def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "country", "city", "hostname"]
    )
    with _connections_lock:
        connections_snapshot = list(_connections)
    for record in connections_snapshot:
        conn = record["connection"]
        dst_geo = record["dst_geo"]
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record["timestamp"]))
        writer.writerow([
            ts,
            conn.src_ip,
            conn.dst_ip,
            conn.protocol,
            conn.src_port if conn.src_port is not None else "",
            conn.dst_port if conn.dst_port is not None else "",
            dst_geo.country if dst_geo else "",
            dst_geo.city if dst_geo else "",
            conn.dns_query or conn.http_host or "",
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=connections.csv"},
    )


@app.on_event("startup")
async def startup():
    global _captures
    interface = os.environ.get("PACKET_MAPPER_IFACE") or None
    key = _iface_key(interface)
    capture = PacketCapture(interface=interface)
    capture.add_callback(_make_on_connection(interface))
    capture.start()
    _captures[key] = capture


@app.on_event("shutdown")
async def shutdown():
    for capture in list(_captures.values()):
        capture.stop()
    _captures.clear()
