"""FastAPI application: serves the UI and broadcasts connections via WebSocket."""

import asyncio
import collections
import csv
import io
import json
import logging
import os
import tempfile
import time
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, WebSocket, WebSocketDisconnect
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
_capture: PacketCapture | None = None
_connections: collections.deque = collections.deque(maxlen=10_000)


@app.get("/", response_class=HTMLResponse)
async def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/health")
async def health():
    flagged = sum(1 for r in list(_connections) if r.get("is_flagged"))
    return {"status": "ok", "clients": len(_clients), "flagged_connections": flagged}


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
        "connection": conn.as_dict(),
        "src_geo": src_geo.as_dict() if src_geo else None,
        "dst_geo": dst_geo.as_dict() if dst_geo else None,
        "src_threat": src_threat.as_dict() if src_threat else None,
        "dst_threat": dst_threat.as_dict() if dst_threat else None,
    }

    _connections.append({
        "timestamp": ts,
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


@app.get("/api/timeline")
async def get_timeline():
    records = []
    for record in list(_connections):
        conn = record["connection"]
        src_geo = record["src_geo"]
        dst_geo = record["dst_geo"]
        src_threat = record.get("src_threat")
        dst_threat = record.get("dst_threat")
        records.append({
            "timestamp": record["timestamp"],
            "type": "connection",
            "connection": conn.as_dict(),
            "src_geo": src_geo.as_dict() if src_geo else None,
            "dst_geo": dst_geo.as_dict() if dst_geo else None,
            "src_threat": src_threat.as_dict() if src_threat else None,
            "dst_threat": dst_threat.as_dict() if dst_threat else None,
        })
    return JSONResponse(records)


@app.get("/api/export/pcap")
async def export_pcap(background_tasks: BackgroundTasks):
    if _capture is None:
        return JSONResponse({"error": "capture not started"}, status_code=503)
    packets = _capture.get_packets()
    if not packets:
        return JSONResponse({"error": "no packets captured yet"}, status_code=404)

    from scapy.utils import wrpcap

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        tmp_path = f.name
    wrpcap(tmp_path, packets)
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
    for record in list(_connections):
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
    global _capture
    interface = os.environ.get("PACKET_MAPPER_IFACE")  # None = default interface
    _capture = PacketCapture(interface=interface)
    _capture.add_callback(_on_connection)
    _capture.start()


@app.on_event("shutdown")
async def shutdown():
    if _capture:
        _capture.stop()
