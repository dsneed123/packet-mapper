"""FastAPI application: serves the UI and broadcasts connections via WebSocket."""

import asyncio
import json
import logging
import os
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
    src_geo = lookup(conn.src_ip)
    dst_geo = lookup(conn.dst_ip)

    # Skip if both endpoints are private/unresolvable
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
