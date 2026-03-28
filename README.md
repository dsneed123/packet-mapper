# packet-mapper

Web-based packet sniffer that geolocates network connections and plots them on a live world map.

## Features

- Live packet capture via [Scapy](https://scapy.net/) (TCP, UDP, raw IP)
- IP geolocation using the [ip-api.com](http://ip-api.com/) free API
- Real-time map rendered with [Leaflet.js](https://leafletjs.com/) + dark CartoDB tiles
- WebSocket broadcast — open multiple browser tabs, all stay in sync
- Sidebar showing recent connections with protocol + country

## Requirements

- Python 3.10+
- Root/sudo or `CAP_NET_RAW` capability (required for raw packet capture)

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Run

```bash
# Requires root for packet capture
sudo .venv/bin/packet-mapper --host 0.0.0.0 --port 8000

# Or specify an interface
sudo .venv/bin/packet-mapper --iface eth0 --debug
```

Open `http://localhost:8000` in your browser.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PACKET_MAPPER_IFACE` | auto | Network interface to sniff |

## Development

```bash
# Lint
ruff check src/ tests/

# Test
pytest

# Format
ruff format src/ tests/
```

## Architecture

```
src/packet_mapper/
  capture.py   — scapy sniff loop, emits Connection objects
  geo.py       — IP → lat/lon via ip-api.com, with in-process cache
  api.py       — FastAPI app, WebSocket broadcast, static file serving
  main.py      — CLI entry point (argparse + uvicorn)

static/
  index.html   — single-page UI shell
  css/style.css
  js/map.js    — Leaflet map + WebSocket client
```
