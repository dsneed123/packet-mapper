'use strict';

const map = L.map('map', { zoomControl: true }).setView([20, 0], 2);

L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
  attribution: '&copy; <a href="https://carto.com/">CARTO</a>',
  subdomains: 'abcd',
  maxZoom: 19,
}).addTo(map);

const statusEl   = document.getElementById('ws-status');
const countEl    = document.getElementById('conn-count');
const listEl     = document.getElementById('conn-list');

let totalConns = 0;
const MAX_LIST  = 50;   // sidebar items to keep
const MAX_LINES = 200;  // unique connection groups before pruning

// Connection groups: key → { count, line, protocol, fadeTimer }
const connGroups = new Map();
const groupOrder = [];  // insertion order for LRU pruning

// Heat map: destination key → { lat, lon, count }
const heatPoints = new Map();
let heatLayer = null;
let heatDirty = false;
let viewMode = 'lines';

const PROTOCOL_COLORS = {
  HTTP:  '#58a6ff',  // blue
  HTTPS: '#58a6ff',  // blue
  DNS:   '#3fb950',  // green
  ICMP:  '#f85149',  // red
  UDP:   '#d29922',  // yellow
  TCP:   '#c9d1d9',  // white
};

function protocolColor(protocol) {
  return PROTOCOL_COLORS[protocol] || '#8b949e';
}

function lineWeight(count) {
  return Math.min(1.5 + Math.log2(count) * 1.2, 8);
}

function lineOpacity(count) {
  return Math.min(0.5 + count * 0.04, 0.95);
}

function makeMarker(lat, lon, label) {
  return L.circleMarker([lat, lon], {
    radius: 5,
    color: '#58a6ff',
    fillColor: '#58a6ff',
    fillOpacity: 0.8,
    weight: 1,
  }).bindTooltip(label, { permanent: false });
}

function scheduleFade(key) {
  const group = connGroups.get(key);
  if (!group) return;
  if (group.fadeTimer) clearTimeout(group.fadeTimer);
  group.fadeTimer = setTimeout(() => {
    const g = connGroups.get(key);
    if (g) {
      g.line.setStyle({ opacity: Math.max(lineOpacity(g.count) * 0.35, 0.08) });
      g.fadeTimer = null;
    }
  }, 5000);
}

function rebuildHeatLayer() {
  const pts = Array.from(heatPoints.values()).map(p => [p.lat, p.lon, p.count]);
  if (heatLayer) {
    heatLayer.setLatLngs(pts);
  } else {
    heatLayer = L.heatLayer(pts, {
      radius: 30,
      blur: 20,
      maxZoom: 10,
      gradient: { 0.4: '#3fb950', 0.6: '#d29922', 0.8: '#f85149' },
    });
    if (viewMode === 'heatmap') heatLayer.addTo(map);
  }
  heatDirty = false;
}

function addConnection(data) {
  const { connection: conn, src_geo: src, dst_geo: dst } = data;

  const points = [];
  if (src && !src.is_private) points.push([src.lat, src.lon]);
  if (dst && !dst.is_private) points.push([dst.lat, dst.lon]);

  if (points.length === 2) {
    const key = `${conn.src_ip}|${conn.dst_ip}`;

    if (connGroups.has(key)) {
      const group = connGroups.get(key);
      group.count++;
      group.line.setStyle({
        weight:  lineWeight(group.count),
        opacity: lineOpacity(group.count),
      });
      scheduleFade(key);
    } else {
      const line = L.polyline(points, {
        color:   protocolColor(conn.protocol),
        weight:  lineWeight(1),
        opacity: lineOpacity(1),
      });

      if (viewMode === 'lines') line.addTo(map);

      connGroups.set(key, { count: 1, line, protocol: conn.protocol, fadeTimer: null });
      groupOrder.push(key);
      scheduleFade(key);

      if (groupOrder.length > MAX_LINES) {
        const oldKey = groupOrder.shift();
        const old = connGroups.get(oldKey);
        if (old) {
          if (old.fadeTimer) clearTimeout(old.fadeTimer);
          map.removeLayer(old.line);
          connGroups.delete(oldKey);
        }
      }
    }

    // Accumulate heat map data at destination
    if (dst && !dst.is_private) {
      const hKey = `${dst.lat},${dst.lon}`;
      const existing = heatPoints.get(hKey) || { lat: dst.lat, lon: dst.lon, count: 0 };
      existing.count++;
      heatPoints.set(hKey, existing);
      heatDirty = true;
      if (viewMode === 'heatmap') rebuildHeatLayer();
    }

    if (src && !src.is_private) makeMarker(src.lat, src.lon, `${src.ip} (${src.city || src.country})`).addTo(map);
    if (dst && !dst.is_private) makeMarker(dst.lat, dst.lon, `${dst.ip} (${dst.city || dst.country})`).addTo(map);
  }

  // Sidebar entry
  totalConns++;
  countEl.textContent = `${totalConns} connections`;

  const li = document.createElement('li');
  const dstLabel = dst ? `${dst.ip} <span class="country">${dst.country}</span>` : conn.dst_ip;
  const extra = conn.dns_query ? ` ${conn.dns_query}` : (conn.http_host ? ` ${conn.http_host}` : '');
  li.innerHTML = `<span class="proto" style="color:${protocolColor(conn.protocol)}">${conn.protocol}</span> ${conn.src_ip} → ${dstLabel}${extra}`;
  listEl.prepend(li);

  while (listEl.children.length > MAX_LIST) {
    listEl.lastChild.remove();
  }
}

function setViewMode(mode) {
  if (viewMode === mode) return;
  viewMode = mode;

  document.getElementById('btn-lines').classList.toggle('active', mode === 'lines');
  document.getElementById('btn-heatmap').classList.toggle('active', mode === 'heatmap');

  if (mode === 'lines') {
    if (heatLayer) {
      map.removeLayer(heatLayer);
      heatLayer = null;
    }
    for (const group of connGroups.values()) {
      group.line.addTo(map);
    }
  } else {
    for (const group of connGroups.values()) {
      map.removeLayer(group.line);
    }
    if (heatPoints.size > 0) rebuildHeatLayer();
  }
}

// WebSocket
let ws;
let reconnectDelay = 1000;

function connect() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws`);

  ws.onopen = () => {
    statusEl.textContent = 'connected';
    statusEl.className = 'badge connected';
    reconnectDelay = 1000;
  };

  ws.onmessage = (evt) => {
    try {
      const data = JSON.parse(evt.data);
      if (data.type === 'connection') addConnection(data);
    } catch (e) {
      console.warn('bad message', e);
    }
  };

  ws.onclose = () => {
    statusEl.textContent = 'disconnected';
    statusEl.className = 'badge disconnected';
    setTimeout(connect, reconnectDelay);
    reconnectDelay = Math.min(reconnectDelay * 2, 15000);
  };
}

connect();
