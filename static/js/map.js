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
const MAX_LINES = 200;  // polylines on map before pruning

const lines = [];

function makeMarker(lat, lon, label) {
  return L.circleMarker([lat, lon], {
    radius: 5,
    color: '#58a6ff',
    fillColor: '#58a6ff',
    fillOpacity: 0.8,
    weight: 1,
  }).bindTooltip(label, { permanent: false });
}

function addConnection(data) {
  const { connection: conn, src_geo: src, dst_geo: dst } = data;

  // Draw line between the two geolocated endpoints
  const points = [];
  if (src && !src.is_private) points.push([src.lat, src.lon]);
  if (dst && !dst.is_private) points.push([dst.lat, dst.lon]);

  if (points.length === 2) {
    const line = L.polyline(points, {
      color: '#58a6ff',
      weight: 1.5,
      opacity: 0.6,
    }).addTo(map);

    lines.push(line);
    if (lines.length > MAX_LINES) {
      const old = lines.shift();
      map.removeLayer(old);
    }

    // Animate fade-out
    setTimeout(() => {
      line.setStyle({ opacity: 0.2 });
    }, 5000);
  }

  if (src && !src.is_private) makeMarker(src.lat, src.lon, `${src.ip} (${src.city || src.country})`).addTo(map);
  if (dst && !dst.is_private) makeMarker(dst.lat, dst.lon, `${dst.ip} (${dst.city || dst.country})`).addTo(map);

  // Sidebar entry
  totalConns++;
  countEl.textContent = `${totalConns} connections`;

  const li = document.createElement('li');
  const dstLabel = dst ? `${dst.ip} <span class="country">${dst.country}</span>` : conn.dst_ip;
  li.innerHTML = `<span class="proto">${conn.protocol}</span> ${conn.src_ip} → ${dstLabel}`;
  listEl.prepend(li);

  while (listEl.children.length > MAX_LIST) {
    listEl.lastChild.remove();
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
