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
      color: protocolColor(conn.protocol),
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
  const extra = conn.dns_query ? ` ${conn.dns_query}` : (conn.http_host ? ` ${conn.http_host}` : '');
  li.innerHTML = `<span class="proto" style="color:${protocolColor(conn.protocol)}">${conn.protocol}</span> ${conn.src_ip} → ${dstLabel}${extra}`;
  listEl.prepend(li);

  while (listEl.children.length > MAX_LIST) {
    listEl.lastChild.remove();
  }
}

// ── Stats panel ──────────────────────────────────────────────────────────────

function fmtNum(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return String(n);
}

function fmtBandwidth(bps) {
  if (bps <= 0) return '—';
  if (bps >= 1048576) return (bps / 1048576).toFixed(1) + ' MB/s';
  if (bps >= 1024) return (bps / 1024).toFixed(1) + ' KB/s';
  return bps + ' B/s';
}

function polarToCartesian(cx, cy, r, angleDeg) {
  const rad = (angleDeg - 90) * Math.PI / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

function renderProtoPie(protocols) {
  const pie = document.getElementById('proto-pie');
  const legend = document.getElementById('proto-legend');
  pie.innerHTML = '';
  legend.innerHTML = '';

  const entries = Object.entries(protocols).filter(([, v]) => v > 0);
  if (!entries.length) return;

  const total = entries.reduce((s, [, v]) => s + v, 0);
  const cx = 50, cy = 50, r = 46;
  let startAngle = 0;

  entries.forEach(([proto, count]) => {
    const pct = count / total;
    const sweepAngle = pct * 360;
    const endAngle = startAngle + sweepAngle;
    const color = PROTOCOL_COLORS[proto] || '#8b949e';

    let el;
    if (pct >= 1) {
      el = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      el.setAttribute('cx', cx);
      el.setAttribute('cy', cy);
      el.setAttribute('r', r);
    } else {
      const s = polarToCartesian(cx, cy, r, startAngle);
      const e = polarToCartesian(cx, cy, r, endAngle);
      const largeArc = sweepAngle > 180 ? 1 : 0;
      el = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      el.setAttribute('d',
        `M ${cx} ${cy} L ${s.x.toFixed(2)} ${s.y.toFixed(2)} ` +
        `A ${r} ${r} 0 ${largeArc} 1 ${e.x.toFixed(2)} ${e.y.toFixed(2)} Z`);
    }
    el.setAttribute('fill', color);
    pie.appendChild(el);

    const item = document.createElement('div');
    item.className = 'legend-item';
    item.innerHTML =
      `<span class="legend-dot" style="background:${color}"></span>` +
      `<span>${proto} ${Math.round(pct * 100)}%</span>`;
    legend.appendChild(item);

    startAngle = endAngle;
  });
}

function renderBars(containerId, items, labelKey, color) {
  const container = document.getElementById(containerId);
  container.innerHTML = '';
  if (!items.length) return;

  const max = items[0].count;
  items.forEach(item => {
    const pct = max > 0 ? (item.count / max) * 100 : 0;
    const label = item[labelKey] || '—';
    const row = document.createElement('div');
    row.className = 'bar-row';
    row.innerHTML =
      `<span class="bar-label" title="${label}">${label}</span>` +
      `<div class="bar-track"><div class="bar-fill" style="width:${pct.toFixed(1)}%;background:${color}"></div></div>` +
      `<span class="bar-count">${fmtNum(item.count)}</span>`;
    container.appendChild(row);
  });
}

function updateStats(data) {
  document.getElementById('stat-total').textContent = fmtNum(data.total);
  document.getElementById('stat-rate').textContent = data.rate.toFixed(1);
  document.getElementById('stat-bw').textContent = fmtBandwidth(data.bandwidth_bps);
  renderProtoPie(data.protocols);
  renderBars('countries-bars', data.top_countries, 'name', '#3fb950');
  renderBars('ips-bars', data.top_ips, 'ip', '#58a6ff');
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
      else if (data.type === 'stats') updateStats(data);
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
