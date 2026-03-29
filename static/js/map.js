'use strict';

const map = L.map('map', { zoomControl: true }).setView([20, 0], 2);

L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
  attribution: '&copy; <a href="https://carto.com/">CARTO</a>',
  subdomains: 'abcd',
  maxZoom: 19,
}).addTo(map);

const statusEl      = document.getElementById('ws-status');
const countEl       = document.getElementById('conn-count');
const listEl        = document.getElementById('conn-list');
const searchInput   = document.getElementById('search-input');
const filterCountry = document.getElementById('filter-country');
const filterPort    = document.getElementById('filter-port');

let totalConns = 0;
const MAX_LIST  = 50;   // sidebar items to keep
const MAX_LINES = 200;  // total tracked connections before pruning

// Each entry: { line, srcMarker, dstMarker, conn, src, dst, faded, li }
const connections = [];

const knownCountries = new Set();

// Known protocols with checkboxes — others always pass through
const KNOWN_PROTOCOLS = new Set(['HTTP', 'HTTPS', 'DNS', 'ICMP', 'UDP', 'TCP']);

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

// --- Filter helpers ---

function getSelectedProtocols() {
  return new Set(
    [...document.querySelectorAll('#filter-protocols input:checked')].map(el => el.value)
  );
}

function matchesHardFilters(item) {
  const { conn, src, dst } = item;

  // Protocol: only filter known protocols; unknown ones always pass
  if (KNOWN_PROTOCOLS.has(conn.protocol) && !getSelectedProtocols().has(conn.protocol)) {
    return false;
  }

  // Country
  const country = filterCountry.value;
  if (country) {
    const srcC = src && src.country;
    const dstC = dst && dst.country;
    if (srcC !== country && dstC !== country) return false;
  }

  // Port
  const portVal = filterPort.value.trim();
  if (portVal) {
    const port = parseInt(portVal, 10);
    if (conn.src_port !== port && conn.dst_port !== port) return false;
  }

  return true;
}

function matchesSearch(item) {
  const q = searchInput.value.trim().toLowerCase();
  if (!q) return true;
  const { conn, src, dst } = item;
  const fields = [
    conn.src_ip, conn.dst_ip,
    conn.dns_query, conn.http_host,
    src && src.ip, src && src.city, src && src.country,
    dst && dst.ip, dst && dst.city, dst && dst.country,
  ].filter(Boolean);
  return fields.some(f => f.toLowerCase().includes(q));
}

// Apply the current filter + search state to a single connection item.
function refreshItem(item) {
  const visible      = matchesHardFilters(item);
  const searchActive = searchInput.value.trim().length > 0;
  const matched      = matchesSearch(item);

  let lineOpacity, markerOpacity, markerFill;

  if (!visible) {
    lineOpacity = 0;
    markerOpacity = 0;
    markerFill = 0;
  } else if (searchActive && matched) {
    // Highlight: bright and thick
    lineOpacity = 0.9;
    markerOpacity = 1;
    markerFill = 1;
    if (item.line) item.line.setStyle({ weight: 2.5 });
  } else if (searchActive && !matched) {
    // Dim non-matching
    lineOpacity = 0.07;
    markerOpacity = 0.1;
    markerFill = 0.1;
    if (item.line) item.line.setStyle({ weight: 1.5 });
  } else {
    // Normal: respect fade state
    lineOpacity = item.faded ? 0.2 : 0.6;
    markerOpacity = 0.8;
    markerFill = 0.8;
    if (item.line) item.line.setStyle({ weight: 1.5 });
  }

  if (item.line)      item.line.setStyle({ opacity: lineOpacity });
  if (item.srcMarker) item.srcMarker.setStyle({ opacity: markerOpacity, fillOpacity: markerFill });
  if (item.dstMarker) item.dstMarker.setStyle({ opacity: markerOpacity, fillOpacity: markerFill });

  if (item.li && item.li.isConnected) {
    item.li.classList.toggle('filtered-out', !visible);
    item.li.classList.toggle('highlighted', visible && searchActive && matched);
  }
}

function applyFilters() {
  for (const item of connections) {
    refreshItem(item);
  }
}

// --- Country dropdown ---

function updateCountryDropdown(country) {
  if (!country || knownCountries.has(country)) return;
  knownCountries.add(country);
  const option = document.createElement('option');
  option.value = country;
  option.textContent = country;
  // Insert in alphabetical order after the "All countries" placeholder
  const existing = [...filterCountry.options].slice(1);
  const before = existing.find(o => o.value > country);
  if (before) {
    filterCountry.insertBefore(option, before);
  } else {
    filterCountry.appendChild(option);
  }
}

// --- Main connection handler ---

function addConnection(data) {
  const { connection: conn, src_geo: src, dst_geo: dst } = data;

  const item = {
    line: null, srcMarker: null, dstMarker: null,
    conn, src, dst,
    faded: false,
    li: null,
  };

  // Draw polyline between the two public endpoints
  const points = [];
  if (src && !src.is_private) points.push([src.lat, src.lon]);
  if (dst && !dst.is_private) points.push([dst.lat, dst.lon]);

  if (points.length === 2) {
    item.line = L.polyline(points, {
      color: protocolColor(conn.protocol),
      weight: 1.5,
      opacity: 0.6,
    }).addTo(map);

    // Fade out after 5 s
    setTimeout(() => {
      item.faded = true;
      refreshItem(item);
    }, 5000);
  }

  if (src && !src.is_private) {
    item.srcMarker = makeMarker(src.lat, src.lon, `${src.ip} (${src.city || src.country})`).addTo(map);
  }
  if (dst && !dst.is_private) {
    item.dstMarker = makeMarker(dst.lat, dst.lon, `${dst.ip} (${dst.city || dst.country})`).addTo(map);
  }

  // Add new countries to the dropdown
  if (src && !src.is_private && src.country) updateCountryDropdown(src.country);
  if (dst && !dst.is_private && dst.country) updateCountryDropdown(dst.country);

  // Sidebar entry
  totalConns++;
  countEl.textContent = `${totalConns} connections`;

  const li = document.createElement('li');
  const dstLabel = dst ? `${dst.ip} <span class="country">${dst.country}</span>` : conn.dst_ip;
  const extra = conn.dns_query ? ` ${conn.dns_query}` : (conn.http_host ? ` ${conn.http_host}` : '');
  li.innerHTML = `<span class="proto" style="color:${protocolColor(conn.protocol)}">${conn.protocol}</span> ${conn.src_ip} → ${dstLabel}${extra}`;
  item.li = li;
  listEl.prepend(li);

  while (listEl.children.length > MAX_LIST) {
    listEl.lastChild.remove();
  }

  // Track connection; prune oldest when limit exceeded
  connections.push(item);
  if (connections.length > MAX_LINES) {
    const old = connections.shift();
    if (old.line)      map.removeLayer(old.line);
    if (old.srcMarker) map.removeLayer(old.srcMarker);
    if (old.dstMarker) map.removeLayer(old.dstMarker);
  }

  // Apply current filter/search state to the new item
  refreshItem(item);
}

// --- Filter event listeners ---

document.querySelectorAll('#filter-protocols input').forEach(cb => {
  cb.addEventListener('change', applyFilters);
});
searchInput.addEventListener('input', applyFilters);
filterCountry.addEventListener('change', applyFilters);
filterPort.addEventListener('input', applyFilters);

// --- WebSocket ---

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
