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
const threatCountEl = document.getElementById('threat-count');

let totalConns = 0;
let threatConns = 0;
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

// Timeline / playback state
const timelineData = [];       // [{timestamp, type, connection, src_geo, dst_geo, ...}] sorted by ts
let timelineMin = 0;
let timelineMax = 0;
let playbackTime = 0;
let liveMode = true;
let isPlaying = false;
let playbackSpeed = 1;
let lastFrameTime = null;
let playbackAnimFrame = null;
const playbackLayers = [];     // temporary Leaflet layers added during playback
const PLAYBACK_WINDOW = 30;    // seconds of history visible during playback

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

function makeMarker(lat, lon, label, threatened = false) {
  const color = threatened ? '#da3633' : '#58a6ff';
  return L.circleMarker([lat, lon], {
    radius: threatened ? 6 : 5,
    color,
    fillColor: color,
    fillOpacity: 0.8,
    weight: 1,
  }).bindTooltip(label, { permanent: false });
}

function threatLabel(geo, threat) {
  let label = `${geo.ip} (${geo.city || geo.country})`;
  if (threat && threat.is_flagged) {
    label += ` ⚠ Threat score: ${threat.score}`;
    if (threat.reports > 0) label += ` (${threat.reports} reports)`;
  }
  return label;
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
  // Always track in timeline regardless of live/playback mode
  const ts = typeof data.timestamp === 'number' ? data.timestamp : Date.now() / 1000;
  timelineData.push(Object.assign({}, data, { timestamp: ts }));
  if (!timelineMin) timelineMin = ts;
  if (ts > timelineMax) {
    timelineMax = ts;
    const scrubber = document.getElementById('tl-scrubber');
    if (scrubber) {
      scrubber.min = timelineMin;
      scrubber.max = timelineMax;
      document.getElementById('tl-start').textContent = fmtTime(timelineMin);
      document.getElementById('tl-end').textContent = fmtTime(timelineMax);
      if (liveMode) {
        scrubber.value = timelineMax;
        document.getElementById('tl-current').textContent = fmtTime(ts);
      }
    }
  }

  // Don't update live map layers during playback
  if (!liveMode) return;

  const { connection: conn, src_geo: src, dst_geo: dst, src_threat, dst_threat } = data;
  const isFlagged = (src_threat && src_threat.is_flagged) || (dst_threat && dst_threat.is_flagged);
  const lineColor = isFlagged ? '#da3633' : protocolColor(conn.protocol);

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
        color:   lineColor,
        weight:  lineWeight(1),
        opacity: lineOpacity(1),
      });

      if (viewMode === 'lines') line.addTo(map);

      connGroups.set(key, { count: 1, line, protocol: conn.protocol, isFlagged, fadeTimer: null });
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

    if (src && !src.is_private) {
      makeMarker(src.lat, src.lon, threatLabel(src, src_threat), !!(src_threat && src_threat.is_flagged)).addTo(map);
    }
    if (dst && !dst.is_private) {
      makeMarker(dst.lat, dst.lon, threatLabel(dst, dst_threat), !!(dst_threat && dst_threat.is_flagged)).addTo(map);
    }
  }

  // Sidebar entry
  totalConns++;
  countEl.textContent = `${totalConns} connections`;

  if (isFlagged) {
    threatConns++;
    threatCountEl.textContent = `${threatConns} threats`;
    threatCountEl.className = 'threat-badge active';
  }

  const li = document.createElement('li');
  if (isFlagged) li.classList.add('threat-entry');
  const dstLabel = dst ? `${dst.ip} <span class="country">${dst.country}</span>` : conn.dst_ip;
  const extra = conn.dns_query ? ` ${conn.dns_query}` : (conn.http_host ? ` ${conn.http_host}` : '');
  const warn = isFlagged ? ' <span class="threat-icon">⚠</span>' : '';
  const protoColor = isFlagged ? '#da3633' : protocolColor(conn.protocol);
  li.innerHTML = `<span class="proto" style="color:${protoColor}">${conn.protocol}</span>${warn} ${conn.src_ip} → ${dstLabel}${extra}`;
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

// Timeline helpers

function fmtTime(ts) {
  if (!ts) return '\u2014';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function enterPlaybackMode() {
  if (!liveMode) return;
  liveMode = false;
  // Hide live layers so playback layers show cleanly
  for (const group of connGroups.values()) map.removeLayer(group.line);
  if (heatLayer && map.hasLayer(heatLayer)) map.removeLayer(heatLayer);
  document.getElementById('btn-live').classList.remove('active');
}

function renderPlayback() {
  // Remove previously rendered playback layers
  for (const layer of playbackLayers) map.removeLayer(layer);
  playbackLayers.length = 0;

  if (!timelineData.length) return;

  const windowStart = playbackTime - PLAYBACK_WINDOW;

  // Binary search for first event in window
  let lo = 0, hi = timelineData.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (timelineData[mid].timestamp < windowStart) lo = mid + 1;
    else hi = mid;
  }

  for (let i = lo; i < timelineData.length; i++) {
    const event = timelineData[i];
    if (event.timestamp > playbackTime) break;

    const { connection: conn, src_geo: src, dst_geo: dst, src_threat, dst_threat } = event;
    const isFlagged = (src_threat && src_threat.is_flagged) || (dst_threat && dst_threat.is_flagged);
    const color = isFlagged ? '#da3633' : protocolColor(conn.protocol);

    const pts = [];
    if (src && !src.is_private) pts.push([src.lat, src.lon]);
    if (dst && !dst.is_private) pts.push([dst.lat, dst.lon]);

    if (pts.length === 2) {
      const age = playbackTime - event.timestamp;
      const opacity = Math.max(0.05, 1 - age / PLAYBACK_WINDOW);
      const line = L.polyline(pts, { color, weight: 2, opacity });
      line.addTo(map);
      playbackLayers.push(line);
    }
  }
}

function updateScrubberPosition() {
  const scrubber = document.getElementById('tl-scrubber');
  if (!scrubber || !timelineMax) return;
  scrubber.value = playbackTime;
  document.getElementById('tl-current').textContent = fmtTime(playbackTime);
}

function setLiveMode() {
  if (isPlaying) stopPlayback();

  // Remove playback layers
  for (const layer of playbackLayers) map.removeLayer(layer);
  playbackLayers.length = 0;

  liveMode = true;

  // Restore live layers for current view mode
  if (viewMode === 'lines') {
    for (const group of connGroups.values()) {
      if (!map.hasLayer(group.line)) group.line.addTo(map);
    }
  } else if (viewMode === 'heatmap') {
    if (heatDirty) rebuildHeatLayer();
    else if (heatLayer && !map.hasLayer(heatLayer)) heatLayer.addTo(map);
  }

  document.getElementById('btn-live').classList.add('active');
  document.getElementById('btn-play').innerHTML = '&#x25B6;';

  const scrubber = document.getElementById('tl-scrubber');
  if (scrubber && timelineMax) {
    scrubber.value = timelineMax;
    document.getElementById('tl-current').textContent = fmtTime(timelineMax);
  }
}

function onScrub(value) {
  enterPlaybackMode();
  stopPlayback();
  playbackTime = parseFloat(value);
  renderPlayback();
  document.getElementById('tl-current').textContent = fmtTime(playbackTime);
}

function togglePlayback() {
  if (isPlaying) stopPlayback();
  else startPlayback();
}

function startPlayback() {
  if (!timelineData.length) return;
  enterPlaybackMode();
  isPlaying = true;
  document.getElementById('btn-play').innerHTML = '&#x23F8;';
  // If at or past the end, restart from the beginning
  if (playbackTime >= timelineMax) playbackTime = timelineMin;
  lastFrameTime = null;
  playbackAnimFrame = requestAnimationFrame(playbackLoop);
}

function stopPlayback() {
  isPlaying = false;
  document.getElementById('btn-play').innerHTML = '&#x25B6;';
  if (playbackAnimFrame !== null) {
    cancelAnimationFrame(playbackAnimFrame);
    playbackAnimFrame = null;
  }
  lastFrameTime = null;
}

function playbackLoop(realTimeMs) {
  if (!isPlaying) return;
  if (lastFrameTime !== null) {
    const elapsed = (realTimeMs - lastFrameTime) / 1000;
    playbackTime += elapsed * playbackSpeed;
    if (playbackTime >= timelineMax) {
      playbackTime = timelineMax;
      renderPlayback();
      updateScrubberPosition();
      stopPlayback();
      return;
    }
    renderPlayback();
    updateScrubberPosition();
  }
  lastFrameTime = realTimeMs;
  playbackAnimFrame = requestAnimationFrame(playbackLoop);
}

function setPlaybackSpeed(value) {
  playbackSpeed = parseFloat(value);
}

async function loadTimeline() {
  try {
    const resp = await fetch('/api/timeline');
    if (!resp.ok) return;
    const records = await resp.json();
    if (!records.length) return;
    for (const rec of records) {
      timelineData.push(rec);
      if (!timelineMin || rec.timestamp < timelineMin) timelineMin = rec.timestamp;
      if (rec.timestamp > timelineMax) timelineMax = rec.timestamp;
    }
    // Ensure sorted order (API returns insertion order which should already be sorted)
    timelineData.sort((a, b) => a.timestamp - b.timestamp);
    const scrubber = document.getElementById('tl-scrubber');
    if (scrubber) {
      scrubber.min = timelineMin;
      scrubber.max = timelineMax;
      scrubber.value = timelineMax;
      document.getElementById('tl-start').textContent = fmtTime(timelineMin);
      document.getElementById('tl-end').textContent = fmtTime(timelineMax);
      document.getElementById('tl-current').textContent = fmtTime(timelineMax);
    }
  } catch (e) {
    console.warn('Timeline load failed', e);
  }
}

// Interface management

const ifaceSelect = document.getElementById('iface-select');

async function loadInterfaces() {
  try {
    const resp = await fetch('/api/interfaces');
    if (!resp.ok) return;
    const interfaces = await resp.json();
    const prev = ifaceSelect.value;
    ifaceSelect.innerHTML = '';
    for (const iface of interfaces) {
      const opt = document.createElement('option');
      opt.value = iface.name;
      const ip = iface.ip ? ` (${iface.ip})` : '';
      opt.textContent = `${iface.name}${ip}`;
      opt.dataset.capturing = iface.capturing ? 'true' : 'false';
      if (iface.name === prev) opt.selected = true;
      ifaceSelect.appendChild(opt);
    }
    updateIfaceButton();
  } catch (e) {
    console.warn('Failed to load interfaces', e);
  }
}

function updateIfaceButton() {
  const btn = document.getElementById('btn-iface-toggle');
  if (!btn || !ifaceSelect.options.length) return;
  const selected = ifaceSelect.options[ifaceSelect.selectedIndex];
  const capturing = selected && selected.dataset.capturing === 'true';
  btn.textContent = capturing ? 'Stop' : 'Start';
  btn.classList.toggle('active', capturing);
}

ifaceSelect.addEventListener('change', updateIfaceButton);

async function toggleInterfaceCapture() {
  const iface = ifaceSelect.value;
  if (!iface) return;
  const btn = document.getElementById('btn-iface-toggle');
  const capturing = btn.textContent === 'Stop';
  const endpoint = capturing ? '/api/capture/stop' : '/api/capture/start';
  try {
    await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interface: iface }),
    });
    await loadInterfaces();
  } catch (e) {
    console.warn('Failed to toggle capture', e);
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
loadTimeline();
loadInterfaces();
