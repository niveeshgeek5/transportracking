// BusTrack Service Worker — background GPS persistence
// Handles: background sync, offline buffering, keep-alive pings

const CACHE_NAME = 'bustrack-v3';
const OFFLINE_QUEUE_KEY = 'bustrack-offline-queue';

// ── Install & Activate ──────────────────────────────────────────────
self.addEventListener('install', (e) => {
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(clients.claim());
});

// ── Background Sync — flush buffered location points ────────────────
self.addEventListener('sync', async (e) => {
  if (e.tag === 'flush-location') {
    e.waitUntil(flushOfflineQueue());
  }
});

// ── Periodic Background Sync (where supported) ──────────────────────
self.addEventListener('periodicsync', async (e) => {
  if (e.tag === 'gps-keepalive') {
    // Send a ping so the server knows this driver is still live
    e.waitUntil(sendKeepalive());
  }
});

// ── Messages from main page ──────────────────────────────────────────
self.addEventListener('message', async (e) => {
  const { type, payload } = e.data || {};

  if (type === 'BUFFER_LOCATION') {
    await bufferLocation(payload);
    // Request background sync
    try {
      await self.registration.sync.register('flush-location');
    } catch(_) {
      // Background sync not supported — try direct flush
      await flushOfflineQueue();
    }
  }

  if (type === 'SET_SESSION') {
    // Store session in SW scope so keepalive can use it
    await storeSession(payload);
  }

  if (type === 'CLEAR_SESSION') {
    await clearSession();
  }
});

// ── Helpers ──────────────────────────────────────────────────────────

async function bufferLocation(point) {
  const cache = await caches.open(CACHE_NAME);
  let queue = [];
  try {
    const resp = await cache.match(OFFLINE_QUEUE_KEY);
    if (resp) queue = await resp.json();
  } catch(_) {}
  queue.push(point);
  if (queue.length > 500) queue = queue.slice(-500); // keep last 500
  await cache.put(OFFLINE_QUEUE_KEY, new Response(JSON.stringify(queue)));
}

async function flushOfflineQueue() {
  const cache = await caches.open(CACHE_NAME);
  let queue = [];
  try {
    const resp = await cache.match(OFFLINE_QUEUE_KEY);
    if (resp) queue = await resp.json();
  } catch(_) { return; }

  if (!queue.length) return;

  // Send in batches of 20
  while (queue.length > 0) {
    const batch = queue.splice(0, 20);
    try {
      const resp = await fetch('/api/location-batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ points: batch })
      });
      if (!resp.ok) {
        // Put batch back
        queue = [...batch, ...queue];
        break;
      }
    } catch(_) {
      queue = [...batch, ...queue];
      break;
    }
  }

  await cache.put(OFFLINE_QUEUE_KEY, new Response(JSON.stringify(queue)));
}

async function storeSession(session) {
  const cache = await caches.open(CACHE_NAME);
  await cache.put('driver-session', new Response(JSON.stringify(session)));
}

async function clearSession() {
  const cache = await caches.open(CACHE_NAME);
  await cache.delete('driver-session');
  await cache.delete(OFFLINE_QUEUE_KEY);
}

async function sendKeepalive() {
  try {
    const cache = await caches.open(CACHE_NAME);
    const resp = await cache.match('driver-session');
    if (!resp) return;
    const session = await resp.json();
    await fetch('/api/driver/keepalive', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ driverId: session.driverId, routeId: session.routeId })
    });
  } catch(_) {}
}
