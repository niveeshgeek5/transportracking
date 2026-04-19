const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.static('public'));
app.use(express.json());

// ─────────────────────────────────────────────
// DATABASE SETUP
// Stored in ./bustrack.db  (SQLite file on disk)
// ─────────────────────────────────────────────
const db = new Database('./bustrack.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS routes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    route_id      TEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    INTEGER DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS drivers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    bus_no        TEXT NOT NULL,
    route_id      TEXT NOT NULL,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    INTEGER DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS location_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    route_id    TEXT NOT NULL,
    driver_id   INTEGER NOT NULL,
    driver_name TEXT NOT NULL,
    bus_no      TEXT NOT NULL,
    lat         REAL NOT NULL,
    lng         REAL NOT NULL,
    accuracy    REAL,
    speed_kmh   REAL,
    timestamp   INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_history_route_time
    ON location_history(route_id, timestamp);
`);

// Clean up history older than 24 hours every 15 minutes
setInterval(() => {
  const cutoff = Math.floor(Date.now() / 1000) - 24 * 3600;
  db.prepare('DELETE FROM location_history WHERE timestamp < ?').run(cutoff);
}, 15 * 60 * 1000);


// ─────────────────────────────────────────────
// NGROK — auto tunnel so anyone on internet can access
// Install: npm install @ngrok/ngrok
// Set env:  NGROK_AUTHTOKEN=your_token_here
// Get free token at https://dashboard.ngrok.com
// ─────────────────────────────────────────────
let publicUrl = null;

async function tryStartNgrok(port) {
  // Try @ngrok/ngrok (v5+)
  let ngrok;
  try { ngrok = require('@ngrok/ngrok'); } catch(_) {}
  if (ngrok) {
    try {
      const listener = await ngrok.forward({
        addr: port,
        authtoken: process.env.NGROK_AUTHTOKEN || undefined,
        authtoken_from_env: !process.env.NGROK_AUTHTOKEN
      });
      publicUrl = listener.url();
      console.log(`🌐 Public URL (share this): ${publicUrl}`);
      return;
    } catch(e) {
      console.log('⚠️  ngrok error:', e.message);
      console.log('   Make sure NGROK_AUTHTOKEN is set in your environment');
    }
  }
  // Try ngrok v4
  try { ngrok = require('ngrok'); } catch(_) {}
  if (ngrok) {
    try {
      publicUrl = await ngrok.connect({ addr: port, authtoken: process.env.NGROK_AUTHTOKEN });
      console.log(`🌐 Public URL (share this): ${publicUrl}`);
      return;
    } catch(e) {
      console.log('⚠️  ngrok v4 error:', e.message);
    }
  }
  console.log('ℹ️  ngrok not installed. Only accessible on local WiFi.');
  console.log('   For internet access run: npm install @ngrok/ngrok');
  console.log('   Then get a free token at https://dashboard.ngrok.com');
  console.log('   And start with: NGROK_AUTHTOKEN=your_token node server.js');
}

// ─────────────────────────────────────────────
// SERVER INFO — used by the share/connect page
// ─────────────────────────────────────────────
app.get('/api/server-info', (req, res) => {
  const routes = db.prepare('SELECT route_id, name FROM routes ORDER BY name').all();
  res.json({
    publicUrl,        // ngrok URL (null if not running)
    localUrl: `http://${getLocalIp()}:${PORT}`,
    hasPublicUrl: !!publicUrl,
    routes
  });
});


// ─────────────────────────────────────────────
// REST API — DRIVER AUTH
// ─────────────────────────────────────────────

// Register a NEW driver (unique username, joins or creates a route)
app.post('/api/driver/register', (req, res) => {
  const { routeName, routeId, routePassword, driverName, busNo, username, password } = req.body;
  if (!routeName || !routeId || !routePassword || !driverName || !busNo || !username || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (username.trim().length < 3)
    return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 4)
    return res.status(400).json({ error: 'Password must be at least 4 characters' });

  const cleanRouteId   = routeId.trim().toLowerCase().replace(/\s+/g, '-');
  const cleanUsername  = username.trim().toLowerCase();

  try {
    // Username must be unique
    const existingUser = db.prepare('SELECT id FROM drivers WHERE username = ?').get(cleanUsername);
    if (existingUser)
      return res.status(409).json({ error: 'Username already taken — choose a different one.' });

    // Route: join if exists (verify password), create if new
    const existingRoute = db.prepare('SELECT * FROM routes WHERE route_id = ?').get(cleanRouteId);
    if (existingRoute) {
      const ok = bcrypt.compareSync(routePassword, existingRoute.password_hash);
      if (!ok)
        return res.status(403).json({ error: 'Wrong route password. This route already exists — ask the first driver for the correct password.' });
    } else {
      const hash = bcrypt.hashSync(routePassword, 8);
      db.prepare('INSERT INTO routes (route_id, name, password_hash) VALUES (?, ?, ?)')
        .run(cleanRouteId, routeName.trim(), hash);
    }

    // Create driver with personal credentials
    const driverPassHash = bcrypt.hashSync(password, 8);
    const result = db.prepare(
      'INSERT INTO drivers (name, bus_no, route_id, username, password_hash) VALUES (?, ?, ?, ?, ?)'
    ).run(driverName.trim(), busNo.trim(), cleanRouteId, cleanUsername, driverPassHash);

    const route = db.prepare('SELECT name FROM routes WHERE route_id = ?').get(cleanRouteId);

    res.json({
      success:    true,
      driverId:   result.lastInsertRowid,
      driverName: driverName.trim(),
      busNo:      busNo.trim(),
      routeId:    cleanRouteId,
      routeName:  route.name,
      username:   cleanUsername
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login existing driver
app.post('/api/driver/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Enter username and password' });

  const cleanUsername = username.trim().toLowerCase();
  const driver = db.prepare('SELECT * FROM drivers WHERE username = ?').get(cleanUsername);
  if (!driver)
    return res.status(404).json({ error: 'Username not found — register first if you\'re new.' });

  const ok = bcrypt.compareSync(password, driver.password_hash);
  if (!ok) return res.status(403).json({ error: 'Wrong password' });

  const route = db.prepare('SELECT name FROM routes WHERE route_id = ?').get(driver.route_id);

  res.json({
    success:    true,
    driverId:   driver.id,
    driverName: driver.name,
    busNo:      driver.bus_no,
    routeId:    driver.route_id,
    routeName:  route ? route.name : driver.route_id,
    username:   driver.username
  });
});


// ─────────────────────────────────────────────
// REST API — COMMUTER
// ─────────────────────────────────────────────

// Batch location upload — used by Service Worker background sync
// when socket was offline and SW buffered points
app.post('/api/location-batch', (req, res) => {
  const { points } = req.body;
  if (!Array.isArray(points) || points.length === 0)
    return res.status(400).json({ error: 'No points' });

  const insert = db.prepare(`
    INSERT INTO location_history
      (route_id, driver_id, driver_name, bus_no, lat, lng, accuracy, speed_kmh, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertMany = db.transaction((pts) => {
    let prev = null;
    for (const p of pts) {
      if (!p.routeId || !p.driverId || !p.lat || !p.lng) continue;

      let speedKmh = 0;
      if (prev && prev.routeId === p.routeId && prev.driverId === p.driverId) {
        const dist    = getDistance(prev.lat, prev.lng, p.lat, p.lng);
        const timeDiff = (p.timestamp - prev.timestamp) / 3600;
        if (timeDiff > 0) speedKmh = Math.min(dist / timeDiff, 120);
      }

      insert.run(
        p.routeId, p.driverId, p.driverName || 'Driver', p.busNo || '',
        p.lat, p.lng, p.accuracy || 0, speedKmh,
        p.timestamp || Math.floor(Date.now() / 1000)
      );

      // Also broadcast to any connected commuters for this route
      io.to(`route:${p.routeId}`).emit('bus:update', {
        driverId:   p.driverId,
        driverName: p.driverName,
        busNo:      p.busNo,
        lat:        p.lat,
        lng:        p.lng,
        accuracy:   p.accuracy || 0,
        speedKmh,
        isMoving:   speedKmh > 2,
        timestamp:  p.timestamp
      });

      prev = p;
    }
  });

  try {
    insertMany(points);
    res.json({ success: true, saved: points.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Keepalive — driver pings this to prevent being marked offline during background
app.post('/api/driver/keepalive', (req, res) => {
  const { driverId, routeId } = req.body;
  if (!driverId || !routeId) return res.status(400).json({ error: 'Missing fields' });
  // Touch the session so the 15s grace timer knows the driver is still alive
  if (driverSessions[routeId]?.[driverId]) {
    driverSessions[routeId][driverId].lastTime = Math.floor(Date.now() / 1000);
  }
  res.json({ ok: true });
});

app.post('/api/join-route', (req, res) => {
  const { routeId, password } = req.body;
  if (!routeId || !password)
    return res.status(400).json({ error: 'Enter route ID and password' });

  const cleanId = routeId.trim().toLowerCase().replace(/\s+/g, '-');
  const route = db.prepare('SELECT * FROM routes WHERE route_id = ?').get(cleanId);
  if (!route)
    return res.status(404).json({ error: `Route "${cleanId}" not found. Ask your driver for the correct route ID.` });

  const ok = bcrypt.compareSync(password, route.password_hash);
  if (!ok) return res.status(403).json({ error: 'Wrong route password' });

  res.json({ success: true, routeId: cleanId, routeName: route.name });
});

app.get('/api/history/:routeId', (req, res) => {
  const { routeId } = req.params;
  const { password }  = req.query;

  const route = db.prepare('SELECT * FROM routes WHERE route_id = ?').get(routeId);
  if (!route) return res.status(404).json({ error: 'Route not found' });

  const ok = bcrypt.compareSync(password, route.password_hash);
  if (!ok) return res.status(403).json({ error: 'Wrong password' });

  const cutoff = Math.floor(Date.now() / 1000) - 24 * 3600;
  const rows   = db.prepare(
    'SELECT * FROM location_history WHERE route_id = ? AND timestamp > ? ORDER BY timestamp ASC'
  ).all(routeId, cutoff);

  res.json({ success: true, history: rows });
});

app.get('/api/routes', (req, res) => {
  const routes = db.prepare('SELECT route_id, name FROM routes ORDER BY name').all();
  res.json({ routes });
});


// ─────────────────────────────────────────────
// SOCKET.IO — REAL-TIME
// ─────────────────────────────────────────────
const driverSessions = {};

io.on('connection', (socket) => {
  let myRouteId  = null;
  let myDriverId = null;
  let myRole     = null;

  socket.on('driver:start', ({ routeId, driverId, driverName, busNo }) => {
    myRouteId  = routeId;
    myDriverId = driverId;
    myRole     = 'driver';
    socket.join(`route:${routeId}`);

    if (!driverSessions[routeId]) driverSessions[routeId] = {};
    // If session already exists (reconnect), preserve history and update socket ID
    const existing = driverSessions[routeId][driverId];
    if (existing) {
      existing._socketId = socket.id;
    } else {
      driverSessions[routeId][driverId] = {
        name: driverName, busNo,
        lastLat: null, lastLng: null, lastTime: null,
        speedHistory: [],
        _socketId: socket.id
      };
    }
  });

  socket.on('driver:location', ({ routeId, driverId, driverName, busNo, lat, lng, accuracy }) => {
    if (!routeId || !driverId) return;

    const now     = Math.floor(Date.now() / 1000);
    const session = driverSessions[routeId]?.[driverId];
    let speedKmh  = 0;

    if (session?.lastLat != null) {
      const dist     = getDistance(session.lastLat, session.lastLng, lat, lng);
      const timeDiff = (now - session.lastTime) / 3600;
      if (timeDiff > 0) {
        const raw = dist / timeDiff;
        if (raw < 120) {
          session.speedHistory.push(raw);
          if (session.speedHistory.length > 20) session.speedHistory.shift();
        }
      }
    }

    if (session) {
      session.lastLat  = lat;
      session.lastLng  = lng;
      session.lastTime = now;
      speedKmh = session.speedHistory.length
        ? session.speedHistory.reduce((a, b) => a + b) / session.speedHistory.length
        : 0;
    }

    db.prepare(`
      INSERT INTO location_history
        (route_id, driver_id, driver_name, bus_no, lat, lng, accuracy, speed_kmh, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(routeId, driverId, driverName, busNo, lat, lng, accuracy || 0, speedKmh, now);

    io.to(`route:${routeId}`).emit('bus:update', {
      driverId, driverName, busNo, lat, lng,
      accuracy:  accuracy || 0,
      speedKmh,
      isMoving:  speedKmh > 2,
      timestamp: now
    });
  });

  socket.on('tracker:join', ({ routeId }) => {
    myRouteId = routeId;
    myRole    = 'tracker';
    socket.join(`route:${routeId}`);

    if (driverSessions[routeId]) {
      Object.entries(driverSessions[routeId]).forEach(([dId, s]) => {
        if (s.lastLat != null) {
          socket.emit('bus:update', {
            driverId:   dId,
            driverName: s.name,
            busNo:      s.busNo,
            lat:        s.lastLat,
            lng:        s.lastLng,
            speedKmh:   s.speedHistory.length
              ? s.speedHistory.reduce((a,b)=>a+b) / s.speedHistory.length : 0,
            timestamp:  s.lastTime
          });
        }
      });
    }
  });

  socket.on('disconnect', () => {
    if (myRole === 'driver' && myRouteId && myDriverId) {
      // Grace period: wait 15s before marking offline
      // (handles brief network drops, screen lock reconnects, etc.)
      setTimeout(() => {
        // Only mark offline if this driver hasn't reconnected
        const session = driverSessions[myRouteId]?.[myDriverId];
        if (session && session._socketId === socket.id) {
          delete driverSessions[myRouteId][myDriverId];
          io.to(`route:${myRouteId}`).emit('bus:offline', { driverId: myDriverId });
        }
      }, 15000);
    }
  });
});


// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────
function getDistance(lat1, lng1, lat2, lng2) {
  // Vincenty formula on WGS84 ellipsoid — matches Google Maps
  const a = 6378.137, b = 6356.752, f = 1 / 298.257223563;
  const φ1 = lat1 * Math.PI / 180, φ2 = lat2 * Math.PI / 180;
  const L  = (lng2 - lng1) * Math.PI / 180;
  const tanU1 = (1-f)*Math.tan(φ1), cosU1 = 1/Math.sqrt(1+tanU1*tanU1), sinU1 = tanU1*cosU1;
  const tanU2 = (1-f)*Math.tan(φ2), cosU2 = 1/Math.sqrt(1+tanU2*tanU2), sinU2 = tanU2*cosU2;
  let λ = L, λʹ, limit = 100, sinσ, cosσ, σ, sinα, cos2α, cos2σm, C;
  do {
    const sinλ = Math.sin(λ), cosλ = Math.cos(λ);
    sinσ   = Math.sqrt((cosU2*sinλ)**2 + (cosU1*sinU2 - sinU1*cosU2*cosλ)**2);
    if (sinσ === 0) return 0;
    cosσ   = sinU1*sinU2 + cosU1*cosU2*cosλ;
    σ      = Math.atan2(sinσ, cosσ);
    sinα   = cosU1*cosU2*sinλ/sinσ;
    cos2α  = 1 - sinα*sinα;
    cos2σm = cos2α ? cosσ - 2*sinU1*sinU2/cos2α : 0;
    C      = f/16*cos2α*(4 + f*(4 - 3*cos2α));
    λʹ = λ;
    λ  = L + (1-C)*f*sinα*(σ + C*sinσ*(cos2σm + C*cosσ*(-1 + 2*cos2σm**2)));
  } while (Math.abs(λ-λʹ) > 1e-12 && --limit > 0);
  if (!limit) {
    const R=6371.009, dLat=φ2-φ1, dLng=(lng2-lng1)*Math.PI/180;
    const aa=Math.sin(dLat/2)**2+Math.cos(φ1)*Math.cos(φ2)*Math.sin(dLng/2)**2;
    return R*2*Math.atan2(Math.sqrt(aa),Math.sqrt(1-aa));
  }
  const uSq = cos2α*(a*a-b*b)/(b*b);
  const A2  = 1 + uSq/16384*(4096 + uSq*(-768 + uSq*(320 - 175*uSq)));
  const B2  = uSq/1024*(256 + uSq*(-128 + uSq*(74 - 47*uSq)));
  const Δσ  = B2*sinσ*(cos2σm + B2/4*(cosσ*(-1+2*cos2σm**2) - B2/6*cos2σm*(-3+4*sinσ**2)*(-3+4*cos2σm**2)));
  return b*A2*(σ-Δσ);
}

function getLocalIp() {
  try {
    const { networkInterfaces } = require('os');
    const nets = networkInterfaces();
    for (const name of Object.keys(nets)) {
      for (const net of nets[name]) {
        if (net.family === 'IPv4' && !net.internal) return net.address;
      }
    }
  } catch(_) {}
  return 'localhost';
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`\n✅  BusTrack v3 running`);
  console.log(`📱  Local WiFi: http://${getLocalIp()}:${PORT}`);
  console.log(`    (Friends on same WiFi can use this URL)\n`);
  tryStartNgrok(PORT);
});
