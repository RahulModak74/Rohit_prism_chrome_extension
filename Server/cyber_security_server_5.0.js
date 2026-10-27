// ===== IMPORTS =====
const express = require('express');
const { ClickHouse } = require('clickhouse');
const session = require('express-session');
const path = require('path');
const bodyParser = require('body-parser');
const geoip = require('geoip-lite');
const http = require('http');
const flash = require('express-flash');
const basicAuth = require('express-basic-auth');
const axios = require('axios');
require('dotenv').config();
const SecurityModule = require('./security');
const crypto = require('crypto');

// ===== APP INITIALIZATION =====
const app = express();
const PORT = process.env.PORT || 5002;
const server = require('http').createServer(app);
const { Server } = require('socket.io');
const io = new Server(server);

const security = new SecurityModule({
  enableAntiProxy: true,
  enableRequestSigning: false,    // Disable this to avoid crypto.subtle
  enableTimestampValidation: false, // Also disable this as it's related
  enableRateLimiting: true,
  enableFingerprinting: true,
  maxRequestAge: 30000,
  maxRequestsPerWindow: 1000,
  serverSecret: process.env.SECURITY_SECRET || crypto.randomBytes(32).toString('hex'),
  allowedOrigins: ['http://142.93.222.202:8000', 'http://localhost:8000', 'https://yourdomain.com','https://metrics.bayesiancybersecurity.com','https://battery.bluebotanalytics.com/']
});

// Security configuration logging
console.log('Security Module Initialized:');
console.log('- Anti-Proxy:', security.config.enableAntiProxy);
console.log('- Rate Limiting:', security.config.enableRateLimiting);
console.log('- Request Signing:', security.config.enableRequestSigning);
console.log('- Max Requests/Window:', security.config.maxRequestsPerWindow);

// ===== DATABASE CONNECTION =====
const clickhouse = new ClickHouse({
  url: 'http://localhost',
  port: 8123,
  basicAuth: { username: 'default', password: '' },
  isUseGzip: false,
  format: 'json',
  config: { database: 'default' },
});

app.set('trust proxy', 'loopback');
app.use('/collect', express.json({ limit: '5mb' }));

// ===== MIDDLEWARE CONFIGURATION =====
app.set('trust proxy', 'loopback');   // nginx on same box -> req.ip = real visitor IP
app.use(flash());
app.use('/track', express.text({ type: '*/*', limit: '20mb' }));  // must be FIRST (pixel v2 sends text/plain)
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
}));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://accounts.google.com https://www.google.com; " +
    "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://accounts.google.com https://www.google.com; " +
    "img-src 'self' data: https://accounts.google.com https://www.google.com; " +
    "font-src 'self' https://cdnjs.cloudflare.com https://accounts.google.com https://www.google.com; " +
    "frame-src 'self' https://accounts.google.com https://www.google.com; " +
    "connect-src 'self' https://accounts.google.com https://www.google.com https://play.google.com https://www.googleapis.com;" // Added googleapis.com
  );
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
app.use('/js', express.static(path.join(__dirname, 'client')));

// HTML escaping utility
app.locals.escapeHTML = function (text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
};

// Basic Auth Configuration
const myAuthorizer = (username, password) => {
  const userMatches = basicAuth.safeCompare(username, 'user');
  const passwordMatches = basicAuth.safeCompare(password, 'blubot12@');
  return userMatches & passwordMatches;
};

const authOptions = {
  authorizer: myAuthorizer,
  challenge: true,
  unauthorizedResponse: (req) => '401 Unauthorized'
};



// ===== SESSION MANAGEMENT =====
let sessions = [];  // Store session IDs in an array
const lastTrackingId = new Map(); // sessionId -> { id, seen }  (links security_headers to tracking10)

// Session cleanup configuration
const CLEANUP_INTERVAL = 60000; // 60 seconds
const SESSION_TIMEOUT = 900000; // 15 minutes

// ===== HELPER FUNCTIONS =====

// Authentication middleware
function isAuthenticated(req, res, next) {
  if (req.session && req.session.authenticated) {
    req.username = req.session.username;
    next();
  } else {
    res.redirect('/');
  }
}

// Validate credentials
async function verifyCredentials(req) {
  const { username, password } = req.body;

  const query = `
    SELECT username, passwordHash, hostname, version
    FROM users_new
    WHERE username = {username:String}
    LIMIT 1
  `;

  try {
    const result = await clickhouse
      .query(query, { params: { username } })
      .toPromise();

    if (result.length === 0) {
      return false;
    }

    const user = result[0];
    return password === user.passwordHash ? user : false;
  } catch (error) {
    console.error('Error verifying credentials:', error);
    return false;
  }
}

// Date validation

function isValidDate(dateString) {
  // console.log("Validating date:", dateString);

  // Check if the format is YYYY-MM-DD
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateString)) {
    console.log("Date format doesn't match YYYY-MM-DD");
    return false;
  }

  // Parse the date parts and create a date object
  const parts = dateString.split('-');
  const year = parseInt(parts[0], 10);
  const month = parseInt(parts[1], 10) - 1; // Months are 0-indexed in JS
  const day = parseInt(parts[2], 10);

  const date = new Date(year, month, day);

  // Check if the date is valid by comparing the components
  const isValid = (
    date.getFullYear() === year &&
    date.getMonth() === month &&
    date.getDate() === day
  );

  // console.log(`Date validation result for ${dateString}: ${isValid}`);
  return isValid;
}

// Get IP details from region_details table
async function getIpDetails(ipAddress) {
  try {
    const ipQuery = `SELECT country, region, city FROM region_details WHERE ip_address = '${ipAddress}' LIMIT 1;`;
    const ipResult = await clickhouse.query(ipQuery).toPromise();
    return ipResult[0];
  } catch (error) {
    console.error('Error fetching IP details:', error);
    return null;
  }
}


// ===== DATABASE INITIALIZATION =====
const initDb = async () => {
  try {
    await clickhouse.query(`CREATE TABLE IF NOT EXISTS tracking10 (
        id Int32,
        timestamp DateTime DEFAULT now(),
        url String,
        referrer String,
        ip_address String,
        user_agent String,
        platform String,
        language String,
        hostname String,
        session_id String,
        browser_id String,
        fingerprint_id String,
        clickdata String,
        enhanced_data_id Int64
    ) ENGINE = MergeTree()
    ORDER BY id`).toPromise();
  } catch (err) {
    console.error('Error initializing ClickHouse table:', err);
  }
};

// Initialize database
initDb();

// ===== SOCKET.IO SETUP =====
io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  socket.on('join', (data) => {
    const sessionId = data.sessionId;
    socket.join(sessionId);
    console.log(`User joined session room: ${sessionId}`);
  });

  socket.on('sendMessage', (data) => {
    const { sessionId, message } = data;
    io.to(sessionId).emit('receiveMessage', message);
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// ===== SESSION CLEANUP =====
setInterval(() => {
  const now = Date.now();
  for (const sessionId in sessions) {
    if (now - sessions[sessionId] > SESSION_TIMEOUT) {
      delete sessions[sessionId];
    }
  }
  for (const [sid, v] of lastTrackingId) {
    if (now - v.seen > SESSION_TIMEOUT) lastTrackingId.delete(sid);
  }
}, CLEANUP_INTERVAL);

// Security token endpoint
app.get('/api/security-token',security.protect(), (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  res.json({
    success: true,
    token: token,
    secretKey: security.currentSecret
  });
});

// Token verification endpoint
app.post('/api/verify-token',security.protect(), (req, res) => {
  const { token } = req.body;
  res.json({
    success: true,
    valid: token && token.length === 64
  });
});

// Security event logging endpoint
app.post('/api/security-event',security.protect(), (req, res) => {
  console.log('Security Event:', req.body);
  res.json({ success: true });
});



// ===== ROUTES =====

// Public routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.post('/signup', security.protect({
  maxRequestsPerWindow: 5
}), async (req, res) => {
  const { username, password, hostname, version } = req.body;

  // Add input validation
  if (!username || !password || !hostname) {
    return res.status(400).json({
      success: false,
      message: 'All fields are required'
    });
  }

  if (username.length > 100 || password.length > 100 || hostname.length > 100) {
    return res.status(400).json({
      success: false,
      message: 'Input too long'
    });
  }

  // Validate version if provided
  if (version !== undefined && (isNaN(parseInt(version)) || parseInt(version) < 1)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid version number'
    });
  }

  try {
    // Step 1: Fetch all hostnames from the users_new table
    const query = 'SELECT hostname FROM users_new';
    const result = await clickhouse.query(query).toPromise();

    // Step 2: Check in JavaScript for substring issues
    const existingHostnames = result.map(row => row.hostname);
    const isHostnameConflict = existingHostnames.some(existing => {
      return existing.includes(hostname) || hostname.includes(existing);
    });

    if (isHostnameConflict) {
      // Hostname too similar to an existing one
      return res.status(400).json({
        success: false,
        message: 'Hostname too similar to an existing one. Please choose a different one.'
      });
    } else {
      // Step 3: If no conflict, proceed with inserting the new user
      const insertQuery = `
        INSERT INTO users_new (username, passwordHash, hostname, version)
        VALUES ({username:String}, {passwordHash:String}, {hostname:String}, {version:UInt32})
      `;

      await clickhouse.query(insertQuery, {
        params: {
          username,
          passwordHash: password, // Use the password directly for simplicity; consider hashing in production
          hostname,
          version: version || 1, // Default version is 1 if not provided
        },
      }).toPromise();

      // Return success response
      res.status(200).json({
        success: true,
        message: 'Signup successful'
      });
    }
  } catch (error) {
    console.error('Error during signup:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error. Please try again later.'
    });
  }
});

app.post('/content', security.protect(), async (req, res) => {
  try {
    // Validate input
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password are required'
      });
    }

    if (username.length > 100 || password.length > 100) {
      return res.status(400).json({
        success: false,
        message: 'Input too long'
      });
    }

    // Use verifyCredentials function with parameterized query
    const user = await verifyCredentials(req);

    if (user) {
      req.session.authenticated = true;
      req.session.username = req.body.username;
      res.status(200).json({
        success: true,
        message: 'Authentication successful'
      });
    } else {
      res.status(401).json({
        success: false,
        message: 'Invalid username or password'
      });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Protected routes
app.get('/content.html', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'content.html'));
});

app.get('/dashboard.html', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Could not log out.');
    } else {
      // Clear localStorage to reset page history when logging out
      res.send(`
        <script>
          // Clear localStorage to reset navigation history
          localStorage.removeItem('lastPage');
          localStorage.removeItem('lastPageWithParams');
          // Redirect to login page
          window.location.href = '/';
        </script>
      `);
    }
  });
});


// ===== /track HELPERS =====
const PAGE_EVENTS = new Set(['page_view', 'url_change', 'click']);
const MAX_EVENTS_PER_BEACON = 200;
const IP_RE = /^[0-9a-fA-F:.]{3,45}$/;
 
const str = (v, n = 2000) => (v == null ? '' : String(v)).slice(0, n);
const int = (v) => (Number.isFinite(+v) ? Math.trunc(+v) : 0);
const flag = (v) => (v ? 1 : 0);
 
function generateEnhancedDataId(sessionId) {
  let numericValue = 0;
  for (let i = 0; i < sessionId.length; i++) numericValue += sessionId.charCodeAt(i);
  return parseInt(`${Date.now()}${numericValue % 1000}`);
}
 
async function lookupRegion(ipAddress) {
  const geo = { country: 'Unknown', region: 'Unknown', city: 'Unknown' };
  if (!IP_RE.test(ipAddress)) return geo;
 
  try {
    const cached = await clickhouse.query(
      'SELECT country, region, city FROM region_details WHERE ip_address = {ip:String} LIMIT 1',
      { params: { ip: ipAddress } }
    ).toPromise();
 
    if (cached.length > 0) {
      console.log(`Using cached data for IP: ${ipAddress}`);
      return cached[0];
    }
 
    const response = await axios.get(`http://ip-api.com/json/${ipAddress}`, { timeout: 5000 });
    const { country, regionName, city, status } = response.data;
    if (status !== 'success') {
      console.log(`IP lookup failed for ${ipAddress}:`, response.data.message || 'Unknown error');
      return geo;
    }
 
    geo.country = country || 'Unknown';
    geo.region = regionName || 'Unknown';
    geo.city = city || 'Unknown';
    console.log(`Fetched new IP data from ip-api.com: ${ipAddress} - ${geo.country}, ${geo.region}, ${geo.city}`);
 
    try {
      const again = await clickhouse.query(
        'SELECT ip_address FROM region_details WHERE ip_address = {ip:String} LIMIT 1',
        { params: { ip: ipAddress } }
      ).toPromise();
 
      if (again.length === 0) {
        const r = await clickhouse.query('SELECT max(id) AS m FROM region_details').toPromise();
        const row = { id: (r[0].m || 0) + 1, ip_address: ipAddress, country: geo.country, region: geo.region, city: geo.city };
        await clickhouse.insert(`INSERT INTO region_details (${Object.keys(row).join(', ')})`, [row]).toPromise();
        console.log(`Inserted new IP into region_details: ${ipAddress}`);
      }
    } catch (e) {
      console.error('Error inserting region data:', e.message);
    }
  } catch (e) {
    console.error('Error processing IP details:', e.message);
  }
  return geo;
}
 
 
// ============================================================================
// 3) /track
// ============================================================================
app.post('/track', async (req, res) => {
  try {
    // ---------- parse (text/plain from v2, application/json from v1) ----------
    let data = req.body;
    if (typeof data === 'string') {
      try { data = JSON.parse(data || '{}'); } catch { return res.status(400).end(); }
    }
    if (!data || typeof data !== 'object') return res.status(400).end();
 
    const isV2 = data.pixelVersion === 2;
    const eventType = str(data.eventType || 'page_view', 32);
    const sessionId = str(data.sessionId, 64);
    if (!sessionId) return res.status(400).end();
 
    // Real client IP from the connection, not from the payload (cannot be spoofed)
    const ipAddress = str((req.ip || '').replace(/^::ffff:/, '') || data.ipAddress, 64);
 
    const hostname = str(data.hostname, 255);
    const pageUrl = str(data.url, 4000);
    const device = data.deviceInfo || {};
    const securityHeaders = data.securityHeaders || {};
    const domMonitoring = data.domMonitoringData || {};
    const ts = new Date(data.timestamp || Date.now());
    const timestamp = (isNaN(ts) ? new Date() : ts).toISOString().slice(0, 19).replace('T', ' ');
 
    sessions[sessionId] = Date.now(); // keep session alive for terminate / captcha
 
    // Geo (cached per IP; result not stored on these rows, same as before)
    await lookupRegion(ipAddress);
 
    const enhanced_data_id = generateEnhancedDataId(sessionId);
 
    // ---------- tracking10: page views, URL changes, clicks (old pixel: every beacon) ----------
    const writeTracking = !isV2 || PAGE_EVENTS.has(eventType);
    if (writeTracking) {
      const r = await clickhouse.query('SELECT max(id) AS m FROM tracking10').toPromise();
      const trackingRow = {
        id: (r[0].m || 0) + 1,
        timestamp,
        url: pageUrl,
        referrer: str(data.referrer, 4000),
        ip_address: ipAddress,
        user_agent: str(device.userAgent, 1000),
        platform: str(device.platform, 100),
        language: str(device.language, 50),
        hostname,
        session_id: sessionId,
        browser_id: str(data.browser_id, 64),
        fingerprint_id: str(data.fingerprint_id, 64),
        clickdata: JSON.stringify(data.clickData || ''),
        enhanced_data_id
      };
      await clickhouse.insert(`INSERT INTO tracking10 (${Object.keys(trackingRow).join(', ')})`, [trackingRow]).toPromise();
      lastTrackingId.set(sessionId, { id: enhanced_data_id, seen: Date.now() });
    }
    const linked = lastTrackingId.get(sessionId);
    const trackingIdForSec = writeTracking ? enhanced_data_id : (linked ? linked.id : enhanced_data_id);
 
    // ---------- security_headers: every beacon (v2 only sends when something happened) ----------
    const sr = await clickhouse.query('SELECT max(id) AS m FROM security_headers').toPromise();
    let canvasRaw = '';
    try {
      canvasRaw = typeof securityHeaders.canvas_fingerprint === 'string'
        ? securityHeaders.canvas_fingerprint
        : JSON.stringify(securityHeaders.canvas_fingerprint || '');
    } catch { canvasRaw = ''; }
 
    const securityRow = {
      id: (sr[0].m || 0) + 1,
      tracking_id: trackingIdForSec,
      session_id: sessionId,
      security_cors_origin: str(securityHeaders.security_cors_origin),
      security_allow_origin: str(securityHeaders.security_allow_origin),  // '' from pixel v2
      security_allow_methods: str(securityHeaders.security_allow_methods),
      security_allow_headers: str(securityHeaders.security_allow_headers),
      security_allow_credentials: flag(securityHeaders.security_allow_credentials),
      security_expose_headers: str(securityHeaders.security_expose_headers),
      security_max_age: int(securityHeaders.security_max_age) || 86400,
      security_frame_ancestors: str(securityHeaders.security_frame_ancestors),
      security_csp: str(securityHeaders.security_csp, 8000),
      security_referrer_policy: str(securityHeaders.security_referrer_policy),
      security_permissions_policy: str(securityHeaders.security_permissions_policy),
      security_cross_origin: str(securityHeaders.security_cross_origin),
      security_is_framed: flag(securityHeaders.security_is_framed),
      security_sandbox: str(securityHeaders.security_sandbox),
      dom_changes_count: int(domMonitoring.dom_changes_count),
      dom_monitoring_active: flag(domMonitoring.dom_monitoring_active),
      dom_last_change: (domMonitoring.dom_last_change ? String(domMonitoring.dom_last_change) : new Date().toISOString())
        .slice(0, 23).replace('T', ' '),
      dom_added_elements: str(domMonitoring.dom_added_elements || '[]', 2000000),
      dom_removed_elements: str(domMonitoring.dom_removed_elements || '[]', 2000000),
      dom_modified_attributes: str(domMonitoring.dom_modified_attributes || '[]', 2000000),
      dom_sensitive_changes: str(domMonitoring.dom_sensitive_changes || '[]', 2000000),
      dom_security_violations: str(domMonitoring.dom_security_violations || '[]', 2000000),
      hardware_concurrency: int(securityHeaders.hardware_concurrency),
      platform_version: str(securityHeaders.platform_version, 200),
      canvas_fingerprint: str(canvasRaw, 100000),
      webgl_vendor: str(securityHeaders.webgl_vendor, 200),
      webgl_renderer: str(securityHeaders.webgl_renderer, 300),
      web_driver: flag(securityHeaders.web_driver),
      max_touch_points: int(securityHeaders.max_touch_points)
    };
    await clickhouse.insert(`INSERT INTO security_headers (${Object.keys(securityRow).join(', ')})`, [securityRow]).toPromise();
 
    // ---------- security_events (v2) ----------
    const events = Array.isArray(data.securityEvents) ? data.securityEvents.slice(0, MAX_EVENTS_PER_BEACON) : [];
    if (events.length) {
      const rows = events.map((e) => ({
        session_id: sessionId,
        hostname,
        page_url: str(e.page_url || pageUrl, 4000),
        ip_address: ipAddress,
        event_type: str(e.event_type, 40),
        element_type: str(e.element_type, 20),
        origin: str(e.origin, 300),
        is_third_party: flag(e.is_third_party),
        is_initial: flag(e.is_initial),
        attr_name: str(e.attr_name, 60),
        method: str(e.method, 10),
        page_ms: Math.max(0, int(e.page_ms)),
        detail: str(JSON.stringify(e.detail || {}), 4000)
      }));
      await clickhouse.insert(`INSERT INTO security_events (${Object.keys(rows[0]).join(', ')})`, rows).toPromise();
    }
 
    // ---------- session_behavior (v2) ----------
    if (isV2 && data.botSignals) {
      const b = data.botSignals;
      const h = data.behavior || {};
      const behaviorRow = {
        session_id: sessionId,
        hostname,
        ip_address: ipAddress,
        page_url: pageUrl,
        event_type: eventType,
        web_driver: flag(b.web_driver),
        headless_ua: flag(b.headless_ua),
        chrome_no_obj: flag(b.chrome_no_obj),
        desktop_chrome_no_plugins: flag(b.desktop_chrome_no_plugins),
        no_languages: flag(b.no_languages),
        zero_outer: flag(b.zero_outer),
        pointer_events: Math.max(0, int(h.pointer_events)),
        key_events: Math.max(0, int(h.key_events)),
        scroll_events: Math.max(0, int(h.scroll_events)),
        touch_events: Math.max(0, int(h.touch_events)),
        click_events: Math.max(0, int(h.click_events)),
        first_interaction_ms: int(h.first_interaction_ms),
        time_on_page_ms: Math.max(0, int(h.time_on_page_ms))
      };
      await clickhouse.insert(`INSERT INTO session_behavior (${Object.keys(behaviorRow).join(', ')})`, [behaviorRow]).toPromise();
    }
 
    res.status(204).end();
  } catch (error) {
    console.error('Error inserting into database:', error);
    res.status(500).json({ status: 'error', message: error.message });
  }
});

// ===== /collect helpers =====
const cStr = (v, n = 2000) => (v == null ? '' : String(v)).slice(0, n);
const cInt = (v) => (Number.isFinite(+v) ? Math.trunc(+v) : 0);
const cFlag = (v) => (v ? 1 : 0);
const C_MAX_EVENTS = 600;

app.post('/collect', async (req, res) => {
  try {
    const data = req.body;
    if (!data || typeof data !== 'object') return res.status(400).end();
    const orgId = cStr(data.orgId, 64);
    const userId = cStr(data.userId, 128);
    if (!orgId) return res.status(400).end();
    const events = Array.isArray(data.events) ? data.events.slice(0, C_MAX_EVENTS) : [];
    if (!events.length) return res.status(204).end();
    const ipAddress = cStr((req.ip || '').replace(/^::ffff:/, ''), 64);
    const rows = events.map((e) => ({
      timestamp: (() => { const d = new Date(e.ts || Date.now()); return (isNaN(d) ? new Date() : d).toISOString().slice(0, 23).replace('T', ' '); })(),
      org_id: orgId,
      user_id: userId,
      ip_address: ipAddress,
      page: cStr(e.page, 4000),
      referrer: cStr(e.referrer, 4000),
      device_fp: cStr(e.device_fp, 32),
      frame_is_top: cFlag(e.frame_is_top),
      event_type: cStr(e.type, 40),
      origin: cStr(e.origin, 300),
      is_third_party: cFlag(e.is_third_party),
      is_initial: cFlag(e.is_initial),
      novel: cFlag(e.novel),
      element_type: cStr(e.element_type, 20),
      attr_name: cStr(e.attr_name, 60),
      method: cStr(e.method, 10),
      severity: cStr(e.severity, 10),
      detail: cStr(JSON.stringify(e.detail || {}), 8000)
    }));
    await clickhouse.insert(`INSERT INTO shield_events (${Object.keys(rows[0]).join(', ')})`, rows).toPromise();
    res.status(204).end();
  } catch (error) {
    console.error('Error in /collect:', error);
    res.status(500).json({ status: 'error', message: error.message });
  }
});

// Session management endpoints
app.post('/message', security.protect(), (req, res) => {
  console.log('Received /message request:', req.body);
  const sessionId = req.body.sessionId.trim();
  const message = req.body.message;

  if (sessions[sessionId]) {
    io.to(sessionId).emit('receiveMessage', { message: message });
    sessions[sessionId] = Date.now(); // Update session activity
    res.json({ success: true, message: 'Message sent successfully.' });
  } else {
    res.status(400).json({ success: false, message: 'Session ID not found' });
  }
});

app.post('/session', security.protect(), (req, res) => {
  console.log('Received /session request:', req.body);
  const sessionId = req.body.sessionId;
  if (sessions[sessionId]) {
    res.json({ success: true });
  } else {
    res.status(400).json({ success: false, message: 'Session ID not found' });
  }
});

app.get('/sessions', security.protect(), (req, res) => {
  res.json(Object.keys(sessions));
});

// Session termination endpoints
app.route('/terminate-session')
  .get(security.protect(), (req, res) => {
    const activeSessions = Object.keys(sessions);
    res.render('terminateSession', { sessions: activeSessions });
  })
  .post(security.protect(), (req, res) => {
    const { sessionId } = req.body;

    if (sessions[sessionId]) {
      io.to(sessionId).emit('session-terminated', { message: 'Your session has been terminated.' });
      delete sessions[sessionId];
      res.json({ success: true, message: 'Session terminated successfully.' });
    } else {
      res.status(400).json({ success: false, message: 'Session ID not found.' });
    }
  });

app.post('/terminate-sessions', security.protect({
  maxRequestsPerWindow: 5,
  requestWindow: 300000 // 5 minutes for admin actions
}), isAuthenticated, async (req, res) => {
  const { timestamp } = req.body;
  const name = req.username;

  try {
    // Fetch the hostname for the user
    const q2 = `SELECT hostname FROM users_new WHERE username = '${name}'`;
    const hostarray = await clickhouse.query(q2).toPromise();
    const host = hostarray[0].hostname;

    // Build the SQL query dynamically with the fetched hostname
    const sqlQuery = `SELECT DISTINCT session_id FROM tracking10 WHERE timestamp >= '${timestamp}' AND hostname LIKE '%${host}%'`;

    // The actual URL you are using with the ClickHouse server
    const url = `http://64.227.140.163:8001/terminate-sessions?query1=${encodeURIComponent(sqlQuery)}`;

    // Use axios to send the query to the ClickHouse server
    const response = await axios.get(url);

    // Return the response from ClickHouse to the frontend
    res.json({
      success: true,
      message: 'Sessions terminated successfully',
      data: response.data
    });
  } catch (error) {
    // Handle error from the request
    console.error('Error executing query:', error);
    res.status(500).json({ success: false, message: 'Failed to terminate sessions', error: error.message });
  }
});

// CAPTCHA endpoints
app.route('/send-captcha')
  .get(security.protect(), (req, res) => {
    const activeSessions = Object.keys(sessions);
    res.render('sendCaptcha', { sessions: activeSessions });
  })
  .post(security.protect(), (req, res) => {
    const { sessionId } = req.body;

    if (sessions[sessionId]) {
      io.to(sessionId).emit('captcha-required', { message: 'Solve the CAPTCHA to continue.' });
      res.json({ success: true, message: 'CAPTCHA sent successfully.' });
    } else {
      res.status(400).json({ success: false, message: 'Session ID not found.' });
    }
  });

app.post('/send-captcha-session', security.protect(), isAuthenticated, async (req, res) => {
  const { sessionId } = req.body;
  const username = req.username;

  try {
    // Basic validation
    if (!sessionId) {
      req.flash('error', 'Session ID is required');
      return res.redirect('/risk-analysis');
    }

    // Verify the session exists
    if (!sessions[sessionId]) {
      req.flash('error', 'Session not found');
      return res.redirect('/risk-analysis');
    }

    try {
      // First, verify session belongs to user's hostname
      const userQuery = `SELECT hostname FROM users_new WHERE username = '${username}'`;
      const userResult = await clickhouse.query(userQuery).toPromise();
      const userHostname = userResult[0].hostname;

      const sessionQuery = `
          SELECT hostname
          FROM live_sessions_mv_new
          WHERE session_id = '${sessionId}'
          LIMIT 1
        `;
      const sessionResult = await clickhouse.query(sessionQuery).toPromise();

      if (sessionResult.length === 0 || !sessionResult[0].hostname.includes(userHostname)) {
        req.flash('error', 'Unauthorized to send captcha to this session');
        return res.redirect('/risk-analysis');
      }

      // Send CAPTCHA challenge to the session
      io.to(sessionId).emit('captcha-required', {
        message: 'Solve the CAPTCHA to continue.'
      });

      req.flash('success', 'CAPTCHA sent successfully');
      res.redirect('/risk-analysis');

    } catch (dbError) {
      console.error('Database error:', dbError);
      req.flash('error', 'Failed to process captcha request');
      res.redirect('/risk-analysis');
    }
  } catch (error) {
    console.error('Error sending CAPTCHA:', error);
    req.flash('error', 'Failed to send CAPTCHA');
    res.redirect('/risk-analysis');
  }
});

// ============================================================================
// Jev live "is this user legit?" check — no table, no batch.
// Frontend calls GET /api/jev/check?user_id=... ; server gathers the user's
// signals, asks Jev, returns the verdict straight back.
//
// Requires: axios, clickhouse, app, security, isAuthenticated already defined,
// and JEV_API_KEY in .env (loaded via dotenv at top of server).
// ============================================================================

const JEV_URL = 'https://api.getjevai.com/v1/decisions';

// Small in-memory cache so a dashboard refresh doesn't spend a credit each time.
// Lives only in the Node process; cleared on restart. Not a database.
const _jevCache = new Map();           // key "org|user" -> { at, verdict }
const JEV_TTL_MS = 10 * 60 * 1000;

async function buildJevState(org, userId) {
  // Everything comes from shield_events (the extension's only table).
  const ev = await clickhouse.query(`
    SELECT
      count() AS total_events,
      countIf(severity='high') AS high_events,
      countIf(novel=1 AND is_third_party=1) AS novel_thirdparty,
      uniqExactIf(page, event_type='page_start' AND frame_is_top=1) AS pages_visited,
      uniqExact(device_fp) AS devices,
      uniqExactIf(ip_address, ip_address!='') AS ips,
      countIf(event_type='prehooked_api') AS prehooked_apis,
      countIf(event_type='script_added') AS scripts_added,
      countIf(event_type='iframe_added') AS iframes_added,
      countIf(event_type='network_request' AND method!='GET') AS post_requests,
      countIf(event_type='image_beacon') AS image_beacons,
      countIf(event_type='csp_violation') AS csp_violations,
      countIf(event_type='form_submit') AS form_submits,
      dateDiff('second', min(timestamp), max(timestamp)) AS span_seconds,
      min(timestamp) AS window_start, max(timestamp) AS window_end
    FROM shield_events
    WHERE org_id = {org:String} AND user_id = {uid:String}
  `, { params: { org, uid: userId } }).toPromise();

  // A few domains for context (small)
  const pg = await clickhouse.query(`
    SELECT DISTINCT domain(page) AS d
    FROM shield_events
    WHERE org_id = {org:String} AND user_id = {uid:String}
      AND event_type='page_start' AND frame_is_top=1
    LIMIT 20
  `, { params: { org, uid: userId } }).toPromise();

  const e = ev[0] || {};
  return {
    events_scored: +e.total_events || 0,
    state: {
      note: 'Browser-extension telemetry for one user across sites. Decide if a real human is browsing, or an automated bot / headless script. Note: this feed has no mouse/keyboard interaction or navigator.webdriver data, so judge from browsing variety and injected-resource patterns. Many pages across varied, well-known domains over time looks human. A burst of injected scripts/iframes, pre-hooked browser APIs, hidden iframes, or data-exfil beacons looks automated or compromised.',
      activity: {
        pages_visited: +e.pages_visited || 0,
        distinct_domains: pg.map(r => r.d).filter(Boolean),
        devices: +e.devices || 0,
        distinct_ips: +e.ips || 0,
        span_seconds: +e.span_seconds || 0,
        security_events_total: +e.total_events || 0,
        high_severity_events: +e.high_events || 0
      },
      suspicious_signals: {
        prehooked_browser_apis: +e.prehooked_apis || 0,
        scripts_injected_after_load: +e.scripts_added || 0,
        iframes_injected_after_load: +e.iframes_added || 0,
        non_get_third_party_requests: +e.post_requests || 0,
        data_exfil_image_beacons: +e.image_beacons || 0,
        csp_violations: +e.csp_violations || 0,
        cross_origin_form_submits: +e.form_submits || 0,
        novel_thirdparty_resources: +e.novel_thirdparty || 0
      }
    },
    meta: { window_start: e.window_start, window_end: e.window_end }
  };
}

const JEV_QUESTIONS = {
  genuine_human: {
    type: 'noul',
    instructions: 'A genuine human is browsing normally, rather than an automated bot, headless browser, or a compromised/injected session. Judge from the signals given: visiting several well-known domains over a span of time looks human. Pre-hooked browser APIs, injected scripts/iframes after load, data-exfil image beacons, or cross-origin form submits indicate automation or a compromised browser.',
    criteria: { true: 'Genuine human', false: 'Automated bot or compromised session' }
  },
  verdict: {
    type: 'choice',
    instructions: 'Classify this session.',
    criteria: { human: 'A real human user', bot: 'An automated bot or script', unsure: 'Not enough signal to tell' }
  }
};

app.get('/api/jev/check', security.protect(), isAuthenticated, async (req, res) => {
  try {
    const key = process.env.JEV_API_KEY;
    if (!key) return res.status(500).json({ success: false, message: 'JEV_API_KEY not set' });

    const h = await clickhouse.query('SELECT hostname FROM users_new WHERE username = {u:String} LIMIT 1',
      { params: { u: req.username } }).toPromise();
    if (!h.length) return res.status(404).json({ success: false, message: 'No org for user' });
    const org = h[0].hostname;

    const userId = String(req.query.user_id || '');
    if (!userId) return res.status(400).json({ success: false, message: 'user_id required' });

    const cacheKey = org + '|' + userId;
    const cached = _jevCache.get(cacheKey);
    if (cached && Date.now() - cached.at < JEV_TTL_MS) {
      return res.json({ success: true, cached: true, ...cached.verdict });
    }

    const { state, events_scored } = await buildJevState(org, userId);
    if (!events_scored) return res.json({ success: true, verdict: 'unsure', genuine: null, message: 'No data for this user' });

    const r = await axios.post(JEV_URL,
      { state, questions: JEV_QUESTIONS },
      { headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' }, timeout: 20000 });

    const a = r.data.answers || {};
    const verdict = {
      genuine: a.genuine_human ? a.genuine_human.noul : null,          // 0..1
      verdict: a.verdict ? a.verdict.choice : 'unsure',                 // human | bot | unsure
      confidence: a.verdict ? a.verdict.confidence : 0,
      model: r.data.model,
      credits_remaining: r.data.credits_remaining
    };
    _jevCache.set(cacheKey, { at: Date.now(), verdict });
    res.json({ success: true, cached: false, ...verdict });
  } catch (err) {
    const code = err.response ? err.response.status : 500;
    const msg = (err.response && err.response.data && err.response.data.error && err.response.data.error.message) || err.message;
    console.error('jev check error:', code, msg);
    res.status(code === 402 ? 402 : 500).json({ success: false, message: msg });
  }
});

// ============================================================================
// Chrome-extension "user journey" endpoints, gated by the same login as the
// pixel dashboard. The logged-in user's hostname (from users_new) is used as
// the org_id, so each customer sees only their own org's extension data.
//
// Requires: shield_events table, and the extension deployed with
//   orgId == that customer's `hostname` value in users_new.
//
// Mount after your other routes, with isAuthenticated already defined.
// ============================================================================

// ---- helper: resolve the logged-in user's org (= their hostname) ----
async function orgForUser(username) {
  const r = await clickhouse.query(
    'SELECT hostname FROM users_new WHERE username = {u:String} LIMIT 1',
    { params: { u: username } }
  ).toPromise();
  return r.length ? r[0].hostname : null;
}

// ---- 1) List employees (user_ids) seen for this org, with a risk summary ----
app.get('/api/shield/users', security.protect(), isAuthenticated, async (req, res) => {
  try {
    const org = await orgForUser(req.username);
    if (!org) return res.status(404).json({ success: false, message: 'No org for user' });

    const q = `
      SELECT
        user_id,
        uniqExact(device_fp)                         AS devices,
        uniqExact(page)                              AS pages_seen,
        countIf(severity = 'high')                   AS high_events,
        countIf(novel = 1 AND is_third_party = 1)    AS novel_thirdparty,
        anyIf(ip_address, ip_address != '')          AS ip,
        max(timestamp)                               AS last_seen,
        min(timestamp)                               AS first_seen
      FROM shield_events
      WHERE org_id = {org:String}
      GROUP BY user_id
      ORDER BY high_events DESC, last_seen DESC`;
    const rows = await clickhouse.query(q, { params: { org } }).toPromise();

    // Attach country/city from the user's IP via the existing helper
    const users = await Promise.all(rows.map(async row => {
      const g = row.ip ? await getIpDetails(row.ip) : null;
      row.country = g ? g.country : 'Unknown';
      row.region = g ? g.region : 'Unknown';
      row.city = g ? g.city : 'Unknown';
      return row;
    }));
    res.json({ success: true, org, users });
  } catch (e) {
    console.error('shield/users error:', e);
    res.status(500).json({ success: false, message: e.message });
  }
});

// ---- 2) One employee's journey: pages visited + notable events, in order ----
app.get('/api/shield/journey', security.protect(), isAuthenticated, async (req, res) => {
  try {
    const org = await orgForUser(req.username);
    if (!org) return res.status(404).json({ success: false, message: 'No org for user' });

    const userId = String(req.query.user_id || '');
    if (!userId) return res.status(400).json({ success: false, message: 'user_id required' });
    const page = parseInt(req.query.page) || 1;
    const perPage = 100;
    const offset = (page - 1) * perPage;

    // One row per thing that happened, newest first:
    //   - 'visit'  : a top-frame page load (the journey backbone)
    //   - 'alert'  : a high-severity security event
    // Info-level noise (script_present on normal sites) is left out.
    const q = `
      SELECT
        timestamp,
        multiIf(event_type = 'page_start', 'visit', 'alert') AS kind,
        page,
        referrer,
        event_type,
        origin,
        is_third_party,
        novel,
        severity,
        device_fp
      FROM shield_events
      WHERE org_id = {org:String}
        AND user_id = {uid:String}
        AND ( (event_type = 'page_start' AND frame_is_top = 1)
              OR severity = 'high' )
      ORDER BY timestamp DESC
      LIMIT ${perPage} OFFSET ${offset}`;
    const rows = await clickhouse.query(q, { params: { org, uid: userId } }).toPromise();

    const countRes = await clickhouse.query(
      `SELECT count() AS n FROM shield_events
       WHERE org_id = {org:String} AND user_id = {uid:String}
         AND ((event_type='page_start' AND frame_is_top=1) OR severity='high')`,
      { params: { org, uid: userId } }
    ).toPromise();
    const total = countRes[0].n;

    res.json({
      success: true, org, user_id: userId,
      journey: rows,
      currentPage: page,
      totalPages: Math.ceil(total / perPage)
    });
  } catch (e) {
    console.error('shield/journey error:', e);
    res.status(500).json({ success: false, message: e.message });
  }
});

app.get('/shield-journey', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'html', 'shield_journey.html'));
});

app.get('/api/shield-visitors', security.protect(), isAuthenticated, async (req, res) => {
  const customUrl = req.query.custom_url || '';
  const name = req.username;
  const page = parseInt(req.query.page) || 1;
  const perPage = 10;
  const startDate = req.query.start_date || '2026-10-01';
  const endDate = req.query.end_date || '2026-12-31';

  if (!isValidDate(startDate) || !isValidDate(endDate)) {
    return res.status(400).json({ success: false, message: 'Invalid date format' });
  }
  if (isNaN(page) || page < 1) {
    return res.status(400).json({ success: false, message: 'Invalid page number' });
  }
  if (customUrl.length > 200) {
    return res.status(400).json({ success: false, message: 'Custom URL too long' });
  }

  try {
    const q2 = `SELECT hostname FROM users_new WHERE username = {name:String}`;
    const hostarray = await clickhouse.query(q2, { params: { name } }).toPromise();
    if (!hostarray.length) {
      return res.status(404).json({ success: false, message: 'Hostname not found' });
    }
    const host = hostarray[0].hostname;   // == extension orgId

    // One row per top-frame page visit. end date is made inclusive by adding a day.
    const query = `
      SELECT
        user_id, device_fp, ip_address, page, referrer, timestamp,
        (SELECT countIf(severity='high') FROM shield_events s2
           WHERE s2.org_id = {host:String} AND s2.user_id = s1.user_id
             AND s2.timestamp >= s1.timestamp AND s2.timestamp < s1.timestamp + INTERVAL 1 MINUTE) AS high_near
      FROM shield_events s1
      WHERE org_id = {host:String}
        AND event_type = 'page_start'
        AND frame_is_top = 1
        AND page LIKE concat('%', {customUrl:String}, '%')
        AND timestamp BETWEEN {startDate:String} AND concat({endDate:String}, ' 23:59:59')
      ORDER BY timestamp DESC`;
    const result = await clickhouse.query(query, {
      params: { customUrl, startDate, endDate, host }
    }).toPromise();

    const totalRows = result.length;
    const totalPages = Math.ceil(totalRows / perPage);
    const startIdx = (page - 1) * perPage;
    const paginatedData = result.slice(startIdx, startIdx + perPage);

    const rows = await Promise.all(paginatedData.map(async row => {
      const ipDetails = await getIpDetails(row.ip_address);
      row.country = ipDetails ? ipDetails.country : 'Unknown';
      row.region = ipDetails ? ipDetails.region : 'Unknown';
      row.city = ipDetails ? ipDetails.city : 'Unknown';
      const t = new Date(row.timestamp);
      row.date = t.toISOString().split('T')[0];
      row.time = t.toTimeString().split(' ')[0].substring(0, 8);
      return row;
    }));

    res.json({
      success: true,
      visitors: rows,
      totalRows, totalPages, currentPage: page,
      custom_url: customUrl, start_date: startDate, end_date: endDate
    });
  } catch (error) {
    console.error('Error in shield-visitors API:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error', error: error.message });
  }
});

// Serve the report page
app.get('/shield-report', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'html', 'shield-visitors-report.html'));
});



// API route to get rules
app.get('/api/rules', security.protect(), isAuthenticated, async (req, res) => {
  const username = req.username;

  try {
    // Fetch the hostname for the user
    const q2 = `SELECT hostname FROM users_new WHERE username = {username:String}`;
    const hostarray = await clickhouse.query(q2, {
      params: { username }
    }).toPromise();

    if (!hostarray.length) {
      return res.status(404).json({
        success: false,
        message: 'Hostname not found'
      });
    }

    const hostname = hostarray[0].hostname;

    // Query to fetch rules for the specific hostname
    const query = `
      SELECT * FROM rules 
      WHERE hostname LIKE concat('%', {hostname:String}, '%') 
      ORDER BY creation_time DESC
    `;

    const rules = await clickhouse.query(query, {
      params: { hostname }
    }).toPromise();

    // Return rules as JSON
    res.json({
      success: true,
      rules: rules
    });
  } catch (error) {
    console.error('Error fetching rules:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching rules'
    });
  }
});

// API route to add a new rule
app.post('/api/rules', security.protect(), isAuthenticated, async (req, res) => {
  const { rule, name, action_time, action } = req.body;
  const username = req.username;

  // Input validation
  if (!rule || !name || !action_time || !action) {
    return res.status(400).json({
      success: false,
      message: 'All fields are required'
    });
  }

  if (rule.length > 1000 || name.length > 100 || action.length > 500) {
    return res.status(400).json({
      success: false,
      message: 'Input too long'
    });
  }

  if (isNaN(parseInt(action_time)) || parseInt(action_time) < 0) {
    return res.status(400).json({
      success: false,
      message: 'Invalid action time'
    });
  }

  try {
    // Get hostname
    const q2 = `SELECT hostname FROM users_new WHERE username = {username:String}`;
    const hostarray = await clickhouse.query(q2, {
      params: { username }
    }).toPromise();

    if (!hostarray.length) {
      return res.status(404).json({
        success: false,
        message: 'Hostname not found'
      });
    }

    const hostname = hostarray[0].hostname;

    // Get max ID
    const result = await clickhouse.query('SELECT max(id) AS maxId FROM rules').toPromise();
    const maxId = result.length > 0 ? result[0].maxId : null;
    let nextId = maxId !== null ? maxId + 1 : 0;

    const creationTime = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const version = 1; // Start versioning from 1

    // Insert new rule
    const query = `
      INSERT INTO rules (id, rule, hostname, name, creation_time, last_edit_time, version, action_time, action) 
      VALUES ({nextId:Int32}, {rule:String}, {hostname:String}, {name:String}, {creationTime:String}, {creationTime:String}, {version:Int32}, {action_time:Int32}, {action:String})
    `;

    await clickhouse.query(query, {
      params: {
        nextId,
        rule,
        hostname,
        name,
        creationTime,
        version,
        action_time: parseInt(action_time),
        action
      }
    }).toPromise();

    // Return success message
    res.json({
      success: true,
      message: 'Rule added successfully'
    });
  } catch (error) {
    console.error('Error creating rule:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating rule'
    });
  }
});

// API route to update a rule
app.post('/api/rules/edit/:id', security.protect(), isAuthenticated, async (req, res) => {
  const { rule, name, action_time, action } = req.body;
  const { id } = req.params;
  const username = req.username;

  // Input validation
  if (!rule || !name || !action_time || !action) {
    return res.status(400).json({
      success: false,
      message: 'All fields are required'
    });
  }

  if (rule.length > 1000 || name.length > 100 || action.length > 500) {
    return res.status(400).json({
      success: false,
      message: 'Input too long'
    });
  }

  if (isNaN(parseInt(action_time)) || parseInt(action_time) < 0) {
    return res.status(400).json({
      success: false,
      message: 'Invalid action time'
    });
  }

  if (isNaN(parseInt(id)) || parseInt(id) < 0) {
    return res.status(400).json({
      success: false,
      message: 'Invalid rule ID'
    });
  }

  try {
    // Get hostname
    const q2 = `SELECT hostname FROM users_new WHERE username = {username:String}`;
    const hostarray = await clickhouse.query(q2, {
      params: { username }
    }).toPromise();

    if (!hostarray.length) {
      return res.status(404).json({
        success: false,
        message: 'Hostname not found'
      });
    }

    const hostname = hostarray[0].hostname;

    // Get current version
    const versionQuery = `
      SELECT version FROM rules 
      WHERE id = {id:Int32} 
      ORDER BY version DESC 
      LIMIT 1
    `;

    const result = await clickhouse.query(versionQuery, {
      params: { id: parseInt(id) }
    }).toPromise();

    const currentVersion = result.length > 0 ? result[0].version : 0;

    const newVersion = currentVersion + 1;
    const lastEditTime = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const creationTime = lastEditTime; // Use the same time for creation

    // Delete old version
    await clickhouse.query(`ALTER TABLE rules DELETE WHERE id = {id:Int32} AND version = {currentVersion:Int32}`, {
      params: {
        id: parseInt(id),
        currentVersion
      }
    }).toPromise();

    // Insert updated rule
    const insertQuery = `
      INSERT INTO rules (id, rule, hostname, name, creation_time, last_edit_time, version, action_time, action) 
      VALUES ({id:Int32}, {rule:String}, {hostname:String}, {name:String}, {creationTime:String}, {lastEditTime:String}, {newVersion:Int32}, {action_time:Int32}, {action:String})
    `;

    await clickhouse.query(insertQuery, {
      params: {
        id: parseInt(id),
        rule,
        hostname,
        name,
        creationTime,
        lastEditTime,
        newVersion,
        action_time: parseInt(action_time),
        action
      }
    }).toPromise();

    // Return success message
    res.json({
      success: true,
      message: 'Rule updated successfully'
    });
  } catch (error) {
    console.error('Error updating rule:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating rule'
    });
  }
});

// API route to delete a rule
app.post('/api/rules/delete/:id', security.protect(), isAuthenticated, async (req, res) => {
  const { id } = req.params;

  // Input validation
  if (isNaN(parseInt(id)) || parseInt(id) < 0) {
    return res.status(400).json({
      success: false,
      message: 'Invalid rule ID'
    });
  }

  try {
    // Delete rule
    const query = `ALTER TABLE rules DELETE WHERE id = {id:Int32}`;

    await clickhouse.query(query, {
      params: { id: parseInt(id) }
    }).toPromise();

    // Return success message
    res.json({
      success: true,
      message: 'Rule deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting rule:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting rule'
    });
  }
});

// Update the existing rules endpoint to serve HTML instead of EJS
app.get('/rules', isAuthenticated, (req, res) => {
  // Send the HTML file instead of rendering EJS
  // res.sendFile(path.join(__dirname, 'public', 'rules.html'));
  res.sendFile(path.join(__dirname, 'public', 'html', 'rules.html'));

});

// Analytics endpoints

app.get('/api/visitors', security.protect(), isAuthenticated, async (req, res) => {
  // Get parameters with hardcoded defaults
  const customUrl = req.query.custom_url || 'cloudsdigital';
  const name = req.username;
  const page = parseInt(req.query.page) || 1;
  const perPage = 10; // Number of rows per page
  const startDate = req.query.start_date || '2025-10-10';
  const endDate = req.query.end_date || '2025-10-14';

  // Validate input
  if (!isValidDate(startDate) || !isValidDate(endDate)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid date format'
    });
  }

  if (isNaN(page) || page < 1) {
    return res.status(400).json({
      success: false,
      message: 'Invalid page number'
    });
  }

  if (customUrl.length > 100) {
    return res.status(400).json({
      success: false,
      message: 'Custom URL too long'
    });
  }

  try {
    // Fetch the hostname for the user using parameterized query
    const q2 = `SELECT hostname FROM users_new WHERE username = {name:String}`;
    const hostarray = await clickhouse.query(q2, {
      params: { name }
    }).toPromise();

    if (!hostarray.length) {
      return res.status(404).json({
        success: false,
        message: 'Hostname not found'
      });
    }

    const host = hostarray[0].hostname;

    // Use the hostname in the query with parameterization
    const query = `
      SELECT session_id, ip_address, timestamp, url, session_id, browser_id, fingerprint_id 
      FROM tracking10 
      WHERE url LIKE concat('%', {customUrl:String}, '%')
        AND timestamp BETWEEN {startDate:String} AND {endDate:String}
        AND hostname LIKE concat('%', {host:String}, '%')
      ORDER BY timestamp DESC
    `;

    const result = await clickhouse.query(query, {
      params: {
        customUrl,
        startDate,
        endDate,
        host
      }
    }).toPromise();

    // Process the results - keeping all the existing logic
    const uniqueSessions = new Set();
    const uniqueData = result.filter(row => {
      if (!uniqueSessions.has(row.session_id)) {  // Correctly using the full session_id string
        uniqueSessions.add(row.session_id);  // Added full session_id for deduplication
        return true;
      }
      return false;
    });

    const totalRows = uniqueData.length;
    const totalPages = Math.ceil(totalRows / perPage);
    const startIdx = (page - 1) * perPage;
    const endIdx = startIdx + perPage;
    const paginatedData = uniqueData.slice(startIdx, endIdx);

    const paginatedDataWithDetails = await Promise.all(paginatedData.map(async row => {
      const ipDetails = await getIpDetails(row.ip_address);
      if (ipDetails) {
        row.country = ipDetails.country;
        row.region = ipDetails.region;
        row.city = ipDetails.city;
      } else {
        row.country = 'Unknown';
        row.region = 'Unknown';
        row.city = 'Unknown';
      }

      // Process timestamp
      const timestamp = new Date(row.timestamp);
      row.date = timestamp.toISOString().split('T')[0];
      row.time = timestamp.toTimeString().split(' ')[0].substring(0, 8);
      return row;
    }));

    const filteredData = paginatedDataWithDetails.filter(row => row !== null);

    // Return JSON response
    res.json({
      success: true,
      visitors: filteredData,
      totalRows: totalRows,
      totalPages: totalPages,
      currentPage: page,
      custom_url: customUrl,
      start_date: startDate,
      end_date: endDate
    });

  } catch (error) {
    console.error("Error in API endpoint:", error);
    res.status(500).json({
      success: false,
      message: 'Internal Server Error',
      error: error.message
    });
  }
});

// Update the existing /rawreport endpoint to serve HTML instead of rendering EJS
app.get('/rawreport', isAuthenticated, (req, res) => {
  // Send the HTML file instead of rendering EJS
  res.sendFile(path.join(__dirname, 'public', 'html', 'visitors-report.html'));
});


// New API endpoint for session journey data
app.get('/api/session_journey', security.protect(), isAuthenticated, async (req, res) => {
  // Get parameters with hardcoded defaults
  const sessionid = req.query.session_id || 'uz8fray3629x8m5mqw';
  const name = req.username;

  // Input validation
  if (sessionid.length > 100) {
    return res.status(400).json({
      success: false,
      message: 'Session ID too long'
    });
  }

  try {
    // Get the hostname associated with the user
    const hostQuery = `SELECT hostname FROM users_new WHERE username = {name:String}`;
    const hostResult = await clickhouse.query(hostQuery, {
      params: { name }
    }).toPromise();

    if (!hostResult.length) {
      return res.status(404).json({
        success: false,
        message: 'Hostname not found for user'
      });
    }

    const host = hostResult[0].hostname;

    // Use the hostname to filter the data in the tracking10 table
    const query = `
      SELECT url, timestamp, clickdata
      FROM tracking10
      WHERE session_id LIKE concat('%', {sessionid:String}, '%')
        AND hostname LIKE concat('%', {host:String}, '%')
      ORDER BY timestamp
    `;

    const result = await clickhouse.query(query, {
      params: {
        sessionid,
        host
      }
    }).toPromise();

    // Process each row but only keep URL changes and click events
    let filteredData = [];
    let previousUrl = null;

    result.forEach(row => {
      // Create a Date object from the timestamp
      const timestamp = new Date(row.timestamp);

      // Extract and format date and time
      row.date = timestamp.toISOString().split('T')[0];
      row.time = timestamp.toTimeString().split(' ')[0].substring(0, 8);

      // Check if URL changed from previous or has clickdata
      const isUrlChange = row.url !== previousUrl;
      const hasClickData = row.clickdata && row.clickdata !== '""';

      // Only include the row if it's a URL change or has click data
      if (isUrlChange || hasClickData) {
        // Store this URL as the previous for the next iteration
        previousUrl = row.url;

        // Add to filtered data
        filteredData.push(row);
      }
    });

    // Return JSON response
    res.json({
      success: true,
      sessionId: sessionid,
      journeyData: filteredData
    });

  } catch (error) {
    console.error('Error fetching session journey data:', error);
    res.status(500).json({
      success: false,
      message: 'Internal Server Error',
      error: error.message
    });
  }
});

// Update the existing /session_journey endpoint to serve HTML instead of rendering EJS
app.get('/session_journey', isAuthenticated, (req, res) => {
  // Send the HTML file instead of rendering EJS
  res.sendFile(path.join(__dirname, 'public', 'html', 'session_journey.html'));
});


// New API endpoint for bot requests data
app.get('/api/botrequests', security.protect(), isAuthenticated, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const perPage = 10; // Number of records per page
  const name = req.username;
  const customUrl = req.query.custom_url || 'bot'; // Default value for custom URL
  const startDate = req.query.start_date || '2024-07-01'; // Default start date
  const endDate = req.query.end_date || '2024-08-31'; // Default end date

  // Input validation
  if (!isValidDate(startDate) || !isValidDate(endDate)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid date format'
    });
  }

  if (isNaN(page) || page < 1) {
    return res.status(400).json({
      success: false,
      message: 'Invalid page number'
    });
  }

  if (customUrl.length > 100) {
    return res.status(400).json({
      success: false,
      message: 'Custom URL too long'
    });
  }

  try {
    // Fetch the hostname for the user
    const q2 = `SELECT hostname FROM users_new WHERE username = {name:String}`;
    const hostarray = await clickhouse.query(q2, {
      params: { name }
    }).toPromise();

    if (!hostarray.length) {
      return res.status(404).json({
        success: false,
        message: 'Hostname not found'
      });
    }

    const host = hostarray[0].hostname;

    // Query to get bot requests filtered by host, custom URL, start and end date
    const query = `
      SELECT user_agent, url, count(*) as request_count
      FROM tracking10
      WHERE user_agent LIKE '%bot%'
        AND hostname LIKE concat('%', {host:String}, '%')
        AND user_agent LIKE concat('%', {customUrl:String}, '%')
        AND timestamp BETWEEN {startDate:String} AND {endDate:String}
      GROUP BY user_agent, url
      ORDER BY request_count DESC
      LIMIT {limit:Int32} OFFSET {offset:Int32}
    `;

    const result = await clickhouse.query(query, {
      params: {
        host,
        customUrl,
        startDate,
        endDate,
        limit: perPage,
        offset: (page - 1) * perPage
      }
    }).toPromise();

    // Query to get the total number of records
    const countQuery = `
      SELECT COUNT(*) as total
      FROM (
        SELECT user_agent, url
        FROM tracking10
        WHERE user_agent LIKE '%bot%'
          AND hostname LIKE concat('%', {host:String}, '%')
          AND user_agent LIKE concat('%', {customUrl:String}, '%')
          AND timestamp BETWEEN {startDate:String} AND {endDate:String}
        GROUP BY user_agent, url
      ) AS temp
    `;

    const totalCountResult = await clickhouse.query(countQuery, {
      params: {
        host,
        customUrl,
        startDate,
        endDate
      }
    }).toPromise();

    const totalRows = totalCountResult[0].total;
    const totalPages = Math.ceil(totalRows / perPage);

    // Return JSON response
    res.json({
      success: true,
      botRequests: result,
      totalRows: totalRows,
      totalPages: totalPages,
      currentPage: page,
      custom_url: customUrl,
      start_date: startDate,
      end_date: endDate
    });

  } catch (error) {
    console.error("Error in API endpoint:", error);
    res.status(500).json({
      success: false,
      message: 'Internal Server Error',
      error: error.message
    });
  }
});

// Update the existing /botrequests endpoint to serve HTML instead of rendering EJS
app.get('/botrequests', isAuthenticated, (req, res) => {
  // Send the HTML file instead of rendering EJS
  res.sendFile(path.join(__dirname, 'public', 'html', 'bot_requests.html'));
});


// New API endpoint for risk analysis data
app.get('/api/updated-session-risk-analysis', security.protect(), isAuthenticated, async (req, res) => {
  const name = req.username;
  const page = parseInt(req.query.page) || 1;
  const perPage = 10;
  const startDate = req.query.start_date || '2024-08-24';
  const endDate = req.query.end_date || '2025-12-15';

  // Input validation
  if (!isValidDate(startDate) || !isValidDate(endDate)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid date format'
    });
  }

  if (isNaN(page) || page < 1) {
    return res.status(400).json({
      success: false,
      message: 'Invalid page number'
    });
  }

  try {
    // Fetch the hostname for the user
    const q2 = `SELECT hostname FROM users_new WHERE username = {name:String}`;
    const hostarray = await clickhouse.query(q2, {
      params: { name }
    }).toPromise();

    if (!hostarray.length) {
      return res.status(404).json({
        success: false,
        message: 'Hostname not found'
      });
    }

    const host = hostarray[0].hostname;

    // SQL query for enhanced session risk scores with parameters
    const query = `
      SELECT
        session_id,
        total_risk_score,
        browser_risk,
        login_risk,
        ip_risk,
        freq_risk,
        bot_risk,
        geo_risk,
        xss_risk,
        redirect_risk,
        ssrf_risk,
        sqli_risk,
        request_count,
        distinct_ip_count,
        login_attempts,
        session_duration,
        url_change_count,
        action_recommendations,
        host,
        timestamp
      FROM default.updated_hist_session_risk_scores
      WHERE timestamp BETWEEN {startDate:String} AND {endDate:String}
      AND host LIKE concat('%', {host:String}, '%')
      ORDER BY timestamp DESC
    `;

    const result = await clickhouse.query(query, {
      params: {
        startDate,
        endDate,
        host
      }
    }).toPromise();

    // Sort the results by total_risk_score in descending order
    result.sort((a, b) => b.total_risk_score - a.total_risk_score);

    // Calculate pagination
    const totalRows = result.length;
    const totalPages = Math.ceil(totalRows / perPage);
    const startIdx = (page - 1) * perPage;
    const endIdx = startIdx + perPage;

    // Paginate the sorted data
    const paginatedData = result.slice(startIdx, endIdx);

    // Parse action_recommendations JSON for each entry
    const parsedData = paginatedData.map((entry) => {
      let actionRecommendations = entry.action_recommendations;

      // Check if action_recommendations is a stringified JSON and parse it
      if (typeof actionRecommendations === 'string') {
        try {
          actionRecommendations = JSON.parse(actionRecommendations);
        } catch (err) {
          console.error('Error parsing action recommendations:', err);
          actionRecommendations = {};
        }
      }

      return {
        ...entry,
        action_recommendations: actionRecommendations
      };
    });

    // Return JSON response
    res.json({
      success: true,
      riskData: parsedData,
      totalRows: totalRows,
      totalPages: totalPages,
      currentPage: page,
      hostname: host,
      start_date: startDate,
      end_date: endDate
    });
  } catch (error) {
    console.error('Error in risk analysis API:', error);
    res.status(500).json({
      success: false,
      message: 'Internal Server Error',
      error: error.message
    });
  }
});

// Update the existing /updated_session_risk_analysis endpoint to serve HTML instead of rendering EJS
app.get('/updated_session_risk_analysis', isAuthenticated, (req, res) => {
  // Send the HTML file instead of rendering EJS
  res.sendFile(path.join(__dirname, 'public', 'html', 'updated_session_risk_analysis.html'));
});


// New API endpoint for risk analysis data
app.get('/api/risk-analysis', security.protect(), isAuthenticated, async (req, res) => {
  const name = req.username;
  const page = parseInt(req.query.page) || 1;
  const perPage = 10;

  // Input validation
  if (isNaN(page) || page < 1) {
    return res.status(400).json({
      success: false,
      message: 'Invalid page number'
    });
  }

  try {
    // Calculate LIMIT and OFFSET for pagination
    const limit = perPage;
    const offset = (page - 1) * perPage;

    // Fetch the hostname for the user using parameterized query
    const q2 = `SELECT hostname FROM users_new WHERE username = {name:String}`;
    const hostarray = await clickhouse.query(q2, {
      params: { name }
    }).toPromise();

    if (!hostarray.length) {
      return res.status(404).json({
        success: false,
        message: 'Hostname not found'
      });
    }

    const host = hostarray[0].hostname;

    // First, get the total count for pagination
    const countQuery = `
    SELECT COUNT(*) as total_sessions
    FROM (
      SELECT session_id
      FROM live_sessions_mv_new 
      WHERE hostname LIKE concat('%', {host:String}, '%')
      GROUP BY session_id
    )`;

    const countResult = await clickhouse.query(countQuery, {
      params: { host }
    }).toPromise();

    const totalRows = countResult[0].total_sessions;
    const totalPages = Math.ceil(totalRows / perPage);

    // Modified risk analysis query with pagination
    const riskAnalysisQuery = `
    WITH RiskFactors AS (
      SELECT
        t.session_id,
        (uniqExact(t.browser_id) > 1) * 3 AS browser_risk,
        (uniqExact(t.ip_address) > 1) * 3 AS ip_risk,
        (COUNT(CASE WHEN t.url LIKE '%login%' THEN 1 END) > 2) * 2 AS login_risk,
        ((COUNT(DISTINCT t.url) > 40 AND dateDiff('second', MIN(t.first_activity), MAX(t.last_activity)) < 180)) * 2 AS freq_risk,
        (COUNT(CASE WHEN t.user_agent LIKE '%bot%' THEN 1 END) > 0) * 2 AS bot_risk,
        (uniqExact(concat(rd.country, rd.region, rd.city)) > 1) * 3 AS geo_risk,
        -- New attack detection risks
        (COUNT(CASE WHEN t.url LIKE '%script%' OR t.url LIKE '%</script>%' OR t.url LIKE '%src%' THEN 1 END) > 0) * 8 AS xss_risk,
        (COUNT(CASE WHEN t.url LIKE '%redirect%' OR t.url LIKE '%target=%' THEN 1 END) > 0) * 8 AS redirect_risk,
        (COUNT(CASE WHEN t.url LIKE '%localhost%' OR t.url LIKE '%127.0.0.1%' THEN 1 END) > 0) * 8 AS ssrf_risk,
        (COUNT(CASE WHEN 
          t.url LIKE '% OR %=% OR %' OR
          t.url LIKE '%''%' OR 
          t.url LIKE '%1=1%' OR
          t.url LIKE '%1=2%' OR
          t.url LIKE '%--%' OR
          t.url LIKE '%DBMS_PIPE%' OR
          t.url LIKE '%WAITFOR%' OR
          t.url LIKE '%pg_sleep%' OR
          t.url LIKE '%SLEEP%' OR
          t.url LIKE '%BENCHMARK%' OR
          t.url LIKE '%CASE%WHEN%' OR
          t.url LIKE '%IF(%' OR
          t.url LIKE '%SELECT%FROM%' OR
          t.url LIKE '%AND (%' OR
          t.url LIKE '%OR (%' OR
          t.url LIKE '%)) OR%' OR
          t.url LIKE '%)) AND%'
        THEN 1 END) > 0) * 8 AS sqli_risk,
        COUNT(DISTINCT concat(t.url, toString(t.last_activity))) AS request_count,
        uniqExact(t.ip_address) AS distinct_ip_count,
        COUNT(CASE WHEN t.url LIKE '%login%' THEN 1 END) AS login_attempts,
        dateDiff('second', MIN(t.first_activity), MAX(t.last_activity)) AS session_duration
      FROM live_sessions_mv_new t
      LEFT JOIN region_details rd ON t.ip_address = rd.ip_address
      WHERE t.hostname LIKE concat('%', {host:String}, '%')
      GROUP BY t.session_id
    ),
    RiskScores AS (
      SELECT
        *,
        least(browser_risk + ip_risk + login_risk + freq_risk + bot_risk + geo_risk +
              xss_risk + redirect_risk + ssrf_risk + sqli_risk, 10) AS total_risk_score
      FROM RiskFactors
    )
    SELECT
      session_id,
      total_risk_score,
      browser_risk,
      login_risk,
      ip_risk,
      freq_risk,
      bot_risk,
      geo_risk,
      xss_risk,
      redirect_risk,
      ssrf_risk,
      sqli_risk,
      request_count,
      distinct_ip_count,
      login_attempts,
      session_duration
    FROM RiskScores
    ORDER BY total_risk_score DESC
    LIMIT ${limit} OFFSET ${offset}`;

    // Execute the risk analysis query with timeout handling
    let result = [];
    try {
      result = await new Promise((resolve, reject) => {
        const timeoutId = setTimeout(() => {
          reject(new Error('Risk analysis query timed out'));
        }, 60000); // 60 second timeout

        clickhouse.query(riskAnalysisQuery, { params: { host } })
          .toPromise()
          .then(data => {
            clearTimeout(timeoutId);
            resolve(data);
          })
          .catch(err => {
            clearTimeout(timeoutId);
            reject(err);
          });
      });
    } catch (err) {
      console.error('Risk analysis query error:', err);
      return res.status(500).json({
        success: false,
        message: 'Failed to load risk analysis data: ' + err.message
      });
    }

    if (result.length === 0) {
      return res.json({
        success: true,
        riskData: [],
        hostname: host,
        totalPages: totalPages,
        currentPage: page,
        aiScores: req.session.aiScores || {},
        bayesianScores: req.session.bayesianScores || {} // Added Bayesian scores support
      });
    }

    // Get session IDs for the URL changes query
    const sessionIds = result.map(row => `'${row.session_id}'`).join(',');

    // URL Changes Query - only for sessions in the current page
    const urlChangesQuery = `
    SELECT
      session_id,
      COUNT(*) AS url_change_count
    FROM (
      SELECT
        session_id,
        url,
        lagInFrame(url) OVER (PARTITION BY session_id ORDER BY last_activity) AS prev_url
      FROM live_sessions_mv_new
      WHERE session_id IN (${sessionIds})
    ) 
    WHERE (url != prev_url) OR (prev_url IS NULL)
    GROUP BY session_id`;

    // Execute URL changes query with fallback
    let urlChanges = [];
    try {
      urlChanges = await new Promise((resolve, reject) => {
        const timeoutId = setTimeout(() => {
          console.warn('URL changes query timed out, continuing with partial data');
          resolve([]); // Empty array on timeout
        }, 20000); // 20 second timeout

        clickhouse.query(urlChangesQuery)
          .toPromise()
          .then(data => {
            clearTimeout(timeoutId);
            resolve(data);
          })
          .catch(err => {
            clearTimeout(timeoutId);
            console.error('Error fetching URL changes:', err);
            resolve([]); // Empty array on error
          });
      });
    } catch (urlError) {
      console.error('Failed to get URL changes, continuing without them:', urlError);
    }

    // Create a map of session_id to url_change_count
    const urlChangeMap = {};
    urlChanges.forEach(row => {
      urlChangeMap[row.session_id] = row.url_change_count;
    });

    // Merge the URL change data with the risk analysis data
    const mergedResults = result.map(row => {
      return {
        ...row,
        url_change_count: urlChangeMap[row.session_id] || 0,
        action_recommendations: {}
      };
    });

    // Get AI scores and Bayesian scores from session
    const aiScores = req.session.aiScores || {};
    const bayesianScores = req.session.bayesianScores || {};
    
    // Debug logging to help troubleshoot
    console.log('API Debug - Session ID:', req.session.id);
    console.log('API Debug - AI Scores:', Object.keys(aiScores).length, 'entries');
    console.log('API Debug - Bayesian Scores:', Object.keys(bayesianScores).length, 'entries');
    console.log('API Debug - Sample Bayesian Scores:', bayesianScores);

    // Return JSON response with both AI and Bayesian scores
    res.json({
      success: true,
      riskData: mergedResults,
      hostname: host,
      totalPages: totalPages,
      currentPage: page,
      aiScores: aiScores,
      bayesianScores: bayesianScores // Added Bayesian scores to response
    });
  } catch (error) {
    console.error('Error in risk analysis API:', error);
    res.status(500).json({
      success: false,
      message: 'Internal Server Error: ' + error.message
    });
  }
});

// Update the existing risk-analysis route to serve the HTML file instead of rendering EJS
app.get('/risk-analysis', isAuthenticated, (req, res) => {
  // Send the HTML file instead of rendering EJS
  res.sendFile(path.join(__dirname, 'public', 'html', 'risk_analysis.html'));
});

// Updated POST route for terminating sessions to support AJAX requests
app.post('/risk-analysis', security.protect(), isAuthenticated, async (req, res) => {
  const { sessionId, return_url } = req.body;
  const username = req.username;
  try {
    // Basic validation
    if (!sessionId) {
      if (req.xhr || req.headers.accept.indexOf('json') !== -1) {
        return res.status(400).json({
          success: false,
          message: 'Session ID is required'
        });
      } else {
        req.flash('error', 'Session ID is required');
        return res.redirect(return_url || '/risk-analysis');
      }
    }

    // Verify the session exists
    if (!sessions[sessionId]) {
      if (req.xhr || req.headers.accept.indexOf('json') !== -1) {
        return res.status(400).json({
          success: false,
          message: 'Session not found or already terminated'
        });
      } else {
        req.flash('error', 'Session not found or already terminated');
        return res.redirect(return_url || '/risk-analysis');
      }
    }

    try {
      // First, verify session belongs to user's hostname
      const userQuery = `SELECT hostname FROM users_new WHERE username = '${username}'`;
      const userResult = await clickhouse.query(userQuery).toPromise();
      const userHostname = userResult[0].hostname;
      const sessionQuery = `
        SELECT hostname
        FROM live_sessions_mv_new
        WHERE session_id = '${sessionId}'
        LIMIT 1
      `;
      const sessionResult = await clickhouse.query(sessionQuery).toPromise();

      if (sessionResult.length === 0 || !sessionResult[0].hostname.includes(userHostname)) {
        if (req.xhr || req.headers.accept.indexOf('json') !== -1) {
          return res.status(403).json({
            success: false,
            message: 'Unauthorized to terminate this session'
          });
        } else {
          req.flash('error', 'Unauthorized to terminate this session');
          return res.redirect(return_url || '/risk-analysis');
        }
      }

      // Delete from both materialized views
      const deleteQueries = [
        `ALTER TABLE live_sessions_mv_new
         DELETE WHERE session_id = '${sessionId}'`,
        `ALTER TABLE live_security_headers_mv
         DELETE WHERE session_id = '${sessionId}'`
      ];

      // Execute both deletion queries
      for (const query of deleteQueries) {
        await clickhouse.query(query).toPromise();
      }

      // Terminate the session
      io.to(sessionId).emit('session-terminated', {
        message: 'Your session has been terminated by an administrator.',
        redirectUrl: 'https://google.com'
      });

      // Remove from sessions object
      delete sessions[sessionId];

      // Return success response based on request type
      if (req.xhr || req.headers.accept.indexOf('json') !== -1) {
        return res.json({
          success: true,
          message: 'Session terminated successfully'
        });
      } else {
        req.flash('success', 'Session terminated successfully');
        res.redirect(return_url || '/risk-analysis');
      }
    } catch (dbError) {
      console.error('Database error:', dbError);

      if (req.xhr || req.headers.accept.indexOf('json') !== -1) {
        return res.status(500).json({
          success: false,
          message: 'Failed to process session termination'
        });
      } else {
        req.flash('error', 'Failed to process session termination');
        res.redirect(return_url || '/risk-analysis');
      }
    }
  } catch (error) {
    console.error('Error terminating session:', error);

    if (req.xhr || req.headers.accept.indexOf('json') !== -1) {
      return res.status(500).json({
        success: false,
        message: 'Failed to terminate session'
      });
    } else {
      req.flash('error', 'Failed to terminate session');
      res.redirect(return_url || '/risk-analysis');
    }
  }
});

// Updated AI scoring route to support AJAX requests
app.post('/internal-algo-check', security.protect(), isAuthenticated, async (req, res) => {
  const { sessionId } = req.body;
  const username = req.username;

  try {
    // Verify session belongs to user's hostname
    const userQuery = `SELECT hostname FROM users_new WHERE username = '${username}'`;
    const userResult = await clickhouse.query(userQuery).toPromise();
    const userHostname = userResult[0].hostname;

    const sessionQuery = `
      SELECT hostname
      FROM live_sessions_mv_new
      WHERE session_id = '${sessionId}'
      LIMIT 1
    `;
    const sessionResult = await clickhouse.query(sessionQuery).toPromise();

    if (sessionResult.length === 0 || !sessionResult[0].hostname.includes(userHostname)) {
      if (req.xhr || req.headers.accept.indexOf('json') !== -1) {
        return res.status(403).json({
          success: false,
          message: 'Unauthorized to check this session'
        });
      } else {
        req.flash('error', 'Unauthorized to check this session');
        return res.redirect('/risk-analysis');
      }
    }

    // Get URLs for this session
    const urlQuery = `
      SELECT url
      FROM tracking10
      WHERE session_id LIKE '%${sessionId}%'
      ORDER BY timestamp;
    `;
    const urlResult = await clickhouse.query(urlQuery).toPromise();

    // Create temporary file with URLs
    const fs = require('fs').promises;
    const path = require('path');
    const os = require('os');
    const tempDir = os.tmpdir();
    const tempFile = path.join(tempDir, `session_${sessionId}.txt`);
    const urlContent = urlResult.map(row => row.url).join('\n');
    await fs.writeFile(tempFile, urlContent);

    // Log the tempFile contents for debugging
    console.log('TempFile contents:', urlContent);

    // Execute curl command with OpenRouter API
    const result = await new Promise((resolve, reject) => {
      const { exec } = require('child_process');
      const curlCommand = `curl https://openrouter.ai/api/v1/chat/completions \\
        -H "Content-Type: application/json" \\
        -d '{
          "model": "openai/gpt-3.5-turbo", 
          "messages": [
            {
              "role": "user", 
              "content": "Please review the session log in the journey.csv file and return ONLY a single number on scale 1-10 (with no other text, punctuation or explanation) indicating how risky this session is likely to be a bot or malicious session. A score of 1 means very safe, and 10 means definitely malicious.
              \\n\\nWhen evaluating, consider common attack patterns such as SQL injection, XSS attacks, path traversal, suspicious parameters, automated scanning patterns, and other potentially malicious behaviors in URLs. Also consider abnormal navigation patterns like multiple URLs loaded in the same second which may indicate automation.
              \\n\\nBe thorough in your security analysis and err on the side of caution for potential security threats."
            }
          ],
          "journey": "${tempFile.replace(/\\/g, '\\\\')}"
        }'`;

      exec(curlCommand, { shell: 'bash', maxBuffer: 1024 * 1024 }, async (error, stdout, stderr) => {
        try {
          await fs.unlink(tempFile);  // Clean up temp file
        } catch (cleanupError) {
          console.error('Cleanup error:', cleanupError);
        }

        if (error) {
          console.error('Curl error:', error);
          reject(error);
          return;
        }

        if (stderr) {
          console.error('Curl stderr:', stderr);
        }

        console.log('Raw curl response length:', stdout.length);
        console.log('Raw curl response:', JSON.stringify(stdout));

        try {
          const response = JSON.parse(stdout);
          console.log('Parsed response:', response);

          // Extract the risk score from the response
          const riskScore = response.choices &&
            response.choices[0] &&
            response.choices[0].message &&
            response.choices[0].message.content ?
            response.choices[0].message.content.trim() : null;

          const result = { riskScore };
          console.log('Extracted result:', result);
          resolve(result);
        } catch (parseError) {
          console.error('Parse error:', parseError, 'for stdout:', stdout);
          reject(parseError);
        }
      });
    });

    // Store the result in the session for display
    req.session.aiScores = req.session.aiScores || {};
    req.session.aiScores[sessionId] = result.riskScore;

    // Return response based on request type
    if (req.xhr || req.headers.accept.indexOf('json') !== -1) {
      return res.json({
        success: true,
        message: `AI Risk Score for session ${sessionId}: ${result.riskScore}/10`,
        score: result.riskScore
      });
    } else {
      // Add flash message with the score
      req.flash('success', `AI Risk Score for session ${sessionId}: ${result.riskScore}/10`);

      // Redirect back to the appropriate page based on referer
      const referer = req.headers.referer || '/risk-analysis';
      if (referer.includes('attack-detection')) {
        return res.redirect('/attack-detection');
      } else {
        return res.redirect('/risk-analysis');
      }
    }
  } catch (error) {
    console.error('Error in internal algo check:', error);

    if (req.xhr || req.headers.accept.indexOf('json') !== -1) {
      return res.status(500).json({
        success: false,
        message: `Failed to process internal algorithm check: ${error.message}`
      });
    } else {
      req.flash('error', `Failed to process internal algorithm check: ${error.message}`);
      return res.redirect('/risk-analysis');
    }
  }
});

app.post('/bayesian-ai-check', security.protect(), isAuthenticated, async (req, res) => {
  const { sessionId } = req.body;
  const username = req.username;

  try {
    // Verify session belongs to user's hostname
    const userQuery = `SELECT hostname FROM users_new WHERE username = '${username}'`;
    const userResult = await clickhouse.query(userQuery).toPromise();
    const userHostname = userResult[0].hostname;

    const sessionQuery = `
      SELECT hostname
      FROM live_sessions_mv_new
      WHERE session_id = '${sessionId}'
      LIMIT 1
    `;
    const sessionResult = await clickhouse.query(sessionQuery).toPromise();

    if (sessionResult.length === 0 || !sessionResult[0].hostname.includes(userHostname)) {
      if (req.xhr || req.headers.accept.indexOf('json') !== -1) {
        return res.status(403).json({
          success: false,
          message: 'Unauthorized to check this session'
        });
      } else {
        req.flash('error', 'Unauthorized to check this session');
        return res.redirect('/risk-analysis');
      }
    }

    // Get session data for this session (similar to session journey)
    const sessionDataQuery = `
      SELECT 
        session_id,
        url,
        ip_address,
        user_agent,
        browser_id,
        timestamp,
        clickdata
      FROM tracking10
      WHERE session_id LIKE '%${sessionId}%'
      ORDER BY timestamp;
    `;
    const sessionData = await clickhouse.query(sessionDataQuery).toPromise();

    // Create temporary CSV file with session data
    const fs = require('fs').promises;
    const path = require('path');
    const os = require('os');
    const tempDir = os.tmpdir();
    const tempFile = path.join(tempDir, `bayesian_session_${sessionId}.csv`);
    
    // Create CSV content with proper headers matching session journey format
    const csvHeader = 'Date,Time,Time Spent (seconds),URL Visited,Clicked Data\n';
    const csvRows = sessionData.map((row, index) => {
      // Convert timestamp to date and time
      const date = new Date(row.timestamp);
      const dateStr = date.toISOString().split('T')[0]; // YYYY-MM-DD
      const timeStr = date.toTimeString().split(' ')[0]; // HH:MM:SS
      
      // Calculate time spent (same logic as session journey HTML)
      let timeSpent = '-';
      if (index < sessionData.length - 1) {
        const currentTime = new Date(row.timestamp);
        const nextTime = new Date(sessionData[index + 1].timestamp);
        const timeDiff = Math.round((nextTime - currentTime) / 1000);
        timeSpent = timeDiff.toString();
      }
      // Last row always gets '-'
      
      // Escape CSV values properly - handle empty clickdata like session journey
      const url = `"${row.url.replace(/"/g, '""')}"`;
      
      // Handle clickdata - if empty or null, use empty quotes
      let clickedData = '""';
      if (row.clickdata && row.clickdata.trim() !== '' && row.clickdata.trim() !== '""') {
        // Only escape if there's actual content
        clickedData = `"${row.clickdata.replace(/"/g, '""')}"`;
      }
      
      return `${dateStr},${timeStr},${timeSpent},${url},${clickedData}`;
    });
    
    const csvContent = csvHeader + csvRows.join('\n');
    await fs.writeFile(tempFile, csvContent);

    // Log the tempFile contents for debugging
    console.log('Bayesian TempFile contents:', csvContent);

    // Execute curl command with Bayesian AI endpoint
    const result = await new Promise((resolve, reject) => {
      const { exec } = require('child_process');
      const curlCommand = `curl -X POST http://139.59.90.156:8000/analyze -F "csv_file=@${tempFile}"`;

      exec(curlCommand, { shell: 'bash', maxBuffer: 1024 * 1024 }, async (error, stdout, stderr) => {
        try {
          await fs.unlink(tempFile);  // Clean up temp file
        } catch (cleanupError) {
          console.error('Cleanup error:', cleanupError);
        }

        if (error) {
          console.error('Bayesian curl error:', error);
          reject(error);
          return;
        }

        if (stderr) {
          console.error('Bayesian curl stderr:', stderr);
        }

        console.log('Raw Bayesian curl response length:', stdout.length);
        console.log('Raw Bayesian curl response:', JSON.stringify(stdout));

        try {
          const response = JSON.parse(stdout);
          console.log('Parsed Bayesian response:', response);

          // Extract the attack probability and convert to percentage
          const attackProbability = response.risk_assessment && 
            response.risk_assessment.attack_probability !== undefined ?
            (response.risk_assessment.attack_probability * 100).toFixed(2) : null;

          // Also extract additional useful information
          const riskLevel = response.risk_assessment?.risk_level || 'UNKNOWN';
          const confidence = response.risk_assessment?.confidence || 0;
          const recommendation = response.risk_assessment?.recommendation || 'No recommendation available';

          const result = { 
            attackProbability,
            riskLevel,
            confidence: (confidence * 100).toFixed(1),
            recommendation
          };
          console.log('Extracted Bayesian result:', result);
          resolve(result);
        } catch (parseError) {
          console.error('Bayesian parse error:', parseError, 'for stdout:', stdout);
          reject(parseError);
        }
      });
    });

    // Store the result in the session for display
    req.session.bayesianScores = req.session.bayesianScores || {};
    req.session.bayesianScores[sessionId] = result.attackProbability;

    // Return response based on request type
    if (req.xhr || req.headers.accept.indexOf('json') !== -1) {
      return res.json({
        success: true,
        message: `Bayesian AI Analysis Complete - Attack Probability: ${result.attackProbability}% (Risk Level: ${result.riskLevel})`,
        score: result.attackProbability,
        riskLevel: result.riskLevel,
        confidence: result.confidence,
        recommendation: result.recommendation
      });
    } else {
      // Add flash message with the score
      req.flash('success', `Bayesian AI Score for session ${sessionId}: ${result.attackProbability}% (Risk: ${result.riskLevel})`);

      // Redirect back to the appropriate page based on referer
      const referer = req.headers.referer || '/risk-analysis';
      if (referer.includes('attack-detection')) {
        return res.redirect('/attack-detection');
      } else {
        return res.redirect('/risk-analysis');
      }
    }
  } catch (error) {
    console.error('Error in Bayesian AI check:', error);

    if (req.xhr || req.headers.accept.indexOf('json') !== -1) {
      return res.status(500).json({
        success: false,
        message: `Failed to process Bayesian AI check: ${error.message}`
      });
    } else {
      req.flash('error', `Failed to process Bayesian AI check: ${error.message}`);
      return res.redirect('/risk-analysis');
    }
  }
});

// Add new API endpoint for attack detection data
// app.get('/api/attack-detection', security.protect(), isAuthenticated, async (req, res) => {
//   const name = req.username;
//   const page = parseInt(req.query.page) || 1;
//   const perPage = 10;

//   // Input validation
//   if (isNaN(page) || page < 1) {
//     return res.status(400).json({
//       success: false,
//       message: 'Invalid page number'
//     });
//   }

//   try {
//     // Fetch the hostname for the user using parameterized query
//     const q2 = `SELECT hostname FROM users_new WHERE username = {name:String}`;
//     const hostarray = await clickhouse.query(q2, {
//       params: { name }
//     }).toPromise();

//     if (!hostarray.length) {
//       return res.status(404).json({
//         success: false,
//         message: 'Hostname not found'
//       });
//     }

//     const host = hostarray[0].hostname;

//     // This is a complex query with multiple SQL patterns that are not easily parameterized
//     // We'll parameterize the hostname pattern and leave the static patterns as is
//     const attackDetectionQuery = `
//           WITH
//           t_agg AS (
//             SELECT
//               session_id,
//               min(timestamp) AS first_activity,
//               max(timestamp) AS last_activity,
//               dateDiff('second', min(timestamp), max(timestamp)) AS duration_s,
//               uniqExact(ip_address) AS ip_count,
//               uniqExact(browser_id) AS browser_count,
//               countIf(url LIKE '%/login%' OR url LIKE '%/signin%') AS login_hits,
//               countIf(url ILIKE '%UNION SELECT%' OR url ILIKE '%UNION ALL SELECT%'
//                   OR url ILIKE '%; SELECT%' OR url ILIKE '%information_schema%') AS sqli_hits,
//               countIf(url LIKE '%redirect%' AND url LIKE '%http%') AS redirect_hits,
//               countIf(url LIKE '%upload%' AND match(url, '\\\\.(php|jsp|exe)')) AS upload_hits,
//               count() AS request_count
//             FROM live_sessions_mv_new
//             WHERE hostname LIKE concat('%', {host:String}, '%')
//             GROUP BY session_id
//           ),
//           sh AS (
//             SELECT
//               session_id,
//               max(dom_changes_count)                     AS dom_changes,
//               argMax(dom_added_elements, timestamp)      AS added,
//               argMax(dom_removed_elements, timestamp)    AS removed,
//               argMax(dom_modified_attributes, timestamp) AS modified,
//               argMax(dom_sensitive_changes, timestamp)   AS sensitive,
//               argMax(dom_security_violations, timestamp) AS violations,
//               max(security_is_framed)                    AS is_framed
//             FROM live_security_headers_mv
//             WHERE session_id IN (SELECT session_id FROM t_agg)
//             GROUP BY session_id
//           ),
//           m AS (
//             SELECT
//               t.*,
//               sh.dom_changes                                    AS dom_changes_count,
//               sh.violations NOT IN ('', '[]')                   AS has_violations,
//               sh.sensitive  NOT IN ('', '[]')                   AS has_sensitive,
//               sh.violations                                     AS violations_raw,
//               sh.sensitive                                      AS sensitive_raw,
//               sh.is_framed                                      AS is_framed,
//               match(sh.added,   '"type":"(SCRIPT|IFRAME|OBJECT|EMBED)"') AS added_exec,
//               match(sh.added,   '"type":"(FORM|INPUT|BUTTON)"')          AS added_form,
//               match(sh.removed, '"type":"(FORM|INPUT|BUTTON)"')          AS removed_form,
//               match(sh.modified, '"attribute":"(src|href|integrity|sandbox)"') AS sens_attr,
//               match(sh.modified, '"attribute":"action"')
//                 AND match(sh.modified, '"attribute":"(method|enctype)"')       AS form_retarget
//             FROM t_agg t
//             LEFT JOIN sh ON t.session_id = sh.session_id
//           ),
//           scored AS (
//             SELECT *,
//               (ip_count > 1 OR browser_count > 1) * 4                     AS session_hijack_attack,
//               (login_hits > 10) * 5                                       AS credential_stuffing_attack,
//               (sqli_hits > 0) * 8                                         AS sqli_attack,
//               (redirect_hits > 0) * 5                                     AS redirect_attack,
//               (upload_hits > 0 OR violations_raw LIKE '%file upload%') * 5 AS file_upload_attack,
//               (violations_raw LIKE '%script injection%'
//                 OR (has_sensitive AND sensitive_raw LIKE '%"SCRIPT%')) * 8 AS xss_attack,
//               (is_framed = 1 AND (added_form OR form_retarget)) * 4       AS clickjacking_attack,
//               added_exec * 8                                              AS dynamic_script_risk,
//               form_retarget * 6                                           AS form_mod_risk,
//               (added_form AND removed_form) * 4                           AS element_cycling_risk,
//               sens_attr * 5                                               AS sensitive_attr_risk,
//               (duration_s > 10 AND sens_attr) * 6                         AS post_load_risk,
//               multiIf(
//                 (has_sensitive OR has_violations) AND dom_changes_count > 50 AND duration_s < 5, 8,
//                 added_form AND dom_changes_count > 30, 6,
//                 0)                                                        AS dom_behavior_risk,
//               has_violations                                              AS security_violations_count
//             FROM m
//           )
//           SELECT *,
//             multiIf(
//               xss_attack > 0 OR sqli_attack > 0 OR dom_behavior_risk >= 8,                   10,
//               dynamic_script_risk > 0 OR form_mod_risk > 0,                                   9,
//               (session_hijack_attack > 0 AND credential_stuffing_attack > 0)
//                 OR (file_upload_attack > 0 AND sensitive_attr_risk > 0),                      8,
//               post_load_risk > 0,                                                             7,
//               dom_behavior_risk >= 6 OR session_hijack_attack > 0
//                 OR credential_stuffing_attack > 0,                                            6,
//               clickjacking_attack > 0 OR redirect_attack > 0 OR element_cycling_risk > 0,     5,
//               security_violations_count > 0 OR sensitive_attr_risk > 0,                       4,
//               0) AS total_attack_score,
//             multiIf(
//               total_attack_score >= 9, map('Block', 100, 'Challenge', 0,  'Monitor', 0),
//               total_attack_score >= 8, map('Block', 80,  'Challenge', 20, 'Monitor', 0),
//               total_attack_score >= 6, map('Block', 60,  'Challenge', 30, 'Monitor', 10),
//               total_attack_score >= 4, map('Block', 30,  'Challenge', 50, 'Monitor', 20),
//                                       map('Block', 0,   'Challenge', 20, 'Monitor', 80)
//             ) AS recommended_actions
//           FROM scored
//           ORDER BY total_attack_score DESC`;

//     const result = await clickhouse.query(attackDetectionQuery, {
//       params: { host }
//     }).toPromise();

//     // Deduplicate sessions by keeping only the first occurrence of each session_id
//     const seenSessions = new Set();
//     const uniqueResults = result.filter(row => {
//       if (!seenSessions.has(row.session_id)) {
//         seenSessions.add(row.session_id);
//         return true;
//       }
//       return false;
//     });

//     // Calculate pagination
//     const totalRows = uniqueResults.length;
//     const totalPages = Math.ceil(totalRows / perPage);
//     const startIdx = (page - 1) * perPage;
//     const endIdx = startIdx + perPage;

//     // Get paginated data from deduplicated results
//     const paginatedData = uniqueResults.slice(startIdx, endIdx);

//     // Return JSON response
//     res.json({
//       success: true,
//       attackData: paginatedData,
//       hostname: host,
//       totalPages: totalPages,
//       currentPage: page,
//       aiScores: req.session.aiScores || {}
//     });
//   } catch (error) {
//     console.error('Error in attack detection API:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Failed to load attack detection data: ' + error.message
//     });
//   }
// });

// ============================================================================
// /api/attack-detection  (pixel v2)
//
// Signals come from security_events + session_behavior (new tables) plus the
// existing live_sessions_mv_new / live_security_headers_mv views.
//
// "Known" origins = script_allowlist  +  origins seen in at least
// BASELINE_MIN_SESSIONS sessions between 7 days and 1 day ago. The last 24 h
// are excluded so a site-wide injected skimmer stays "novel" for a day.
//
// Score = strongest signal + half of all other signals, capped at 10.
// Output keeps every column the current UI reads, plus new ones.
// ============================================================================

// ============================================================================
// /api/attack-detection  (pixel v2)
//
// Signals come from security_events + session_behavior (new tables) plus the
// existing live_sessions_mv_new / live_security_headers_mv views.
//
// "Known" origins = script_allowlist  +  origins seen in at least
// BASELINE_MIN_SESSIONS sessions between 7 days and 1 day ago. The last 24 h
// are excluded so a site-wide injected skimmer stays "novel" for a day.
//
// Score = strongest signal + half of all other signals, capped at 10.
// Output keeps every column the current UI reads, plus new ones.
// ============================================================================

const BASELINE_DAYS = 7;
const BASELINE_EXCLUDE_DAYS = 1;
const BASELINE_MIN_SESSIONS = 3;

const attackDetectionQuery = `
WITH
sess AS (
  SELECT
    session_id,
    min(timestamp) AS first_activity,
    max(timestamp) AS last_activity,
    uniqExact(ip_address) AS ip_count,
    uniqExact(browser_id) AS browser_count,
    countIf(url ILIKE '%/login%' OR url ILIKE '%/signin%') AS login_hits,
    countIf(url ILIKE '%UNION SELECT%' OR url ILIKE '%UNION ALL SELECT%'
         OR url ILIKE '%; SELECT%' OR url ILIKE '%information_schema%') AS sqli_hits,
    countIf(url ILIKE '%redirect%' AND url ILIKE '%=http%') AS redirect_hits,
    countIf(url ILIKE '%upload%' AND match(url, '\\\\.(php|jsp|exe)')) AS upload_hits,
    count() AS request_count
  FROM live_sessions_mv_new
  WHERE hostname LIKE concat('%', {host:String}, '%')
  GROUP BY session_id
),

hdr AS (
  SELECT
    session_id,
    max(dom_changes_count)  AS dom_changes,
    max(security_is_framed) AS framed,
    max(timestamp)          AS hdr_last
  FROM live_security_headers_mv
  WHERE session_id IN (SELECT session_id FROM sess)
  GROUP BY session_id
),

known AS (
  SELECT origin
  FROM security_events
  WHERE hostname LIKE concat('%', {host:String}, '%')
    AND origin != ''
    AND timestamp >= now() - toIntervalDay({baselineDays:UInt32})
    AND timestamp <  now() - toIntervalDay({excludeDays:UInt32})
  GROUP BY origin
  HAVING uniqExact(session_id) >= {minSessions:UInt32}
  UNION DISTINCT
  SELECT origin
  FROM script_allowlist FINAL
  WHERE hostname LIKE concat('%', {host:String}, '%')
     OR {host:String} LIKE concat('%', hostname, '%')
),

ev AS (
  SELECT
    session_id,
    countIf(event_type = 'script_added'   AND is_third_party = 1 AND origin NOT IN (SELECT origin FROM known)) AS novel_script_added,
    countIf(event_type = 'script_present' AND is_third_party = 1 AND origin NOT IN (SELECT origin FROM known)) AS novel_script_present,
    countIf(event_type = 'script_added'   AND origin = 'inline')                                               AS inline_scripts_added,
    countIf(event_type IN ('iframe_added', 'object_added')
            AND (is_third_party = 1 OR origin IN ('srcdoc', 'about:', 'data:', 'blob:', 'javascript:'))
            AND origin NOT IN (SELECT origin FROM known))                                                      AS novel_iframe_added,
    countIf(event_type = 'network_request' AND origin NOT IN (SELECT origin FROM known))                       AS novel_network,
    countIf(event_type = 'network_request' AND method != 'GET' AND origin NOT IN (SELECT origin FROM known))   AS novel_network_send,
    countIf(event_type = 'image_beacon'    AND origin NOT IN (SELECT origin FROM known))                       AS novel_image_beacon,
    countIf(event_type = 'form_submit'     AND is_third_party = 1)                                             AS xorigin_submit,
    countIf(event_type = 'form_submit'     AND is_third_party = 1
            AND JSONExtractUInt(detail, 'sensitive') = 1)                                                      AS xorigin_sensitive_submit,
    countIf(event_type = 'attr_change' AND attr_name IN ('action', 'formaction') AND is_third_party = 1)       AS form_retarget,
    countIf(event_type = 'attr_change' AND attr_name IN ('src', 'href', 'data', 'srcdoc', 'integrity', 'sandbox')
            AND (is_third_party = 1 OR attr_name IN ('integrity', 'sandbox', 'srcdoc'))
            AND origin NOT IN (SELECT origin FROM known))                                                      AS sens_attr,
    countIf(event_type IN ('inline_handler', 'javascript_url'))                                                AS inline_handlers,
    countIf(event_type = 'csp_violation')                                                                      AS csp_violations,
    countIf(event_type IN ('base_injected', 'meta_refresh_injected'))                                          AS nav_hijack,
    countIf(event_type = 'form_added')                                                                         AS forms_added,
    countIf(event_type = 'element_removed' AND element_type = 'FORM')                                          AS forms_removed,
    countIf(event_type = 'password_field_added' OR (event_type = 'form_added'
            AND JSONExtractUInt(detail, 'has_password') = 1))                                                  AS password_added,
    countIf(event_type = 'prehooked_api' AND origin NOT IN (SELECT origin FROM known))                       AS novel_prehook,
    maxIf(JSONExtractUInt(detail, 'async') + JSONExtractUInt(detail, 'injected')
          + (JSONExtractUInt(detail, 'third_party_before') > 0), event_type = 'pixel_loaded') > 0            AS pixel_coverage_warning,
    groupUniqArrayIf(10)(origin, is_third_party = 1 AND origin NOT IN (SELECT origin FROM known))             AS novel_origins
  FROM security_events
  WHERE session_id IN (SELECT session_id FROM sess)
  GROUP BY session_id
),

bh AS (
  SELECT
    session_id,
    max(web_driver)                AS webdriver,
    max(headless_ua)               AS headless,
    max(chrome_no_obj)             AS chrome_no_obj,
    max(desktop_chrome_no_plugins) AS no_plugins,
    max(no_languages)              AS no_languages,
    max(zero_outer)                AS zero_outer,
    max(pointer_events + key_events + scroll_events + touch_events) AS interactions,
    max(time_on_page_ms)           AS time_on_page_ms,
    count()                        AS beacons
  FROM session_behavior
  WHERE session_id IN (SELECT session_id FROM sess)
  GROUP BY session_id
),

joined AS (
  SELECT
    s.session_id                 AS session_id,
    s.first_activity             AS first_activity,
    greatest(s.last_activity, h.hdr_last) AS last_activity,
    s.ip_count                   AS ip_count,
    s.browser_count              AS browser_count,
    s.login_hits                 AS login_hits,
    s.sqli_hits                  AS sqli_hits,
    s.redirect_hits              AS redirect_hits,
    s.upload_hits                AS upload_hits,
    s.request_count              AS request_count,
    h.dom_changes                AS dom_changes_count,
    h.framed                     AS framed,
    e.novel_script_added         AS novel_script_added,
    e.novel_script_present       AS novel_script_present,
    e.inline_scripts_added       AS inline_scripts_added,
    e.novel_iframe_added         AS novel_iframe_added,
    e.novel_network              AS novel_network,
    e.novel_network_send         AS novel_network_send,
    e.novel_image_beacon         AS novel_image_beacon,
    e.xorigin_submit             AS xorigin_submit,
    e.xorigin_sensitive_submit   AS xorigin_sensitive_submit,
    e.form_retarget              AS form_retarget,
    e.sens_attr                  AS sens_attr,
    e.inline_handlers            AS inline_handlers,
    e.csp_violations             AS csp_violations,
    e.nav_hijack                 AS nav_hijack,
    e.forms_added                AS forms_added,
    e.forms_removed              AS forms_removed,
    e.password_added             AS password_added,
    e.novel_origins              AS novel_origins,
    e.novel_prehook              AS novel_prehook,
    e.pixel_coverage_warning     AS pixel_coverage_warning,
    b.webdriver                  AS webdriver,
    b.headless                   AS headless,
    b.chrome_no_obj              AS chrome_no_obj,
    b.no_plugins                 AS no_plugins,
    b.no_languages               AS no_languages,
    b.zero_outer                 AS zero_outer,
    b.interactions               AS interactions,
    b.time_on_page_ms            AS time_on_page_ms,
    b.beacons                    AS beacons
  FROM sess AS s
  LEFT JOIN hdr AS h ON s.session_id = h.session_id
  LEFT JOIN ev  AS e ON s.session_id = e.session_id
  LEFT JOIN bh  AS b ON s.session_id = b.session_id
),

scored AS (
  SELECT
    *,
    -- server-side / URL signals (WAF is the better place for these)
    (sqli_hits > 0) * 8                                    AS sqli_attack,
    (redirect_hits > 0) * 5                                AS redirect_attack,
    (upload_hits > 0) * 5                                  AS file_upload_attack,
    (login_hits > 10) * 5                                  AS credential_stuffing_attack,
    (ip_count > 1 OR browser_count > 1) * 4                AS session_hijack_attack,

    -- client-side attack signals
    greatest((csp_violations > 0) * 8, (inline_handlers > 0) * 6)                            AS xss_attack,
    greatest((novel_script_added > 0) * 8, (novel_iframe_added > 0) * 6)                     AS dynamic_script_risk,
    greatest((novel_image_beacon > 0) * 8, (novel_network_send > 0) * 7)                     AS exfil_risk,
    -- weak: unseen vendor in the page HTML, or a plain GET to an unseen origin.
    -- Informational only (never raises the score above Monitor on its own).
    ((novel_script_present > 0) OR (novel_network > 0 AND novel_network_send = 0)) * 2      AS new_vendor_risk,
    greatest((xorigin_sensitive_submit > 0) * 9, (form_retarget > 0) * 7,
             (xorigin_submit > 0) * 3)                                                       AS form_mod_risk,
    greatest((framed = 1 AND (password_added > 0 OR forms_added > 0)) * 6, (framed = 1) * 2) AS clickjacking_attack,
    (forms_added > 0 AND forms_removed > 0) * 4                                              AS element_cycling_risk,
    (sens_attr > 0) * 5                                                                      AS sensitive_attr_risk,
    (nav_hijack > 0) * 7                                                                     AS post_load_risk,
    (novel_prehook > 0) * 5                                                                  AS api_tamper_risk,

    -- automation
    greatest(
      (webdriver = 1 OR headless = 1) * 6,
      (zero_outer + chrome_no_obj + no_plugins + no_languages >= 2) * 5,
      (beacons > 0 AND interactions = 0 AND request_count >= 5) * 3
    )                                                                                        AS bot_risk,

    csp_violations + inline_handlers + novel_script_added + novel_iframe_added + form_retarget
      + nav_hijack + xorigin_sensitive_submit + novel_image_beacon                           AS security_violations_count
  FROM joined
),

ranked AS (
  SELECT
    *,
    exfil_risk AS dom_behavior_risk,   -- legacy column name used by the UI
    [sqli_attack, redirect_attack, file_upload_attack, credential_stuffing_attack, session_hijack_attack,
     xss_attack, dynamic_script_risk, exfil_risk, form_mod_risk, clickjacking_attack,
     element_cycling_risk, sensitive_attr_risk, post_load_risk, bot_risk, api_tamper_risk,
     new_vendor_risk] AS signals,
    toUInt8(least(10, round(arrayMax(signals) + 0.5 * (arraySum(signals) - arrayMax(signals))))) AS total_attack_score
  FROM scored
)

SELECT
  session_id,
  first_activity,
  last_activity,
  dom_changes_count,
  session_hijack_attack,
  clickjacking_attack,
  credential_stuffing_attack,
  file_upload_attack,
  xss_attack,
  sqli_attack,
  redirect_attack,
  dynamic_script_risk,
  form_mod_risk,
  dom_behavior_risk,
  element_cycling_risk,
  sensitive_attr_risk,
  post_load_risk,
  exfil_risk,
  bot_risk,
  api_tamper_risk,
  new_vendor_risk,
  pixel_coverage_warning,
  security_violations_count,
  request_count,
  novel_origins,
  inline_scripts_added,
  total_attack_score,
  multiIf(
    total_attack_score >= 9, map('Block', 100, 'Challenge', 0,  'Monitor', 0),
    total_attack_score >= 8, map('Block', 80,  'Challenge', 20, 'Monitor', 0),
    total_attack_score >= 6, map('Block', 60,  'Challenge', 30, 'Monitor', 10),
    total_attack_score >= 4, map('Block', 30,  'Challenge', 50, 'Monitor', 20),
                             map('Block', 0,   'Challenge', 20, 'Monitor', 80)
  ) AS recommended_actions
FROM ranked
ORDER BY total_attack_score DESC, last_activity DESC`;

app.get('/api/attack-detection', security.protect(), isAuthenticated, async (req, res) => {
  const name = req.username;
  const page = parseInt(req.query.page) || 1;
  const perPage = 10;

  if (isNaN(page) || page < 1) {
    return res.status(400).json({ success: false, message: 'Invalid page number' });
  }

  try {
    const hostarray = await clickhouse.query(
      'SELECT hostname FROM users_new WHERE username = {name:String}',
      { params: { name } }
    ).toPromise();

    if (!hostarray.length) {
      return res.status(404).json({ success: false, message: 'Hostname not found' });
    }
    const host = hostarray[0].hostname;

    const result = await clickhouse.query(attackDetectionQuery, {
      params: {
        host,
        baselineDays: BASELINE_DAYS,
        excludeDays: BASELINE_EXCLUDE_DAYS,
        minSessions: BASELINE_MIN_SESSIONS
      }
    }).toPromise();

    const totalRows = result.length;
    const totalPages = Math.ceil(totalRows / perPage);
    const startIdx = (page - 1) * perPage;

    res.json({
      success: true,
      attackData: result.slice(startIdx, startIdx + perPage),
      hostname: host,
      totalPages,
      currentPage: page,
      aiScores: req.session.aiScores || {}
    });
  } catch (error) {
    console.error('Error in attack detection API:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to load attack detection data: ' + error.message
    });
  }
});

// Update the existing attack-detection endpoint to serve HTML instead of rendering EJS
app.get('/attack-detection', isAuthenticated, (req, res) => {
  // Send the HTML file instead of rendering EJS
  res.sendFile(path.join(__dirname, 'public', 'html', 'attack_detection.html'));
});


// New API endpoint for fingerprint analysis data
app.get('/api/fingerprint-analysis', security.protect(), isAuthenticated, async (req, res) => {
  const fingerprintId = req.query.fingerprint_id || '';
  const page = parseInt(req.query.page) || 1;
  const perPage = 10;
  const startDate = req.query.start_date || '2024-12-01';
  const endDate = req.query.end_date || '2025-12-31';

  // Input validation
  if (!isValidDate(startDate) || !isValidDate(endDate)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid date format'
    });
  }

  if (isNaN(page) || page < 1) {
    return res.status(400).json({
      success: false,
      message: 'Invalid page number'
    });
  }

  if (fingerprintId && fingerprintId.length > 100) {
    return res.status(400).json({
      success: false,
      message: 'Fingerprint ID too long'
    });
  }

  try {
    let query;
    let result;

    if (fingerprintId) {
      // Query when fingerprint ID is provided with parameters
      query = `
        SELECT DISTINCT
          fingerprint_id,
          session_id,
          hostname,
          MIN(timestamp) as first_seen,
          MAX(timestamp) as last_seen
        FROM tracking10
        WHERE fingerprint_id = {fingerprintId:String}
          AND timestamp BETWEEN {startDate:String} AND {endDate:String}
        GROUP BY fingerprint_id, session_id, hostname
        ORDER BY last_seen DESC
      `;

      result = await clickhouse.query(query, {
        params: {
          fingerprintId,
          startDate,
          endDate
        }
      }).toPromise();
    } else {
      // Query to show all distinct fingerprint IDs with parameters
      query = `
        SELECT
          fingerprint_id,
          count(DISTINCT session_id) as session_count,
          count(DISTINCT hostname) as domain_count,
          MIN(timestamp) as first_seen,
          MAX(timestamp) as last_seen
        FROM tracking10
        WHERE timestamp BETWEEN {startDate:String} AND {endDate:String}
          AND fingerprint_id != ''
        GROUP BY fingerprint_id
        ORDER BY last_seen DESC
      `;

      result = await clickhouse.query(query, {
        params: {
          startDate,
          endDate
        }
      }).toPromise();
    }

    // Pagination
    const totalRows = result.length;
    const totalPages = Math.ceil(totalRows / perPage);
    const startIdx = (page - 1) * perPage;
    const endIdx = startIdx + perPage;
    const paginatedData = result.slice(startIdx, endIdx);

    // Format dates
    const formattedData = paginatedData.map(row => ({
      ...row,
      first_seen: new Date(row.first_seen).toLocaleString(),
      last_seen: new Date(row.last_seen).toLocaleString()
    }));

    // Return JSON response
    res.json({
      success: true,
      fingerprintData: formattedData,
      totalRows: totalRows,
      totalPages: totalPages,
      currentPage: page,
      fingerprint_id: fingerprintId,
      start_date: startDate,
      end_date: endDate
    });

  } catch (error) {
    console.error('Error in fingerprint analysis API:', error);
    res.status(500).json({
      success: false,
      message: 'Internal Server Error',
      error: error.message
    });
  }
});

// Update the existing /fingerprint-analysis endpoint to serve HTML instead of rendering EJS
app.get('/fingerprint-analysis', isAuthenticated, (req, res) => {
  // Send the HTML file instead of rendering EJS
  res.sendFile(path.join(__dirname, 'public', 'html', 'fingerprint_analysis.html'));
});

// Malicious Files Detection API Endpoint
app.get('/api/malicious-files', security.protect(), isAuthenticated, async (req, res) => {
  // Get parameters with defaults based on today's date
  const page = parseInt(req.query.page) || 1;
  const perPage = 10;
  
  // Calculate default date range: today-2 to today+1 (3 days total)
  const today = new Date();
  const defaultStartDate = new Date(today);
  defaultStartDate.setDate(today.getDate() - 2);
  const defaultEndDate = new Date(today);
  defaultEndDate.setDate(today.getDate() + 1);
  
  // Format dates as YYYY-MM-DD
  const formatDate = (date) => {
    return date.toISOString().split('T')[0];
  };
  
  const startDate = req.query.start_date || formatDate(defaultStartDate);
  const endDate = req.query.end_date || formatDate(defaultEndDate);
  
  // Validate input
  if (!isValidDate(startDate) || !isValidDate(endDate)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid date format'
    });
  }
  
  if (isNaN(page) || page < 1) {
    return res.status(400).json({
      success: false,
      message: 'Invalid page number'
    });
  }

  try {
    // Query to get malicious file requests
    const query = `
      SELECT 
        session_id,
        ip_address,
        timestamp,
        url,
        fingerprint_id,
        COUNT(*) OVER (PARTITION BY ip_address) as ip_requests,
        COUNT(*) OVER (PARTITION BY session_id) as session_requests
      FROM tracking10
      WHERE (url LIKE '%.ps1%' OR url LIKE '%.hta%' OR url LIKE '%.lnk%' OR url LIKE '%.js%' OR url LIKE '%.vbs%' OR url LIKE '%.bat%')
        AND timestamp BETWEEN {startDate:String} AND {endDate:String}
      ORDER BY timestamp DESC
    `;

    const result = await clickhouse.query(query, {
      params: {
        startDate,
        endDate
      }
    }).toPromise();

    // Process results and determine threat types
    const processedData = result.map(row => {
      // Determine threat type based on file extension
      let threatType = 'Unknown';
      
      const url = row.url.toLowerCase();
      
      if (url.includes('.ps1')) {
        threatType = 'PowerShell Script';
      } else if (url.includes('.hta')) {
        threatType = 'HTML Application';
      } else if (url.includes('.lnk')) {
        threatType = 'Windows Shortcut';
      } else if (url.includes('.js')) {
        threatType = 'JavaScript File';
      } else if (url.includes('.vbs')) {
        threatType = 'VBScript File';
      } else if (url.includes('.bat')) {
        threatType = 'Batch Script';
      }

      // Process timestamp
      const timestamp = new Date(row.timestamp);
      const formattedTimestamp = timestamp.toISOString().replace('T', ' ').substring(0, 19);

      return {
        timestamp: formattedTimestamp,
        alert_type: 'Suspicious File',
        threat_type: threatType,
        url: row.url,
        ip_address: row.ip_address,
        session_id: row.session_id,
        fingerprint_id: row.fingerprint_id,
        ip_requests: row.ip_requests,
        session_requests: row.session_requests
      };
    });

    // Pagination
    const totalRows = processedData.length;
    const totalPages = Math.ceil(totalRows / perPage);
    const startIdx = (page - 1) * perPage;
    const endIdx = startIdx + perPage;
    const paginatedData = processedData.slice(startIdx, endIdx);

    // Return JSON response
    res.json({
      success: true,
      malicious_files: paginatedData,
      totalRows: totalRows,
      totalPages: totalPages,
      currentPage: page,
      start_date: startDate,
      end_date: endDate
    });

  } catch (error) {
    console.error("Error in malicious files API endpoint:", error);
    res.status(500).json({
      success: false,
      message: 'Internal Server Error',
      error: error.message
    });
  }
});

// Route to serve the malicious files HTML page
app.get('/malicious-files', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'html', 'malicious-files.html'));
});

// In-memory attack detection endpoint
app.get('/api/in-memory-attacks', security.protect(), isAuthenticated, async (req, res) => {
  const name = req.username;
  const page = parseInt(req.query.page) || 1;
  const perPage = 10;

  // Input validation
  if (isNaN(page) || page < 1) {
    return res.status(400).json({
      success: false,
      message: 'Invalid page number'
    });
  }

  try {
    // Fetch the hostname for the user
    const q2 = `SELECT hostname FROM users_new WHERE username = {name:String}`;
    const hostarray = await clickhouse.query(q2, {
      params: { name }
    }).toPromise();

    if (!hostarray.length) {
      return res.status(404).json({
        success: false,
        message: 'Hostname not found'
      });
    }

    const host = hostarray[0].hostname;

    // In-memory attack detection query
    const inMemoryAttackQuery = `
    WITH InMemoryAttacks AS (
      SELECT
        t.session_id,
        t.ip_address,
        MIN(t.timestamp) as first_activity,
        MAX(t.timestamp) as last_activity,
       
        -- HTA File Download/Execution Detection
        (COUNT(CASE WHEN
          t.url LIKE '%.hta' OR
          t.url LIKE '%.hta?' OR
          t.url LIKE '%.hta%'
        THEN 1 END) > 0) * 10 AS hta_execution_risk,
       
        -- PowerShell In-Memory Execution
        (COUNT(CASE WHEN
          t.url LIKE '%powershell%' OR
          t.url LIKE '%invoke-expression%' OR
          t.url LIKE '%downloadstring%' OR
          t.url LIKE '%iex%' OR
          t.url LIKE '%EncodedCommand%' OR
          t.url LIKE '%-enc %' OR
          t.url LIKE '%bypass%' OR
          t.url LIKE '%unrestricted%'
        THEN 1 END) > 0) * 10 AS powershell_execution_risk,
       
        -- JavaScript/Script Executable Downloads
        (COUNT(CASE WHEN
          t.url LIKE '%.js' OR
          t.url LIKE '%.vbs' OR
          t.url LIKE '%.vba' OR
          t.url LIKE '%.wsf' OR
          t.url LIKE '%.jse' OR
          t.url LIKE '%.ps1'
        THEN 1 END) > 0) * 9 AS script_execution_risk,
       
        -- Binary/Executable Downloads
        (COUNT(CASE WHEN
          t.url LIKE '%.exe' OR
          t.url LIKE '%.scr' OR
          t.url LIKE '%.com' OR
          t.url LIKE '%.bat' OR
          t.url LIKE '%.cmd' OR
          t.url LIKE '%.msi' OR
          t.url LIKE '%.dll'
        THEN 1 END) > 0) * 9 AS binary_download_risk,
       
        -- Base64 Encoded Payload Detection
        (COUNT(CASE WHEN
          t.url LIKE '%data:application/octet-stream;base64%' OR
          t.url LIKE '%javascript:eval(atob(%' OR
          t.url LIKE '%fromCharCode%' OR
          t.url LIKE '%String.fromCharCode%' OR
          t.url LIKE '%eval(%' OR
          t.url LIKE '%Function(%'
        THEN 1 END) > 0) * 10 AS encoded_payload_risk,
       
        -- Memory Injection Patterns
        (COUNT(CASE WHEN
          t.url LIKE '%VirtualAlloc%' OR
          t.url LIKE '%CreateThread%' OR
          t.url LIKE '%WriteProcessMemory%' OR
          t.url LIKE '%shellcode%' OR
          t.url LIKE '%NtAllocateVirtualMemory%' OR
          t.url LIKE '%RtlMoveMemory%'
        THEN 1 END) > 0) * 10 AS memory_injection_risk,
       
        -- Fileless Malware Indicators
        (COUNT(CASE WHEN
          t.url LIKE '%wmic%' OR
          t.url LIKE '%regsvr32%' OR
          t.url LIKE '%rundll32%' OR
          t.url LIKE '%mshta%' OR
          t.url LIKE '%cscript%' OR
          t.url LIKE '%wscript%' OR
          t.url LIKE '%bitsadmin%'
        THEN 1 END) > 0) * 9 AS fileless_malware_risk,
       
        -- Client-Side SQL Injection via DOM
        (COUNT(CASE WHEN
          sh.dom_security_violations LIKE '%sql injection%' OR
          sh.dom_security_violations LIKE '%database%' OR
          (sh.dom_added_elements LIKE '%sql%' AND
           (t.url LIKE '%websql%' OR t.url LIKE '%indexeddb%'))
        THEN 1 END) > 0) * 8 AS client_sql_injection_risk,
       
        -- WebAssembly Exploitation
        (COUNT(CASE WHEN
          t.url LIKE '%.wasm' OR
          sh.dom_added_elements LIKE '%WebAssembly%' OR
          sh.dom_security_violations LIKE '%wasm%'
        THEN 1 END) > 0) * 7 AS webasm_exploitation_risk,
       
        -- Crypto Mining/Resource Hijacking
        (COUNT(CASE WHEN
          t.url LIKE '%coinhive%' OR
          t.url LIKE '%crypto%mine%' OR
          t.url LIKE '%monero%' OR
          sh.dom_security_violations LIKE '%cpu usage%' OR
          sh.hardware_concurrency > 16
        THEN 1 END) > 0) * 6 AS cryptomining_risk,
       
        -- Suspicious DOM Manipulation for Memory Attacks
        (COUNT(CASE WHEN
          sh.dom_added_elements LIKE '%iframe%' AND
          sh.dom_added_elements LIKE '%data:%' AND
          sh.dom_security_violations LIKE '%injection%'
        THEN 1 END) > 0) * 7 AS dom_injection_risk,

        COUNT(*) as request_count,
        uniqExact(t.url) as unique_urls,
        MAX(sh.dom_changes_count) as max_dom_changes
       
      FROM live_sessions_mv_new t
      LEFT JOIN live_security_headers_mv sh ON t.enhanced_data_id = sh.tracking_id
      WHERE t.hostname LIKE concat('%', {host:String}, '%')
      GROUP BY t.session_id, t.ip_address
    )
   
    SELECT
      session_id,
      ip_address,
      first_activity,
      last_activity,
      hta_execution_risk,
      powershell_execution_risk,
      script_execution_risk,
      binary_download_risk,
      encoded_payload_risk,
      memory_injection_risk,
      fileless_malware_risk,
      client_sql_injection_risk,
      webasm_exploitation_risk,
      cryptomining_risk,
      dom_injection_risk,
      request_count,
      unique_urls,
      max_dom_changes,
     
      -- Calculate total in-memory attack score
      (hta_execution_risk + powershell_execution_risk + script_execution_risk +
       binary_download_risk + encoded_payload_risk + memory_injection_risk +
       fileless_malware_risk + client_sql_injection_risk + webasm_exploitation_risk +
       cryptomining_risk + dom_injection_risk) AS total_memory_attack_score,
       
      -- Risk classification
      CASE
        WHEN (hta_execution_risk > 0 OR powershell_execution_risk > 0 OR
              encoded_payload_risk > 0 OR memory_injection_risk > 0) THEN 'CRITICAL'
        WHEN (script_execution_risk > 0 OR binary_download_risk > 0 OR
              fileless_malware_risk > 0) THEN 'HIGH'
        WHEN (client_sql_injection_risk > 0 OR webasm_exploitation_risk > 0 OR
              dom_injection_risk > 0) THEN 'MEDIUM'
        WHEN cryptomining_risk > 0 THEN 'LOW'
        ELSE 'NONE'
      END AS risk_level,
     
      -- Action recommendations
      multiIf(
        hta_execution_risk > 0 OR powershell_execution_risk > 0 OR encoded_payload_risk > 0 OR memory_injection_risk > 0,
        map('Action', 'IMMEDIATE_BLOCK', 'Alert', 'CRITICAL_THREAT', 'Escalate', 'YES'),
       
        script_execution_risk > 0 OR binary_download_risk > 0 OR fileless_malware_risk > 0,
        map('Action', 'BLOCK_SESSION', 'Alert', 'HIGH_RISK', 'Escalate', 'YES'),
       
        client_sql_injection_risk > 0 OR webasm_exploitation_risk > 0 OR dom_injection_risk > 0,
        map('Action', 'CHALLENGE_USER', 'Alert', 'MEDIUM_RISK', 'Escalate', 'NO'),
       
        cryptomining_risk > 0,
        map('Action', 'MONITOR', 'Alert', 'RESOURCE_ABUSE', 'Escalate', 'NO'),
       
        map('Action', 'ALLOW', 'Alert', 'NONE', 'Escalate', 'NO')
      ) AS recommended_action
     
    FROM InMemoryAttacks
    WHERE (hta_execution_risk + powershell_execution_risk + script_execution_risk +
           binary_download_risk + encoded_payload_risk + memory_injection_risk +
           fileless_malware_risk + client_sql_injection_risk + webasm_exploitation_risk +
           cryptomining_risk + dom_injection_risk) > 0
    ORDER BY total_memory_attack_score DESC`;

    const result = await clickhouse.query(inMemoryAttackQuery, {
      params: { host }
    }).toPromise();

    // Calculate pagination
    const totalRows = result.length;
    const totalPages = Math.ceil(totalRows / perPage);
    const startIdx = (page - 1) * perPage;
    const endIdx = startIdx + perPage;
    const paginatedData = result.slice(startIdx, endIdx);

    // Send immediate alerts for critical threats
    const criticalThreats = result.filter(row => row.risk_level === 'CRITICAL');
   
    if (criticalThreats.length > 0) {
      criticalThreats.forEach(threat => {
        // Emit real-time alert via Socket.IO
        io.to(threat.session_id).emit('critical-threat-detected', {
          message: 'CRITICAL: In-memory attack detected - Session will be terminated',
          action: 'immediate_termination',
          severity: 'CRITICAL',
          attackType: 'IN_MEMORY_EXECUTION',
          redirectUrl: 'https://google.com'
        });
       
        // Log critical event
        console.log(`CRITICAL IN-MEMORY ATTACK: Session ${threat.session_id}, Score: ${threat.total_memory_attack_score}`);
       
        // Terminate critical sessions immediately
        if (sessions[threat.session_id]) {
          delete sessions[threat.session_id];
        }
      });
    }

    // Return JSON response
    res.json({
      success: true,
      inMemoryAttacks: paginatedData,
      totalRows: totalRows,
      totalPages: totalPages,
      currentPage: page,
      hostname: host,
      criticalAlerts: criticalThreats.length,
      summary: {
        critical: result.filter(r => r.risk_level === 'CRITICAL').length,
        high: result.filter(r => r.risk_level === 'HIGH').length,
        medium: result.filter(r => r.risk_level === 'MEDIUM').length,
        low: result.filter(r => r.risk_level === 'LOW').length,
        total_detected: result.length
      },
      attackVectors: {
        hta_attacks: result.filter(r => r.hta_execution_risk > 0).length,
        powershell_attacks: result.filter(r => r.powershell_execution_risk > 0).length,
        script_downloads: result.filter(r => r.script_execution_risk > 0).length,
        binary_downloads: result.filter(r => r.binary_download_risk > 0).length,
        encoded_payloads: result.filter(r => r.encoded_payload_risk > 0).length,
        memory_injection: result.filter(r => r.memory_injection_risk > 0).length,
        fileless_malware: result.filter(r => r.fileless_malware_risk > 0).length
      }
    });

  } catch (error) {
    console.error('Error in in-memory attack detection API:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to load in-memory attack data: ' + error.message
    });
  }
});

// Route handler for in-memory attacks page
app.get('/in-memory-attacks', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'html', 'in-memory-attacks.html'));
});

// Security error handling middleware
app.use((err, req, res, next) => {
  if (err && err.code) {
    switch (err.code) {
      case 'PROXY_DETECTED':
        res.status(403).json({
          success: false,
          message: 'Proxy detected. Please access directly.',
          code: 'PROXY_DETECTED'
        });
        break;
      case 'RATE_LIMITED':
        res.status(429).json({
          success: false,
          message: 'Too many requests. Please wait.',
          code: 'RATE_LIMITED'
        });
        break;
      case 'INVALID_SIGNATURE':
        res.status(401).json({
          success: false,
          message: 'Invalid request signature.',
          code: 'INVALID_SIGNATURE'
        });
        break;
      default:
        next(err);
    }
  } else {
    next(err);
  }
});

// Security status endpoint  
app.get('/api/security-status',security.protect(), isAuthenticated, (req, res) => {
  res.json({
    success: true,
    stats: {
      totalRequests: security.clientState.size,
      activeClients: security.requestHistory.size,
      cryptoAvailable: true,
      signingEnabled: security.config.enableRequestSigning
    }
  });
});

const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// // Replace your existing /auth/google endpoint with this fixed version:

// app.post('/auth/google', async (req, res) => {
//     try {
//         const { credential } = req.body;
        
//         // Verify the Google token
//         const ticket = await client.verifyIdToken({
//             idToken: credential,
//             audience: process.env.GOOGLE_CLIENT_ID,
//         });
        
//         const payload = ticket.getPayload();
//         const { sub: googleId, email, name, picture } = payload;
        
//         console.log('Google OAuth payload:', { googleId, email, name });
        
//         // Check for existing user by email or google_id using proper ClickHouse syntax
//         const existingUserQuery = `
//             SELECT username, passwordHash, hostname, google_id, auth_method, version
//             FROM users_new 
//             WHERE username = {email:String} OR google_id = {googleId:String}
//             ORDER BY version DESC 
//             LIMIT 1
//         `;
        
//         const existingUserResult = await clickhouse.query(existingUserQuery, {
//             params: { email, googleId }
//         }).toPromise();
        
//         let user;
        
//         if (existingUserResult.length > 0) {
//             // User exists - update with Google info if needed
//             const existingUser = existingUserResult[0];
//             const currentVersion = existingUser.version + 1;
            
//             // Insert updated user record with new version
//             const updateQuery = `
//                 INSERT INTO users_new (username, passwordHash, hostname, google_id, auth_method, profile_picture, version)
//                 VALUES ({email:String}, {passwordHash:String}, {hostname:String}, {googleId:String}, {authMethod:String}, {picture:String}, {version:UInt32})
//             `;
            
//             await clickhouse.query(updateQuery, {
//                 params: {
//                     email,
//                     passwordHash: existingUser.passwordHash || '', // Keep existing password if any
//                     hostname: existingUser.hostname || 'google.com',
//                     googleId,
//                     authMethod: 'google',
//                     picture: picture || '',
//                     version: currentVersion
//                 }
//             }).toPromise();
            
//             user = { username: email, google_id: googleId, hostname: existingUser.hostname };
            
//         } else {
//             // Create new user
//             const insertQuery = `
//                 INSERT INTO users_new (username, passwordHash, hostname, google_id, auth_method, profile_picture, version)
//                 VALUES ({email:String}, '', 'google.com', {googleId:String}, 'google', {picture:String}, 1)
//             `;
            
//             await clickhouse.query(insertQuery, {
//                 params: {
//                     email,
//                     googleId,
//                     picture: picture || ''
//                 }
//             }).toPromise();
            
//             user = { username: email, google_id: googleId, hostname: 'google.com' };
//         }
        
//         // Set session for authentication
//         req.session.authenticated = true;
//         req.session.username = email;
//         req.session.authMethod = 'google';
        
//         res.json({
//             success: true,
//             user: { username: email, name },
//             message: 'Google authentication successful'
//         });
        
//     } catch (error) {
//         console.error('Google OAuth error:', error);
//         res.status(400).json({
//             success: false,
//             message: 'Google authentication failed: ' + error.message
//         });
//     }
// });

// Replace your existing /auth/google endpoint with this version:

app.post('/auth/google', async (req, res) => {
    try {
        const { credential } = req.body;
        
        // Verify the Google token
        const ticket = await client.verifyIdToken({
            idToken: credential,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        
        const payload = ticket.getPayload();
        const { sub: googleId, email, name, picture } = payload;
        
        console.log('Google OAuth payload:', { googleId, email, name });
        
        // Check if user already exists by email OR google_id
        const existingUserQuery = `
            SELECT username, passwordHash, hostname, google_id, auth_method, version
            FROM users_new 
            WHERE username = {email:String} OR google_id = {googleId:String}
            ORDER BY version DESC 
            LIMIT 1
        `;
        
        const existingUserResult = await clickhouse.query(existingUserQuery, {
            params: { email, googleId }
        }).toPromise();
        
        if (existingUserResult.length > 0) {
            // User already exists - just login, don't create new entry
            const existingUser = existingUserResult[0];
            
            // Set session for authentication
            req.session.authenticated = true;
            req.session.username = email;
            req.session.authMethod = 'google';
            
            console.log('Existing user logged in:', email);
            
            res.json({
                success: true,
                user: { username: email, name },
                message: 'Login successful',
                isExistingUser: true
            });
            
        } else {
            // New user - need to collect hostname first
            // Store temporary Google data in session for hostname collection
            req.session.tempGoogleAuth = {
                googleId,
                email,
                name,
                picture
            };
            
            console.log('New Google user - needs hostname:', email);
            
            res.json({
                success: true,
                requiresHostname: true,
                user: { email, name },
                message: 'Please provide hostname to complete registration'
            });
        }
        
    } catch (error) {
        console.error('Google OAuth error:', error);
        res.status(400).json({
            success: false,
            message: 'Google authentication failed: ' + error.message
        });
    }
});

// Add new endpoint to complete Google registration with hostname
app.post('/auth/google/complete', async (req, res) => {
    try {
        const { hostname } = req.body;
        
        // Get stored Google auth data from session
        const tempGoogleAuth = req.session.tempGoogleAuth;
        
        if (!tempGoogleAuth) {
            return res.status(400).json({
                success: false,
                message: 'No pending Google authentication found'
            });
        }
        
        // Validate hostname
        if (!hostname || hostname.length > 100) {
            return res.status(400).json({
                success: false,
                message: 'Valid hostname is required'
            });
        }
        
        // Check for hostname conflicts (same logic as regular signup)
        const hostQuery = 'SELECT hostname FROM users_new';
        const hostResult = await clickhouse.query(hostQuery).toPromise();
        
        const existingHostnames = hostResult.map(row => row.hostname);
        const isHostnameConflict = existingHostnames.some(existing => {
            return existing.includes(hostname) || hostname.includes(existing);
        });
        
        if (isHostnameConflict) {
            return res.status(400).json({
                success: false,
                message: 'Hostname too similar to an existing one. Please choose a different one.'
            });
        }
        
        // Create new user with provided hostname
        const insertQuery = `
            INSERT INTO users_new (username, passwordHash, hostname, google_id, auth_method, profile_picture, version)
            VALUES ({email:String}, '', {hostname:String}, {googleId:String}, 'google', {picture:String}, 1)
        `;
        
        await clickhouse.query(insertQuery, {
            params: {
                email: tempGoogleAuth.email,
                hostname,
                googleId: tempGoogleAuth.googleId,
                picture: tempGoogleAuth.picture || ''
            }
        }).toPromise();
        
        // Set session for authentication
        req.session.authenticated = true;
        req.session.username = tempGoogleAuth.email;
        req.session.authMethod = 'google';
        
        // Clear temporary auth data
        delete req.session.tempGoogleAuth;
        
        console.log('New Google user created:', tempGoogleAuth.email, 'with hostname:', hostname);
        
        res.json({
            success: true,
            user: { username: tempGoogleAuth.email, name: tempGoogleAuth.name },
            message: 'Registration completed successfully'
        });
        
    } catch (error) {
        console.error('Google registration completion error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to complete registration: ' + error.message
        });
    }
});

// Add this to your server code
app.post('/auth/google/popup', async (req, res) => {
    try {
        const { email, name, googleId, picture } = req.body;
        
        console.log('Google popup auth:', { email, name, googleId });
        
        if (!email || !googleId) {
            return res.status(400).json({
                success: false,
                message: 'Missing required user information'
            });
        }
        
        const existingUserQuery = `
            SELECT username, passwordHash, hostname, google_id, auth_method, version
            FROM users_new 
            WHERE username = {email:String} OR google_id = {googleId:String}
            ORDER BY version DESC 
            LIMIT 1
        `;
        
        const existingUserResult = await clickhouse.query(existingUserQuery, {
            params: { email, googleId }
        }).toPromise();
        
        if (existingUserResult.length > 0) {
            req.session.authenticated = true;
            req.session.username = email;
            req.session.authMethod = 'google';
            
            res.json({
                success: true,
                user: { username: email, name },
                message: 'Login successful',
                isExistingUser: true
            });
        } else {
            req.session.tempGoogleAuth = {
                googleId, email, name, picture: picture || ''
            };
            
            res.json({
                success: true,
                requiresHostname: true,
                user: { email, name },
                message: 'Please provide hostname to complete registration'
            });
        }
    } catch (error) {
        console.error('Google popup OAuth error:', error);
        res.status(400).json({
            success: false,
            message: 'Google authentication failed: ' + error.message
        });
    }
});

// ===== SERVER STARTUP =====
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});