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
const PORT = process.env.PORT || 7002;
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
  maxRequestsPerWindow: 50,
  serverSecret: process.env.SECURITY_SECRET || crypto.randomBytes(32).toString('hex'),
  allowedOrigins: ['http://64.227.151.232:7002', 'http://localhost:7002', 'https://yourdomain.com']
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

// ===== MIDDLEWARE CONFIGURATION =====
app.use(flash());
app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
}));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
// app.use((req, res, next) => {
//   res.setHeader('X-Content-Type-Options', 'nosniff');
//   res.setHeader('X-Frame-Options', 'DENY');
//   res.setHeader('X-XSS-Protection', '1; mode=block');
//   res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
//   // res.setHeader('Content-Security-Policy', "default-src 'self'");
//   // Updated - allows necessary external resources
//   res.setHeader('Content-Security-Policy',
//     "default-src 'self'; " +
//     "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; " +
//     "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
//     "img-src 'self' data:; " +
//     "font-src 'self' https://cdnjs.cloudflare.com;"
//   );
//   res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
//   next();
// });

// Updated headers that allow iframe usage
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN'); // Changed from DENY to SAMEORIGIN
  res.setHeader('X-XSS-Protection', '1; mode=block');
  // Comment out HTTPS-only header for HTTP development
  // res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; " +
    "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
    "img-src 'self' data:; " +
    "font-src 'self' https://cdnjs.cloudflare.com; " +
    "frame-src 'self'; " +
    "connect-src 'self';" // ADD THIS LINE
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
    FROM users
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
}, CLEANUP_INTERVAL);

// Security token endpoint
app.get('/api/security-token', (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  res.json({
    success: true,
    token: token,
    secretKey: security.currentSecret
  });
});

// Token verification endpoint
app.post('/api/verify-token', (req, res) => {
  const { token } = req.body;
  res.json({
    success: true,
    valid: token && token.length === 64
  });
});

// Security event logging endpoint
app.post('/api/security-event', (req, res) => {
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
    // Step 1: Fetch all hostnames from the users table
    const query = 'SELECT hostname FROM users';
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
        INSERT INTO users (username, passwordHash, hostname, version)
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

// Data tracking endpoint
app.post('/track', security.protect({
  maxRequestsPerWindow: 100, // Higher limit for tracking
  requestWindow: 60000
}), async (req, res) => {
  try {
    const data = req.body;
    const ipAddress = data.ipAddress || '';
    const userAgent = data.deviceInfo ? data.deviceInfo.userAgent.replace(/'/g, "\\'") : '';
    const platform = data.deviceInfo ? data.deviceInfo.platform : '';
    const language = data.deviceInfo ? data.deviceInfo.language : '';
    const hostname = data.hostname || '';
    const sessionId = data.sessionId || '';
    const browser_id = data.browser_id || '';
    const fingerprint_id = data.fingerprint_id || '';
    const timestamp = new Date(data.timestamp).toISOString().slice(0, 19).replace('T', ' ');
    const clickData = data.clickData || '';
    const clickDataString = JSON.stringify(clickData).replace(/'/g, "''");

    // Generate enhanced data ID
    function generateEnhancedDataId(sessionId) {
      let numericValue = 0;
      for (let i = 0; i < sessionId.length; i++) {
        numericValue += sessionId.charCodeAt(i);
      }
      const timestamp = Date.now();
      return parseInt(`${timestamp}${numericValue % 1000}`);
    }

    const enhanced_data_id = generateEnhancedDataId(sessionId);

    // Geo location data
    const geo = geoip.lookup(ipAddress);
    const country = (geo && geo.country) ? geo.country.replace(/'/g, "''") : 'Unknown';
    const region = (geo && geo.region) ? geo.region.replace(/'/g, "''") : 'Unknown';
    const city = (geo && geo.city) ? geo.city.replace(/'/g, "''") : 'Unknown';

    // Get next IDs
    const result = await clickhouse.query('SELECT max(id) FROM tracking10').toPromise();
    const resultOne = await clickhouse.query('SELECT max(id) FROM region_details').toPromise();
    const securityResult = await clickhouse.query('SELECT max(id) FROM security_headers').toPromise();

    const maxId = result[0]['max(id)'] || 0;
    const maxIdOne = resultOne[0]['max(id)'] || 0;
    const maxSecurityId = securityResult[0]['max(id)'] || 0;

    const nextId = maxId + 1;
    const nextIdOne = maxIdOne + 1;
    const nextSecurityId = maxSecurityId + 1;

    // Sanitize and prepare security headers data
    const securityHeaders = data.securityHeaders || {};
    const domMonitoring = data.domMonitoringData || {
      dom_changes_count: 0,
      dom_monitoring_active: 1,
      dom_last_change: new Date().toISOString(),
      dom_added_elements: '[]',
      dom_removed_elements: '[]',
      dom_modified_attributes: '[]',
      dom_sensitive_changes: '[]',
      dom_security_violations: '[]'
    };

    // Sanitize canvas fingerprint
    let canvasFingerprint = '';
    try {
      const canvasData = typeof securityHeaders.canvas_fingerprint === 'string' ?
        securityHeaders.canvas_fingerprint :
        JSON.stringify(securityHeaders.canvas_fingerprint || '');
      canvasFingerprint = canvasData.replace(/'/g, "''");
    } catch (e) {
      console.error('Error processing canvas fingerprint:', e);
      canvasFingerprint = '';
    }

    // Build tracking query
    const trackingQuery = `
      INSERT INTO tracking10 (
        id, timestamp, url, referrer, ip_address, user_agent, 
        platform, language, hostname, session_id, browser_id, 
        fingerprint_id, clickdata, enhanced_data_id
      ) VALUES (
        ${nextId}, 
        '${timestamp}', 
        '${(data.url || '').replace(/'/g, "''")}', 
        '${(data.referrer || '').replace(/'/g, "''")}', 
        '${ipAddress}', 
        '${userAgent}', 
        '${platform}', 
        '${language}', 
        '${hostname}', 
        '${sessionId}',
        '${browser_id}', 
        '${fingerprint_id}', 
        '${clickDataString}', 
        ${enhanced_data_id}
      )`;

    // Build region query
    const regionQuery = `
      INSERT INTO region_details (id, ip_address, country, region, city)
      VALUES (${nextIdOne}, '${ipAddress}', '${country}', '${region}', '${city}')`;

    // Build security headers query with proper null handling
    const securityQuery = `
      INSERT INTO security_headers (
        id, tracking_id, session_id,
        security_cors_origin, security_allow_origin, security_allow_methods, security_allow_headers,
        security_allow_credentials, security_expose_headers, security_max_age, security_frame_ancestors,
        security_csp, security_referrer_policy, security_permissions_policy, security_cross_origin,
        security_is_framed, security_sandbox, dom_changes_count, dom_monitoring_active, 
        dom_last_change, dom_added_elements, dom_removed_elements, dom_modified_attributes, 
        dom_sensitive_changes, dom_security_violations,
        hardware_concurrency, platform_version, canvas_fingerprint, webgl_vendor, webgl_renderer,
        web_driver, max_touch_points
      ) VALUES (
        ${nextSecurityId},
        ${enhanced_data_id},
        '${sessionId}',
        '${(securityHeaders.security_cors_origin || '').replace(/'/g, "''")}',
        '${(securityHeaders.security_allow_origin || '*').replace(/'/g, "''")}',
        '${(securityHeaders.security_allow_methods || '').replace(/'/g, "''")}',
        '${(securityHeaders.security_allow_headers || '').replace(/'/g, "''")}',
        ${securityHeaders.security_allow_credentials || 0},
        '${(securityHeaders.security_expose_headers || '').replace(/'/g, "''")}',
        ${securityHeaders.security_max_age || 86400},
        '${(securityHeaders.security_frame_ancestors || '').replace(/'/g, "''")}',
        '${(securityHeaders.security_csp || '').replace(/'/g, "''")}',
        '${(securityHeaders.security_referrer_policy || '').replace(/'/g, "''")}',
        '${(securityHeaders.security_permissions_policy || '').replace(/'/g, "''")}',
        '${(securityHeaders.security_cross_origin || '').replace(/'/g, "''")}',
        ${securityHeaders.security_is_framed || 0},
        '${(securityHeaders.security_sandbox || '').replace(/'/g, "''")}',
        ${parseInt(domMonitoring.dom_changes_count) || 0},
        ${domMonitoring.dom_monitoring_active ? 1 : 0},
        '${(domMonitoring.dom_last_change ? domMonitoring.dom_last_change.slice(0, 23).replace('T', ' ') : new Date().toISOString().slice(0, 23).replace('T', ' '))}',
        '${(domMonitoring.dom_added_elements || '[]').replace(/'/g, "''")}',
        '${(domMonitoring.dom_removed_elements || '[]').replace(/'/g, "''")}',
        '${(domMonitoring.dom_modified_attributes || '[]').replace(/'/g, "''")}',
        '${(domMonitoring.dom_sensitive_changes || '[]').replace(/'/g, "''")}',
        '${(domMonitoring.dom_security_violations || '[]').replace(/'/g, "''")}',
        ${securityHeaders.hardware_concurrency || 0},
        '${(securityHeaders.platform_version || '').replace(/'/g, "''")}',
        '${canvasFingerprint}',
        '${((securityHeaders.webgl_vendor || '').toString()).replace(/'/g, "''")}',
        '${((securityHeaders.webgl_renderer || '').toString()).replace(/'/g, "''")}',
        ${securityHeaders.web_driver ? 1 : 0},
        ${securityHeaders.max_touch_points || 0}
      )`;

    // Execute queries
    await clickhouse.query(trackingQuery).toPromise();
    await clickhouse.query(regionQuery).toPromise();
    await clickhouse.query(securityQuery).toPromise();

    sessions[sessionId] = Date.now();
    res.json({ status: 'success' });
  } catch (error) {
    console.error("Error inserting into database:", error);
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
    const q2 = `SELECT hostname FROM users WHERE username = '${name}'`;
    const hostarray = await clickhouse.query(q2).toPromise();
    const host = hostarray[0].hostname;

    // Build the SQL query dynamically with the fetched hostname
    const sqlQuery = `SELECT DISTINCT session_id FROM tracking10 WHERE timestamp >= '${timestamp}' AND hostname LIKE '%${host}%'`;

    // The actual URL you are using with the ClickHouse server
    const url = `http://65.2.172.119:8001/terminate-sessions?query1=${encodeURIComponent(sqlQuery)}`;

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
      const userQuery = `SELECT hostname FROM users WHERE username = '${username}'`;
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


// API route to get rules
app.get('/api/rules', security.protect(), isAuthenticated, async (req, res) => {
  const username = req.username;

  try {
    // Fetch the hostname for the user
    const q2 = `SELECT hostname FROM users WHERE username = {username:String}`;
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
    const q2 = `SELECT hostname FROM users WHERE username = {username:String}`;
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
    const q2 = `SELECT hostname FROM users WHERE username = {username:String}`;
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
  const customUrl = req.query.custom_url || 'bluebot';
  const name = req.username;
  const page = parseInt(req.query.page) || 1;
  const perPage = 10; // Number of rows per page
  const startDate = req.query.start_date || '2025-04-01';
  const endDate = req.query.end_date || '2025-04-30';

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
    const q2 = `SELECT hostname FROM users WHERE username = {name:String}`;
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
  const sessionid = req.query.session_id || '5bnrzox1eatq1k3yew';
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
    const hostQuery = `SELECT hostname FROM users WHERE username = {name:String}`;
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
    const q2 = `SELECT hostname FROM users WHERE username = {name:String}`;
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
    const q2 = `SELECT hostname FROM users WHERE username = {name:String}`;
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
    const q2 = `SELECT hostname FROM users WHERE username = {name:String}`;
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
        aiScores: req.session.aiScores || {}
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

    // Return JSON response
    res.json({
      success: true,
      riskData: mergedResults,
      hostname: host,
      totalPages: totalPages,
      currentPage: page,
      aiScores: req.session.aiScores || {}
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
      const userQuery = `SELECT hostname FROM users WHERE username = '${username}'`;
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
    const userQuery = `SELECT hostname FROM users WHERE username = '${username}'`;
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
        -H "Authorization: Bearer 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" \\
        -H "Content-Type: application/json" \\
        -d '{
          "model": "deepseek/deepseek-chat:free", 
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

// Add new API endpoint for attack detection data
app.get('/api/attack-detection', security.protect(), isAuthenticated, async (req, res) => {
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
    // Fetch the hostname for the user using parameterized query
    const q2 = `SELECT hostname FROM users WHERE username = {name:String}`;
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

    // This is a complex query with multiple SQL patterns that are not easily parameterized
    // We'll parameterize the hostname pattern and leave the static patterns as is
    const attackDetectionQuery = `WITH SessionSecurityMetrics AS (
    SELECT
    t.session_id,
    MIN(t.timestamp) as first_activity,
    MAX(t.timestamp) as last_activity,
    sh.dom_changes_count,
    
    -- CSRF Attack Detection
    (COUNT(CASE WHEN 
      t.url LIKE '%/api/%' OR 
      t.url LIKE '%/action/%' OR
      t.url LIKE '%/submit%' OR
      t.url LIKE '%/update%'
    THEN 1 END) > 0 AND MAX(sh.security_allow_origin) = '*') * 4 AS csrf_attack,
    
    -- Session Hijacking Detection
    (uniqExact(t.ip_address) > 1 OR uniqExact(t.browser_id) > 1) * 4 AS session_hijack_attack,

    -- Clickjacking Detection
    (COUNT(CASE WHEN 
      sh.dom_security_violations LIKE '%framing attempt%' OR
      (sh.security_is_framed = 1 AND sh.dom_sensitive_changes LIKE '%form%')
    THEN 1 END) > 0) * 4 AS clickjacking_attack,

    -- Credential Stuffing Detection
    (COUNT(CASE WHEN 
      t.url LIKE '%/login%' OR 
      t.url LIKE '%/signin%'
    THEN 1 END) > 10) * 5 AS credential_stuffing_attack,

    -- File Upload Attack Detection
    (COUNT(CASE WHEN 
      sh.dom_security_violations LIKE '%file upload%' OR
      (t.url LIKE '%upload%' AND (
        t.url LIKE '%.php%' OR 
        t.url LIKE '%.jsp%' OR 
        t.url LIKE '%.exe%'
      ))
    THEN 1 END) > 0) * 5 AS file_upload_attack,

    -- XSS Attack Detection
    (COUNT(CASE WHEN 
      sh.dom_security_violations LIKE '%script injection%' OR
      sh.dom_added_elements LIKE '%<script%' OR
      sh.dom_sensitive_changes LIKE '%script%'
    THEN 1 END) > 0) * 8 AS xss_attack,

    -- SQLi Attack Detection
    (COUNT(CASE WHEN 
      t.url LIKE '%UNION SELECT%' OR
      t.url LIKE '%UNION ALL SELECT%' OR
      t.url LIKE '%; SELECT%' OR
      t.url LIKE '%information_schema%'
    THEN 1 END) > 0) * 8 AS sqli_attack,

    -- Open Redirect Attack
    (COUNT(CASE WHEN 
      t.url LIKE '%redirect%' AND 
      t.url LIKE '%http%'
    THEN 1 END) > 0) * 5 AS redirect_attack,

    -- Dynamic Script/IFRAME Detection with Behavioral Analysis
    (COUNT(CASE WHEN 
      sh.dom_added_elements LIKE '%"type":"SCRIPT"%' OR 
      sh.dom_added_elements LIKE '%"type":"IFRAME"%'
    THEN 1 END) > 0) * 8 AS dynamic_script_risk,

    -- Form Action Modifications with Context
    (COUNT(CASE WHEN 
      sh.dom_modified_attributes LIKE '%"attribute":"action"%' AND
      (
        sh.dom_modified_attributes LIKE '%"attribute":"method"%' OR
        sh.dom_modified_attributes LIKE '%"attribute":"enctype"%'
      )
    THEN 1 END) > 0) * 6 AS form_mod_risk,

    -- Enhanced DOM Change Analysis - Modified to handle animations
    (CASE 
        WHEN sh.dom_changes_count > 50 AND dateDiff('second', MIN(t.timestamp), MAX(t.timestamp)) < 5 
        AND COUNT(CASE WHEN 
            -- Exclude pure class/style changes during page load
            sh.dom_modified_attributes NOT LIKE '%"attribute":"class"%' AND
            sh.dom_modified_attributes NOT LIKE '%"attribute":"style"%' AND
            (
                sh.dom_sensitive_changes != '[]' OR 
                sh.dom_security_violations != '[]'
            )
        THEN 1 END) > 0 THEN 8
        
        WHEN sh.dom_changes_count > 30 AND COUNT(CASE WHEN
            sh.dom_modified_attributes NOT LIKE '%"attribute":"class"%' AND
            sh.dom_modified_attributes NOT LIKE '%"attribute":"style"%' AND
            (
                sh.dom_added_elements LIKE '%form%' OR
                sh.dom_added_elements LIKE '%input%' OR
                sh.dom_added_elements LIKE '%button%'
            )
        THEN 1 END) > 0 THEN 6
        
        WHEN sh.dom_changes_count > 50 AND dateDiff('second', MIN(t.timestamp), MAX(t.timestamp)) > 30 THEN 0
        
        WHEN sh.dom_changes_count > 20 AND 
             dateDiff('second', MIN(t.timestamp), MAX(t.timestamp)) < 2 AND
             COUNT(CASE WHEN 
                sh.dom_modified_attributes NOT LIKE '%"attribute":"class"%' AND
                sh.dom_modified_attributes NOT LIKE '%"attribute":"style"%'
             THEN 1 END) > 0 THEN 4
        
        ELSE 0
    END) AS dom_behavior_risk,

    -- Enhanced Element Cycling Detection
    (COUNT(CASE WHEN 
        sh.dom_added_elements != '[]' AND 
        sh.dom_removed_elements != '[]' AND
        (
            sh.dom_added_elements LIKE '%form%' OR
            sh.dom_added_elements LIKE '%input%' OR
            sh.dom_added_elements LIKE '%button%'
        )
    THEN 1 END) > 0) * 4 AS element_cycling_risk,

    -- Sensitive Attribute Modifications
    (COUNT(CASE WHEN 
        sh.dom_modified_attributes LIKE '%"attribute":"href"%' OR
        sh.dom_modified_attributes LIKE '%"attribute":"src"%' OR
        sh.dom_modified_attributes LIKE '%"attribute":"integrity"%' OR
        sh.dom_modified_attributes LIKE '%"attribute":"sandbox"%'
    THEN 1 END) > 0) * 5 AS sensitive_attr_risk,

    -- Post-Load Suspicious Changes
    (CASE WHEN 
        dateDiff('second', MIN(t.timestamp), MAX(t.timestamp)) > 10 AND
        sh.dom_changes_count > 20 AND
        COUNT(CASE WHEN
            sh.dom_modified_attributes LIKE '%"attribute":"src"%' OR
            sh.dom_modified_attributes LIKE '%"attribute":"href"%'
        THEN 1 END) > 0
    THEN 6
    ELSE 0 END) AS post_load_risk,

    -- Keep track of basic metrics
    COUNT(CASE WHEN sh.dom_security_violations != '[]' THEN 1 END) AS security_violations_count,
    COUNT(*) AS request_count

    FROM live_sessions_mv_new t
    LEFT JOIN live_security_headers_mv sh ON t.enhanced_data_id = sh.tracking_id
    WHERE t.hostname LIKE concat('%', {host:String}, '%')
    GROUP BY t.session_id, sh.dom_changes_count
    )

    SELECT 
        *,
    -- Enhanced Attack Score Calculation
   CASE
    -- Critical security violations (now including DOM behavior risk)
    WHEN xss_attack > 0 OR sqli_attack > 0 OR csrf_attack > 0 OR dom_behavior_risk > 0 THEN 10
    
    -- Dynamic script injection and form tampering
    WHEN dynamic_script_risk > 0 OR form_mod_risk > 0 THEN 9
    
    -- Suspicious DOM behavior with sensitive elements
    WHEN dom_behavior_risk >= 8 AND (sensitive_attr_risk > 0 OR element_cycling_risk > 0) THEN 8
    
    -- Multiple suspicious activities
    WHEN (session_hijack_attack > 0 AND credential_stuffing_attack > 0) OR
         (file_upload_attack > 0 AND sensitive_attr_risk > 0) THEN 8
    
    -- Suspicious post-load behavior
    WHEN post_load_risk > 0 AND (dom_behavior_risk > 0 OR sensitive_attr_risk > 0) THEN 7
    
    -- Individual serious risks
    WHEN dom_behavior_risk >= 6 OR session_hijack_attack > 0 OR credential_stuffing_attack > 0 THEN 6
    
    -- Lower risk activities
    WHEN clickjacking_attack > 0 OR redirect_attack > 0 OR element_cycling_risk > 0 THEN 5
    
    -- Basic security violations
    WHEN security_violations_count > 0 OR sensitive_attr_risk > 0 THEN 4
    
    -- Low level DOM risks
    WHEN dom_behavior_risk > 0 THEN 3
    
      ELSE 0
  END AS total_attack_score,

    -- Enhanced Action Recommendations
    multiIf(
        -- Critical threats
        (xss_attack > 0 OR sqli_attack > 0 OR csrf_attack > 0 OR 
         dynamic_script_risk > 0 OR form_mod_risk > 0),
        map('Block', 100, 'Challenge', 0, 'Monitor', 0),
        
        -- High risk behavior
        (dom_behavior_risk >= 8 AND (sensitive_attr_risk > 0 OR element_cycling_risk > 0)) OR
        (session_hijack_attack > 0 AND credential_stuffing_attack > 0) OR
        (file_upload_attack > 0 AND sensitive_attr_risk > 0),
        map('Block', 80, 'Challenge', 20, 'Monitor', 0),
        
        -- Suspicious behavior
        (post_load_risk > 0 AND (dom_behavior_risk > 0 OR sensitive_attr_risk > 0)) OR
        dom_behavior_risk >= 6 OR session_hijack_attack > 0 OR credential_stuffing_attack > 0,
        map('Block', 60, 'Challenge', 30, 'Monitor', 10),
        
        -- Low risk behavior
        clickjacking_attack > 0 OR redirect_attack > 0 OR element_cycling_risk > 0 OR
        security_violations_count > 0 OR sensitive_attr_risk > 0,
        map('Block', 30, 'Challenge', 50, 'Monitor', 20),
        
        -- Default case - no significant risks
        map('Block', 0, 'Challenge', 20, 'Monitor', 80)
    ) AS recommended_actions

    FROM SessionSecurityMetrics
    ORDER BY total_attack_score DESC`;

    const result = await clickhouse.query(attackDetectionQuery, {
      params: { host }
    }).toPromise();

    // Deduplicate sessions by keeping only the first occurrence of each session_id
    const seenSessions = new Set();
    const uniqueResults = result.filter(row => {
      if (!seenSessions.has(row.session_id)) {
        seenSessions.add(row.session_id);
        return true;
      }
      return false;
    });

    // Calculate pagination
    const totalRows = uniqueResults.length;
    const totalPages = Math.ceil(totalRows / perPage);
    const startIdx = (page - 1) * perPage;
    const endIdx = startIdx + perPage;

    // Get paginated data from deduplicated results
    const paginatedData = uniqueResults.slice(startIdx, endIdx);

    // Return JSON response
    res.json({
      success: true,
      attackData: paginatedData,
      hostname: host,
      totalPages: totalPages,
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
app.get('/api/security-status', isAuthenticated, (req, res) => {
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

// ===== SERVER STARTUP =====
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});