// ===== Advanced Security Module =====
// This module provides comprehensive protection against Burp Suite and proxy-based attacks

const crypto = require('crypto');
const os = require('os');

class SecurityModule {
  constructor(options = {}) {
    this.config = {
      // Anti-proxy protection settings
      enableAntiProxy: options.enableAntiProxy !== false,
      enableRequestSigning: options.enableRequestSigning !== false,
      enableTimestampValidation: options.enableTimestampValidation !== false,
      enableRateLimiting: options.enableRateLimiting !== false,
      enableFingerprinting: options.enableFingerprinting !== false,
      
      // Timing and thresholds
      maxRequestAge: options.maxRequestAge || 30000, // 30 seconds
      requestWindow: options.requestWindow || 60000, // 1 minute for rate limiting
      maxRequestsPerWindow: options.maxRequestsPerWindow || 30,
      
      // Security keys and secrets
      serverSecret: options.serverSecret || crypto.randomBytes(32).toString('hex'),
      secretRotationInterval: options.secretRotationInterval || 3600000, // 1 hour
      
      // Proxy detection settings
      suspiciousHeaders: [
        'x-forwarded-for',
        'x-forwarded-proto',
        'x-forwarded-host',
        'x-burp-interceptor',
        'x-requested-with',
        'via',
        'forwarded',
        'x-real-ip',
        'x-original-for',
        'proxy-connection'
      ],
      
      // Allowed Origins (configure based on your needs)
      allowedOrigins: options.allowedOrigins || []
    };
    
    // Initialize state tracking
    this.clientState = new Map();
    this.requestHistory = new Map();
    this.secretHistory = []; // For secret rotation
    this.activeSecrets = new Map();
    
    // Initialize secret rotation
    this.initializeSecrets();
    this.startSecretRotation();
  }
  
  // ===== Secret Management =====
  initializeSecrets() {
    this.currentSecret = this.config.serverSecret;
    this.secretHistory.push({
      secret: this.currentSecret,
      created: Date.now()
    });
  }
  
  startSecretRotation() {
    if (this.config.secretRotationInterval > 0) {
      setInterval(() => {
        this.rotateSecret();
      }, this.config.secretRotationInterval);
    }
  }
  
  rotateSecret() {
    this.currentSecret = crypto.randomBytes(32).toString('hex');
    this.secretHistory.push({
      secret: this.currentSecret,
      created: Date.now()
    });
    
    // Keep only last 5 secrets for validation
    if (this.secretHistory.length > 5) {
      this.secretHistory = this.secretHistory.slice(-5);
    }
  }
  
  // ===== Request Signing and Validation =====
  generateRequestSignature(req, nonce, timestamp) {
    const payload = {
      method: req.method,
      url: req.originalUrl || req.url,
      timestamp: timestamp,
      nonce: nonce,
      origin: req.get('origin') || '',
      userAgent: req.get('user-agent') || ''
    };
    
    // Create deterministic string from payload
    const payloadString = JSON.stringify(payload, Object.keys(payload).sort());
    
    // Generate HMAC signature
    const hmac = crypto.createHmac('sha256', this.currentSecret);
    hmac.update(payloadString);
    return hmac.digest('hex');
  }
  
  validateSignature(req, signature, nonce, timestamp) {
    // Check against current and recent secrets
    for (const secretEntry of this.secretHistory) {
      const payload = {
        method: req.method,
        url: req.originalUrl || req.url,
        timestamp: timestamp,
        nonce: nonce,
        origin: req.get('origin') || '',
        userAgent: req.get('user-agent') || ''
      };
      
      const payloadString = JSON.stringify(payload, Object.keys(payload).sort());
      const hmac = crypto.createHmac('sha256', secretEntry.secret);
      hmac.update(payloadString);
      const expectedSignature = hmac.digest('hex');
      
      if (crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
        return true;
      }
    }
    return false;
  }
  
  // ===== Client Fingerprinting =====
  generateClientFingerprint(req) {
    const components = [
      req.get('user-agent') || '',
      req.get('accept-language') || '',
      req.get('accept-encoding') || '',
      req.get('accept') || '',
      req.ip || '',
      (req.get('x-forwarded-for') || '').split(',')[0].trim()
    ];
    
    const fingerprintString = components.join('|');
    return crypto.createHash('sha256').update(fingerprintString).digest('hex');
  }
  
  // ===== Proxy Detection =====
  detectProxy(req) {
    const suspiciousIndicators = [];
    
    // Check for suspicious headers
    for (const header of this.config.suspiciousHeaders) {
      if (req.get(header)) {
        suspiciousIndicators.push(`suspicious_header_${header}`);
      }
    }
    
    // Check for multiple X-Forwarded-For entries (proxy chaining)
    const xForwardedFor = req.get('x-forwarded-for');
    if (xForwardedFor && xForwardedFor.split(',').length > 1) {
      suspiciousIndicators.push('proxy_chaining');
    }
    
    // Check for timing inconsistencies (basic check)
    const clientId = this.generateClientFingerprint(req);
    const clientHistory = this.clientState.get(clientId) || [];
    
    if (clientHistory.length > 1) {
      const timingPattern = this.analyzeTimingPattern(clientHistory);
      if (timingPattern.suspicious) {
        suspiciousIndicators.push('timing_anomaly');
      }
    }
    
    return {
      isProxied: suspiciousIndicators.length > 0,
      indicators: suspiciousIndicators,
      confidence: Math.min(suspiciousIndicators.length * 0.3, 1.0)
    };
  }
  
  analyzeTimingPattern(history) {
    if (history.length < 3) return { suspicious: false };
    
    const intervals = [];
    for (let i = 1; i < history.length; i++) {
      intervals.push(history[i].timestamp - history[i-1].timestamp);
    }
    
    // Check for too consistent timing (bot-like behavior)
    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((acc, interval) => acc + Math.pow(interval - avgInterval, 2), 0) / intervals.length;
    const standardDeviation = Math.sqrt(variance);
    
    // Suspicious if timing is too regular (coefficient of variation < 0.1)
    const coefficientOfVariation = standardDeviation / avgInterval;
    
    return {
      suspicious: coefficientOfVariation < 0.1 && avgInterval < 1000,
      variance: variance,
      avgInterval: avgInterval
    };
  }
  
  // ===== Rate Limiting =====
  checkRateLimit(clientId) {
    const now = Date.now();
    const windowStart = now - this.config.requestWindow;
    
    if (!this.requestHistory.has(clientId)) {
      this.requestHistory.set(clientId, []);
    }
    
    const requests = this.requestHistory.get(clientId);
    
    // Remove old requests outside the window
    const validRequests = requests.filter(req => req.timestamp > windowStart);
    
    // Add current request
    validRequests.push({ timestamp: now });
    
    // Update the history
    this.requestHistory.set(clientId, validRequests);
    
    return {
      allowed: validRequests.length <= this.config.maxRequestsPerWindow,
      count: validRequests.length,
      resetTime: windowStart + this.config.requestWindow
    };
  }
  
  // ===== Main Middleware Function =====
  protect(options = {}) {
    return async (req, res, next) => {
      const startTime = Date.now();
      
      try {
        // Generate client fingerprint
        const clientId = this.generateClientFingerprint(req);
        
        // Update client history
        if (!this.clientState.has(clientId)) {
          this.clientState.set(clientId, []);
        }
        const clientHistory = this.clientState.get(clientId);
        clientHistory.push({ timestamp: startTime });
        if (clientHistory.length > 50) {
          clientHistory.shift(); // Keep only recent history
        }
        
        // Proxy detection
        if (this.config.enableAntiProxy) {
          const proxyDetection = this.detectProxy(req);
          if (proxyDetection.isProxied && proxyDetection.confidence > 0.7) {
            return res.status(403).json({
              success: false,
              message: 'Request appears to be proxied',
              code: 'PROXY_DETECTED'
            });
          }
        }
        
        // Rate limiting
        if (this.config.enableRateLimiting) {
          const rateLimitCheck = this.checkRateLimit(clientId);
          if (!rateLimitCheck.allowed) {
            return res.status(429).json({
              success: false,
              message: 'Rate limit exceeded',
              code: 'RATE_LIMITED',
              resetTime: rateLimitCheck.resetTime
            });
          }
        }
        
        // Request signature validation
        if (this.config.enableRequestSigning) {
          const signature = req.get('x-signature');
          const nonce = req.get('x-nonce');
          const timestamp = req.get('x-timestamp');
          
          if (!signature || !nonce || !timestamp) {
            return res.status(400).json({
              success: false,
              message: 'Missing security headers',
              code: 'MISSING_SIGNATURE'
            });
          }
          
          // Timestamp validation
          if (this.config.enableTimestampValidation) {
            const requestTime = parseInt(timestamp);
            const now = Date.now();
            
            if (Math.abs(now - requestTime) > this.config.maxRequestAge) {
              return res.status(400).json({
                success: false,
                message: 'Request timestamp is invalid',
                code: 'INVALID_TIMESTAMP'
              });
            }
          }
          
          // Nonce validation (prevent replay attacks)
          const nonceKey = `${clientId}:${nonce}`;
          if (this.activeSecrets.has(nonceKey)) {
            return res.status(400).json({
              success: false,
              message: 'Nonce has been used',
              code: 'NONCE_REPLAY'
            });
          }
          
          // Validate signature
          if (!this.validateSignature(req, signature, nonce, parseInt(timestamp))) {
            return res.status(401).json({
              success: false,
              message: 'Invalid request signature',
              code: 'INVALID_SIGNATURE'
            });
          }
          
          // Store nonce to prevent replay
          this.activeSecrets.set(nonceKey, Date.now());
          
          // Clean up old nonces
          setTimeout(() => {
            this.activeSecrets.delete(nonceKey);
          }, this.config.maxRequestAge);
        }
        
        // Add security info to response
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        res.setHeader('Content-Security-Policy', "default-src 'self'");
        
        // Add timing information for monitoring
        res.locals.securityInfo = {
          clientId: clientId,
          processingTime: Date.now() - startTime,
          timestamp: startTime
        };
        
        next();
      } catch (error) {
        console.error('Security module error:', error);
        res.status(500).json({
          success: false,
          message: 'Security validation failed',
          code: 'SECURITY_ERROR'
        });
      }
    };
  }
  
  // ===== Client-side Helper =====
  generateClientHeaders(url, method = 'GET') {
    const timestamp = Date.now().toString();
    const nonce = crypto.randomBytes(16).toString('hex');
    
    // This would be implemented on the client side
    // For now, return the structure
    return {
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature': 'PLACEHOLDER_FOR_CLIENT_IMPLEMENTATION'
    };
  }
}

// ===== Export the module =====
module.exports = SecurityModule;
