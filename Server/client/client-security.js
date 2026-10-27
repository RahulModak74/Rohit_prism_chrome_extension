// ===== Client-side Security Module =====
// Protects AJAX requests and forms from proxy manipulation

class ClientSecurity {
  constructor(options = {}) {
    this.config = {
      // Security settings
      enableRequestSigning: options.enableRequestSigning !== false,
      enableAntiInspection: options.enableAntiInspection !== false,
      enableIntegrityChecks: options.enableIntegrityChecks !== false,
      
      // Detection settings
      detectProxyTools: options.detectProxyTools !== false,
      enableTimingChecks: options.enableTimingChecks !== false,
      
      // Server communication
      serverEndpoint: options.serverEndpoint || '/api/security-challenge',
      secretKey: null // Will be fetched from server
    };
    
    this.state = {
      isSecure: false,
      proxyDetected: false,
      lastRequestTime: 0,
      requestCounter: 0,
      securityToken: null,
      cryptoSubtleAvailable: false
    };
    
    this.initialize();
  }
  
  // ===== Initialization =====
  async initialize() {
    // Check if crypto.subtle is available
    this.state.cryptoSubtleAvailable = this.checkCryptoSubtleAvailability();
    
    if (!this.state.cryptoSubtleAvailable) {
      console.warn('crypto.subtle not available. Running in HTTP mode - request signing disabled.');
      this.config.enableRequestSigning = false;
      this.config.enableIntegrityChecks = false;
    }
    
    // Check for proxy tools
    this.detectProxyEnvironment();
    
    // Set up event listeners
    this.setupEventListeners();
    
    // Initialize security token
    await this.initializeSecurityToken();
    
    // Start monitoring
    this.startMonitoring();
  }
  
  // Check if crypto.subtle is available
  checkCryptoSubtleAvailability() {
    return (
      typeof window !== 'undefined' &&
      window.crypto &&
      window.crypto.subtle &&
      typeof window.crypto.subtle.digest === 'function'
    );
  }
  
  // ===== Proxy Detection =====
  detectProxyEnvironment() {
    const indicators = [];
    
    try {
      // Check for common proxy headers in environment
      const userAgent = navigator.userAgent;
      if (userAgent.includes('Burp') || userAgent.includes('OWASP ZAP')) {
        indicators.push('proxy_user_agent');
      }
      
      // Check for unusual window properties
      if (window.BurpExtender || window.BurpSuite) {
        indicators.push('burp_extension_detected');
      }
      
      // Check for timing anomalies
      const start = performance.now();
      for (let i = 0; i < 1000; i++) {
        Math.random();
      }
      const duration = performance.now() - start;
      
      if (duration > 10) { // Unusually slow for simple operations
        indicators.push('execution_timing_anomaly');
      }
      
      // Check for common proxy ports in referrer
      const referrer = document.referrer;
      if (referrer && (referrer.includes(':8080') || referrer.includes(':8081'))) {
        indicators.push('proxy_port_detected');
      }
      
    } catch (error) {
      console.warn('Security check error:', error);
    }
    
    this.state.proxyDetected = indicators.length > 0;
    return indicators;
  }
  
  // ===== Request Signing (only if crypto.subtle available) =====
  async generateSignature(url, method, body = null, timestamp, nonce) {
    if (!this.state.cryptoSubtleAvailable) {
      // Return a simple hash for HTTP mode
      return this.simpleHash(url + method + timestamp + nonce);
    }
    
    // Create payload for signing
    const payload = {
      method: method.toUpperCase(),
      url: url,
      timestamp: timestamp,
      nonce: nonce,
      origin: window.location.origin,
      userAgent: navigator.userAgent
    };
    
    // Add body hash if present
    if (body) {
      const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
      payload.bodyHash = await this.hashString(bodyStr);
    }
    
    // Create deterministic string
    const payloadString = JSON.stringify(payload, Object.keys(payload).sort());
    
    // Generate signature
    return await this.hashString(payloadString + (this.config.secretKey || ''));
  }
  
  async hashString(str) {
    if (this.state.cryptoSubtleAvailable) {
      const msgUint8 = new TextEncoder().encode(str);
      const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } else {
      // Fallback simple hash for HTTP mode
      return this.simpleHash(str);
    }
  }
  
  // Simple hash function for HTTP mode
  simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16);
  }
  
  // ===== Secure Request Wrapper =====
  async secureRequest(url, options = {}) {
    const method = options.method || 'GET';
    const body = options.body;
    
    // Generate security headers
    const timestamp = Date.now();
    const nonce = this.generateNonce();
    
    // Create headers object
    const headers = {
      ...options.headers,
      'X-Timestamp': timestamp.toString(),
      'X-Nonce': nonce,
      'X-Request-ID': this.generateRequestId(),
      'X-Client-Type': 'web_browser',
      'X-Security-Token': this.state.securityToken
    };
    
    // Only add signature if crypto.subtle is available and signing is enabled
    if (this.state.cryptoSubtleAvailable && this.config.enableRequestSigning) {
      const signature = await this.generateSignature(url, method, body, timestamp, nonce);
      headers['X-Signature'] = signature;
    }
    
    // Add anti-tampering checks if available
    if (this.config.enableIntegrityChecks && this.state.cryptoSubtleAvailable) {
      headers['X-Client-Integrity'] = await this.generateIntegrityCheck();
    }
    
    // Create secure request options
    const secureOptions = {
      ...options,
      headers: headers,
      credentials: 'same-origin',
      cache: 'no-cache'
    };
    
    // Perform timing analysis
    const startTime = performance.now();
    
    try {
      // Use the original fetch to avoid recursion
      const response = await (window.originalFetch || fetch)(url, secureOptions);
      
      // Analyze response timing
      const endTime = performance.now();
      this.analyzeTiming(endTime - startTime);
      
      // Verify response integrity if enabled
      if (response.ok && this.config.enableIntegrityChecks && this.state.cryptoSubtleAvailable) {
        const responseIntegrity = response.headers.get('X-Response-Integrity');
        if (responseIntegrity && !await this.verifyResponseIntegrity(response, responseIntegrity)) {
          throw new Error('Response integrity check failed');
        }
      }
      
      this.state.lastRequestTime = Date.now();
      this.state.requestCounter++;
      
      return response;
    } catch (error) {
      console.error('Secure request failed:', error);
      throw error;
    }
  }
  
  // ===== Utility Functions =====
  generateNonce() {
    if (this.state.cryptoSubtleAvailable && window.crypto && window.crypto.getRandomValues) {
      const array = new Uint8Array(16);
      crypto.getRandomValues(array);
      return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    } else {
      // Fallback for HTTP mode
      return Math.random().toString(16).substring(2, 18);
    }
  }
  
  generateRequestId() {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
  
  async generateIntegrityCheck() {
    if (!this.state.cryptoSubtleAvailable) {
      return this.simpleHash(window.location.href + navigator.userAgent + Date.now());
    }
    
    // Generate a hash of critical page elements
    const elements = [
      window.location.href,
      document.title,
      navigator.userAgent,
      Date.now().toString()
    ];
    
    const combined = elements.join('|');
    return await this.hashString(combined);
  }
  
  async verifyResponseIntegrity(response, expectedIntegrity) {
    if (!this.state.cryptoSubtleAvailable) {
      return true; // Skip verification in HTTP mode
    }
    
    try {
      const responseText = await response.clone().text();
      const calculatedIntegrity = await this.hashString(responseText);
      return calculatedIntegrity === expectedIntegrity;
    } catch (error) {
      console.error('Integrity verification failed:', error);
      return false;
    }
  }
  
  // ===== Timing Analysis =====
  analyzeTiming(requestTime) {
    if (!this.config.enableTimingChecks) return;
    
    // Check for unusual request times (could indicate proxy)
    if (requestTime > 5000) { // More than 5 seconds
      console.warn('Unusually slow request detected:', requestTime);
      this.state.proxyDetected = true;
    }
    
    // Check for request patterns
    const timeSinceLastRequest = Date.now() - this.state.lastRequestTime;
    if (timeSinceLastRequest < 100 && this.state.requestCounter > 0) {
      console.warn('Rapid sequential requests detected');
    }
  }
  
  // ===== Anti-Inspection =====
  enableAntiInspection() {
    if (!this.config.enableAntiInspection) return;
    
    // Detect developer tools
    let devtools = {open: false, orientation: null};
    const threshold = 160;
    
    setInterval(() => {
      if (window.outerHeight - window.innerHeight > threshold || 
          window.outerWidth - window.innerWidth > threshold) {
        if (!devtools.open) {
          devtools.open = true;
          console.warn('Developer tools detected');
          this.handleSecurityViolation('devtools_detected');
        }
      } else {
        devtools.open = false;
      }
    }, 500);
    
    // Detect console access
    const originalLog = console.log;
    console.log = function() {
      if (arguments.length > 0 && typeof arguments[0] === 'string') {
        if (arguments[0].includes('security') || arguments[0].includes('token')) {
          console.warn('Suspicious console access detected');
        }
      }
      originalLog.apply(console, arguments);
    };
  }
  
  // ===== Event Listeners =====
  setupEventListeners() {
    // Intercept form submissions with better priority handling
    document.addEventListener('submit', async (event) => {
      const form = event.target;
      
      // Check if form has data-secure attribute
      if (form.hasAttribute('data-secure')) {
        // Check if form already has a custom handler by looking for existing event listeners
        // If form has an ID, check if there are custom handlers attached
        if (form.id && form.id !== '') {
          // Look for existing handlers - if found, let them run first
          const hasCustomHandler = this.checkForCustomHandlers(form);
          if (hasCustomHandler) {
            // Don't prevent default - let custom handler run
            // The custom handler should call preventDefault if needed
            return;
          }
        }
        
        // No custom handler found, use our secure form submission
        event.preventDefault();
        await this.secureFormSubmit(form);
      }
      // Let other forms submit normally
    });
    
    // Monitor for suspicious activities (reduced logging frequency)
    document.addEventListener('contextmenu', (event) => {
      this.logSecurityEvent('right_click', { target: event.target.tagName });
    });
    
    // Monitor for copy/paste operations on sensitive fields
    document.addEventListener('paste', (event) => {
      const target = event.target;
      if (target.type === 'password' || target.hasAttribute('data-sensitive')) {
        this.logSecurityEvent('paste_sensitive_field');
      }
    });
  }
  
  // Check if a form has custom handlers attached
  checkForCustomHandlers(form) {
    // Check common patterns for custom handlers
    if (form.id === 'loginForm' || form.id === 'signupForm') {
      return true; // These typically have custom handlers
    }
    
    // Check if form has onsubmit attribute
    if (form.getAttribute('onsubmit')) {
      return true;
    }
    
    // Check for event listeners (this is limited but helps)
    return false;
  }
  
  // ===== Secure Form Submission =====
  async secureFormSubmit(form) {
    const formData = new FormData(form);
    const url = form.action || window.location.href;
    const method = (form.method || 'POST').toUpperCase();
    
    // Handle GET requests differently - append data as query parameters
    if (method === 'GET') {
      const params = new URLSearchParams();
      formData.forEach((value, key) => {
        params.append(key, value);
      });
      
      const finalUrl = url + (url.includes('?') ? '&' : '?') + params.toString();
      
      try {
        const response = await this.secureRequest(finalUrl, {
          method: 'GET',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          }
          // No body for GET requests
        });
        
        if (response.ok) {
          // For GET requests, usually redirect or show content
          const result = await response.text();
          window.location.href = response.url;
        } else {
          this.handleFormError(form, response);
        }
      } catch (error) {
        this.handleFormError(form, error);
      }
    } else {
      // Handle POST, PUT, etc. - convert FormData to JSON
      const data = {};
      formData.forEach((value, key) => {
        data[key] = value;
      });
      
      try {
        const response = await this.secureRequest(url, {
          method: method,
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(data)
        });
        
        if (response.ok) {
          const result = await response.json();
          this.handleFormResponse(form, result);
        } else {
          this.handleFormError(form, response);
        }
      } catch (error) {
        this.handleFormError(form, error);
      }
    }
  }
  
  // ===== Response Handlers =====
  handleFormResponse(form, result) {
    // Handle successful form submission
    if (result.redirect) {
      window.location.href = result.redirect;
    } else if (result.message) {
      this.showMessage(result.message, 'success');
    }
  }
  
  handleFormError(form, error) {
    const message = error.message || 'An error occurred';
    this.showMessage(message, 'error');
  }
  
  showMessage(message, type) {
    // Create and show a message to the user
    const messageEl = document.createElement('div');
    messageEl.className = `message ${type}`;
    messageEl.textContent = message;
    messageEl.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 10px 20px;
      background: ${type === 'error' ? '#f44336' : '#4caf50'};
      color: white;
      border-radius: 4px;
      z-index: 10000;
    `;
    
    document.body.appendChild(messageEl);
    
    setTimeout(() => {
      messageEl.remove();
    }, 5000);
  }
  
  // ===== Security Event Handling =====
  logSecurityEvent(eventType, data = {}) {
    const event = {
      type: eventType,
      timestamp: Date.now(),
      url: window.location.href,
      userAgent: navigator.userAgent,
      ...data
    };
    
    // Send to server for logging
    this.secureRequest('/api/security-event', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(event)
    }).catch(error => {
      console.warn('Failed to log security event:', error);
    });
  }
  
  handleSecurityViolation(violationType) {
    this.logSecurityEvent('security_violation', { violation: violationType });
    
    // Take action based on violation
    switch (violationType) {
      case 'devtools_detected':
        // Could disable functionality or redirect
        break;
      case 'proxy_detected':
        // Show warning or restrict access
        this.showMessage('Proxy detected. Some features may be restricted.', 'error');
        break;
    }
  }
  
  // ===== Monitoring =====
  startMonitoring() {
    // Periodic security checks
    setInterval(() => {
      this.performSecurityCheck();
    }, 30000); // Every 30 seconds
  }
  
  async performSecurityCheck() {
    // Check for environmental changes
    const currentIndicators = this.detectProxyEnvironment();
    
    if (currentIndicators.length > 0 && !this.state.proxyDetected) {
      this.state.proxyDetected = true;
      this.handleSecurityViolation('proxy_detected');
    }
    
    // Verify security token
    if (this.state.securityToken) {
      try {
        const response = await this.secureRequest('/api/verify-token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ token: this.state.securityToken })
        });
        
        if (!response.ok) {
          console.warn('Security token validation failed');
          await this.initializeSecurityToken();
        }
      } catch (error) {
        console.error('Security check failed:', error);
      }
    }
  }
  
  // ===== Token Management =====
  async initializeSecurityToken() {
    try {
      const response = await fetch('/api/security-token', {
        method: 'GET',
        credentials: 'same-origin'
      });
      
      if (response.ok) {
        const data = await response.json();
        this.state.securityToken = data.token;
        this.config.secretKey = data.secretKey;
      }
    } catch (error) {
      console.warn('Failed to initialize security token:', error);
    }
  }
}

// ===== Auto-initialization =====
document.addEventListener('DOMContentLoaded', () => {
  // Initialize client security
  window.clientSecurity = new ClientSecurity({
    enableRequestSigning: false,  // Disabled for HTTP mode
    enableAntiInspection: true,
    enableIntegrityChecks: false, // Disabled for HTTP mode
    detectProxyTools: true,
    enableTimingChecks: true
  });
  
  // DO NOT override fetch globally - it causes recursion
  // Instead, manually use clientSecurity.secureRequest() where needed
  console.log('Client security initialized in HTTP mode');
});

// ===== Export =====
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ClientSecurity;
}