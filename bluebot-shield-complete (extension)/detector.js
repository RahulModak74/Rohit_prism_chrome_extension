/* BlueBot Browser Shield - page detector (MAIN world, document_start)
 *
 * Runs in the page's own JS context BEFORE any page script, so skimmers cannot
 * hook fetch/XHR ahead of us. It reuses the pixel's detection logic.
 *
 * It holds NO config and NO identifiers. It only emits detection events to the
 * isolated-world bridge via window.postMessage. The bridge decides, per managed
 * policy, whether this page is monitored and what may leave the device.
 *
 * Privacy: this script sends origins and event metadata, never page content,
 * form values, or cookies.
 */
(function () {
  'use strict';
  if (window.__bbShieldDetector) return;
  window.__bbShieldDetector = true;

  var CHANNEL = '__bb_shield_evt';
  var PAGE_START = Date.now();
  var PAGE_HOST = location.hostname.replace(/^www\./, '');
  var OWN = location.origin;

  // Native refs captured before anything (ours or an attacker's) can wrap them
  var NATIVE = {
    fetch: window.fetch ? window.fetch.bind(window) : null,
    postMessage: window.postMessage.bind(window)
  };

  var seen = {};
  function once(k) { if (seen[k]) return false; seen[k] = 1; return true; }
  function trunc(s, n) { s = (s == null ? '' : String(s)); return s.length > n ? s.slice(0, n) : s; }

  function emit(type, f) {
    f = f || {};
    try {
      NATIVE.postMessage({
        __bbShield: CHANNEL,
        type: type,
        origin: f.origin || '',
        is_third_party: f.is_third_party ? 1 : 0,
        is_initial: f.is_initial ? 1 : 0,
        element_type: f.element_type || '',
        attr_name: f.attr_name || '',
        method: f.method || '',
        page_ms: Date.now() - PAGE_START,
        is_top: (window.top === window) ? 1 : 0,
        detail: f.detail || {}
      }, OWN);
    } catch (e) { }
  }

  function originOf(u) {
    if (!u) return '';
    try {
      var x = new URL(String(u), location.href);
      if (/^(https?|wss?):$/.test(x.protocol)) return x.protocol + '//' + x.host;
      return x.protocol;
    } catch (e) { return ''; }
  }
  function hostOf(o) { var m = /^[a-z]+:\/\/([^\/:]+)/i.exec(o || ''); return m ? m[1].toLowerCase() : ''; }
  function isThirdParty(o) {
    var h = hostOf(o); if (!h) return 0;
    h = h.replace(/^www\./, '');
    if (h === PAGE_HOST) return 0;
    if (h.slice(-(PAGE_HOST.length + 1)) === '.' + PAGE_HOST) return 0;
    if (PAGE_HOST.slice(-(h.length + 1)) === '.' + h) return 0;
    return 1;
  }
  function isOwn(o) { return o === OWN; }
  function fnv1a(s) {
    var h = 0x811c9dc5;
    for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0; }
    return ('0000000' + h.toString(16)).slice(-8);
  }

  // Device fingerprint: canvas + WebGL + stable environment, hashed.
  // No localStorage id, so it survives storage wipes - useful for spotting a
  // bot or hijack where the same device appears under a new session.
  function deviceFingerprint() {
    var parts = [];
    try {
      parts.push(navigator.userAgent, navigator.platform, (navigator.languages || []).join(','),
        screen.width + 'x' + screen.height, screen.colorDepth, navigator.hardwareConcurrency || 0,
        navigator.deviceMemory || 0, new Date().getTimezoneOffset(), navigator.maxTouchPoints || 0);
    } catch (e) { }
    try {
      var c = document.createElement('canvas'); var x = c.getContext('2d');
      x.textBaseline = 'top'; x.font = "14px 'Arial'"; x.fillStyle = '#f60'; x.fillRect(125, 1, 62, 20);
      x.fillStyle = '#069'; x.fillText('BB,shield!', 2, 15);
      parts.push(c.toDataURL());
    } catch (e) { parts.push('nocanvas'); }
    try {
      var gl = document.createElement('canvas').getContext('webgl');
      var dbg = gl && gl.getExtension('WEBGL_debug_renderer_info');
      if (dbg) parts.push(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL), gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL));
    } catch (e) { }
    return fnv1a(parts.join('|'));
  }

  // ---- load-order integrity: were our targets already wrapped? ----
  function isNative(fn) {
    try { return typeof fn === 'function' && /\{\s*\[native code\]\s*\}\s*$/.test(Function.prototype.toString.call(fn)); }
    catch (e) { return true; }
  }
  (function preHooks() {
    var apis = {};
    try { apis.fetch = window.fetch; } catch (e) { }
    try { apis.xhr_open = XMLHttpRequest.prototype.open; } catch (e) { }
    try { apis.send_beacon = navigator.sendBeacon; } catch (e) { }
    try { apis.form_submit = HTMLFormElement.prototype.submit; } catch (e) { }
    for (var n in apis) if (apis[n] && !isNative(apis[n])) emit('prehooked_api', { origin: 'prehook:' + n, attr_name: n, is_initial: 1 });
  })();

  // ---- network / exfil hooks ----
  function noteRequest(api, url, method) {
    var o = originOf(url);
    if (!/^(https?|wss?):\/\//.test(o) || isOwn(o) || !isThirdParty(o)) return;
    if (!once('net|' + api + '|' + method + '|' + o)) return;
    emit('network_request', { origin: o, is_third_party: 1, method: method, attr_name: api });
  }
  try {
    if (window.fetch) {
      var of = window.fetch;
      window.fetch = function (i, init) {
        try { var u = typeof i === 'string' ? i : (i && i.url) || String(i); noteRequest('fetch', u, ((init && init.method) || 'GET').toUpperCase()); } catch (e) { }
        return of.apply(this, arguments);
      };
    }
    var oo = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (m, u) { try { noteRequest('xhr', u, String(m || 'GET').toUpperCase()); } catch (e) { } return oo.apply(this, arguments); };
    if (navigator.sendBeacon) { var ob = navigator.sendBeacon.bind(navigator); navigator.sendBeacon = function (u, d) { try { noteRequest('beacon', u, 'BEACON'); } catch (e) { } return ob(u, d); }; }
  } catch (e) { }

  // ---- form submit (credential destination, not values) ----
  var SENS = 'input[type="password"],input[autocomplete^="cc-"],input[name*="card" i],input[name*="cvv" i]';
  function noteSubmit(form) {
    try {
      var action = form.getAttribute('action');
      var o = action ? originOf(form.action) : OWN;
      emit('form_submit', {
        element_type: 'FORM', origin: o, is_third_party: isThirdParty(o),
        method: (form.getAttribute('method') || 'GET').toUpperCase(),
        detail: { sensitive: form.querySelector(SENS) ? 1 : 0 }
      });
    } catch (e) { }
  }
  try {
    document.addEventListener('submit', function (e) { if (e.target && e.target.nodeName === 'FORM') noteSubmit(e.target); }, true);
    var os = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function () { noteSubmit(this); return os.apply(this, arguments); };
  } catch (e) { }

  // ---- CSP violations ----
  try {
    document.addEventListener('securitypolicyviolation', function (e) {
      var blocked = e.blockedURI || '';
      var o = /^(https?|wss?):/.test(blocked) ? originOf(blocked) : blocked;
      if (isOwn(o) || !once('csp|' + e.violatedDirective + '|' + o)) return;
      emit('csp_violation', { origin: o, is_third_party: isThirdParty(o), attr_name: e.violatedDirective || '', detail: { disposition: e.disposition || '' } });
    }, true);
  } catch (e) { }

  // ---- DOM: injected scripts / iframes / password fields ----
  function handleEl(el, initial) {
    var tag = el.nodeName, o, src;
    if (tag === 'SCRIPT') {
      src = el.getAttribute('src');
      if (src) {
        o = originOf(src); if (isOwn(o)) return;
        emit(initial ? 'script_present' : 'script_added', { element_type: 'SCRIPT', origin: o, is_third_party: isThirdParty(o), is_initial: initial, detail: { integrity: el.integrity ? 1 : 0 } });
      } else if (!initial) {
        var code = el.textContent || '';
        emit('script_added', { element_type: 'SCRIPT', origin: 'inline', detail: { hash: fnv1a(code), len: code.length } });
      }
      return;
    }
    if (tag === 'IFRAME' || tag === 'FRAME') {
      src = el.getAttribute('src') || '';
      o = el.hasAttribute('srcdoc') ? 'srcdoc' : (src ? originOf(src) : 'about:');
      if (isOwn(o)) return;
      emit(initial ? 'iframe_present' : 'iframe_added', { element_type: tag, origin: o, is_third_party: isThirdParty(o), is_initial: initial, detail: { hidden: (el.offsetWidth === 0 && el.offsetHeight === 0) ? 1 : 0 } });
      return;
    }
    if (!initial && tag === 'INPUT' && (el.getAttribute('type') || '').toLowerCase() === 'password') {
      emit('password_field_added', { element_type: 'INPUT' });
    }
  }
  function parsing() { return document.readyState === 'loading'; }
  function onAdded(node) {
    if (!node || node.nodeType !== 1) return;
    var init = parsing();
    if (node.matches && node.matches('script,iframe,frame,input')) handleEl(node, init);
    if (node.querySelectorAll && node.firstElementChild) {
      var inner = node.querySelectorAll('script,iframe,frame,input[type="password"]');
      for (var i = 0; i < inner.length && i < 50; i++) handleEl(inner[i], init);
    }
  }
  try {
    new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) {
        var m = muts[i];
        if (m.type === 'childList') for (var a = 0; a < m.addedNodes.length; a++) onAdded(m.addedNodes[a]);
        else if (m.type === 'attributes') {
          var el = m.target, name = (m.attributeName || '').toLowerCase(), v = el.getAttribute(name);
          if (name.indexOf('on') === 0 && v) emit('inline_handler', { element_type: el.nodeName, attr_name: name });
          else if (/^(src|href|action|formaction)$/.test(name) && v && /^\s*javascript:/i.test(v)) emit('javascript_url', { element_type: el.nodeName, attr_name: name });
          else if ((name === 'action' || name === 'formaction') && isThirdParty(originOf(v))) emit('form_retarget', { element_type: el.nodeName, attr_name: name, origin: originOf(v), is_third_party: 1 });
        }
      }
    }).observe(document, { childList: true, subtree: true, attributes: true, attributeFilter: ['src', 'href', 'action', 'formaction', 'onclick', 'onload', 'onerror', 'onsubmit', 'onmouseover', 'sandbox', 'integrity'] });
  } catch (e) { }

  function inventory() {
    try { var els = document.querySelectorAll('script[src],iframe,frame'); for (var i = 0; i < els.length && i < 100; i++) handleEl(els[i], true); } catch (e) { }
  }
  emit('page_start', {
    element_type: 'DOC', is_initial: 1,
    detail: {
      ready: document.readyState,
      device_fp: (window.top === window) ? deviceFingerprint() : '',  // top frame only
      full_url: location.href,
      referrer: document.referrer || ''
    }
  });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', inventory);
  else inventory();
})();
