/* BlueBot Browser Shield - page bridge (ISOLATED world, document_start)
 *
 * Receives detection events from the MAIN-world detector via window.postMessage
 * and forwards them to the service worker. The detector cannot reach
 * chrome.* APIs; only this isolated-world script can.
 *
 * It does not decide policy. The service worker holds config and applies the
 * monitored / excluded / incognito rules.
 */
(function () {
  'use strict';
  if (window.__bbShieldBridge) return;
  window.__bbShieldBridge = true;

  var CHANNEL = '__bb_shield_evt';

  window.addEventListener('message', function (e) {
    // Only accept messages from this same page, carrying our marker
    if (e.source !== window) return;
    var d = e.data;
    if (!d || d.__bbShield !== CHANNEL || typeof d.type !== 'string') return;

    var evt = {
      type: String(d.type).slice(0, 40),
      origin: String(d.origin || '').slice(0, 300),
      is_third_party: d.is_third_party ? 1 : 0,
      is_initial: d.is_initial ? 1 : 0,
      element_type: String(d.element_type || '').slice(0, 20),
      attr_name: String(d.attr_name || '').slice(0, 60),
      method: String(d.method || '').slice(0, 10),
      page_ms: Math.max(0, parseInt(d.page_ms, 10) || 0),
      is_top: d.is_top ? 1 : 0,
      detail: d.detail && typeof d.detail === 'object' ? d.detail : {}
    };

    try {
      chrome.runtime.sendMessage({ kind: 'shield_event', pageHost: location.hostname, event: evt });
    } catch (err) { /* worker asleep or context gone; event is best-effort */ }
  }, true);
})();
