/* BlueBot Browser Shield - service worker (policy brain + transport)
 *
 * Responsibilities:
 *   1. Load managed policy. Stay INACTIVE until an orgId is present, so a
 *      manually-installed copy collects and sends nothing.
 *   2. Apply exclusions: personal domains, and incognito unless allowed.
 *   3. Minimise: send origins + event metadata only; full URLs only if policy
 *      explicitly turns them on.
 *   4. Batch and POST to the org's ingest endpoint.
 *   5. Periodic posture: installed extensions (chrome.management).
 *
 * Never sends: page content, form values, cookies, full browsing unless the
 * org enables full URLs.
 */
'use strict';

var POLICY = null;         // { orgId, userId, serverUrl, allowlist:Set, personal:Set, collectFullUrl, monitorIncognito }
var QUEUE = [];
var MAX_QUEUE = 500;
var FLUSH_MS = 15000;
var SESSION_SALT = Math.random().toString(36).slice(2) + Date.now();

// ---- registrable-ish domain (no public-suffix list; good enough for exclusion) ----
function regDomain(host) {
  host = (host || '').toLowerCase().replace(/^www\./, '');
  var p = host.split('.');
  return p.length <= 2 ? host : p.slice(-2).join('.');
}

function loadPolicy() {
  return new Promise(function (resolve) {
    chrome.storage.managed.get(null, function (cfg) {
      cfg = cfg || {};
      if (!cfg.orgId || !cfg.serverUrl) { POLICY = null; resolve(null); return; }
      POLICY = {
        orgId: String(cfg.orgId),
        userId: String(cfg.userId || 'unknown'),
        serverUrl: String(cfg.serverUrl),
        allowlist: new Set((cfg.allowlistOrigins || []).map(String)),
        personal: new Set((cfg.personalDomains || []).map(function (d) { return regDomain(String(d)); })),
        collectFullUrl: !!cfg.collectFullUrl,
        monitorIncognito: !!cfg.monitorIncognito
      };
      resolve(POLICY);
    });
  });
}

function excludedHost(host) {
  if (!POLICY) return true;
  return POLICY.personal.has(regDomain(host));
}

function enqueue(rec) {
  if (!POLICY) return;
  if (QUEUE.length >= MAX_QUEUE) QUEUE.shift();
  QUEUE.push(rec);
  if (rec.severity === 'high') flush();
}

function flush() {
  if (!POLICY || QUEUE.length === 0) return;
  var batch = QUEUE.splice(0, QUEUE.length);
  var body = JSON.stringify({
    orgId: POLICY.orgId,
    userId: POLICY.userId,
    sentAt: new Date().toISOString(),
    agent: 'shield-ext/1.0.0',
    events: batch
  });
  fetch(POLICY.serverUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body,
    keepalive: body.length < 60000
  }).catch(function () {
    // put a trimmed remainder back so a transient failure is not total loss
    if (QUEUE.length < MAX_QUEUE) QUEUE = batch.slice(-100).concat(QUEUE);
  });
}

// High severity = acted on in real time; the rest ride the batch.
var HIGH = { script_added: 1, iframe_added: 1, form_retarget: 1, javascript_url: 1, inline_handler: 1, csp_violation: 1, prehooked_api: 1 };

function severityFor(evt) {
  if (evt.type === 'form_submit' && evt.is_third_party && evt.detail && evt.detail.sensitive) return 'high';
  if (HIGH[evt.type] && (evt.is_third_party || evt.origin === 'inline' || String(evt.origin).indexOf('prehook:') === 0)) return 'high';
  return 'info';
}

chrome.runtime.onMessage.addListener(function (msg, sender) {
  if (!POLICY || !msg || msg.kind !== 'shield_event') return;
  var tab = sender.tab;
  if (tab && tab.incognito && !POLICY.monitorIncognito) return;

  var host = msg.pageHost || (sender.url ? new URL(sender.url).hostname : '');
  if (!host || excludedHost(host)) return;

  var e = msg.event;
  var det = e.detail || {};

  // Minimise: unless the org enabled full URLs, keep only the page's registrable domain.
  var fullUrl = det.full_url || sender.url || '';
  var pageRef = POLICY.collectFullUrl ? fullUrl : regDomain(host);
  // Referrer only travels when the org turned full URLs on.
  var referrer = POLICY.collectFullUrl ? (det.referrer || '') : '';

  // Novelty against the org allowlist (origin only)
  var novel = e.origin && e.is_third_party && !POLICY.allowlist.has(e.origin) ? 1 : 0;

  enqueue({
    ts: new Date().toISOString(),
    page: pageRef,
    referrer: referrer,
    device_fp: det.device_fp || '',
    frame_is_top: e.is_top,
    type: e.type,
    origin: e.origin,
    is_third_party: e.is_third_party,
    is_initial: e.is_initial,
    novel: novel,
    element_type: e.element_type,
    attr_name: e.attr_name,
    method: e.method,
    detail: e.detail,
    severity: severityFor(e)
  });
});

// ---- posture: other installed extensions (weekly + on install) ----
function scanExtensions() {
  if (!POLICY || !chrome.management || !chrome.management.getAll) return;
  chrome.management.getAll(function (list) {
    var items = (list || []).filter(function (x) { return x.type === 'extension' && x.id !== chrome.runtime.id; })
      .map(function (x) {
        return { id: x.id, name: String(x.name).slice(0, 120), enabled: x.enabled ? 1 : 0, from_store: x.installType === 'normal' ? 1 : 0, install_type: x.installType, perms: (x.permissions || []).slice(0, 40) };
      });
    enqueue({ ts: new Date().toISOString(), type: 'extension_inventory', severity: 'info', detail: { count: items.length, items: items } });
    flush();
  });
}

// ---- lifecycle ----
chrome.runtime.onInstalled.addListener(function () { loadPolicy().then(function () { scanExtensions(); }); });
chrome.runtime.onStartup.addListener(function () { loadPolicy(); });
chrome.storage.onChanged.addListener(function (_c, area) { if (area === 'managed') loadPolicy(); });

chrome.alarms.create('flush', { periodInMinutes: 0.5 });
chrome.alarms.create('posture', { periodInMinutes: 60 * 24 * 7 });
chrome.alarms.onAlarm.addListener(function (a) {
  if (a.name === 'flush') flush();
  else if (a.name === 'posture') scanExtensions();
});

loadPolicy();
