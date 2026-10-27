/* Popup: shows the user, in plain terms, whether the shield is active and what
 * it collects. Transparency is a requirement for a monitoring tool, not a nicety.
 */
chrome.storage.managed.get(null, function (cfg) {
  cfg = cfg || {};
  var active = !!(cfg.orgId && cfg.serverUrl);
  var s = document.getElementById('status');
  s.textContent = active ? 'Active' : 'Inactive';
  s.className = 'pill ' + (active ? 'on' : 'off');
  document.getElementById('org').textContent = cfg.orgId || '—';
  document.getElementById('full').textContent = cfg.collectFullUrl ? 'On' : 'Off (domain only)';
  document.getElementById('excl').textContent = (cfg.personalDomains || []).length + ' domains';
  document.getElementById('note').textContent = active
    ? 'Deployed by your IT team on this managed device. It records security signals (injected scripts, suspicious requests, risky logins) as domains and event metadata. It does not capture page content, passwords, or your personal browsing on excluded domains.'
    : 'No managed policy found. The shield is inactive and collects nothing. It only activates when deployed by an organisation through managed browser policy.';
});
