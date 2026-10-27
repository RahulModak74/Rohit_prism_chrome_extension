# BlueBot Browser Shield — everything in one place

Enterprise browser extension. Protects an organisation's employees across every
site. Separate from the website pixel (`/track` → `tracking10`). This writes
only to `shield_events` via `/collect`.

Extension ID used below: `oledlpaekbcdpoeajacbdhjngoldpcjo`
Server: `https://battery.bluebotanalytics.com`

---

## Files in this bundle

Extension (unzip to `C:\bluebot-ext\` on Windows):
- manifest.json, detector.js, bridge.js, sw.js, schema.json,
  popup.html, popup.js, icon16.png, icon48.png, icon128.png

Server (Linux):
- collect_route.js    — paste into the Node server
- shield_schema.sql   — run once in ClickHouse

Windows helper:
- bluebot-policy.reg  — double-click to turn the extension on

---

## A. Server (Linux) — once

1. Create the table (fresh install):
```bash
clickhouse-client --multiquery < shield_schema.sql
```

2. In the Node server, with the other `app.use(...)` lines:
```js
app.set('trust proxy', 'loopback');
app.use('/collect', express.json({ limit: '5mb' }));
```

3. Paste the body of `collect_route.js` next to the `/track` route (above any
   catch-all route). Restart Node.

4. Verify (expect `204`):
```bash
curl -i -X POST https://battery.bluebotanalytics.com/collect \
  -H "Content-Type: application/json" \
  -d '{"orgId":"test","userId":"x","events":[{"ts":"2026-10-16T00:00:00Z","type":"page_start"}]}'
```

---

## B. Extension (Windows) — once

1. Unzip all 10 files into `C:\bluebot-ext\`.
2. `chrome://extensions` → Developer mode ON → Load unpacked → pick the folder.
3. Confirm the ID is `oledlpaekbcdpoeajacbdhjngoldpcjo`. If yours differs, edit
   bluebot-policy.reg and replace the ID.

---

## C. Turn it on (Windows) — the easy way

1. Double-click **bluebot-policy.reg**.
2. Click **Yes**, then **OK**.
3. Quit Chrome fully, reopen.
4. Extension popup → **Active**.

That's it. It sets orgId, serverUrl, and full-URL capture on.

(If you ever need to change a setting, edit bluebot-policy.reg in Notepad and
double-click again.)

---

## D. Test

Browse a few sites, then on Linux:
```bash
clickhouse-client -q "SELECT event_type, page, referrer, device_fp, origin, severity, timestamp FROM shield_events WHERE user_id='self-test' ORDER BY timestamp DESC LIMIT 20"
```

---

## E. Updating the extension later

After editing any extension file: `chrome://extensions` → click the refresh
arrow on the card. No need to touch the registry again.

---

## What is collected
- Always: security events (injected scripts, iframes, exfil requests, form
  hijack, CSP violations), bot signals, device_fp, page URL.
- With the provided .reg (collectFullUrl on): full URL + referrer.
- Never: page content, form values, cookies, excluded personal domains,
  incognito.

## Before deploying to anyone else
Employee notice, data-retention limit, customer DPA — reviewed by counsel.
Enterprise managed-device tool. Not for consumer install.
