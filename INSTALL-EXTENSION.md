# BlueBot Browser Shield — Install Guide

Enterprise browser extension. Runs on a managed Windows device, reports security
events to the BlueBot server, and shows up in the dashboard under **Browser Shield**.

- **Extension ID:** `oledlpaekbcdpoeajacbdhjngoldpcjo`
- **Server:** `https://battery.bluebotanalytics.com`
- **Data lands in:** `shield_events` (ClickHouse)

The extension does **nothing** until a managed policy gives it an `orgId`. A
hand-installed copy with no policy stays inactive and sends nothing.

---

## A. Server side (Linux) — do once

1. Create the table:
   ```bash
   clickhouse-client --multiquery < shield_schema.sql
   ```
2. In the Node server, with the other `app.use(...)` lines:
   ```js
   app.set('trust proxy', 'loopback');
   app.use('/collect', express.text({ type: '*/*', limit: '20mb' }));
   ```
3. Paste `collect_route.js` into the server, above any catch-all route. Restart Node.
4. Check it is live (expect `204`):
   ```bash
   curl -i -X POST https://battery.bluebotanalytics.com/collect \
     -H "Content-Type: application/json" \
     -d '{"orgId":"test","userId":"x","events":[{"ts":"2026-10-27T00:00:00Z","type":"page_start"}]}'
   ```

---

## B. Load the extension (Windows) — do once

1. Put all 10 extension files in one folder, e.g. `C:\bluebot-ext\`:
   `manifest.json, detector.js, bridge.js, sw.js, schema.json, popup.html,
   popup.js, icon16.png, icon48.png, icon128.png`
2. Open `chrome://extensions`.
3. Turn on **Developer mode** (top-right).
4. Click **Load unpacked** and select `C:\bluebot-ext\`.
5. The card appears. Confirm the ID is `oledlpaekbcdpoeajacbdhjngoldpcjo`.
   If it differs, use your own ID in Step C.
6. Click the icon — the popup says **Inactive**. Correct for now.

---

## C. Turn it on (Windows)

### Easy way — double-click a .reg file
1. Double-click `bluebot-policy.reg`.
2. Click **Yes**, then **OK**.
3. Quit Chrome fully, reopen.
4. Icon → popup says **Active**.

`bluebot-policy.reg` contents (edit the ID if yours differs):
```
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\oledlpaekbcdpoeajacbdhjngoldpcjo\policy]
"orgId"="test"
"userId"="self-test"
"serverUrl"="https://battery.bluebotanalytics.com/collect"
"collectFullUrl"=dword:00000001
"monitorIncognito"=dword:00000000
```

### Or — admin Command Prompt
Start → type `cmd` → right-click → **Run as administrator**, then:
```cmd
reg add "HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\oledlpaekbcdpoeajacbdhjngoldpcjo\policy" /v orgId /t REG_SZ /d test /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\oledlpaekbcdpoeajacbdhjngoldpcjo\policy" /v userId /t REG_SZ /d self-test /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\oledlpaekbcdpoeajacbdhjngoldpcjo\policy" /v serverUrl /t REG_SZ /d https://battery.bluebotanalytics.com/collect /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\oledlpaekbcdpoeajacbdhjngoldpcjo\policy" /v collectFullUrl /t REG_DWORD /d 1 /f
```
Then quit Chrome fully and reopen.

### Policy settings
| Key | Meaning |
|---|---|
| `orgId` | Tenant. **Must match the login user's `hostname` in `users_new`** so the dashboard shows this data. |
| `userId` | Per-employee id. Give each person a different value (e.g. a hash of their work email). |
| `serverUrl` | The `/collect` endpoint. |
| `collectFullUrl` | `1` = send full URLs + referrer; `0` = domain only. Full URLs = full browsing history; needs employee notice. |
| `monitorIncognito` | `1` = also watch incognito. Keep `0`. |

---

## D. Verify it works

1. `chrome://policy` → **Reload policies** → the BlueBot section should show
   `orgId`, `serverUrl`, etc. (If it says *No policies set*, Step C did not apply.)
2. Extension popup → **Active**.
3. Browse two or three sites.
4. On the server:
   ```bash
   clickhouse-client -q "SELECT event_type, page, origin, severity, timestamp FROM shield_events WHERE user_id='self-test' ORDER BY timestamp DESC LIMIT 20"
   ```
   Fresh rows = the chain works (browser → /collect → ClickHouse).

---

## E. See it in the dashboard

- Log in as the user whose `hostname` equals the extension's `orgId`
  (e.g. `orgId=test` → log in as the user with `hostname=test`).
- Menu → **Browser Shield**.
- Each visit lists the user, page, risk, and the **Legit (Jev)** verdict.
- Click a user → their full journey.

---

## F. Updating the extension later

After editing any extension file in `C:\bluebot-ext\`:
- `chrome://extensions` → click the **refresh arrow** on the card.
- If a service-worker change does not take effect: **Remove** → **Load unpacked** again.
  The ID stays the same, so the policy still applies.

No server restart is needed for an HTML dashboard change — just reload the page.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Popup stays **Inactive** | Policy not read. Check `chrome://policy`; the `managed_schema` must be nested under `storage` in `manifest.json`. |
| `/collect` returns 400 | Server has no `text/plain` parser. Add `app.use('/collect', express.text({ type:'*/*', limit:'20mb' }))` before the global JSON parser. |
| `ip_address` is `127.0.0.1` | nginx not passing the real IP. Add `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` and `trust proxy`. |
| Country/City show **Unknown** | IP not in `region_details`. Add `await lookupRegion(ipAddress)` inside `/collect`. |
| Dashboard shows no data | Login `hostname` ≠ extension `orgId`. Make them equal. |
| `device_fp` blank | Old `detector.js`/`sw.js` loaded, or old `/collect` route. Replace all three, reload the extension, restart Node. |

---

## Important

This is an **enterprise, managed-device** tool. Deploy it only on company
devices, with employees informed. Before any real rollout: employee notice,
data-retention limit, and a customer DPA, reviewed by counsel. Do not ship a
consumer build that records browsing silently.
