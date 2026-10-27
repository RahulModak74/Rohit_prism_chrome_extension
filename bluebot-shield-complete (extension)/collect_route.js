// ============================================================================
// /collect  - ingest endpoint for the browser-shield extension
//
// Mount on the shield server (can be the same Node app or a separate one).
// Writes to shield_events (see shield_schema.sql). Mirrors the /track pattern:
// values go in the request BODY via clickhouse.insert(), never the URL.
//
//   app.use('/collect', express.json({ limit: '5mb' }));
//   app.set('trust proxy', 'loopback');   // real device egress IP from nginx
// ============================================================================

const str = (v, n = 2000) => (v == null ? '' : String(v)).slice(0, n);
const int = (v) => (Number.isFinite(+v) ? Math.trunc(+v) : 0);
const flag = (v) => (v ? 1 : 0);

const MAX_EVENTS = 600;

app.post('/collect', async (req, res) => {
  try {
    const data = req.body;
    if (!data || typeof data !== 'object') return res.status(400).end();

    const orgId = str(data.orgId, 64);
    const userId = str(data.userId, 128);
    if (!orgId) return res.status(400).end();

    const events = Array.isArray(data.events) ? data.events.slice(0, MAX_EVENTS) : [];
    if (!events.length) return res.status(204).end();

    // Device egress IP from the connection, not the payload
    const ipAddress = str((req.ip || '').replace(/^::ffff:/, ''), 64);

    const rows = events.map((e) => ({
      timestamp: (() => { const d = new Date(e.ts || Date.now()); return (isNaN(d) ? new Date() : d).toISOString().slice(0, 23).replace('T', ' '); })(),
      org_id: orgId,
      user_id: userId,
      ip_address: ipAddress,
      page: str(e.page, 4000),
      referrer: str(e.referrer, 4000),
      device_fp: str(e.device_fp, 32),
      frame_is_top: flag(e.frame_is_top),
      event_type: str(e.type, 40),
      origin: str(e.origin, 300),
      is_third_party: flag(e.is_third_party),
      is_initial: flag(e.is_initial),
      novel: flag(e.novel),
      element_type: str(e.element_type, 20),
      attr_name: str(e.attr_name, 60),
      method: str(e.method, 10),
      severity: str(e.severity, 10),
      detail: str(JSON.stringify(e.detail || {}), 8000)
    }));

    await clickhouse.insert(`INSERT INTO shield_events (${Object.keys(rows[0]).join(', ')})`, rows).toPromise();

    res.status(204).end();
  } catch (error) {
    console.error('Error in /collect:', error);
    res.status(500).json({ status: 'error', message: error.message });
  }
});
