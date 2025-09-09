// Minimal AuraSync backend: redeem codes and check premium status
const express = require('express');
// Note: using a custom CORS handler to meet exact policy requirements
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json());

const PORT = Number(process.env.PORT || 8787);
const STORE_FILE = path.join(__dirname, 'store.json');
const ACCEPT_ANY_CODE = process.env.ACCEPT_ANY_CODE === '1';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'changeme';
const TOKEN_LIFETIME_MS = 1000 * 60 * 60 * 24 * 365; // 12 months
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 5;
const rateLimitMap = new Map(); // { ip+code: [timestamps] }
const ALLOW_ORIGINS = (process.env.ALLOW_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const CORS_HAS_WILDCARD = ALLOW_ORIGINS.includes('*');

// --- Simple JSON "DB" helpers ---
async function ensureStore() {
  try {
    await fs.access(STORE_FILE);
  } catch {
    const initial = { codes: { 'DEMO-AURASYNC-1234': { redeemed: false } }, tokens: {} };
    await fs.writeFile(STORE_FILE, JSON.stringify(initial, null, 2));
  }
}
async function readStore() {
  await ensureStore();
  const raw = await fs.readFile(STORE_FILE, 'utf8');
  return JSON.parse(raw || '{}');
}
async function writeStore(store) {
  await fs.writeFile(STORE_FILE, JSON.stringify(store, null, 2));
}

function now() { return Date.now(); }
function tokenTail(token) { return token ? token.slice(-6) : ''; }

// --- CORS configuration (custom) ---
app.use((req, res, next) => {
  const origin = req.headers.origin || '';

  let allowed = false;
  if (CORS_HAS_WILDCARD) {
    allowed = true;
  } else if (!origin) {
    // Allow requests without Origin header (extensions/native/curl)
    allowed = true;
  } else if (ALLOW_ORIGINS.length === 0) {
    // No list provided -> allow all during early testing
    allowed = true;
  } else if (ALLOW_ORIGINS.includes(origin)) {
    // Exact match including chrome-extension://<ID>
    allowed = true;
  }

  // Log decision
  console.log(`[CORS] Origin: ${origin || '(none)'} => ${allowed ? 'allowed' : 'denied'}`);

  // Apply headers if allowed
  if (allowed) {
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Credentials', 'false');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Origin', CORS_HAS_WILDCARD ? '*' : (origin || '*'));
  }

  // Always handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (!allowed) {
    return res.status(403).json({ error: 'Not allowed by CORS' });
  }

  next();
});

// --- Routes ---
app.get('/health', (req, res) => {
  res.json({ ok: true });
});

// POST /redeem { code }
app.post('/redeem', async (req, res) => {
  try {
    const code = String(req.body?.code || '').trim();
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || '';
    const key = ip + ':' + code;
    const nowMs = now();
    // --- Rate limit ---
    let arr = rateLimitMap.get(key) || [];
    arr = arr.filter(ts => nowMs - ts < RATE_LIMIT_WINDOW);
    if (arr.length >= RATE_LIMIT_MAX) {
      return res.status(429).json({ error: 'Too many attempts, try again later.' });
    }
    arr.push(nowMs);
    rateLimitMap.set(key, arr);

    const store = await readStore();

    if (ACCEPT_ANY_CODE) {
      const token = crypto.randomUUID();
      const expiresAt = nowMs + TOKEN_LIFETIME_MS;
      store.tokens[token] = { premium: true, createdAt: nowMs, expiresAt, revoked: false };
      await writeStore(store);
      console.info(`[REDEEM] ANY_CODE ip=${ip} code=${code} => token=...${tokenTail(token)}`);
      return res.json({ token, premium: true });
    }
      else {
        console.log('TEST_MODE: OFF (/redeem)');
      }

  if (!code) return res.status(400).json({ error: 'missing_code' });

    const entry = store.codes[code];
  if (!entry) return res.status(400).json({ error: 'invalid_code' });
  if (entry.redeemed) return res.status(409).json({ error: 'already_redeemed' });

    const token = crypto.randomUUID();
    const expiresAt = nowMs + TOKEN_LIFETIME_MS;
    entry.redeemed = true;
    entry.redeemedAt = nowMs;
    entry.token = token;
    entry.origin = req.headers.origin || '';
    store.tokens[token] = { premium: true, createdAt: nowMs, expiresAt, revoked: false };
    await writeStore(store);
    console.info(`[REDEEM] ip=${ip} code=${code} => token=...${tokenTail(token)} at ${new Date(nowMs).toISOString()} origin=${entry.origin}`);
    res.json({ token, premium: true });
  } catch (err) {
    console.error('Redeem error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /status?token=...
app.get('/status', async (req, res) => {
  try {
    const token = String(req.query.token || '').trim();
    if (!token) return res.status(400).json({ error: 'Missing token' });
    const store = await readStore();
    const record = store.tokens[token];
    const nowMs = now();
    const valid = Boolean(record && !record.revoked && record.expiresAt && record.expiresAt > nowMs);
    const premium = Boolean(valid && record.premium !== false);
    res.json({ valid, premium });
  } catch (err) {
    console.error('Status error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Admin endpoints (simple secret in header) ---
function checkAdmin(req, res) {
  const sec = req.headers['x-admin-secret'];
  if (!sec || sec !== ADMIN_SECRET) {
    res.status(403).json({ error: 'Forbidden' });
    return false;
  }
  return true;
}

// POST /admin/create-codes { quantity, note }
app.post('/admin/create-codes', async (req, res) => {
  if (!checkAdmin(req, res)) return;
  const { quantity, note } = req.body || {};
  const n = Math.max(1, Math.min(Number(quantity) || 1, 100));
  const store = await readStore();
  const codes = [];
  for (let i = 0; i < n; ++i) {
    const code = 'AURASYNC-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    store.codes[code] = { redeemed: false, note: note || '', createdAt: now() };
    codes.push(code);
  }
  await writeStore(store);
  res.json({ codes });
});

// GET /admin/list-codes
app.get('/admin/list-codes', async (req, res) => {
  if (!checkAdmin(req, res)) return;
  const store = await readStore();
  const out = Object.entries(store.codes).map(([code, entry]) => ({
    code,
    redeemed: !!entry.redeemed,
    redeemedAt: entry.redeemedAt,
    tokenTail: entry.token ? tokenTail(entry.token) : '',
    note: entry.note || '',
    createdAt: entry.createdAt,
    origin: entry.origin || ''
  }));
  res.json({ codes: out });
});

// POST /admin/revoke-token { token }
app.post('/admin/revoke-token', async (req, res) => {
  if (!checkAdmin(req, res)) return;
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Missing token' });
  const store = await readStore();
  if (!store.tokens[token]) return res.status(404).json({ error: 'Token not found' });
  store.tokens[token].revoked = true;
  await writeStore(store);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`AuraSync backend running on http://localhost:${PORT}`);
  if (CORS_HAS_WILDCARD) {
    console.log('CORS: wildcard * active (allowing all origins).');
  } else if (ALLOW_ORIGINS.length === 0) {
    console.log('CORS: ALLOW_ORIGINS not set -> allowing all (dev).');
  } else {
    console.log('CORS allow list (exact match):', ALLOW_ORIGINS);
  }
  if (!ACCEPT_ANY_CODE) {
    console.log('TEST_MODE: OFF');
  } else {
    console.log('TEST_MODE: ON');
  }
});
