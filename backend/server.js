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
    const store = await readStore();

    if (ACCEPT_ANY_CODE) {
      const token = crypto.randomUUID();
      store.tokens[token] = { premium: true, createdAt: Date.now() };
      await writeStore(store);
      return res.json({ token, premium: true });
    }

    if (!code) return res.status(400).json({ error: 'Missing code' });

    const entry = store.codes[code];
    if (!entry) return res.status(400).json({ error: 'Invalid code' });
    if (entry.redeemed) return res.status(409).json({ error: 'Code already redeemed' });

    const token = crypto.randomUUID();
    entry.redeemed = true;
    entry.redeemedAt = Date.now();
    entry.token = token;
    store.tokens[token] = { premium: true, createdAt: Date.now() };
    await writeStore(store);
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
    const valid = Boolean(record);
    const premium = Boolean(record && record.premium !== false);
    res.json({ valid, premium });
  } catch (err) {
    console.error('Status error:', err);
    res.status(500).json({ error: 'Server error' });
  }
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
});
