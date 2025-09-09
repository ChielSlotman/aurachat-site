// Minimal AuraSync backend: redeem codes and check premium status
const express = require('express');
const cors = require('cors');
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

// --- CORS configuration ---
function originMatches(origin, pattern) {
  if (pattern === origin) return true;
  if (pattern.endsWith(':*')) {
    const base = pattern.slice(0, -1);
    if (origin.startsWith(base)) return true;
  }
  if (pattern.startsWith('chrome-extension://')) {
    return origin === pattern;
  }
  return false;
}

const corsOptions =
  ALLOW_ORIGINS.length === 0
    ? { origin: true, credentials: true }
    : {
        origin: (origin, callback) => {
          if (!origin) return callback(null, true);
          const ok = ALLOW_ORIGINS.some((p) => originMatches(origin, p));
          return callback(ok ? null : new Error('Not allowed by CORS'), ok);
        },
        credentials: true,
      };

app.use(cors(corsOptions));

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
  if (ALLOW_ORIGINS.length === 0) {
    console.log('CORS: allowing all origins (dev). Set ALLOW_ORIGINS to restrict.');
  } else {
    console.log('CORS allow list:', ALLOW_ORIGINS);
  }
});
