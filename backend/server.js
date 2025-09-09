// Minimal AuraSync backend: redeem codes and check premium status
const express = require('express');
// Note: using a custom CORS handler to meet exact policy requirements
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();
const { Pool } = require('pg');

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

// --- Database setup (Postgres with in-memory fallback) ---
const DATABASE_URL = process.env.DATABASE_URL || '';
let pool = null;
if (DATABASE_URL) {
  pool = new Pool({ connectionString: DATABASE_URL, ssl: DATABASE_URL.includes('render.com') ? { rejectUnauthorized: false } : undefined });
}

// In-memory fallback store (for local dev when DATABASE_URL is not set)
const mem = {
  codes: new Map(), // codeStr -> { id, code, redeemed, note, created_at, redeemed_at, origin }
  tokens: new Map(), // tokenStr -> { id, token, premium, created_at, expires_at, revoked, code_id }
  redemptions: [], // { id, code_id, token_id, origin, created_at }
  nextId: { code: 1, token: 1, redemption: 1 },
};

async function initStorage() {
  if (pool) {
    // Create tables if missing
    const ddl = `
    CREATE TABLE IF NOT EXISTS codes (
      id SERIAL PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      redeemed BOOLEAN NOT NULL DEFAULT FALSE,
      note TEXT,
      created_at BIGINT NOT NULL,
      redeemed_at BIGINT,
      origin TEXT
    );
    CREATE TABLE IF NOT EXISTS tokens (
      id SERIAL PRIMARY KEY,
      token TEXT UNIQUE NOT NULL,
      premium BOOLEAN NOT NULL DEFAULT TRUE,
      created_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL,
      revoked BOOLEAN NOT NULL DEFAULT FALSE,
      code_id INTEGER REFERENCES codes(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS redemptions (
      id SERIAL PRIMARY KEY,
      code_id INTEGER REFERENCES codes(id) ON DELETE CASCADE,
      token_id INTEGER REFERENCES tokens(id) ON DELETE CASCADE,
      origin TEXT,
      created_at BIGINT NOT NULL
    );`;
    await pool.query(ddl);
    // Seed demo code if not present
    await pool.query('INSERT INTO codes (code, redeemed, created_at) VALUES ($1, FALSE, $2) ON CONFLICT (code) DO NOTHING', ['DEMO-AURASYNC-1234', Date.now()]);
  } else {
    // In-memory seed
    if (!mem.codes.has('DEMO-AURASYNC-1234')) {
      const id = mem.nextId.code++;
      mem.codes.set('DEMO-AURASYNC-1234', { id, code: 'DEMO-AURASYNC-1234', redeemed: false, note: '', created_at: Date.now(), redeemed_at: null, origin: '' });
    }
  }
}

function tokenTail(token) { return token ? token.slice(-6) : ''; }

// --- Storage accessors (DB or memory) ---
async function dbCreateCodes(n, note) {
  const codes = [];
  const nowMs = Date.now();
  if (pool) {
    for (let i = 0; i < n; i++) {
      let code;
      // ensure unique code format DEMO-AURASYNC-####
      while (true) {
        const num = Math.floor(Math.random() * 10000);
        code = `DEMO-AURASYNC-${String(num).padStart(4, '0')}`;
        const { rows } = await pool.query('SELECT 1 FROM codes WHERE code=$1', [code]);
        if (rows.length === 0) break;
      }
      await pool.query('INSERT INTO codes (code, redeemed, note, created_at) VALUES ($1, FALSE, $2, $3)', [code, note || '', nowMs]);
      codes.push(code);
    }
  } else {
    for (let i = 0; i < n; i++) {
      let code;
      do {
        const num = Math.floor(Math.random() * 10000);
        code = `DEMO-AURASYNC-${String(num).padStart(4, '0')}`;
      } while (mem.codes.has(code));
      const id = mem.nextId.code++;
      mem.codes.set(code, { id, code, redeemed: false, note: note || '', created_at: nowMs, redeemed_at: null, origin: '' });
      codes.push(code);
    }
  }
  return codes;
}

async function dbRedeem(codeStr, origin) {
  const nowMs = Date.now();
  const expiresAt = nowMs + TOKEN_LIFETIME_MS;
  const token = crypto.randomUUID();
  if (pool) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query('SELECT * FROM codes WHERE code=$1 FOR UPDATE', [codeStr]);
      if (rows.length === 0) {
        await client.query('ROLLBACK');
        return { error: 'invalid_code' };
      }
      const c = rows[0];
      if (c.redeemed) {
        await client.query('ROLLBACK');
        return { error: 'already_redeemed' };
      }
      const insTok = await client.query('INSERT INTO tokens (token, premium, created_at, expires_at, revoked, code_id) VALUES ($1, TRUE, $2, $3, FALSE, $4) RETURNING id', [token, nowMs, expiresAt, c.id]);
      const tokId = insTok.rows[0].id;
      await client.query('UPDATE codes SET redeemed=TRUE, redeemed_at=$1, origin=$2 WHERE id=$3', [nowMs, origin || '', c.id]);
      await client.query('INSERT INTO redemptions (code_id, token_id, origin, created_at) VALUES ($1, $2, $3, $4)', [c.id, tokId, origin || '', nowMs]);
      await client.query('COMMIT');
      return { token, premium: true };
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  } else {
    const c = mem.codes.get(codeStr);
    if (!c) return { error: 'invalid_code' };
    if (c.redeemed) return { error: 'already_redeemed' };
    c.redeemed = true;
    c.redeemed_at = nowMs;
    c.origin = origin || '';
    const tokenId = mem.nextId.token++;
    mem.tokens.set(token, { id: tokenId, token, premium: true, created_at: nowMs, expires_at: expiresAt, revoked: false, code_id: c.id });
    const redId = mem.nextId.redemption++;
    mem.redemptions.push({ id: redId, code_id: c.id, token_id: tokenId, origin: origin || '', created_at: nowMs });
    return { token, premium: true };
  }
}

async function dbGetToken(tokenStr) {
  if (pool) {
    const { rows } = await pool.query('SELECT * FROM tokens WHERE token=$1', [tokenStr]);
    return rows[0] || null;
  } else {
    return mem.tokens.get(tokenStr) || null;
  }
}

async function dbRevokeToken(tokenStr) {
  if (pool) {
    const { rowCount } = await pool.query('UPDATE tokens SET revoked=TRUE WHERE token=$1', [tokenStr]);
    return rowCount > 0;
  } else {
    const t = mem.tokens.get(tokenStr);
    if (!t) return false;
    t.revoked = true;
    return true;
  }
}

async function dbListCodes() {
  if (pool) {
    const q = `
      SELECT c.id, c.code, c.redeemed, c.note, c.created_at, c.redeemed_at, c.origin,
             (
               SELECT RIGHT(t.token, 6)
               FROM tokens t
               WHERE t.code_id = c.id
               ORDER BY t.created_at DESC
               LIMIT 1
             ) AS token_tail
      FROM codes c
      ORDER BY c.created_at DESC`;
    const { rows } = await pool.query(q);
    return rows.map(r => ({
      code: r.code,
      redeemed: !!r.redeemed,
      redeemedAt: r.redeemed_at,
      tokenTail: r.token_tail || '',
      note: r.note || '',
      createdAt: r.created_at,
      origin: r.origin || ''
    }));
  } else {
    const out = [];
    for (const [code, c] of mem.codes.entries()) {
      // find latest token for this code
      let tail = '';
      for (const [tok, t] of mem.tokens.entries()) {
        if (t.code_id === c.id) tail = tok.slice(-6);
      }
      out.push({
        code,
        redeemed: !!c.redeemed,
        redeemedAt: c.redeemed_at,
        tokenTail: tail,
        note: c.note || '',
        createdAt: c.created_at,
        origin: c.origin || ''
      });
    }
    // newest first
    out.sort((a,b) => (b.createdAt||0) - (a.createdAt||0));
    return out;
  }
}

// --- Simple JSON "DB" helpers ---
function now() { return Date.now(); }

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
app.get('/health', async (req, res) => {
  try {
    if (pool) {
      await pool.query('SELECT 1');
      return res.json({ ok: true, db: 'pg' });
    }
    return res.json({ ok: true, db: 'memory' });
  } catch {
    return res.status(500).json({ ok: false });
  }
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

    if (ACCEPT_ANY_CODE) {
      const token = crypto.randomUUID();
      const expiresAt = nowMs + TOKEN_LIFETIME_MS;
      if (pool) {
        // create a "free" token not linked to a code
        await pool.query('INSERT INTO tokens (token, premium, created_at, expires_at, revoked) VALUES ($1, TRUE, $2, $3, FALSE)', [token, nowMs, expiresAt]);
      } else {
        const id = mem.nextId.token++;
        mem.tokens.set(token, { id, token, premium: true, created_at: nowMs, expires_at: expiresAt, revoked: false, code_id: null });
      }
      console.info(`[REDEEM] ANY_CODE ip=${ip} code=${code} => token=...${tokenTail(token)}`);
      return res.json({ token, premium: true });
    }
      else {
        console.log('TEST_MODE: OFF (/redeem)');
      }

  if (!code) return res.status(400).json({ error: 'missing_code' });
    const origin = req.headers.origin || '';
    const result = await dbRedeem(code, origin);
    if (result.error === 'invalid_code') return res.status(400).json({ error: 'invalid_code' });
    if (result.error === 'already_redeemed') return res.status(409).json({ error: 'already_redeemed' });
    console.info(`[REDEEM] ip=${ip} code=${code} => token=...${tokenTail(result.token)} at ${new Date(nowMs).toISOString()} origin=${origin}`);
    res.json({ token: result.token, premium: true });
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
  const record = await dbGetToken(token);
    const nowMs = now();
  const valid = Boolean(record && !record.revoked && (record.expires_at || record.expiresAt) && (record.expires_at || record.expiresAt) > nowMs);
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
  const codes = await dbCreateCodes(n, note);
  res.json({ codes });
});

// GET /admin/list-codes
app.get('/admin/list-codes', async (req, res) => {
  if (!checkAdmin(req, res)) return;
  const out = await dbListCodes();
  res.json({ codes: out });
});

// POST /admin/revoke-token { token }
app.post('/admin/revoke-token', async (req, res) => {
  if (!checkAdmin(req, res)) return;
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Missing token' });
  const ok = await dbRevokeToken(token);
  if (!ok) return res.status(404).json({ error: 'Token not found' });
  res.json({ ok: true });
});

initStorage().then(() => {
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
}).catch((e) => {
  console.error('Failed to initialize storage:', e);
  process.exit(1);
});
