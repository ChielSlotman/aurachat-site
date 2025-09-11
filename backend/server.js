// Minimal AuraSync backend: redeem codes and check premium status
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const pino = require('pino');
const { z } = require('zod');
// Note: using a custom CORS handler to meet exact policy requirements
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { randomUUID } = require('crypto');
require('dotenv').config();
// Strict env checks in production
const REQUIRED_ENVS = ['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET'];
if (process.env.NODE_ENV === 'production') {
  for (const k of REQUIRED_ENVS) {
    if (!process.env[k]) {
      console.error(`Missing env ${k}`);
      process.exit(1);
    }
  }
}
const VERSION = process.env.APP_VERSION || 'dev';
const { Pool } = require('pg');
const Stripe = require('stripe');
const argon2 = require('argon2');
// Ensure fetch is available (Node 18+ has global fetch)
const _fetch = (typeof fetch !== 'undefined') ? fetch : (...args) => import('node-fetch').then(({default: f}) => f(...args));

const app = express();
// RAW body only for Stripe webhook so signature verification works
app.use('/stripe/webhook', express.raw({ type: 'application/json' }));
// For all other routes use JSON parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Request IDs
app.use((req, res, next) => { res.setHeader('X-Request-Id', crypto.randomUUID()); next(); });
// Security headers & CSP
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'", "https://js.stripe.com"],
      "frame-src": ["'self'", "https://js.stripe.com", "https://checkout.stripe.com"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "img-src": ["'self'", 'data:'],
      "connect-src": ["'self'", "https://api.stripe.com"],
      "base-uri": ["'self'"],
      "form-action": ["'self'"],
      "frame-ancestors": ["'none'"]
    }
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' }
}));
// Compression
app.use(compression());
// Logger
const log = pino();
function maskEmail(e){ return e ? String(e).replace(/(.).+(@.+)/,'$1***$2') : ''; }
app.use((req, res, next) => {
  const id = req.get('X-Request-Id');
  const maybeEmail = (req.body && (req.body.email || req.body.customer_id || req.body.customer || '')) || '';
  log.info({ id, method: req.method, path: req.path, ip: req.ip, email: maskEmail(maybeEmail) }, 'req');
  const end = res.end;
  res.end = function (...args) {
    log.info({ id, status: res.statusCode }, 'res');
    end.apply(this, args);
  };
  next();
});

// Zod validation helper
function validate(schema) {
  return (req, res, next) => {
    const r = schema.safeParse(req.body);
    if (!r.success) return res.status(400).json({ error: 'Invalid input' });
    req.valid = r.data;
    next();
  };
}

const ActivateSchema = z.object({ session_id: z.string().min(10).max(200) });
const RedeemSchema = z.object({
  email: z.string().email().transform((s) => s.trim().toLowerCase()),
  code: z.string().min(8).max(200).transform((s) => s.trim())
});
const LostCodeSchema = z.object({ email: z.string().email(), token: z.string().min(10).max(500) });

const PORT = process.env.PORT || 3000;
const STORE_FILE = path.join(__dirname, 'store.json');
const ACCEPT_ANY_CODE = process.env.ACCEPT_ANY_CODE === '1';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'changeme';
const TOKEN_LIFETIME_MS = 1000 * 60 * 60 * 24 * 365; // 12 months
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 5;
const rateLimitMap = new Map(); // { ip+code: [timestamps] }
let ALLOW_ORIGINS = (process.env.ALLOW_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
// Ensure required origins are present (non-destructive; preserves *)
for (const reqOrigin of ['https://api.aurasync.info', 'https://aurasync.info', 'chrome-extension://*']) {
  if (!ALLOW_ORIGINS.includes(reqOrigin)) ALLOW_ORIGINS.push(reqOrigin);
}
const CORS_HAS_WILDCARD = ALLOW_ORIGINS.includes('*');
const CORS_HAS_EXT_WILDCARD = ALLOW_ORIGINS.includes('chrome-extension://*');
console.info('[ENV] DATABASE_URL set?', !!process.env.DATABASE_URL);
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const BREVO_API_KEY = process.env.BREVO_API_KEY || '';
const FROM_EMAIL = process.env.FROM_EMAIL || '';
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

const DEV_MASTER_CODE = process.env.DEV_MASTER_CODE || '';
console.info('[DEV] master code enabled?', !!DEV_MASTER_CODE);

// --- Database setup (Postgres with in-memory fallback) ---
// Synchronous SSL helper (CommonJS friendly, no top-level await)
function getPgSsl() {
  const insecure = (process.env.PG_SSL_INSECURE || '').toLowerCase() === 'true';
  const caInline = process.env.PG_CA_BUNDLE;
  const caPath = process.env.PG_CA_PATH || path.join(__dirname, 'certs', 'db-ca.pem');
  if (insecure) {
    console.warn('PG SSL INSECURE MODE ENABLED: rejectUnauthorized=false');
    return { require: true, rejectUnauthorized: false };
  }
  if (caInline && caInline.trim().length > 0) {
    console.info('Using inline CA from PG_CA_BUNDLE');
    return { require: true, rejectUnauthorized: true, ca: caInline };
  }
  try {
    if (fs.existsSync(caPath)) {
      const ca = fs.readFileSync(caPath, 'utf8');
      if (ca && ca.trim().length > 0) {
        console.info(`Using CA file at ${caPath}`);
        return { require: true, rejectUnauthorized: true, ca };
      }
    } else {
      console.warn(`CA file not found at ${caPath}, falling back to system trust store`);
    }
  } catch (err) {
    console.warn({ err }, 'Failed to load CA file, falling back to system trust store');
  }
  return { require: true, rejectUnauthorized: true };
}
const DATABASE_URL = process.env.DATABASE_URL || '';
let pool = null;
if (process.env.DATABASE_URL) {
  pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: getPgSsl() });
  console.info('[DB] using pg with SSL');
} else {
  console.info('[DB] using in-memory store');
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
  // Ensure new columns exist without breaking existing databases
  await pool.query('ALTER TABLE tokens ADD COLUMN IF NOT EXISTS email TEXT');
    // Hashing migration columns
    await pool.query("ALTER TABLE codes ADD COLUMN IF NOT EXISTS code_hash TEXT");
  await pool.query("ALTER TABLE codes ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active'");
    await pool.query("ALTER TABLE codes ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ DEFAULT (now() + interval '365 days')");
  await pool.query("ALTER TABLE codes ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ");
    // Ensure licenses table exists for activation bookkeeping
    await pool.query(`
      CREATE TABLE IF NOT EXISTS licenses (
        email TEXT PRIMARY KEY,
        plan TEXT,
        active BOOLEAN,
        activated_at TIMESTAMPTZ
      )`);
    // One-active-per-email (using codes.note as email during migration). Create with cleanup and retry.
    try {
      await pool.query('DROP INDEX IF EXISTS public.codes_active_unique');
      await pool.query("CREATE UNIQUE INDEX public.codes_active_unique ON public.codes (note) WHERE status = 'active'");
    } catch (e) {
      if (e && (e.code === '23505' || e.code === '42P07')) {
        console.warn('[DB] Active index create conflict; normalizing and revoking older active per email, then retrying');
        // 1) normalize emails
        await pool.query("UPDATE public.codes SET note = LOWER(TRIM(note)) WHERE note IS NOT NULL");
        // 2) revoke older active codes (keep most recent)
        await pool.query(`WITH ranked AS (
          SELECT id, note, status, created_at,
                 ROW_NUMBER() OVER (PARTITION BY note ORDER BY created_at DESC) AS rn
          FROM public.codes
          WHERE status = 'active'
        )
        UPDATE public.codes c
           SET status = 'revoked', revoked_at = NOW()
          FROM ranked r
         WHERE c.id = r.id
           AND r.rn > 1`);
        // 3) recreate index
        await pool.query('DROP INDEX IF EXISTS public.codes_active_unique');
        await pool.query("CREATE UNIQUE INDEX public.codes_active_unique ON public.codes (note) WHERE status = 'active'");
      } else {
        console.error('[DB] Failed to create active index:', e);
        throw e;
      }
    }
    await pool.query(`
      CREATE TABLE IF NOT EXISTS purchase_events (
        id SERIAL PRIMARY KEY,
        session_id TEXT UNIQUE NOT NULL,
        email TEXT,
        created_at BIGINT NOT NULL
      )`);
    // New idempotency tables
    await pool.query(`
      CREATE TABLE IF NOT EXISTS processed_events (
        id TEXT PRIMARY KEY,
        created_at TIMESTAMPTZ DEFAULT now()
      )`);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS purchases (
        session_id TEXT PRIMARY KEY,
        email TEXT,
        created_at TIMESTAMPTZ DEFAULT now()
      )`);
    // Seed demo code if not present
    await pool.query('INSERT INTO codes (code, redeemed, created_at) VALUES ($1, FALSE, $2) ON CONFLICT (code) DO NOTHING', ['DEMO-AURASYNC-1234', Date.now()]);
    // Sanity checks for required columns to avoid runtime 25P02 errors later
    const sanity = async (table, col) => {
      const r = await pool.query(`SELECT column_name FROM information_schema.columns WHERE table_name=$1 AND column_name=$2`, [table, col]);
      if (!r.rows.length) {
        console.error(`[SCHEMA] Missing column ${table}.${col}`);
        process.exit(1);
      }
    };
    await sanity('codes','code_hash');
    await sanity('codes','status');
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
      // Secure random raw code; ensure uniqueness against legacy code column for now
      let raw;
      while (true) {
        raw = crypto.randomBytes(16).toString('base64url');
        const { rows } = await pool.query('SELECT 1 FROM codes WHERE code=$1', [raw]);
        if (rows.length === 0) break;
      }
      const hash = await argon2.hash(raw);
      await pool.query('INSERT INTO codes (code, code_hash, redeemed, note, created_at) VALUES ($1, $2, FALSE, $3, $4)', [raw, hash, note || '', nowMs]);
      codes.push(raw);
    }
  } else {
    for (let i = 0; i < n; i++) {
      let code;
      do { code = crypto.randomBytes(16).toString('base64url'); } while (mem.codes.has(code));
      const id = mem.nextId.code++;
      const code_hash = await argon2.hash(code);
      mem.codes.set(code, { id, code, code_hash, status: 'active', expires_at: Date.now() + 365*24*60*60*1000, redeemed: false, note: note || '', created_at: nowMs, redeemed_at: null, origin: '' });
      codes.push(code);
    }
  }
  return codes;
}

// Lightweight query helper with error labeling (keeps PII out of logs)
async function q(client, label, text, params) {
  try { return await client.query(text, params); }
  catch (err) { log.error({ label, code: err.code, detail: err.detail }, 'sql_error'); throw err; }
}

async function dbRedeem(codeStr, origin, email) {
  const nowMs = Date.now();
  const expiresAt = nowMs + TOKEN_LIFETIME_MS;
  const token = crypto.randomUUID();
  if (pool) {
    const client = await pool.connect();
    try {
      await q(client, 'begin', 'BEGIN');
      // Lock latest active code for this email
      const sel = await q(
        client,
        'select_active_code',
        `SELECT id, code, code_hash, redeemed, status, expires_at
           FROM codes
          WHERE lower(note) = $1 AND (status IS NULL OR status = 'active')
          ORDER BY created_at DESC
          FOR UPDATE LIMIT 1`,
        [(email || '').toLowerCase()]
      );
      if (sel.rows.length === 0) { throw new Error('NO_ACTIVE_CODE'); }
      const c = sel.rows[0];
      // Check used/expired status
      if (c.status && ['used','revoked','expired'].includes(String(c.status))) {
        throw new Error('INVALID_CODE');
      }
      if (c.redeemed === true) { throw new Error('INVALID_CODE'); }
      if (c.expires_at && new Date(c.expires_at) < new Date()) { throw new Error('EXPIRED_CODE'); }
      // Verify hash or legacy plaintext
      let ok = false;
      if (c.code_hash) {
        ok = await argon2.verify(c.code_hash, codeStr).catch(() => false);
      }
      if (!ok && c.code) {
        ok = (c.code === codeStr);
        if (ok) {
          const h = await argon2.hash(c.code);
          await q(client, 'backfill_hash', 'UPDATE codes SET code_hash=$1, code=NULL WHERE id=$2', [h, c.id]);
        }
      }
      if (!ok) throw new Error('INVALID_CODE');

      // Create token and mark code as used
      const insTok = await q(
        client,
        'insert_token',
        'INSERT INTO tokens (token, premium, created_at, expires_at, revoked, code_id, email) VALUES ($1, TRUE, $2, $3, FALSE, $4, $5) RETURNING id',
        [token, nowMs, expiresAt, c.id, (email || '').toLowerCase()]
      );
      const tokId = insTok.rows[0].id;
  await q(client, 'update_code_used', 'UPDATE codes SET redeemed=TRUE, redeemed_at=$1, origin=$2, status = $3 WHERE id=$4', [nowMs, origin || '', 'used', c.id]);
      // Clear legacy plaintext if any (best effort)
      try { await q(client, 'clear_plain', 'UPDATE codes SET code=NULL WHERE id=$1', [c.id]); } catch (_) {}
      await q(client, 'insert_redemption', 'INSERT INTO redemptions (code_id, token_id, origin, created_at) VALUES ($1, $2, $3, $4)', [c.id, tokId, origin || '', nowMs]);
      // Upsert license record if email provided
      if (email) {
        await q(client, 'upsert_license', `
          INSERT INTO licenses (email, plan, active, activated_at)
          VALUES ($1, 'premium', true, NOW())
          ON CONFLICT (email)
          DO UPDATE SET active = true, plan = 'premium', activated_at = NOW()
        `, [email.toLowerCase()]);
      }
      await q(client, 'commit', 'COMMIT');
      return { token, premium: true };
    } catch (e) {
      try { await q(client, 'rollback', 'ROLLBACK'); } catch (_) {}
      throw e;
    } finally {
      client.release();
    }
  } else {
    // In-memory fallback
    const c = mem.codes.get(codeStr);
    if (!c) return { error: 'invalid_code' };
    if (c.status && ['used','revoked','expired'].includes(String(c.status))) return { error: 'invalid_code' };
    if (c.redeemed) return { error: 'invalid_code' };
    if (c.expires_at && c.expires_at < Date.now()) return { error: 'expired_code' };
    c.redeemed = true; c.redeemed_at = nowMs; c.origin = origin || ''; try { c.code = null; } catch {}
    const tokenId = mem.nextId.token++;
    mem.tokens.set(token, { id: tokenId, token, premium: true, created_at: nowMs, expires_at: expiresAt, revoked: false, code_id: c.id, email: (email || '').toLowerCase() });
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

async function dbRevokeTokensByEmail(email) {
  if (pool) {
    await pool.query('UPDATE tokens SET revoked=TRUE WHERE code_id IN (SELECT id FROM codes WHERE note=$1)', [email]);
  } else {
    for (const [tok, t] of mem.tokens.entries()) {
      const c = [...mem.codes.values()].find(c => c.id === t.code_id);
      if (c && c.note === email) t.revoked = true;
    }
  }
}

async function dbLatestCodeForEmail(email) {
  if (pool) {
    const { rows } = await pool.query('SELECT * FROM codes WHERE note=$1 ORDER BY created_at DESC LIMIT 1', [email]);
    return rows[0] || null;
  } else {
    const list = [...mem.codes.values()].filter(c => c.note === email).sort((a,b)=> (b.created_at||0)-(a.created_at||0));
    return list[0] || null;
  }
}

async function dbRevokeTokensByCodeId(codeId) {
  if (pool) {
    await pool.query('UPDATE tokens SET revoked=TRUE WHERE code_id=$1', [codeId]);
  } else {
    for (const [, t] of mem.tokens.entries()) {
      if (t.code_id === codeId) t.revoked = true;
    }
  }
}

async function dbGetCodeByToken(tokenStr) {
  if (pool) {
    const q = `
      SELECT c.id, c.code, c.note, c.created_at, t.email as token_email
      FROM tokens t
      JOIN codes c ON c.id = t.code_id
      WHERE t.token = $1
      LIMIT 1`;
    const { rows } = await pool.query(q, [tokenStr]);
    return rows[0] || null;
  } else {
    const t = mem.tokens.get(tokenStr);
    if (!t) return null;
    for (const c of mem.codes.values()) {
      if (c.id === t.code_id) {
        return { id: c.id, code: c.code, note: c.note, created_at: c.created_at, token_email: t.email };
      }
    }
    return null;
  }
}

async function sendEmail(to, subject, html) {
  if (!BREVO_API_KEY || !FROM_EMAIL) {
    console.warn('[EMAIL] Missing BREVO_API_KEY or FROM_EMAIL; skipping send');
    return;
  }
  try {
  const res = await _fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        accept: 'application/json',
        'api-key': BREVO_API_KEY,
      },
      body: JSON.stringify({
        sender: { email: FROM_EMAIL },
        to: [{ email: to }],
        subject,
        htmlContent: html
      })
    });
    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      console.error('[EMAIL] Brevo send failed', res.status, txt);
    }
  } catch (e) {
    console.error('[EMAIL] Brevo send error', e);
  }
}

function renderLicenseEmailHtml(code) {
  return `<!doctype html>
  <html><body style="font-family:system-ui,Segoe UI,Arial,sans-serif;line-height:1.5">
    <h2>Your AuraSync license code</h2>
    <p>We issued you a new license code and revoked any previous code.</p>
    <p style="margin-top:12px">Your new code:</p>
    <div style="font-size:20px;font-weight:700;letter-spacing:1px;background:#f4f6ff;padding:12px 16px;border-radius:8px;display:inline-block">
      ${code}
    </div>
    <p style="margin-top:18px;color:#555">If you didn’t request this, reply to this email for help.</p>
  </body></html>`;
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
             ,(
               SELECT t.email
               FROM tokens t
               WHERE t.code_id = c.id
               ORDER BY t.created_at DESC
               LIMIT 1
             ) AS token_email
      FROM codes c
      ORDER BY c.created_at DESC`;
    const { rows } = await pool.query(q);
    return rows.map(r => ({
      code: r.code,
      redeemed: !!r.redeemed,
      redeemedAt: r.redeemed_at,
      tokenTail: r.token_tail || '',
      note: r.note || '',
      email: (r.token_email || r.note || ''),
      createdAt: r.created_at,
      origin: r.origin || ''
    }));
  } else {
    const out = [];
    for (const [code, c] of mem.codes.entries()) {
      // find latest token for this code
      let tail = '';
      let latestTs = -1;
      let latestEmail = '';
      for (const [tok, t] of mem.tokens.entries()) {
        if (t.code_id === c.id) {
          tail = tok.slice(-6);
          if (typeof t.created_at === 'number' && t.created_at > latestTs) {
            latestTs = t.created_at;
            latestEmail = t.email || '';
          }
        }
      }
      out.push({
        code,
        redeemed: !!c.redeemed,
        redeemedAt: c.redeemed_at,
        tokenTail: tail,
        note: c.note || '',
        email: latestEmail || c.note || '',
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

// --- Request ID middleware ---
app.use((req, res, next) => {
  const rid = crypto.randomUUID();
  req.requestId = rid;
  res.setHeader('X-Request-Id', rid);
  next();
});

// --- CORS configuration (strict) ---
const STRICT_ALLOWED = new Set(['https://aurasync.info', 'https://www.aurasync.info']);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && STRICT_ALLOWED.has(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  res.header('Vary', 'Origin');
  res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

// --- Routes ---
app.get('/healthz', (req, res) => {
  res.json({ ok: true, version: VERSION, uptime: process.uptime(), now: new Date().toISOString() });
});
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

// --- debug: stripe mode/account ---
app.get('/debug/stripe', async (_req, res) => {
  try {
    if (!stripe) return res.status(500).json({ error: 'stripe_not_configured' });
    const acct = await stripe.accounts.retrieve();
    const key = process.env.STRIPE_SECRET_KEY || '';
    const mode = key.startsWith('sk_live_') ? 'live'
               : key.startsWith('sk_test_') ? 'test'
               : 'unknown';
    res.json({ account_id: acct.id, mode });
  } catch (e) {
    res.status(500).json({ error: 'stripe_error', message: String(e.message || e) });
  }
});

// (Removed legacy /webhook handler)

// Stripe webhook (idempotent code issuance)
app.post('/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const requestId = crypto.randomUUID();
  try {
    if (!stripe || !STRIPE_WEBHOOK_SECRET) return res.status(500).json({ error: 'webhook_not_configured' });
    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      console.error(`[WH2 ${requestId}] bad signature:`, err?.message);
      return res.status(400).send('Bad signature');
    }
    const evtId = event.id;
    // DB-backed idempotency for events
    if (await hasProcessedEvent(evtId)) {
      console.info(`[WH2 ${requestId}] duplicate event ${evtId}`);
      return res.json({ received: true, idempotent: true });
    }
    await recordProcessedEvent(evtId);
    const type = event.type;
    if (type !== 'checkout.session.completed') {
      console.info(`[WH2 ${requestId}] ignore ${type}`);
      return res.json({ received: true });
    }
    const session = event.data?.object;
    const sessionId = session?.id;
    if (!sessionId) return res.status(400).json({ error: 'missing_session' });
    // Retrieve to be sure
    let full;
    try {
      full = await stripe.checkout.sessions.retrieve(sessionId, { expand: ['customer'] });
    } catch (e) {
      console.error(`[WH2 ${requestId}] retrieve failed`);
      return res.status(502).json({ error: 'stripe_unavailable' });
    }
    if (!full || full.payment_status !== 'paid') {
      console.info(`[WH2 ${requestId}] not paid`);
      return res.status(400).json({ error: 'not_paid' });
    }
    const email = (full.customer_details?.email || full.customer?.email || '').toLowerCase();
    if (!email) return res.status(400).json({ error: 'no_email' });
    const nowMs = Date.now();
    // Idempotency: ensure we process a given session once
    if (pool) {
      if (await hasPurchase(sessionId)) {
        console.info(`[WH2 ${requestId}] already purchased ${sessionId}`);
        return res.json({ received: true, idempotent: true });
      }
      // Issue code and record purchase atomically
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const last = await client.query('SELECT id FROM codes WHERE note=$1 ORDER BY created_at DESC LIMIT 1', [email]);
        const codes = await dbCreateCodes(1, email);
        const code = codes[0];
        if (last.rows.length) await dbRevokeTokensByCodeId(last.rows[0].id);
        await client.query('INSERT INTO purchases (session_id, email) VALUES ($1, $2) ON CONFLICT DO NOTHING', [sessionId, email]);
        await client.query('COMMIT');
        console.info(`[WH2 ${requestId}] issued code for ${email}`);
        await sendEmail(email, 'Your AuraSync activation code', renderLicenseEmailHtml(code));
        return res.json({ received: true });
      } catch (e) {
        await client.query('ROLLBACK');
        console.error(`[WH2 ${requestId}] tx failed`);
        return res.status(500).json({ error: 'server_error' });
      } finally {
        client.release();
      }
    } else {
      // Memory idempotency
      if (!mem.purchases) mem.purchases = new Set();
      if (mem.purchases.has(sessionId)) {
        return res.json({ received: true, idempotent: true });
      }
      const last = await dbLatestCodeForEmail(email);
      const codes = await dbCreateCodes(1, email);
      const code = codes[0];
      if (last && last.id) await dbRevokeTokensByCodeId(last.id);
      mem.purchases.add(sessionId);
      await sendEmail(email, 'Your AuraSync activation code', renderLicenseEmailHtml(code));
      return res.json({ received: true });
    }
  } catch (e) {
    console.error('[WH2] error', e);
    return res.status(500).end();
  }
});

// Create a Stripe Checkout Session (subscription)
app.post('/create-checkout-session', async (req, res) => {
  try {
    if (!stripe) return res.status(500).json({ error: 'stripe_not_configured' });
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: 'price_1S4FmS1XlsSTEaa9BRFZCCUx', quantity: 1 }],
      customer_creation: 'always',
      success_url: 'https://aurachatapp.github.io/aurachat-premium/success.html?session_id={CHECKOUT_SESSION_ID}',
      cancel_url: 'https://aurachatapp.github.io/aurachat-premium/cancel.html',
    });
    return res.json({ id: session.id, url: session.url });
  } catch (e) {
    console.error('Create checkout session error:', e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Idempotency helpers
async function hasProcessedEvent(id) {
  if (pool) {
    const { rows } = await pool.query('SELECT 1 FROM processed_events WHERE id=$1', [id]);
    return rows.length > 0;
  } else {
    if (!mem.processed_events) mem.processed_events = new Set();
    return mem.processed_events.has(id);
  }
}
async function recordProcessedEvent(id) {
  if (pool) {
    await pool.query('INSERT INTO processed_events (id) VALUES ($1) ON CONFLICT DO NOTHING', [id]);
  } else {
    if (!mem.processed_events) mem.processed_events = new Set();
    mem.processed_events.add(id);
  }
}
async function hasPurchase(sessionId) {
  if (pool) {
    const { rows } = await pool.query('SELECT 1 FROM purchases WHERE session_id=$1', [sessionId]);
    if (rows.length === 0) {
      // Back-compat with old table purchase_events if present
      try {
        const r2 = await pool.query('SELECT 1 FROM purchase_events WHERE session_id=$1', [sessionId]);
        return r2?.rows?.length > 0;
      } catch {}
    }
    return rows.length > 0;
  } else {
    if (!mem.purchases) mem.purchases = new Set();
    return mem.purchases.has(sessionId);
  }
}
async function recordPurchase(sessionId, email) {
  if (pool) {
    await pool.query('INSERT INTO purchases (session_id, email) VALUES ($1, $2) ON CONFLICT DO NOTHING', [sessionId, email]);
  } else {
    if (!mem.purchases) mem.purchases = new Set();
    mem.purchases.add(sessionId);
  }
}

// POST /activate { session_id }
// Apply rate limits
const burstLimiter = rateLimit({ windowMs: 60_000, max: 20, standardHeaders: true, legacyHeaders: false });
app.use('/stripe/webhook', burstLimiter);
const codeLimiter = rateLimit({ windowMs: 5 * 60_000, max: 10, keyGenerator: (req) => (req.body?.email || req.ip) });
app.use(['/activate', '/lost-code'], codeLimiter);

app.post('/activate', validate(ActivateSchema), async (req, res) => {
  try {
    if (!stripe) return res.status(500).json({ error: 'Activation temporarily unavailable' });
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || '';
    const nowMs = now();
    const key = `activate:${ip}`;
    let arr = rateLimitMap.get(key) || [];
    arr = arr.filter(ts => nowMs - ts < RATE_LIMIT_WINDOW);
    if (arr.length >= RATE_LIMIT_MAX) {
      return res.status(429).json({ error: 'Too many attempts, try again later.' });
    }
    arr.push(nowMs);
    rateLimitMap.set(key, arr);

  const { session_id } = req.valid;
    if (!session_id || typeof session_id !== 'string') {
      return res.status(400).json({ error: 'Missing session_id' });
    }

    let session;
    try {
      session = await stripe.checkout.sessions.retrieve(session_id, { expand: ['customer'] });
    } catch (err) {
      const isStripeErr = err?.type && String(err.type).toLowerCase().includes('stripe');
      return res.status(isStripeErr ? 502 : 500).json({ error: 'Activation temporarily unavailable' });
    }

    if (!session || session.payment_status !== 'paid') {
      return res.status(400).json({ error: 'Payment not completed yet' });
    }

    const email = (session.customer_details?.email || session.customer?.email || '').toLowerCase();
    if (!email) return res.status(400).json({ error: 'Email not found on session' });

    const last = await dbLatestCodeForEmail(email);
    const codes = await dbCreateCodes(1, email);
    const code = codes[0];
    if (last && last.id) await dbRevokeTokensByCodeId(last.id);

    return res.json({ code, email });
  } catch (err) {
    const isStripeErr = err?.type && String(err.type).toLowerCase().includes('stripe');
    console.error('Activate error:', err);
    return res.status(isStripeErr ? 502 : 500).json({ error: 'Activation temporarily unavailable' });
  }
});

// Stripe Billing Portal
const BillingSchema = z.object({ customer_id: z.string().min(5).max(200) });
app.post('/billing-portal', validate(BillingSchema), async (req, res) => {
  try {
    if (!stripe) return res.status(500).json({ error: 'Portal unavailable' });
    const return_url = 'https://aurasync.info/pricing/';
    const portal = await stripe.billingPortal.sessions.create({ customer: req.valid.customer_id, return_url });
    res.json({ url: portal.url });
  } catch (e) {
    res.status(500).json({ error: 'Portal unavailable' });
  }
});

// POST /redeem { code }
app.post('/redeem', validate(RedeemSchema), async (req, res) => {
  try {
  const { email, code } = req.valid;
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || '';
  // 5-minute rate limit keyed by IP+email (fallback to code if no email)
  const REDEEM_WINDOW_MS = 5 * 60 * 1000;
  const key = `${ip}:${email || code}`;
  const nowMs = now();
    // --- Developer master code: infinite use, never expires ---
    if (DEV_MASTER_CODE && code === DEV_MASTER_CODE) {
      const token = `dev-${randomUUID()}`;
      try {
        if (typeof saveToken === 'function') {
          await saveToken({ token, code_id: null, origin: body.origin || 'extension', note: 'dev_master', dev: true });
        }
      } catch (_) {}
      return res.json({ token, premium: true, dev: true });
    }
    // --- Rate limit ---
  let arr = rateLimitMap.get(key) || [];
  arr = arr.filter(ts => nowMs - ts < REDEEM_WINDOW_MS);
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
    await pool.query('INSERT INTO tokens (token, premium, created_at, expires_at, revoked, email) VALUES ($1, TRUE, $2, $3, FALSE, $4)', [token, nowMs, expiresAt, email]);
      } else {
        const id = mem.nextId.token++;
    mem.tokens.set(token, { id, token, premium: true, created_at: nowMs, expires_at: expiresAt, revoked: false, code_id: null, email });
      }
      console.info(`[REDEEM] ANY_CODE ip=${ip} code=${code} => token=...${tokenTail(token)}`);
      return res.json({ token, premium: true });
    } else {
      console.log('TEST_MODE: OFF (/redeem)');
    }

    if (!code) return res.status(400).json({ error: 'Invalid or expired code.' });
    const origin = req.headers.origin || '';
    try {
      const result = await dbRedeem(code, origin, email);
      if (result?.error) {
        return res.status(400).json({ error: 'Invalid or expired code.' });
      }
      console.info(`[REDEEM] ip=${ip} code=*** => token=...${tokenTail(result.token)} at ${new Date(nowMs).toISOString()} origin=${origin}`);
      return res.json({ token: result.token, premium: true });
    } catch (e) {
      const msg = String(e?.message || '');
      if (["NO_ACTIVE_CODE","INVALID_CODE","EXPIRED_CODE"].includes(msg)) {
        return res.status(400).json({ error: 'Invalid or expired code.' });
      }
      log.error({ err: msg }, 'redeem_failed');
      return res.status(500).json({ error: 'Server error. Please try again in a minute.' });
    }
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
    // Developer dev- tokens: always premium
    if (typeof token === 'string' && token.startsWith('dev-')) {
      return res.json({ premium: true, dev: true });
    }
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

// --- Regenerate code for a customer (admin protected) ---
app.post('/regenerate', async (req, res) => {
  if (!checkAdmin(req, res)) return;
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ error: 'missing_email' });
    if (!stripe) return res.status(500).json({ error: 'stripe_not_configured' });

    // Verify subscription active
    let customerId = null;
    const customers = await stripe.customers.list({ email, limit: 1 });
    if (customers?.data?.length) customerId = customers.data[0].id;
    if (!customerId) return res.status(404).json({ error: 'customer_not_found' });
    const subs = await stripe.subscriptions.list({ customer: customerId, status: 'active', limit: 1 });
    if (!subs?.data?.length) return res.status(403).json({ error: 'subscription_not_active' });

    // Check last code age > 7 days
    const last = await dbLatestCodeForEmail(email);
    const sevenDays = 7 * 24 * 60 * 60 * 1000;
    if (last && last.created_at && Date.now() - Number(last.created_at) <= sevenDays) {
      return res.status(429).json({ error: 'too_soon' });
    }

    // Generate and revoke old
  const codes = await dbCreateCodes(1, email);
  const code = codes[0];
  if (last && last.id) await dbRevokeTokensByCodeId(last.id);
  await sendEmail(email, 'Your new AuraSync license code', renderLicenseEmailHtml(code));
    res.json({ ok: true });
  } catch (e) {
    console.error('Regenerate error:', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// --- Lost code self-service: validate active sub, 7-day cooldown, send new code ---
app.post('/lost-code', validate(LostCodeSchema), async (req, res) => {
  try {
    // Rate limit per IP+email for lost-code
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || '';
    const rawEmail = String(req.body?.email || '').trim().toLowerCase();
    const keyRL = `lost:${ip}:${rawEmail}`;
    const nowMsRL = Date.now();
    let arrRL = rateLimitMap.get(keyRL) || [];
    arrRL = arrRL.filter(ts => nowMsRL - ts < RATE_LIMIT_WINDOW);
    if (arrRL.length >= RATE_LIMIT_MAX) {
      return res.status(429).json({ error: 'Too many attempts, try again later.' });
    }
    arrRL.push(nowMsRL);
    rateLimitMap.set(keyRL, arrRL);

  const email = req.valid.email.toLowerCase();
  const token = req.valid.token;
    if (!email) return res.status(400).json({ error: 'missing_email' });
    if (!token) return res.status(400).json({ error: 'missing_token' });
    if (!stripe) return res.status(500).json({ error: 'stripe_not_configured' });

    // Verify token exists and is valid (not revoked, not expired)
    const t = await dbGetToken(token);
    const nowMs = Date.now();
    if (!t) return res.status(404).json({ error: 'invalid_token' });
    const exp = t.expires_at || t.expiresAt;
    if (t.revoked) return res.status(403).json({ error: 'token_revoked' });
    if (!exp || exp <= nowMs) return res.status(403).json({ error: 'token_expired' });

  // Get code associated with token and confirm email matches (prefer token.email if captured)
  const codeRow = await dbGetCodeByToken(token);
  if (!codeRow) return res.status(404).json({ error: 'code_not_found' });
  const storedTokenEmail = String(codeRow.token_email || '').toLowerCase();
  const codeEmail = String(codeRow.note || '').toLowerCase();
  const expectedEmail = storedTokenEmail || codeEmail;
  if (expectedEmail !== email) return res.status(403).json({ error: 'email_mismatch' });

    // Verify customer exists and has active subscription
    let customerId = null;
    const customers = await stripe.customers.list({ email, limit: 1 });
    if (customers?.data?.length) customerId = customers.data[0].id;
    if (!customerId) return res.status(404).json({ error: 'customer_not_found' });
    const subs = await stripe.subscriptions.list({ customer: customerId, status: 'active', limit: 1 });
    if (!subs?.data?.length) return res.status(403).json({ error: 'subscription_not_active' });

    // Enforce 7-day cooldown since last issuance (unless bypassed for dev)
    const bypass = String(process.env.DEV_BYPASS_REGEN_COOLDOWN || '').toLowerCase() === 'true';
    if (process.env.LOG_LEVEL === 'debug') console.log('[lost-code] cooldown bypass =', bypass);
    if (!bypass) {
      const last = await dbLatestCodeForEmail(email);
      const sevenDays = 7 * 24 * 60 * 60 * 1000;
      if (last && last.created_at) {
        const age = Date.now() - Number(last.created_at);
        if (age <= sevenDays) {
          const retryAfterIso = new Date(Number(last.created_at) + sevenDays).toISOString();
          return res.status(429).json({ error: 'too_soon', retry_after: retryAfterIso });
        }
      }
    }

    // Revoke current token and any tokens tied to the old code
    await dbRevokeToken(token);
    if (codeRow.id) await dbRevokeTokensByCodeId(codeRow.id);

    // Generate a new code and email it
  const codes = await dbCreateCodes(1, email);
  const newCode = codes[0];
  await sendEmail(email, 'Your new AuraSync license code', renderLicenseEmailHtml(newCode));
    return res.json({ success: true, message: 'New code sent to your email' });
  } catch (e) {
    console.error('Lost-code error:', e);
    return res.status(500).json({ error: 'server_error' });
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

async function start() {
  try {
    await initStorage();
  } catch (e) {
    console.error('Failed to initialize storage:', e);
    process.exit(1);
    return;
  }
  app.listen(PORT, () => {
    console.log(`AuraSync backend listening on ${PORT}`);
  });
}
start();

module.exports = { pool };
