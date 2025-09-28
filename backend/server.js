// (moved admin routes below after app initialization)
// Normalize email: lowercase, trim, Gmail dots/+ collapse
function normalizeEmail(email) {
  if (!email) return '';
  let e = String(email).trim().toLowerCase();
  const [user, domain] = e.split('@');
  if (domain === 'gmail.com' || domain === 'googlemail.com') {
    let local = user.split('+')[0].replace(/\./g, '');
    e = `${local}@gmail.com`;
  }
  return e;
}
// Stripe prefers the exact stored email; do NOT collapse Gmail dots/plus.
// Use this when querying Stripe, and optionally try the DB-normalized variant as a fallback.
function emailForStripe(email) {
  if (!email) return '';
  return String(email).trim().toLowerCase();
}
// Minimal AuraSync backend: redeem codes and check premium status
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const bodyParser = require('body-parser');
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
// Deterministic fingerprint for codes (indexable), complementing non-deterministic argon2
function sha256Hex(s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
}

const app = express();
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
// (Compression mounted after webhook to avoid touching raw body)
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
  email: z.string().email().optional(),
  code: z.string().min(8).max(200).transform((s) => s.trim())
});
// Legacy lost-code schema (kept for admin/test handler). The public /lost-code route is simplified below.
const LostCodeSchema = z.object({
  email: z.string().email(),
  token: z.string().min(10).max(500),
  force: z.boolean().optional(),
});

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
const ALLOW_DUPLICATES = String(process.env.ALLOW_DUPLICATES || 'false').toLowerCase() === 'true';
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// Negative cache for invalid codes to short-circuit repeated bad attempts
const MISS_CACHE_TTL = Number(process.env.REDEEM_MISS_TTL_MS || 60_000);
const MISS_CACHE_MAX = Number(process.env.REDEEM_MISS_MAX || 2000);
const missCache = new Map(); // fp -> expiresAt
function missCacheHas(fp) {
  const now = Date.now();
  const exp = missCache.get(fp);
  if (!exp) return false;
  if (exp < now) { missCache.delete(fp); return false; }
  return true;
}
function missCacheSet(fp) {
  const expires = Date.now() + MISS_CACHE_TTL;
  missCache.set(fp, expires);
  if (missCache.size > MISS_CACHE_MAX) {
    // delete oldest ~10%
    const n = Math.max(1, Math.floor(MISS_CACHE_MAX / 10));
    for (const k of missCache.keys()) { missCache.delete(k); if (--n <= 0) break; }
  }
}

// Dynamically load all STRIPE_PRICE_* env vars.
// Plan name derived from suffix after STRIPE_PRICE_ (lowercased), e.g. STRIPE_PRICE_MONTHLY -> 'monthly'.
const PRICE_TO_PLAN = {};
const ALLOWED_PRICES = [];
for (const [key, val] of Object.entries(process.env)) {
  if (!key.startsWith('STRIPE_PRICE_')) continue;
  const priceId = (val || '').trim();
  if (!priceId) continue;
  const plan = key.replace('STRIPE_PRICE_', '').toLowerCase();
  PRICE_TO_PLAN[priceId] = plan;
  ALLOWED_PRICES.push(priceId);
}
// Backward-compatible support for STRIPE_ALLOWED_PRICE_IDS (comma-separated)
const EXTRA_ALLOWED = (process.env.STRIPE_ALLOWED_PRICE_IDS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);
for (const id of EXTRA_ALLOWED) {
  if (!ALLOWED_PRICES.includes(id)) ALLOWED_PRICES.push(id);
  if (!PRICE_TO_PLAN[id]) PRICE_TO_PLAN[id] = 'extra';
}
if (ALLOWED_PRICES.length === 0) {
  console.warn('[STRIPE] No price IDs configured. Define STRIPE_PRICE_* env vars.');
} else {
  console.info('[INIT] Allowed Stripe price IDs:', ALLOWED_PRICES.join(', '));
}

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

// Fallback controls: allow service to boot using in-memory store if DB is unreachable
// In production, default to NO fallback (to avoid losing state across instances). In dev, default to true.
const DB_FALLBACK_ON_FAIL = String(process.env.DB_FALLBACK_ON_FAIL ?? (process.env.NODE_ENV !== 'production' ? 'true' : 'false')).toLowerCase() === 'true';
const FALLBACK_ERROR_CODES = new Set(['ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND']);
function isConnError(err) {
  if (!err) return false;
  if (err.code && FALLBACK_ERROR_CODES.has(err.code)) return true;
  const subs = err.aggregateErrors || err.errors || [];
  for (const e of subs) if (e && e.code && FALLBACK_ERROR_CODES.has(e.code)) return true;
  return false;
}
function sleep(ms){ return new Promise(r=>setTimeout(r, ms)); }

// In-memory fallback store (for local dev when DATABASE_URL is not set)
const mem = {
  codes: new Map(), // codeStr -> { id, code, redeemed, note, created_at, redeemed_at, origin }
  tokens: new Map(), // tokenStr -> { id, token, premium, created_at, expires_at, revoked, code_id }
  redemptions: [], // { id, code_id, token_id, origin, created_at }
  nextId: { code: 1, token: 1, redemption: 1 },
  licenses: new Map(), // email -> { email, plan, active, activated_at }
};

async function initStorage() {
  if (pool) {
    // Helper to run DDL with clear logs
    const run = async (sql, label) => {
      try {
        await pool.query(sql);
        log.info({ label }, '[DB] bootstrap ok');
      } catch (err) {
        log.error({ err, sql }, `[DB] bootstrap failed: ${label}`);
        throw err;
      }
    };

    // Create tables if missing (schema-qualified, single-table names, no dotted identifiers)
    await run(`
      CREATE TABLE IF NOT EXISTS public.codes (
        id SERIAL PRIMARY KEY,
        code TEXT UNIQUE,
        redeemed BOOLEAN NOT NULL DEFAULT FALSE,
        note TEXT,
        created_at BIGINT NOT NULL,
        redeemed_at BIGINT,
        origin TEXT,
        code_hash TEXT,
        code_sha256 TEXT,
        status TEXT DEFAULT 'active',
        expires_at TIMESTAMPTZ DEFAULT (now() + interval '365 days'),
        revoked_at TIMESTAMPTZ
      )`, 'create codes table');
    // Make sure code column can be cleared post-hash backfill
    await run(`ALTER TABLE public.codes ALTER COLUMN code DROP NOT NULL`, 'alter codes.code drop not null');
    await run(`ALTER TABLE public.codes ADD COLUMN IF NOT EXISTS code_sha256 TEXT`, 'alter codes add code_sha256');

    await run(`
      CREATE TABLE IF NOT EXISTS public.tokens (
        id SERIAL PRIMARY KEY,
        token TEXT UNIQUE NOT NULL,
        premium BOOLEAN NOT NULL DEFAULT TRUE,
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        revoked BOOLEAN NOT NULL DEFAULT FALSE,
        code_id INTEGER REFERENCES public.codes(id) ON DELETE SET NULL,
        email TEXT
      )`, 'create tokens table');
    // Usage tracking columns for active users feature
    await run(`ALTER TABLE public.tokens ADD COLUMN IF NOT EXISTS last_seen_at BIGINT`, 'alter tokens add last_seen_at');
    await run(`ALTER TABLE public.tokens ADD COLUMN IF NOT EXISTS last_premium BOOLEAN`, 'alter tokens add last_premium');
    await run(`ALTER TABLE public.tokens ADD COLUMN IF NOT EXISTS last_origin TEXT`, 'alter tokens add last_origin');
    await run(`ALTER TABLE public.tokens ADD COLUMN IF NOT EXISTS last_agent TEXT`, 'alter tokens add last_agent');

    await run(`
      CREATE TABLE IF NOT EXISTS public.redemptions (
        id SERIAL PRIMARY KEY,
        code_id INTEGER REFERENCES public.codes(id) ON DELETE CASCADE,
        token_id INTEGER REFERENCES public.tokens(id) ON DELETE CASCADE,
        origin TEXT,
        created_at BIGINT NOT NULL
      )`, 'create redemptions table');

    // Ensure licenses table exists for activation bookkeeping
    await run(`
      CREATE TABLE IF NOT EXISTS public.licenses (
        email TEXT PRIMARY KEY,
        plan TEXT,
        active BOOLEAN,
        activated_at TIMESTAMPTZ,
        status TEXT DEFAULT 'active',
        subscription_id TEXT,
        canceled_at TIMESTAMPTZ
      )`, 'create licenses table');

    // Back-compat tables
    await run(`
      CREATE TABLE IF NOT EXISTS public.purchase_events (
        id SERIAL PRIMARY KEY,
        session_id TEXT UNIQUE NOT NULL,
        email TEXT,
        created_at BIGINT NOT NULL
      )`, 'create purchase_events table');

    await run(`
      CREATE TABLE IF NOT EXISTS public.processed_events (
        id TEXT PRIMARY KEY,
        created_at TIMESTAMPTZ DEFAULT now()
      )`, 'create processed_events table');

    await run(`
      CREATE TABLE IF NOT EXISTS public.purchases (
        session_id TEXT PRIMARY KEY,
        email TEXT,
        created_at TIMESTAMPTZ DEFAULT now()
      )`, 'create purchases table');

    // Useful indexes (immutable predicates; no NOW() in predicates)
  await run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_codes_code ON public.codes (code)`, 'index: codes.code unique');
  await run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_codes_sha256 ON public.codes (code_sha256) WHERE code_sha256 IS NOT NULL`, 'index: codes.code_sha256 unique where not null');
    // Note: using "note" as email placeholder during migration
    await run(`CREATE INDEX IF NOT EXISTS idx_codes_email ON public.codes (note)`, 'index: codes.email (note)');
    await run(`CREATE INDEX IF NOT EXISTS idx_codes_redeemed ON public.codes (redeemed)`, 'index: codes.redeemed');
    await run(`
      CREATE INDEX IF NOT EXISTS idx_codes_expires_at_notnull
        ON public.codes (expires_at)
        WHERE expires_at IS NOT NULL
    `, 'index: codes.expires_at not null');
    await run(`
      CREATE INDEX IF NOT EXISTS idx_codes_redeemed_expires_at_notnull
        ON public.codes (redeemed, expires_at)
        WHERE expires_at IS NOT NULL
    `, 'index: codes.redeemed + expires_at (not null)');
    await run(`
      CREATE INDEX IF NOT EXISTS idx_codes_active_infinite
        ON public.codes (redeemed)
        WHERE redeemed = FALSE AND expires_at IS NULL
    `, 'index: codes.active infinite');

    // One-active-per-email (using status='active' and note=email during migration). Recreate safely with cleanup on conflict.
  await run(`DROP INDEX IF EXISTS codes_active_unique`, 'drop active unique index (old)');
    try {
      await run(`CREATE UNIQUE INDEX IF NOT EXISTS codes_active_unique ON public.codes (note) WHERE status = 'active'`, 'create active unique index');
    } catch (e) {
      if (e && (e.code === '23505' || e.code === '42P07')) {
        log.warn('[DB] Active unique index create conflict; normalizing and revoking older active per email, then retrying');
        await run(`UPDATE public.codes SET note = LOWER(TRIM(note)) WHERE note IS NOT NULL`, 'normalize emails to lowercase');
        await run(`
          WITH ranked AS (
            SELECT id, note, status, created_at,
                   ROW_NUMBER() OVER (PARTITION BY note ORDER BY created_at DESC) AS rn
            FROM public.codes
            WHERE status = 'active'
          )
          UPDATE public.codes c
             SET status = 'revoked', revoked_at = NOW()
            FROM ranked r
           WHERE c.id = r.id
             AND r.rn > 1
        `, 'revoke older active codes per email');
        await run(`DROP INDEX IF EXISTS codes_active_unique`, 'drop active unique index (retry)');
        await run(`CREATE UNIQUE INDEX IF NOT EXISTS codes_active_unique ON public.codes (note) WHERE status = 'active'`, 'create active unique index (retry)');
      } else {
        throw e;
      }
    }

    // Seed demo code if not present
    await pool.query('INSERT INTO public.codes (code, redeemed, created_at) VALUES ($1, FALSE, $2) ON CONFLICT (code) DO NOTHING', ['DEMO-AURASYNC-1234', Date.now()]);

    // Sanity checks for required columns to avoid runtime 25P02 errors later
    const sanity = async (table, col) => {
      const r = await pool.query(`SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name=$2`, [table, col]);
      if (!r.rows.length) {
        console.error(`[SCHEMA] Missing column public.${table}.${col}`);
        process.exit(1);
      }
    };
  await sanity('codes','code_hash');
  await sanity('codes','status');
  await sanity('codes','code_sha256');

    // Opportunistic lightweight backfill: fill code_sha256 where plaintext still exists
    try {
      await run(`
        UPDATE public.codes
           SET code_sha256 = CASE WHEN code IS NOT NULL THEN encode(digest(code, 'sha256'), 'hex') ELSE code_sha256 END
         WHERE code IS NOT NULL AND code_sha256 IS NULL
      `, 'backfill code_sha256 where plaintext');
    } catch (e) {
      log.warn({ err: String(e?.message || e) }, '[DB] backfill code_sha256 skipped');
    }
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
      log.info({ params: { code_is_null: raw == null, code_len: raw ? raw.length : null, note: note || '', created_at: nowMs } }, '[DB] insert_code params');
      await pool.query('INSERT INTO codes (code, code_hash, code_sha256, redeemed, note, created_at) VALUES ($1, $2, $3, FALSE, $4, $5)', [raw, hash, sha256Hex(raw), note || '', nowMs]);
      codes.push(raw);
    }
  } else {
    for (let i = 0; i < n; i++) {
      let code;
      do { code = crypto.randomBytes(16).toString('base64url'); } while (mem.codes.has(code));
      const id = mem.nextId.code++;
  const code_hash = await argon2.hash(code);
  mem.codes.set(code, { id, code, code_hash, code_sha256: sha256Hex(code), status: 'active', expires_at: Date.now() + 365*24*60*60*1000, redeemed: false, note: note || '', created_at: nowMs, redeemed_at: null, origin: '' });
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
  // Fast path: direct match by plaintext (legacy rows)
  let { rows } = await q(client, 'sel_by_plain', 'SELECT id, code, code_hash, code_sha256, redeemed, status, expires_at, note FROM public.codes WHERE code=$1 FOR UPDATE', [codeStr]);
  let c = rows[0] || null;
  let verified = false;
  if (c && c.code === codeStr) verified = true;
      // Fast path: fingerprint match for hashed-only rows
      if (!c) {
        const fp = sha256Hex(codeStr);
        ({ rows } = await q(client, 'sel_by_fp', 'SELECT id, code, code_hash, code_sha256, redeemed, status, expires_at, note FROM public.codes WHERE code_sha256=$1 FOR UPDATE', [fp]));
        if (rows[0]) {
          const row = rows[0];
          const ok = row.code_hash ? await argon2.verify(row.code_hash, codeStr).catch(() => false) : false;
          if (ok) { c = row; verified = true; }
        }
      }
      // Legacy fallback: scan limited recent candidates (avoids full table scan)
      if (!c) {
        const recent = await q(client, 'sel_recent_candidates', `
          SELECT id, code, code_hash, code_sha256, redeemed, status, expires_at, note
          FROM public.codes
          WHERE (redeemed = FALSE OR status = 'active')
          ORDER BY created_at DESC
          LIMIT 500
          FOR UPDATE`);
        for (const r of recent.rows) {
          let ok = false;
          if (r.code && r.code === codeStr) ok = true;
          else if (r.code_hash) ok = await argon2.verify(r.code_hash, codeStr).catch(() => false);
          if (ok) { c = r; if (r.code_hash) verified = true; break; }
        }
        if (c && !c.code_sha256) {
          try { await q(client, 'backfill_fp', 'UPDATE public.codes SET code_sha256=$1 WHERE id=$2', [sha256Hex(codeStr), c.id]); } catch (_) {}
        }
      }
      if (!c) { throw new Error('INVALID_CODE'); }
      // Check used/expired status
      if (c.status && ['used','revoked','expired'].includes(String(c.status))) {
        throw new Error('INVALID_CODE');
      }
      if (c.redeemed === true) { throw new Error('INVALID_CODE'); }
      if (c.expires_at && new Date(c.expires_at) < new Date()) { throw new Error('EXPIRED_CODE'); }
      // Re-bind email on first redeem if provided
      const norm = email ? normalizeEmail(email) : null;
      if (norm && (!c.note || normalizeEmail(c.note) !== norm)) {
        await q(client, 'bind_email', 'UPDATE public.codes SET note=$1 WHERE id=$2', [norm, c.id]);
      }
      // Verify hash or legacy plaintext
      let ok = verified;
      if (!ok && c.code_hash) {
        ok = await argon2.verify(c.code_hash, codeStr).catch(() => false);
      }
      if (!ok && c.code) {
        ok = (c.code === codeStr);
        if (ok) {
          const h = await argon2.hash(c.code);
          const fp = c.code_sha256 || sha256Hex(c.code);
          await q(client, 'backfill_hash', 'UPDATE public.codes SET code_hash=$1, code=NULL, code_sha256=COALESCE(code_sha256, $3) WHERE id=$2', [h, c.id, fp]);
        }
      }
      if (!ok) throw new Error('INVALID_CODE');

      // Create token and mark code as used
      log.info({ params: { token, created_at: nowMs, expires_at: expiresAt, code_id: c.id, email: (email || '').toLowerCase() } }, '[DB] insert_token params');
      const insTok = await q(
        client,
        'insert_token',
        'INSERT INTO tokens (token, premium, created_at, expires_at, revoked, code_id, email) VALUES ($1, TRUE, $2, $3, FALSE, $4, $5) RETURNING id',
        [token, nowMs, expiresAt, c.id, norm || (c.note || '').toLowerCase()]
      );
      const tokId = insTok.rows[0].id;
      log.info({ params: { redeemed_at: nowMs, origin: origin || '', status: 'used', code_id: c.id } }, '[DB] update_code_used params');
  await q(client, 'update_code_used', 'UPDATE public.codes SET redeemed=TRUE, redeemed_at=$1, origin=$2, status = $3 WHERE id=$4', [nowMs, origin || '', 'used', c.id]);
      // Clear legacy plaintext if any (best effort)
      try {
        log.info({ params: { code_id: c.id } }, '[DB] clear_plain params');
        await q(client, 'clear_plain', 'UPDATE public.codes SET code=NULL WHERE id=$1', [c.id]);
      } catch (_) {}
      log.info({ params: { code_id: c.id, token_id: tokId, origin: origin || '', created_at: nowMs } }, '[DB] insert_redemption params');
      await q(client, 'insert_redemption', 'INSERT INTO redemptions (code_id, token_id, origin, created_at) VALUES ($1, $2, $3, $4)', [c.id, tokId, origin || '', nowMs]);
      // Upsert license record if email provided
      if (email) {
        await q(client, 'upsert_license', `
          INSERT INTO licenses (email, plan, active, activated_at, status, subscription_id, canceled_at)
          VALUES ($1, 'premium', true, NOW(), 'active', NULL, NULL)
          ON CONFLICT (email)
          DO UPDATE SET active = true, plan = 'premium', activated_at = NOW(), status = 'active', canceled_at = NULL
        `, [email.toLowerCase()]);
        try { mem.licenses.set(normalizeEmail(email), { email: normalizeEmail(email), plan: 'premium', active: true, activated_at: new Date().toISOString(), status: 'active', subscription_id: null, canceled_at: null }); } catch(_) {}
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
  mem.tokens.set(token, { id: tokenId, token, premium: true, created_at: nowMs, expires_at: expiresAt, revoked: false, code_id: c.id, email: (email || '').toLowerCase(), last_seen_at: null, last_premium: null, last_origin: null, last_agent: null });
    const redId = mem.nextId.redemption++;
    mem.redemptions.push({ id: redId, code_id: c.id, token_id: tokenId, origin: origin || '', created_at: nowMs });
    return { token, premium: true };
  }
}

// Compatibility wrapper used by the /redeem route; preserves current JSON error contract
async function dbRedeemWithEmailBind({ code, email, origin }) {
  if (!code || typeof code !== 'string') return { error: 'invalid_code' };
  try {
    const raw = code.trim();
    const fp = sha256Hex(raw);
    if (missCacheHas(fp)) return { error: 'invalid_code' };
    const out = await dbRedeem(raw, origin || '', email || null);
    if (out && out.token) return { token: out.token };
    return { error: 'redeem_failed' };
  } catch (e) {
    const msg = String((e && e.message) || e || '');
    if (msg === 'INVALID_CODE') {
      try { missCacheSet(sha256Hex(code)); } catch {}
      return { error: 'invalid_code' };
    }
    if (msg === 'EXPIRED_CODE') return { error: 'already_used_or_expired' };
    return { error: 'redeem_failed' };
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

// Subscription helpers
async function hasActiveSubscription(email) {
  const raw = emailForStripe(email);
  const norm = normalizeEmail(email);
  // 1) Stripe direct check (use raw first to respect exact Stripe email)
  if (stripe) {
    try {
      let customers = await stripe.customers.list({ email: raw, limit: 1 });
      // Fallback: try normalized if raw yielded nothing (helps legacy rows)
      if (!customers?.data?.length && norm && norm !== raw) {
        customers = await stripe.customers.list({ email: norm, limit: 1 });
      }
      const customerId = customers?.data?.[0]?.id || null;
      if (customerId) {
        const subs = await stripe.subscriptions.list({ customer: customerId, status: 'active', limit: 1 });
        if (subs?.data?.length) return true;
      }
    } catch (_) { /* fall through */ }
  }
  // 2) DB licenses table
  if (pool) {
    try {
      const { rows } = await pool.query('SELECT active FROM licenses WHERE email=$1', [norm]);
      if (rows.length && rows[0].active === true) return true;
    } catch (_) {}
  } else {
    // 3) In-memory fallback
    const lic = mem.licenses.get(norm);
    if (lic && lic.active) return true;
  }
  return false;
}

// Stripe-only premium check (active OR trialing). Returns boolean.
async function hasActiveOrTrialingStripe(email) {
  const raw = emailForStripe(email);
  const norm = normalizeEmail(email);
  const searchEmail = raw || norm;
  if (!searchEmail || !stripe) return false;
  try {
    // Try raw first; if empty result and different, try normalized
    const attempts = [];
    attempts.push(searchEmail);
    if (norm && norm !== searchEmail) attempts.push(norm);
    const nowSec = Math.floor(Date.now() / 1000);
    for (const em of attempts) {
      const customers = await stripe.customers.list({ email: em, limit: 100 });
      for (const c of customers.data) {
        const subs = await stripe.subscriptions.list({ customer: c.id, status: 'all', limit: 100 });
        for (const s of subs.data) {
          const st = String(s.status || '').toLowerCase();
          if (st === 'active' || st === 'trialing') {
            if (!s.current_period_end || s.current_period_end > nowSec) return true;
          }
        }
      }
      // If we found nothing for this variant, continue to next
    }
  } catch (_) {}
  return false;
}

// --- Minimal helpers to mirror purchase behavior for the new /lost-code endpoint ---
async function isActiveSubscriber(email) {
  // Same definition as purchase: active or trialing on Stripe
  return await hasActiveOrTrialingStripe(email);
}

async function getOrCreateLicenseCode(email) {
  const norm = normalizeEmail(email);
  // Try to fetch the most recent active code with plaintext value
  if (pool) {
    try {
      const { rows } = await pool.query(
        "SELECT id, code FROM public.codes WHERE note=$1 AND status='active' ORDER BY created_at DESC LIMIT 1",
        [norm]
      );
      const row = rows[0];
      if (row && row.code) return row.code;
    } catch (_) {}
  } else {
    const list = [...mem.codes.values()]
      .filter(c => normalizeEmail(c.note||'') === norm && (c.status || (c.redeemed ? 'used' : 'active')) === 'active')
      .sort((a,b)=>Number(b.created_at)-Number(a.created_at));
    if (list[0]?.code) return list[0].code;
  }
  // Otherwise issue a new one using the same generator used on purchase
  const { code } = await issueLicenseForPlan({ email: norm, plan: 'premium', priceId: null, mode: 'lost-code', subId: null, sessionId: `lost-code:${Date.now()}` });
  return code;
}

async function sendLicenseEmailSimple(email, code) {
  // Reuse purchase email sender/template
  await sendLicenseEmail({ to: email, code, plan: 'premium', mode: 'lost-code' });
}

// Helper: find a code row by matching plaintext or verifying code_hash
async function dbFindCodeByPlainOrHash(codeStr) {
  if (!codeStr) return null;
  if (pool) {
    // Try fast paths first
    let r;
    r = await pool.query('SELECT id, code, code_hash, code_sha256, note, created_at FROM public.codes WHERE code=$1 LIMIT 1', [codeStr]);
    if (r.rows[0]) return r.rows[0];
    const fp = sha256Hex(codeStr);
    r = await pool.query('SELECT id, code, code_hash, code_sha256, note, created_at FROM public.codes WHERE code_sha256=$1 LIMIT 1', [fp]);
    if (r.rows[0]) {
      const row = r.rows[0];
      try {
        if (row.code_hash && await argon2.verify(row.code_hash, codeStr)) return row;
      } catch {}
    }
    // Fallback scan (rare)
    const { rows } = await pool.query('SELECT id, code, code_hash, code_sha256, note, created_at FROM public.codes ORDER BY created_at DESC LIMIT 1000');
    for (const r of rows) {
      let ok = false;
      if (r.code_hash) {
        try { ok = await argon2.verify(r.code_hash, codeStr); } catch (_) { ok = false; }
      }
      if (!ok && r.code) ok = (r.code === codeStr);
      if (ok) {
        // backfill missing fingerprint if needed
        if (!r.code_sha256) {
          try { await pool.query('UPDATE public.codes SET code_sha256=$1 WHERE id=$2', [sha256Hex(codeStr), r.id]); } catch {}
        }
        return r;
      }
    }
    return null;
  } else {
    for (const c of mem.codes.values()) {
      let ok = false;
      if (c.code_hash) {
        try { ok = await argon2.verify(c.code_hash, codeStr); } catch (_) { ok = false; }
      }
      if (!ok && c.code) ok = (c.code === codeStr);
      if (ok) return { id: c.id, code: c.code, note: c.note, created_at: c.created_at };
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

// --- CORS configuration (strict allowlist with extension support) ---
const STRICT_ALLOWED = new Set([
  'https://aurasync.info',
  'https://www.aurasync.info',
  // Allow GitHub Pages (used in some flows)
  'https://aurachatapp.github.io'
]);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    const isExtension = origin.startsWith('chrome-extension://');
    if (STRICT_ALLOWED.has(origin) || isExtension) {
      res.header('Access-Control-Allow-Origin', origin);
    }
  }
  res.header('Vary', 'Origin');
  // Allow GET for status endpoints
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  // Allow admin testing headers too
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Admin-Secret');
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

// Stripe webhook (idempotent code issuance) — must be before express.json()
// Hardened Stripe webhook handler: strict size limit, event allowlist, livemode guard
app.post('/stripe/webhook', bodyParser.raw({ type: 'application/json', limit: '1mb' }), async (req, res) => {
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
    const allowEvents = new Set([
      'checkout.session.completed',
      'invoice.payment_succeeded',
      'invoice.paid',
      'invoice_payment.paid'
    ]);
    if (!allowEvents.has(event.type)) {
      // Immediately acknowledge to prevent retries but do nothing else
      return res.sendStatus(200);
    }
    // Optional livemode vs key check (best-effort, skip if missing api key)
    try {
      const key = process.env.STRIPE_SECRET_KEY || '';
      const keyIsLive = key.startsWith('sk_live_');
      if (typeof event.livemode === 'boolean' && event.livemode !== keyIsLive) {
        console.warn('[WH] livemode/key mismatch', { event_livemode: event.livemode, keyIsLive });
        return res.sendStatus(200); // do not process
      }
    } catch (_) {}
    // DB-backed idempotency: insert-once and bail if duplicate
    let firstTime = true;
    if (!ALLOW_DUPLICATES) {
      firstTime = await markProcessedOnce(evtId).catch((e) => {
        log.error({ err: String(e?.message || e) }, '[WH] processed mark failed');
        return false;
      });
      if (!firstTime) {
        console.info(`[WH2 ${requestId}] duplicate or mark-failed event ${evtId}`);
        return res.sendStatus(200);
      }
    } else {
      console.warn(`[WH2 ${requestId}] ALLOW_DUPLICATES override active – processing event ${evtId} even if previously seen`);
    }
    const type = event.type;

    // --- Handle Checkout Session (one-time payments or subscriptions) ---
    if (type === 'checkout.session.completed') {
      const sessObj = event.data?.object;
      const sessionId = sessObj?.id;
      if (!sessionId) return res.status(400).json({ error: 'missing_session' });

      // Retrieve full session w/ line items & product
      let session;
      try {
        session = await stripe.checkout.sessions.retrieve(sessionId, {
          expand: ['line_items.data.price.product', 'subscription', 'customer', 'customer_details']
        });
      } catch (e) {
        console.error(`[WH2 ${requestId}] retrieve failed`, e?.message);
        return res.status(502).json({ error: 'stripe_unavailable' });
      }
      if (!session || session.payment_status !== 'paid') {
        console.info(`[WH2 ${requestId}] not paid`);
        return res.status(400).json({ error: 'not_paid' });
      }
  const email = normalizeEmail(session.customer_details?.email || session.customer?.email || session.customer_email || '');
      if (!email) return res.status(400).json({ error: 'no_email' });

      const itemsAll = (session.line_items && session.line_items.data) ? session.line_items.data : [];
      // Cap processed items to avoid pathological large payloads
      const items = itemsAll.slice(0, 25);
      const plans = [];
      for (const it of items) {
        const priceId = it?.price?.id;
        if (!priceId) continue;
        if (!ALLOWED_PRICES.includes(priceId)) {
          log.warn({ priceId }, '[WH] unrecognized price id');
          continue;
        }
        const plan = PRICE_TO_PLAN[priceId] || 'unknown';
        plans.push({ priceId, plan, quantity: it?.quantity || 1 });
      }
      const valid = plans;
      if (valid.length === 0) {
        log.warn({ items: items.map(i => i?.price?.id) }, '[WH] no recognized price ids');
        return res.sendStatus(200);
      }

      const mode = session.mode; // 'subscription' | 'payment'
      const subId = (typeof session.subscription === 'string') ? session.subscription : (session.subscription?.id || null);
      const priceIds = items.map(i => i?.price?.id).filter(Boolean);

      // Issue codes for each recognized item and quantity
      try {
        for (const { plan, priceId, quantity } of valid) {
          for (let i = 0; i < quantity; i++) {
            const info = await issueLicenseForPlan({ email, plan, priceId, mode, subId, sessionId });
            await sendLicenseEmail({ to: email, code: info.code, plan, mode });
            await recordPurchaseEvent({ kind: 'checkout.session.completed', plan, priceId, mode, subId, sessionId, email });
            if (mode === 'subscription' && subId) {
              await upsertLicenseSubscription({ email, subscriptionId: subId, status: 'active' });
            }
          }
        }
        log.info({ type, mode, email, priceIds, trigger: 'checkout.session.completed' }, '[WH] OK');
        return res.sendStatus(200);
      } catch (err) {
        log.error({ err: String(err?.message || err), type, mode, sessionId }, '[WH] error issuing license');
        // Do not throw; Stripe will stop retrying
        return res.sendStatus(200);
      }
    }

    // --- Handle Invoice events (initial subscription payments) ---
    // Support legacy & new naming: invoice.payment_succeeded, invoice.paid (older), invoice_payment.paid (2025+ alias)
    const INVOICE_EVENTS = new Set([
      'invoice.payment_succeeded',
      'invoice.paid', // legacy (already existed in code)
      'invoice_payment.paid'
    ]);
    if (INVOICE_EVENTS.has(type)) {
      const invoice = event.data?.object || {};
      const reason = invoice.billing_reason;
      const paid = !!invoice.paid || invoice.status === 'paid';
      // Skip renewals: only issue license on first creation (subscription_create) or if reason is not subscription_cycle
      if (!paid) {
        log.info({ type, reason, paid }, '[WH] invoice not paid yet');
        return res.sendStatus(200);
      }
      if (reason === 'subscription_cycle') {
        log.info({ type, reason, subscription: invoice.subscription }, '[WH] renewal processed (no new code)');
        return res.sendStatus(200);
      }
      // Extract email
      const rawEmail = (invoice.customer_email || invoice.customer_details?.email || '').toString();
      const email = normalizeEmail(rawEmail);
      if (!email) {
        log.warn({ type, reason }, '[WH] invoice missing email');
        return res.sendStatus(200);
      }
      // Collect price/plan mappings from line items
      const linesAll = (invoice.lines && invoice.lines.data) ? invoice.lines.data : [];
      const lines = linesAll.slice(0, 40); // cap invoice line processing
      const valid = [];
      for (const li of lines) {
        try {
          const priceId = li?.price?.id;
          const qty = li?.quantity || 1;
          if (!priceId) continue;
          if (!ALLOWED_PRICES.includes(priceId)) {
            log.warn({ priceId }, '[WH] unrecognized price id (invoice)');
            continue;
          }
          const plan = PRICE_TO_PLAN[priceId] || 'unknown';
          valid.push({ plan, priceId, quantity: qty });
        } catch (_) { /* ignore malformed line */ }
      }
      if (valid.length === 0) {
        log.warn({ type, items: lines.map(l=>l?.price?.id) }, '[WH] no recognized price ids (invoice)');
        return res.sendStatus(200);
      }
      const subId = invoice.subscription || null;
      const sessionId = `invoice:${invoice.id}`; // synthetic session id for idempotency tracking
      try {
        for (const { plan, priceId, quantity } of valid) {
          for (let i = 0; i < quantity; i++) {
            const info = await issueLicenseForPlan({ email, plan, priceId, mode: 'subscription', subId, sessionId });
            await sendLicenseEmail({ to: email, code: info.code, plan, mode: 'subscription' });
            await recordPurchaseEvent({ kind: type, plan, priceId, mode: 'subscription', subId, sessionId, email });
            if (subId) await upsertLicenseSubscription({ email, subscriptionId: subId, status: 'active' });
          }
        }
        log.info({ type, email, reason, subscription: subId, trigger: 'invoice_event' }, '[WH] OK');
      } catch (err) {
        log.error({ err: String(err?.message || err), type, subscription: subId }, '[WH] error issuing license (invoice)');
      }
      return res.sendStatus(200);
    }

    // --- Subscription cancellation / update events ---
    if (type === 'customer.subscription.updated' || type === 'customer.subscription.deleted') {
      const sub = event.data?.object || {};
      const status = String(sub.status || '').toLowerCase();
      const customerId = sub.customer;
      let email = null;
      if (stripe && customerId) {
        try {
          const cust = await stripe.customers.retrieve(customerId);
          email = normalizeEmail(cust.email || '');
        } catch (_) {}
      }
      if (email) {
        if (status === 'canceled' || status === 'unpaid' || status === 'incomplete_expired') {
          await upsertLicenseSubscription({ email, subscriptionId: sub.id, status: 'canceled' });
          log.info({ type, email, subscription: sub.id, newStatus: 'canceled' }, '[WH] subscription canceled recorded');
        } else if (status === 'active' || status === 'trialing' || status === 'past_due') {
          await upsertLicenseSubscription({ email, subscriptionId: sub.id, status });
          log.info({ type, email, subscription: sub.id, newStatus: status }, '[WH] subscription status updated');
        }
      }
      return res.sendStatus(200);
    }

    // Ignore other events
    console.info(`[WH2 ${requestId}] ignore ${type}`);
  return res.json({ received: true });
  } catch (e) {
  console.error('[WH2] error', e);
  // Do not cause Stripe retries on unexpected errors
  return res.sendStatus(200);
  }
});

// After webhook: global parsers for JSON and urlencoded
app.use(express.json());

// Serve static files for main site
app.use(express.static(path.join(__dirname, '../public')));
// Serve admin static assets under /admin-assets to avoid /admin/* API collision
app.use('/admin-assets', express.static(path.join(__dirname, '../public/admin')));
// Ensure /admin and /admin/ route to index.html (SPA entry)
app.get(['/admin', '/admin/'], (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin/index.html'));
});
app.use(express.urlencoded({ extended: true }));
// Compression
app.use(compression());

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

// Insert event id once; return true if newly inserted
async function markProcessedOnce(eventId) {
  if (pool) {
    const r = await pool.query('INSERT INTO processed_events (id) VALUES ($1) ON CONFLICT DO NOTHING', [eventId]);
    return r.rowCount > 0;
  } else {
    if (!mem.processed_events) mem.processed_events = new Set();
    const before = mem.processed_events.size;
    mem.processed_events.add(eventId);
    return mem.processed_events.size > before;
  }
}

// Issue a new license for a given plan; returns { code, token }
async function issueLicenseForPlan({ email, plan, priceId, mode, subId, sessionId }) {
  const nowMs = Date.now();
  if (pool) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      // Revoke any current active code for this email to satisfy unique active index
      await client.query("UPDATE public.codes SET status='revoked', revoked_at=NOW() WHERE note=$1 AND status='active'", [email]);
      // Generate unique code and insert as active
      let raw;
      while (true) {
        raw = crypto.randomBytes(16).toString('base64url');
        const { rows } = await client.query('SELECT 1 FROM public.codes WHERE code=$1', [raw]);
        if (rows.length === 0) break;
      }
      const hash = await argon2.hash(raw);
      await client.query(
        'INSERT INTO public.codes (code, code_hash, code_sha256, redeemed, note, created_at, status) VALUES ($1, $2, $3, FALSE, $4, $5, $6)',
        [raw, hash, sha256Hex(raw), email, nowMs, 'active']
      );
      await client.query('INSERT INTO public.purchases (session_id, email) VALUES ($1, $2) ON CONFLICT DO NOTHING', [sessionId, email]);
      await client.query('COMMIT');
      return { code: raw };
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch (_) {}
      throw e;
    } finally {
      client.release();
    }
  } else {
    const codes = await dbCreateCodes(1, email);
    const code = codes[0];
    await recordPurchase(sessionId, email);
    return { code };
  }
}

async function sendLicenseEmail({ to, code, plan, mode }) {
  const subject = 'Your AuraSync activation code';
  const html = renderLicenseEmailHtml(code);
  await sendEmail(to, subject, html);
}

async function recordPurchaseEvent({ kind, plan, priceId, mode, subId, sessionId, email }) {
  try {
    if (pool) {
      await pool.query('INSERT INTO purchase_events (session_id, email, created_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [sessionId, email, Date.now()]);
    }
  } catch (_) {}
}

// Upsert or update license record with subscription linkage
async function upsertLicenseSubscription({ email, subscriptionId, status }) {
  const norm = normalizeEmail(email);
  const st = status || 'active';
  if (pool) {
    try {
      await pool.query(`
        INSERT INTO licenses (email, plan, active, activated_at, status, subscription_id, canceled_at)
        VALUES ($1, 'premium', $2, NOW(), $3, $4, CASE WHEN $3='canceled' THEN NOW() ELSE NULL END)
        ON CONFLICT (email) DO UPDATE SET
          status = EXCLUDED.status,
          active = EXCLUDED.active,
          subscription_id = EXCLUDED.subscription_id,
          canceled_at = CASE WHEN EXCLUDED.status='canceled' THEN NOW() ELSE licenses.canceled_at END
      `, [norm, st !== 'canceled', st, subscriptionId || null]);
    } catch (e) {
      console.error('upsertLicenseSubscription error', e?.message || e);
    }
  } else {
    const cur = mem.licenses.get(norm) || {};
    mem.licenses.set(norm, {
      email: norm,
      plan: 'premium',
      active: st !== 'canceled',
      activated_at: cur.activated_at || new Date().toISOString(),
      status: st,
      subscription_id: subscriptionId || null,
      canceled_at: st === 'canceled' ? new Date().toISOString() : cur.canceled_at || null
    });
  }
}

// POST /activate { session_id }
// Apply rate limits
const burstLimiter = rateLimit({ windowMs: 60_000, max: 20, standardHeaders: true, legacyHeaders: false });
app.use('/stripe/webhook', burstLimiter);
const codeLimiter = rateLimit({ windowMs: 5 * 60_000, max: 10, keyGenerator: (req) => (req.body?.email || req.ip) });
// Apply only to /activate; /lost-code has a separate daily limiter per spec
app.use(['/activate'], codeLimiter);

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
    const t0 = Date.now();
    const { email, code } = req.valid;
    if (!code) return res.status(400).json({ error: 'missing_code' });
    const normEmail = email ? normalizeEmail(email) : null;
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || '';
    const REDEEM_WINDOW_MS = 5 * 60 * 1000;
    const key = `${ip}:${normEmail || code}`;
    const nowMs = now();
    // --- Developer master code: infinite use, never expires ---
    if (DEV_MASTER_CODE && code === DEV_MASTER_CODE) {
      const token = `dev-${randomUUID()}`;
      try {
        if (typeof saveToken === 'function') {
          await saveToken({ token, code_id: null, origin: req.headers.origin || 'extension', note: 'dev_master', dev: true });
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

    // Only code is required; email is optional and only used for first-time binding
    const origin = req.headers.origin || '';
    let result;
    try {
      result = await dbRedeemWithEmailBind({ code, email: normEmail, origin });
    } catch (e) {
      log.error({ err: String(e?.message || e) }, 'redeem_failed');
      const ms = Date.now() - t0;
      log.info({ ms }, 'redeem_latency');
      return res.status(500).json({ error: 'redeem_failed' });
    }
    const ms = Date.now() - t0;
    log.info({ ms }, 'redeem_latency');
    if (result?.error === 'invalid_code') return res.status(400).json({ error: 'invalid_code' });
    if (result?.error === 'already_used_or_expired') return res.status(400).json({ error: 'already_used_or_expired' });
    if (!result?.token) return res.status(500).json({ error: 'redeem_failed' });
    return res.json({ token: result.token, premium: true });
  } catch (err) {
    log.error({ err: String(err?.message || err) }, 'redeem_failed');
    res.status(500).json({ error: 'redeem_failed' });
  }
});

// GET /status?token=...  (treat token as email for now)
// Always returns JSON { premium: boolean, email: string }
const BUILD_HASH = process.env.BUILD_HASH || require('crypto').createHash('sha1').update(String(Date.now())).digest('hex').slice(0,8);
app.get('/status', async (req, res) => {
  const t0 = Date.now();
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json');
  try {
    const rawIn = String((req.query.email ?? req.query.token) || '').trim();
    const rawEmail = emailForStripe(rawIn);
    const displayEmail = normalizeEmail(rawIn);
    if (!rawEmail || !rawEmail.includes('@')) return res.json({ premium: false, status: 'inactive', email: '', subscription_id: null });
    // Fetch license record
    let license = null;
    if (pool) {
      try { const { rows } = await pool.query('SELECT email, status, subscription_id, canceled_at, active FROM licenses WHERE email=$1', [normalizeEmail(rawEmail)]); license = rows[0] || null; } catch (_) {}
    } else {
      license = mem.licenses.get(normalizeEmail(rawEmail)) || null;
    }
    let status = 'inactive';
    let subscriptionId = null;
    let canceledAt = null;
    let premium = false;
    let debug = { buildHash: BUILD_HASH, source: 'license_row', stripeLookup: 'skipped', licenseRowPresent: !!license, licenseRowUpdatedAt: null };
    if (license && license.subscription_id && ['active','trialing','past_due'].includes(license.status)) {
      status = license.status;
      subscriptionId = license.subscription_id;
      canceledAt = license.canceled_at ? new Date(license.canceled_at).toISOString() : null;
      premium = true;
      debug.source = 'license_row';
      debug.licenseRowUpdatedAt = license.activated_at || null;
    } else if (stripe) {
      debug.source = 'stripe_fallback';
      try {
        const customers = await stripe.customers.list({ email: rawEmail, limit: 1 });
        const customer = customers.data[0];
        if (customer) {
          debug.stripeLookup = 'hit';
          const subs = await stripe.subscriptions.list({ customer: customer.id, status: 'all', limit: 10 });
          const best = subs.data.find(s => ['active','trialing','past_due'].includes(s.status));
          if (best) {
            status = best.status;
            subscriptionId = best.id;
            premium = true;
            await upsertLicenseSubscription({ email: rawEmail, subscriptionId: best.id, status: best.status });
            debug.stripeLookup = 'active';
          } else {
            const canceled = subs.data.find(s => s.status === 'canceled');
            if (canceled) {
              status = 'canceled';
              subscriptionId = canceled.id;
              canceledAt = canceled.canceled_at ? new Date(canceled.canceled_at * 1000).toISOString() : null;
              await upsertLicenseSubscription({ email: rawEmail, subscriptionId: canceled.id, status: 'canceled' });
              debug.stripeLookup = 'canceled';
            } else {
              debug.stripeLookup = 'miss';
            }
          }
        } else {
          debug.stripeLookup = 'miss';
        }
      } catch (e) {
        debug.source = 'error';
        debug.stripeLookup = 'error';
        debug.error = e?.message || String(e);
        console.error('[status] stripe fallback error', e?.message || e);
      }
    }
    if (process.env.NODE_ENV !== 'production') {
      console.info('[status] resp', { email: displayEmail, status, premium, subscriptionId, debug });
    }
    return res.json({ premium, status, email: displayEmail, subscription_id: subscriptionId, canceled_at: canceledAt, debug });
  } catch (err) {
    console.error('Status error:', err);
    return res.json({ premium: false, status: 'inactive', email: '', subscription_id: null });
  } finally {
    const ms = Date.now() - t0; if (ms > 1900) console.warn('[status] slow', ms);
  }
});

// GET /status-by-email?email=...
// Returns JSON { premium: boolean }
app.get('/status-by-email', async (req, res) => {
  const t0 = Date.now();
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json');
  try {
    const rawIn = String(req.query.email || '');
    const rawEmail = emailForStripe(rawIn);
    const norm = normalizeEmail(rawIn);
    if (!rawEmail || !rawEmail.includes('@')) return res.json({ premium: false, status: 'inactive', email: '', subscription_id: null });
    let license = null;
    if (pool) {
      try { const { rows } = await pool.query('SELECT email, status, subscription_id, canceled_at, active FROM licenses WHERE email=$1', [norm]); license = rows[0] || null; } catch (_) {}
    } else {
      license = mem.licenses.get(norm) || null;
    }
    let status = 'inactive';
    let subscriptionId = null;
    let canceledAt = null;
    let premium = false;
    let debug = { buildHash: BUILD_HASH, source: 'license_row', stripeLookup: 'skipped', licenseRowPresent: !!license, licenseRowUpdatedAt: null };
    if (license && license.subscription_id && ['active','trialing','past_due'].includes(license.status)) {
      status = license.status;
      subscriptionId = license.subscription_id;
      canceledAt = license.canceled_at ? new Date(license.canceled_at).toISOString() : null;
      premium = true;
      debug.source = 'license_row';
      debug.licenseRowUpdatedAt = license.activated_at || null;
    } else if (stripe) {
      debug.source = 'stripe_fallback';
      try {
        const customers = await stripe.customers.list({ email: norm, limit: 1 });
        const customer = customers.data[0];
        if (customer) {
          debug.stripeLookup = 'hit';
          const subs = await stripe.subscriptions.list({ customer: customer.id, status: 'all', limit: 10 });
          const best = subs.data.find(s => ['active','trialing','past_due'].includes(s.status));
          if (best) {
            status = best.status;
            subscriptionId = best.id;
            premium = true;
            await upsertLicenseSubscription({ email: norm, subscriptionId: best.id, status: best.status });
            debug.stripeLookup = 'active';
          } else {
            const canceled = subs.data.find(s => s.status === 'canceled');
            if (canceled) {
              status = 'canceled';
              subscriptionId = canceled.id;
              canceledAt = canceled.canceled_at ? new Date(canceled.canceled_at * 1000).toISOString() : null;
              await upsertLicenseSubscription({ email: norm, subscriptionId: canceled.id, status: 'canceled' });
              debug.stripeLookup = 'canceled';
            } else {
              debug.stripeLookup = 'miss';
            }
          }
        } else {
          debug.stripeLookup = 'miss';
        }
      } catch (e) {
        debug.source = 'error';
        debug.stripeLookup = 'error';
        debug.error = e?.message || String(e);
        console.error('[status-by-email] stripe fallback error', e?.message || e);
      }
    }
    if (process.env.NODE_ENV !== 'production') console.info('[status-by-email] resp', { email: norm, status, premium, subscriptionId, debug });
    return res.json({ premium, status, email: norm, subscription_id: subscriptionId, canceled_at: canceledAt, debug });
  } catch (e) {
    console.error('status-by-email error:', e);
    return res.json({ premium: false, status: 'inactive', email: '', subscription_id: null });
  } finally {
    const ms = Date.now() - t0; if (ms > 1900) console.warn('[status-by-email] slow', ms);
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

// --- Lost code (minimal): POST /lost-code with { email } ---
const lostCodeDailyMap = new Map(); // simple per-email 1/day limiter
app.post('/lost-code', async (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-store');
    const email = normalizeEmail(String(req.body?.email || ''));
    if (!email || !email.includes('@')) {
      return res.status(400).json({ success: false, error: 'invalid_input' });
    }

    // Dev mode detection: NODE_ENV=development or X-Aura-Dev: 1 header
    const isDev = (String(process.env.NODE_ENV).toLowerCase() === 'development') || (req.headers['x-aura-dev'] === '1');
    let skipCooldown = false;
    if (isDev) {
      skipCooldown = true;
      console.info('[lost-code] dev bypass for', email);
    }

    // Optional: 1 email/day (skip in dev)
    const nowMs = Date.now();
    if (!skipCooldown) {
      const last = lostCodeDailyMap.get(email) || 0;
      if (nowMs - last < 24*60*60*1000) {
        return res.status(429).json({ success: false, error: 'rate_limited' });
      }
    }

    // 1) Reuse purchase subscription check (active or trialing)
    const premium = await isActiveSubscriber(email);
    if (!premium) {
      return res.status(400).json({ success: false, error: 'no_subscription' });
    }

    // 2) Reuse purchase code source
    const code = await getOrCreateLicenseCode(email);

    // 3) Reuse purchase email sender/template
    try {
      await sendLicenseEmailSimple(email, code);
    } catch (e) {
      console.error('lost-code send error', e);
      return res.status(500).json({ success: false, error: 'send_failed' });
    }

    if (!skipCooldown) lostCodeDailyMap.set(email, nowMs);
    return res.status(200).json({ success: true });
  } catch (e) {
    console.error('lost-code error', e);
    return res.status(500).json({ success: false, error: 'send_failed' });
  }
});

// Admin utility endpoint to test lost-code without cooldown
app.post('/admin/test-lost-code', async (req, res) => {
  if (!checkAdmin(req, res)) return;
  try {
    const email = normalizeEmail(String(req.body?.email || ''));
    const tokenOrCode = String(req.body?.token || req.body?.code || '').trim();
    if (!email || !tokenOrCode) return res.status(400).json({ error: 'missing_params' });
    // Simulate lost-code flow with bypass
    req.valid = { email, token: tokenOrCode, force: true };
    // Manually call handler logic by forwarding request — simplest is to call underlying operations
    const t = await dbGetToken(tokenOrCode);
    let codeRow = null;
    if (t) {
      codeRow = await dbGetCodeByToken(tokenOrCode);
    } else {
      codeRow = await dbFindCodeByPlainOrHash(tokenOrCode);
    }
    if (!codeRow) return res.status(404).json({ error: 'code_not_found' });
    const expectedEmail = normalizeEmail((codeRow.token_email || codeRow.note || '').toString());
    if (expectedEmail !== email) return res.status(403).json({ error: 'email_mismatch' });
    const active = await hasActiveSubscription(email);
    if (!active) return res.status(403).json({ error: 'subscription_not_active' });
    if (codeRow.id) await dbRevokeTokensByCodeId(codeRow.id);
    const [newCode] = await dbCreateCodes(1, email);
    await sendEmail(email, 'Your AuraSync license code', renderLicenseEmailHtml(newCode));
    return res.json({ ok: true, codeSent: true });
  } catch (e) {
    console.error('Admin test-lost-code error:', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// --- Admin endpoints (simple secret in header) ---
function checkAdmin(req, res) {
  const sec = req.headers['x-admin-secret'];
  let ok = (sec && sec === ADMIN_SECRET);
  if (!ok) {
    const auth = req.headers['authorization'] || '';
    // Accept Bearer <ADMIN_SECRET>
    if (auth && /^Bearer\s+.+/i.test(auth)) {
      const token = auth.replace(/^Bearer\s+/i, '').trim();
      ok = token === ADMIN_SECRET;
    }
  }
  if (!ok) {
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

// --- Admin: customers overview (active licenses, recent codes/tokens) ---
// GET /admin/customers?query=foo  → returns customers with active license matching email fragment
app.get('/admin/customers', async (req, res) => {
  if (!checkAdmin(req, res)) return;
  const q = normalizeEmail(String(req.query?.query || ''));
  try {
    const customers = [];
    if (!pool) {
      // memory store: iterate licenses
      for (const [email, lic] of mem.licenses.entries()) {
        if (!lic?.active) continue;
        if (q && !email.includes(q)) continue;
        const codes = [];
        const tokens = [];
        for (const c of mem.codes.values()) {
          const e = normalizeEmail(c.note || '');
          if (e === email) codes.push({ id: c.id, created_at: c.created_at, status: c.status || (c.redeemed ? 'used' : 'active') });
        }
        for (const [tok, t] of mem.tokens.entries()) {
          const e = normalizeEmail(t.email || '');
          if (e === email) tokens.push({ token: tok, revoked: !!t.revoked, created_at: t.created_at, expires_at: t.expires_at, premium: !!t.premium });
        }
        codes.sort((a,b)=>Number(b.created_at)-Number(a.created_at));
        tokens.sort((a,b)=>Number(b.created_at)-Number(a.created_at));
        customers.push({ email, license: lic, codes: codes.slice(0,10), tokens: tokens.slice(0,10) });
      }
      return res.json({ customers });
    }

    // Postgres-backed: list active licenses (optionally filtered)
    const where = q ? `WHERE active = true AND LOWER(email) LIKE $1` : `WHERE active = true`;
    const params = q ? [`%${q}%`] : [];
    const { rows: lic } = await pool.query(`SELECT email, plan, active, activated_at FROM licenses ${where} ORDER BY email ASC`, params);
    for (const L of lic) {
      const email = normalizeEmail(L.email);
      const { rows: codes } = await pool.query(
        `SELECT id, created_at, status, redeemed FROM codes WHERE note=$1 ORDER BY created_at DESC LIMIT 10`, [email]
      );
      const { rows: tokens } = await pool.query(
        `SELECT token, revoked, expires_at, premium, created_at FROM tokens WHERE email=$1 ORDER BY created_at DESC LIMIT 10`, [email]
      );
      customers.push({
        email,
        license: { plan: L.plan, active: L.active, activated_at: L.activated_at },
        codes: codes.map(c => ({ id: c.id, created_at: c.created_at, status: c.status ?? (c.redeemed ? 'used' : 'active') })),
        tokens: tokens.map(t => ({ token: t.token, revoked: t.revoked, expires_at: t.expires_at, premium: t.premium, created_at: t.created_at }))
      });
    }
    res.json({ customers });
  } catch (e) {
    console.error('admin/customers error:', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// --- Admin: single customer detail (full codes/tokens) ---
// GET /admin/customer?email=foo@example.com
app.get('/admin/customer', async (req, res) => {
  if (!checkAdmin(req, res)) return;
  const email = normalizeEmail(String(req.query?.email || ''));
  if (!email) return res.status(400).json({ error: 'missing_email' });
  try{
    if (pool) {
      const { rows: lic } = await pool.query('SELECT email, plan, active, activated_at FROM licenses WHERE LOWER(email)=$1', [email]);
      const license = lic[0] || null;
      const { rows: codes } = await pool.query('SELECT id, code, code_hash, status, redeemed, created_at, redeemed_at, expires_at FROM codes WHERE note=$1 ORDER BY created_at DESC', [email]);
      const { rows: tokens } = await pool.query('SELECT token, revoked, premium, created_at, expires_at, last_seen_at, last_origin, last_agent FROM tokens WHERE email=$1 ORDER BY created_at DESC', [email]);
      return res.json({ email, license, codes, tokens });
    } else {
      const license = mem.licenses.get(email) || null;
      const codes = [...mem.codes.values()].filter(c=>normalizeEmail(c.note||'')===email).sort((a,b)=>Number(b.created_at)-Number(a.created_at));
      const tokens = [...mem.tokens.values()].filter(t=>normalizeEmail(t.email||'')===email).sort((a,b)=>Number(b.created_at)-Number(a.created_at));
      return res.json({ email, license, codes, tokens });
    }
  }catch(e){
    console.error('/admin/customer error', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// --- Admin: Stripe customers with subscriptions and latest code/token details ---
// GET /admin/stripe-customers?limit=100
app.get('/admin/stripe-customers', async (req, res) => {
  if (!checkAdmin(req, res)) return;
  if (!stripe) return res.status(500).json({ error: 'stripe_not_configured' });
  try {
    const limit = Math.max(1, Math.min(Number(req.query.limit || 100), 200));
    const map = new Map(); // key: email or customer id if email missing
    const customers = await stripe.customers.list({ limit });
    // helper to rank subscription states
    const rank = (s)=>{
      switch(String(s||'inactive')){
        case 'active': return 5;
        case 'trialing': return 4;
        case 'past_due': return 3;
        case 'unpaid': return 2;
        case 'canceled': return 1;
        default: return 0;
      }
    };
    for (const c of customers.data) {
      const email = normalizeEmail(c.email || '');
      const key = email || `cust_${c.id}`;
      // Fetch best subscription
      let plan = null, status = 'inactive', current_period_end = null, priceId = null;
      try {
        const subs = await stripe.subscriptions.list({ customer: c.id, limit: 10, status: 'all' });
        // pick the highest-ranked subscription
        let best = null; let bestRank = -1;
        for (const s of subs.data) {
          const r = rank(s.status);
          if (r > bestRank) { best = s; bestRank = r; }
        }
        if (best) {
          status = best.status;
          current_period_end = (best.current_period_end ? best.current_period_end * 1000 : null);
          priceId = best.items?.data?.[0]?.price?.id;
          plan = PRICE_TO_PLAN[priceId] || best.items?.data?.[0]?.price?.nickname || null;
        }
      } catch {}

      // Pull codes and tokens (up to 5 for quick view)
      let codes = [], tokens = [], tokenCount = 0, lastSeen = null;
      if (email) {
        if (pool) {
          const { rows: codesRows } = await pool.query('SELECT id, created_at, status, expires_at, code FROM codes WHERE note=$1 ORDER BY created_at DESC LIMIT 5', [email]);
          codes = codesRows.map(crow=>({ id: crow.id, created_at: Number(crow.created_at), status: crow.status ?? null, expires_at: crow.expires_at ? Number(new Date(crow.expires_at).getTime()) : null, code: crow.code || null, code_tail: crow.code ? crow.code.slice(-6) : null }));
          const { rows: toksRows } = await pool.query('SELECT token, revoked, created_at, expires_at, last_seen_at FROM tokens WHERE email=$1 ORDER BY created_at DESC LIMIT 5', [email]);
          tokens = toksRows.map(t=>({ token_tail: (t.token||'').slice(-8), token: t.token, revoked: !!t.revoked, created_at: Number(t.created_at), expires_at: Number(t.expires_at), last_seen_at: t.last_seen_at ? Number(t.last_seen_at) : null }));
          const { rows: agg } = await pool.query('SELECT COUNT(*)::int AS cnt, MAX(last_seen_at) AS last_seen FROM tokens WHERE email=$1', [email]);
          tokenCount = (agg?.[0]?.cnt) || 0;
          lastSeen = agg?.[0]?.last_seen ? Number(agg[0].last_seen) : null;
        } else {
          const allCodes = [...mem.codes.values()].filter(x=>normalizeEmail(x.note||'')===email).sort((a,b)=>Number(b.created_at)-Number(a.created_at));
          codes = allCodes.slice(0,5).map(crow=>({ id: crow.id, created_at: Number(crow.created_at), status: crow.status ?? (crow.redeemed ? 'used':'active'), expires_at: crow.expires_at || null, code: crow.code || null, code_tail: (crow.code||'').slice(-6) }));
          const toks = [...mem.tokens.values()].filter(t=>normalizeEmail(t.email||'')===email).sort((a,b)=>Number(b.created_at)-Number(a.created_at));
          tokens = toks.slice(0,5).map(t=>({ token_tail: (t.token||'').slice(-8), token: t.token, revoked: !!t.revoked, created_at: Number(t.created_at), expires_at: Number(t.expires_at), last_seen_at: t.last_seen_at || null }));
          tokenCount = toks.length;
          lastSeen = toks.reduce((m,t)=>Math.max(m, t.last_seen_at||0), 0) || null;
        }
      }

      const next = { email, plan, status, current_period_end, price_id: priceId, codes, tokens, tokens_total: tokenCount, last_seen_at: lastSeen };
      const prev = map.get(key);
      if (!prev || rank(next.status) > rank(prev.status)) {
        map.set(key, next);
      }
    }
    const out = [...map.values()].sort((a,b)=>{
      // Sort active first, then by email
      const d = rank(b.status) - rank(a.status);
      if (d !== 0) return d;
      return (a.email||'').localeCompare(b.email||'');
    });
    res.json({ customers: out });
  } catch (e) {
    console.error('admin/stripe-customers error:', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// --- Admin: grant license and issue a new code ---
// POST /admin/grant-license { email, plan }
app.post('/admin/grant-license', async (req, res) => {
  if (!checkAdmin(req, res)) return;
  const email = normalizeEmail(String(req.body?.email || ''));
  const plan = String(req.body?.plan || 'premium').toLowerCase();
  if (!email) return res.status(400).json({ error: 'missing_email' });
  try {
    if (pool) {
      await pool.query(`
        INSERT INTO licenses (email, plan, active, activated_at)
        VALUES ($1, $2, true, NOW())
        ON CONFLICT (email) DO UPDATE SET plan=EXCLUDED.plan, active=true, activated_at=NOW()
      `, [email, plan]);
    } else {
      mem.licenses.set(email, { email, plan, active: true, activated_at: new Date().toISOString() });
    }
    const [code] = await dbCreateCodes(1, email);
    res.json({ ok: true, code });
  } catch (e) {
    console.error('admin/grant-license error:', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// --- Admin: revoke all tokens for an email and deactivate license ---
// POST /admin/revoke-email { email }
app.post('/admin/revoke-email', async (req, res) => {
  if (!checkAdmin(req, res)) return;
  const email = normalizeEmail(String(req.body?.email || ''));
  if (!email) return res.status(400).json({ error: 'missing_email' });
  try {
    await dbRevokeTokensByEmail(email);
    if (pool) await pool.query(`UPDATE licenses SET active=false WHERE email=$1`, [email]);
    else if (mem.licenses.has(email)) mem.licenses.get(email).active = false;
    res.json({ ok: true });
  } catch (e) {
    console.error('admin/revoke-email error:', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// Admin: list active premium users within window (hours)
// GET /admin/active-users?hours=24
app.get('/admin/active-users', async (req, res) => {
  if (!checkAdmin(req, res)) return;
  try {
    const hours = Math.max(1, Math.min(Number(req.query.hours || 24), 720));
    const since = Date.now() - hours * 60 * 60 * 1000;
    const out = [];
    if (pool) {
      const q = `
        SELECT LOWER(COALESCE(t.email, c.note)) AS email,
               MAX(t.last_seen_at) AS last_seen_at,
               COUNT(*) FILTER (WHERE t.last_premium = TRUE) AS premium_hits,
               COUNT(*) AS tokens,
               ARRAY_AGG(RIGHT(t.token, 6) ORDER BY t.last_seen_at DESC) AS token_tails
        FROM tokens t
        LEFT JOIN codes c ON c.id = t.code_id
        WHERE t.last_seen_at IS NOT NULL AND t.last_seen_at >= $1 AND t.last_premium = TRUE
        GROUP BY 1
        ORDER BY MAX(t.last_seen_at) DESC
        LIMIT 500`;
      const { rows } = await pool.query(q, [since]);
      for (const r of rows) {
        out.push({ email: r.email, last_seen_at: Number(r.last_seen_at), premium_hits: Number(r.premium_hits), tokens: Number(r.tokens), token_tails: r.token_tails || [] });
      }
    } else {
      const map = new Map();
      for (const [tok, t] of mem.tokens.entries()) {
        if (!t.last_seen_at || t.last_seen_at < since) continue;
        if (!t.last_premium) continue;
        const email = (t.email || (mem.codes.get(tok)?.note) || '').toLowerCase();
        if (!email) continue;
        const cur = map.get(email) || { email, last_seen_at: 0, premium_hits: 0, tokens: 0, token_tails: [] };
        cur.last_seen_at = Math.max(cur.last_seen_at, t.last_seen_at);
        cur.premium_hits += 1;
        cur.tokens += 1;
        cur.token_tails.push(tok.slice(-6));
        map.set(email, cur);
      }
      out.push(...[...map.values()].sort((a,b)=>b.last_seen_at-a.last_seen_at));
    }
    res.json({ since, hours, users: out });
  } catch (e) {
    console.error('/admin/active-users error', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// Admin: summarize active extensions/agents within window (hours)
// GET /admin/active-extensions?hours=24
app.get('/admin/active-extensions', async (req, res) => {
  if (!checkAdmin(req, res)) return;
  try {
    const hours = Math.max(1, Math.min(Number(req.query.hours || 24), 720));
    const since = Date.now() - hours * 60 * 60 * 1000;
    if (pool) {
      const q = `
        SELECT COALESCE(NULLIF(t.last_origin, ''), 'unknown') AS origin,
               COALESCE(NULLIF(t.last_agent, ''), 'unknown') AS agent,
               COUNT(*) FILTER (WHERE t.last_premium = TRUE AND t.last_seen_at >= $1) AS hits
        FROM tokens t
        WHERE t.last_seen_at IS NOT NULL AND t.last_seen_at >= $1 AND t.last_premium = TRUE
        GROUP BY 1,2
        ORDER BY hits DESC
        LIMIT 200`;
      const { rows } = await pool.query(q, [since]);
      return res.json({ since, hours, agents: rows.map(r=>({ origin: r.origin, agent: r.agent, hits: Number(r.hits) })) });
    } else {
      const map = new Map();
      for (const [, t] of mem.tokens.entries()) {
        if (!t.last_seen_at || t.last_seen_at < since) continue;
        if (!t.last_premium) continue;
        const key = `${t.last_origin||'unknown'}|${t.last_agent||'unknown'}`;
        map.set(key, (map.get(key)||0)+1);
      }
      const agents = [...map.entries()].map(([k,v])=>{ const [o,a]=k.split('|'); return { origin:o, agent:a, hits:v }; }).sort((a,b)=>b.hits-a.hits).slice(0,200);
      return res.json({ since, hours, agents });
    }
  } catch (e) {
    console.error('/admin/active-extensions error', e);
    res.status(500).json({ error: 'server_error' });
  }
});

async function start() {
  try {
    try {
      await initStorage();
    } catch (e) {
      // Retry a few times before falling back or exiting
      const maxRetries = Number(process.env.DB_BOOT_RETRIES || 3);
      const delayMs = Number(process.env.DB_BOOT_DELAY_MS || 2000);
      let ok = false;
      for (let i = 1; i <= maxRetries; i++) {
        console.warn(`[DB] init failed (attempt ${i}/${maxRetries})`, e?.code || e?.message || e);
        await sleep(delayMs);
        try {
          await initStorage();
          ok = true;
          break;
        } catch (err) {
          e = err;
        }
      }
      if (!ok) {
        if (DB_FALLBACK_ON_FAIL && isConnError(e)) {
          console.error('[DB] falling back to in-memory store due to connection errors');
          pool = null; // disable PG usage
        } else {
          throw e;
        }
      }
    }
  } catch (e) {
    console.error('Failed to initialize storage:', e);
    process.exit(1);
    return;
  }
  // Lightweight health endpoint for platform checks
  app.get('/health', async (req, res) => {
    if (pool) {
      try {
        await pool.query('SELECT 1');
        return res.json({ ok: true, db: 'pg' });
      } catch (e) {
        return res.status(200).json({ ok: true, db: 'pg-error', code: e.code || null });
      }
    }
    return res.json({ ok: true, db: 'memory' });
  });
  app.listen(PORT, () => {
    console.log(`AuraSync backend listening on ${PORT}`);
  });
}
start();

module.exports = { pool };
