#!/usr/bin/env node
/**
 * Minimal diagnostic script: checks Stripe for a given email and prints decisive info.
 * Usage (PowerShell): node backend/scripts/stripe-status-check.js "slotman.chiel@gmail.com"
 */
const Stripe = require('stripe');

function normalizeEmail(email){
  if (!email) return '';
  let e = String(email).trim().toLowerCase();
  const [user, domain] = e.split('@');
  if (domain === 'gmail.com' || domain === 'googlemail.com') {
    let local = user.split('+')[0].replace(/\./g, '');
    e = `${local}@gmail.com`;
  }
  return e;
}

function stripeMode(){
  const key = process.env.STRIPE_SECRET_KEY || '';
  if (key.startsWith('sk_test_')) return 'test';
  if (key.startsWith('sk_live_')) return 'live';
  return 'unknown';
}

function buildQueries(email){
  const e = normalizeEmail(email);
  const out = [];
  const [user, domain] = e.split('@');
  if (domain === 'gmail.com' || domain === 'googlemail.com') {
    const dotless = user.replace(/\./g, '');
    out.push(`email:'${user}@gmail.com'`);
    out.push(`email:'${dotless}@gmail.com'`);
    out.push(`email:'${user}+*@gmail.com'`);
  } else {
    out.push(`email:'${e}'`);
  }
  return out;
}

function rank(st){
  switch(String(st||'')){
    case 'active': return 3;
    case 'trialing': return 2;
    case 'past_due': return 1;
    default: return 0;
  }
}

async function main(){
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) {
    console.error('Missing STRIPE_SECRET_KEY env');
    process.exit(1);
  }
  const stripe = new Stripe(key);
  const email = process.argv[2];
  if (!email) {
    console.error('Usage: node backend/scripts/stripe-status-check.js "email@example.com"');
    process.exit(1);
  }
  const mode = stripeMode();
  console.log(JSON.stringify({ stripeMode: mode, emailCanonical: normalizeEmail(email) }));

  let customers = [];
  const queries = buildQueries(email);
  for (const q of queries) {
    try {
      const r = await stripe.customers.search({ query: q, limit: 100 });
      if (r?.data?.length) { customers = r.data; console.log(JSON.stringify({ searchQuery: q, found: r.data.length })); break; }
    } catch (e) {
      console.log(JSON.stringify({ searchQuery: q, error: String(e?.message||e) }));
    }
  }
  if (!customers.length) {
    const norm = normalizeEmail(email);
    const list = await stripe.customers.list({ email: norm, limit: 100 });
    customers.push(...(list?.data||[]));
  }
  console.log(JSON.stringify({ customersFound: customers.length, ids: customers.map(c=>c.id) }));

  let best = null; let bestCust = null; let bestRank = -1; let scanned = 0;
  for (const c of customers) {
    const subs = await stripe.subscriptions.list({ customer: c.id, status: 'all', limit: 100, expand: ['data.items.data.price.product'] });
    scanned += subs?.data?.length || 0;
    for (const s of subs.data) {
      const st = String(s.status||'');
      const r = rank(st);
      const item = s.items?.data?.[0];
      const priceId = item?.price?.id; const productId = (typeof item?.price?.product === 'string') ? item.price.product : (item?.price?.product?.id);
      const cur = s.current_period_end || 0;
      if ((st==='active'||st==='trialing') && cur*1000 > Date.now()) {
        if (r>bestRank || (r===bestRank && best && cur>(best.current_period_end||0))) {
          best = { id: s.id, status: st, priceId, productId, current_period_end: s.current_period_end, cancel_at_period_end: !!s.cancel_at_period_end, trial_end: s.trial_end || null };
          bestRank = r; bestCust = c.id;
        }
      }
    }
  }
  console.log(JSON.stringify({ subsScanned: scanned, chosenCustomerId: bestCust, chosenSub: best, finalPremium: !!best }));
}

main().catch(e=>{ console.error(e); process.exit(1); });
