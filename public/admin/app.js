(function(){
  const $ = (s)=>document.querySelector(s);
  function hdrs(){
    const s = $('#sec').value.trim();
    const h = { 'Content-Type': 'application/json' };
    if (s) h['Authorization'] = 'Bearer ' + s;
    return h;
  }
  function setStatus(msg){ const el=$('#status'); if(el) el.textContent = msg || ''; }
  function setDbInfo(msg){ const el=$('#dbinfo'); if(el) el.textContent = msg || ''; }
  function setStripeInfo(msg){ const el=$('#stripeinfo'); if(el) el.textContent = msg || ''; }
  function setNav(activeId){
    const buttons = document.querySelectorAll('.nav button');
    buttons.forEach(b=> b.classList.toggle('active', b.id === activeId));
  }

  async function showHealth(){
    try {
      const r = await fetch('/health', { cache: 'no-store' });
      const j = await r.json().catch(()=>({}));
      if (j && j.ok) { setDbInfo(`db: ${j.db || 'unknown'}`); }
      else { setDbInfo('db: unknown'); }
    } catch(_) { setDbInfo('db: unknown'); }
  }
  async function showStripe(){
    try{
      const r = await fetch('/debug/stripe', { cache:'no-store' });
      if(r.status>=400){ setStripeInfo('stripe: off'); return; }
      const j = await r.json().catch(()=>({}));
      if(j && j.mode){ setStripeInfo(`stripe: ${j.mode}`); }
      else setStripeInfo('stripe: off');
    }catch(_){ setStripeInfo('stripe: off'); }
  }
  async function load(){
    try{
      setNav('btnCustomers');
      setStatus('Loading...');
      const q = $('#q').value.trim();
      const r = await fetch(`/admin/customers?query=${encodeURIComponent(q)}`, { headers: hdrs() });
      const j = await r.json();
      if(!j.customers){ $('#out').innerHTML = `<p><b>Error:</b> ${JSON.stringify(j)}</p>`; setStatus(''); return; }
      const rows = (j.customers||[]).map(c => `
        <tr>
          <td><a href="#" data-email="${c.email}" class="detail-link">${c.email}</a></td>
          <td>${c.license?.plan ?? ''}</td>
          <td>${c.license?.active ? 'active' : 'inactive'}</td>
          <td>${c.codes?.[0]?.created_at ? new Date(Number(c.codes[0].created_at)).toLocaleString() : ''}</td>
          <td>${(c.tokens||[]).filter(t=>!t.revoked).length} active</td>
          <td>
            <button data-action="regen" data-email="${c.email}" data-plan="${c.license?.plan ?? 'premium'}">New Code</button>
            <button data-action="revoke" data-email="${c.email}">Revoke</button>
          </td>
        </tr>`).join('');
      $('#out').innerHTML = `<table><tr><th>Email</th><th>Plan</th><th>Status</th><th>Last code</th><th>Tokens</th><th>Actions</th></tr>${rows}</table>`;
      // wire detail links
      document.querySelectorAll('.detail-link').forEach(a=> a.addEventListener('click', (e)=>{ e.preventDefault(); const email=a.getAttribute('data-email'); loadDetail(email); }));
      setStatus(`${(j.customers||[]).length} result(s)`);
    }catch(e){
      $('#out').innerHTML = `<p><b>Error:</b> ${e?.message || e}</p>`;
      setStatus('');
    }
  }
  async function grant(){
    const email = $('#newEmail').value.trim();
    const plan = $('#plan').value;
    if(!email) { alert('Enter email'); return; }
    const r = await fetch('/admin/grant-license', { method:'POST', headers: hdrs(), body: JSON.stringify({ email, plan }) });
    alert(JSON.stringify(await r.json(), null, 2));
    load();
  }
  async function loadActive(){
    try{
      setNav('btnActive');
      setStatus('Loading active users...');
      const hours = Number($('#hours')?.value || 24) || 24;
      const r = await fetch(`/admin/active-users?hours=${encodeURIComponent(hours)}`, { headers: hdrs() });
      if (r.status === 403) {
        const txt = await r.text();
        $('#out').innerHTML = `<p><b>Forbidden</b>: Admin Secret rejected by server. Raw: ${txt.replace(/[<>]/g,'')}</p>`;
        setStatus('');
        showHealth();
        return;
      }
      const j = await r.json();
      if(!Array.isArray(j.users)) { $('#out').innerHTML = `<p><b>Error:</b> ${JSON.stringify(j)}</p>`; setStatus(''); return; }
      const rows = j.users.map(u=>`
        <tr>
          <td>${u.email}</td>
          <td>${u.last_seen_at? new Date(Number(u.last_seen_at)).toLocaleString() : ''}</td>
          <td>${u.premium_hits ?? 0}</td>
          <td>${u.tokens ?? 0}</td>
          <td>${(u.token_tails||[]).map(t=>`<code>${String(t).slice(-8)}</code>`).join(' ')}</td>
        </tr>`).join('');
      $('#out').innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px">
          <h3 style="margin:0">Active Premium (last ${hours}h)</h3>
          <div>
            <button id="btnBack">Back to Customers</button>
          </div>
        </div>
        <table>
          <tr><th>Email</th><th>Last seen</th><th>Premium hits</th><th>Tokens</th><th>Token tails</th></tr>
          ${rows}
        </table>
      `;
      const btnBack = document.getElementById('btnBack'); if (btnBack) btnBack.onclick = ()=> load();
      setStatus(`${j.users.length} active user(s)`);
    }catch(e){
      $('#out').innerHTML = `<p><b>Error:</b> ${e?.message || e}</p>`;
      setStatus('');
    }
  }

  async function loadStripe(){
    try{
      setNav('btnStripe');
      setStatus('Loading Stripe customers...');
      const r = await fetch(`/admin/stripe-customers?limit=100`, { headers: hdrs() });
      if (r.status === 403) { $('#out').innerHTML = '<p><b>Forbidden</b>: Admin Secret rejected.</p>'; setStatus(''); return; }
      const j = await r.json();
      if(!Array.isArray(j.customers)) { $('#out').innerHTML = `<p><b>Error:</b> ${JSON.stringify(j)}</p>`; setStatus(''); return; }
      const rows = j.customers.map(u=>`
        <tr>
          <td>${u.email?`<a href="#" data-email="${u.email}" class="detail-link">${u.email}</a>`:''}</td>
          <td>${u.plan||''}</td>
          <td>${u.status||''}</td>
          <td>${u.current_period_end? new Date(Number(u.current_period_end)).toLocaleString() : ''}</td>
          <td>${(u.codes||[]).slice(0,2).map(c=>`${c.status||''}${c.expires_at?` • exp ${new Date(Number(c.expires_at)).toLocaleString()}`:''}${c.code_tail?` [${c.code_tail}]`:''}`).join('<br>')}</td>
          <td>${u.tokens_total||0}${(u.tokens||[]).length?'<br><small>'+u.tokens.map(t=>`<code>${(t.token_tail||'').toString()}</code>${t.last_seen_at?` @ ${new Date(Number(t.last_seen_at)).toLocaleString()}`:''}`).join('<br>')+'</small>':''}</td>
          <td>${u.last_seen_at? new Date(Number(u.last_seen_at)).toLocaleString() : ''}</td>
        </tr>`).join('');
      $('#out').innerHTML = `
        <h3 style="margin:6px 0">Stripe customers (limit 100)</h3>
        <table>
          <tr><th>Email</th><th>Plan</th><th>Sub status</th><th>Period end</th><th>Latest code</th><th>Tokens</th><th>Last seen</th></tr>
          ${rows}
        </table>`;
      document.querySelectorAll('.detail-link').forEach(a=> a.addEventListener('click', (e)=>{ e.preventDefault(); const email=a.getAttribute('data-email'); loadDetail(email); }));
      setStatus(`${j.customers.length} result(s)`);
    }catch(e){ $('#out').innerHTML = `<p><b>Error:</b> ${e?.message||e}</p>`; setStatus(''); }
  }

  async function loadDetail(email){
    try{
      setStatus('Loading details...');
      const r = await fetch(`/admin/customer?email=${encodeURIComponent(email)}`, { headers: hdrs() });
      if (r.status === 403) { $('#out').innerHTML = '<p><b>Forbidden</b>: Admin Secret rejected.</p>'; setStatus(''); return; }
      const j = await r.json();
      if(!j || !j.email){ $('#out').innerHTML = `<p><b>Error:</b> ${JSON.stringify(j)}</p>`; setStatus(''); return; }

      const codesRows = (j.codes||[]).map(c=>`
        <tr>
          <td>${c.id||''}</td>
          <td>${c.status ?? (c.redeemed ? 'used':'active')}</td>
          <td>${c.code ? `<code class="mono">${c.code}</code>` : (c.code_hash?'<span class="muted">hashed</span>':'')}</td>
          <td>${c.created_at? new Date(Number(c.created_at)).toLocaleString() : ''}</td>
          <td>${c.redeemed_at? new Date(Number(c.redeemed_at)).toLocaleString() : ''}</td>
          <td>${c.expires_at? new Date(Number(c.expires_at)).toLocaleString() : ''}</td>
        </tr>`).join('');
      const tokensRows = (j.tokens||[]).map(t=>`
        <tr>
          <td><code class="mono">${(t.token||'').toString()}</code></td>
          <td>${t.revoked?'<span class="danger">revoked</span>':'active'}</td>
          <td>${t.premium?'<span class="ok">premium</span>':'<span class="muted">free</span>'}</td>
          <td>${t.created_at? new Date(Number(t.created_at)).toLocaleString() : ''}</td>
          <td>${t.expires_at? new Date(Number(t.expires_at)).toLocaleString() : ''}</td>
          <td>${t.last_seen_at? new Date(Number(t.last_seen_at)).toLocaleString() : ''}</td>
          <td>${t.last_origin||''}</td>
          <td class="muted">${t.last_agent||''}</td>
        </tr>`).join('');
      $('#out').innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px">
          <h3 style="margin:0">${email}</h3>
          <div>
            <button id="btnBack">Back</button>
          </div>
        </div>
        <div class="cards">
          <div class="card">
            <h3>Codes</h3>
            <table>
              <tr><th>ID</th><th>Status</th><th>Code</th><th>Created</th><th>Redeemed</th><th>Expires</th></tr>
              ${codesRows}
            </table>
          </div>
          <div class="card">
            <h3>Tokens</h3>
            <table>
              <tr><th>Token</th><th>State</th><th>Tier</th><th>Created</th><th>Expires</th><th>Last seen</th><th>Origin</th><th>User-Agent</th></tr>
              ${tokensRows}
            </table>
          </div>
        </div>
      `;
      const btnBack = document.getElementById('btnBack'); if (btnBack) btnBack.onclick = ()=> load();
      setStatus('');
    }catch(e){ $('#out').innerHTML = `<p><b>Error:</b> ${e?.message||e}</p>`; setStatus(''); }
  }

  async function loadAgents(){
    try{
      setNav('btnAgents');
      setStatus('Loading active extensions...');
      const hours = Number($('#hours')?.value || 24) || 24;
      const r = await fetch(`/admin/active-extensions?hours=${encodeURIComponent(hours)}`, { headers: hdrs() });
      if (r.status === 403) { $('#out').innerHTML = '<p><b>Forbidden</b>: Admin Secret rejected.</p>'; setStatus(''); return; }
      const j = await r.json();
      if(!Array.isArray(j.agents)) { $('#out').innerHTML = `<p><b>Error:</b> ${JSON.stringify(j)}</p>`; setStatus(''); return; }
      const rows = j.agents.map(a=>`
        <tr>
          <td>${a.origin||''}</td>
          <td>${a.agent||''}</td>
          <td>${a.hits||0}</td>
        </tr>`).join('');
      $('#out').innerHTML = `
        <h3 style="margin:6px 0">Active Extensions/Agents (last ${hours}h)</h3>
        <table>
          <tr><th>Origin</th><th>User-Agent</th><th>Premium hits</th></tr>
          ${rows}
        </table>`;
      setStatus(`${j.agents.length} row(s)`);
    }catch(e){ $('#out').innerHTML = `<p><b>Error:</b> ${e?.message||e}</p>`; setStatus(''); }
  }
  async function revoke(email){
    if(!confirm('Revoke all tokens for '+email+'?')) return;
    const r = await fetch('/admin/revoke-email', { method:'POST', headers: hdrs(), body: JSON.stringify({ email }) });
    alert(JSON.stringify(await r.json(), null, 2));
    load();
  }
  async function regen(email, plan){
    const r = await fetch('/admin/grant-license', { method:'POST', headers: hdrs(), body: JSON.stringify({ email, plan }) });
    alert(JSON.stringify(await r.json(), null, 2));
    load();
  }
  function wire(){
    // Prefill secret from ?sec
  let defaultView = '';
  try{ const url = new URL(location.href); const s = url.searchParams.get('sec'); if(s) $('#sec').value = s; defaultView = url.searchParams.get('view') || ''; }catch(_){ }
    $('#btnSearch').addEventListener('click', load);
  $('#btnRefresh').addEventListener('click', ()=>{ showHealth(); showStripe(); load(); });
    $('#btnGrant').addEventListener('click', grant);
  const btnActive = $('#btnActive'); if (btnActive) btnActive.addEventListener('click', loadActive);
  const btnStripe = $('#btnStripe'); if (btnStripe) btnStripe.addEventListener('click', loadStripe);
  const btnAgents = $('#btnAgents'); if (btnAgents) btnAgents.addEventListener('click', loadAgents);
  const btnCustomers = $('#btnCustomers'); if (btnCustomers) btnCustomers.addEventListener('click', ()=>{ load(); document.querySelectorAll('.nav button').forEach(b=>b.classList.toggle('active', b===btnCustomers)); });
    document.body.addEventListener('click', (e)=>{
      const a = e.target.closest('button[data-action]');
      if(!a) return;
      const email = a.getAttribute('data-email');
      const plan = a.getAttribute('data-plan') || 'premium';
      const action = a.getAttribute('data-action');
      if(action === 'revoke') revoke(email);
      if(action === 'regen') regen(email, plan);
    });
    // Auto-load if secret present
    showHealth(); showStripe();
    if($('#sec').value.trim()) setTimeout(()=>load(), 80);
      if ((defaultView||'').toLowerCase() === 'active') setTimeout(()=>loadActive(), 120);
      else setTimeout(()=>load(), 80);
  }
  document.addEventListener('DOMContentLoaded', wire);
})();
