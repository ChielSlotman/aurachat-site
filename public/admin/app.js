(function(){
  const $ = (s)=>document.querySelector(s);
  function hdrs(){
    const s = $('#sec').value.trim();
    const h = { 'Content-Type': 'application/json' };
    if (s) h['Authorization'] = 'Bearer ' + s;
    return h;
  }
  function setStatus(msg){ const el=$('#status'); if(el) el.textContent = msg || ''; }
  async function load(){
    try{
      setStatus('Loading...');
      const q = $('#q').value.trim();
      const r = await fetch(`/admin/customers?query=${encodeURIComponent(q)}`, { headers: hdrs() });
      const j = await r.json();
      if(!j.customers){ $('#out').innerHTML = `<p><b>Error:</b> ${JSON.stringify(j)}</p>`; setStatus(''); return; }
      const rows = (j.customers||[]).map(c => `
        <tr>
          <td>${c.email}</td>
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
    try{ const url = new URL(location.href); const s = url.searchParams.get('sec'); if(s) $('#sec').value = s; }catch(_){ }
    $('#btnSearch').addEventListener('click', load);
    $('#btnRefresh').addEventListener('click', load);
    $('#btnGrant').addEventListener('click', grant);
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
    if($('#sec').value.trim()) setTimeout(()=>load(), 80);
  }
  document.addEventListener('DOMContentLoaded', wire);
})();
