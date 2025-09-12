document.addEventListener('DOMContentLoaded', async () => {
  const includeNodes = document.querySelectorAll('[data-include]');
  for (const node of includeNodes) {
    const src = node.getAttribute('data-include');
    try {
      const res = await fetch(src, { cache: 'no-cache' });
      const html = await res.text();
      node.outerHTML = html.replace(/\s*<!DOCTYPE[^>]*>/i, '');
    } catch (e) {
      console.error('Include failed:', src, e);
    }
  }
  // After include, set active nav
  const active = document.documentElement.getAttribute('data-active') || document.body.getAttribute('data-active');
  if (active) {
    const link = document.querySelector(`nav a[data-nav='${active}']`);
    if (link) {
      link.setAttribute('aria-current', 'page');
      link.classList.add('active');
    }
  }

  // Cache-bust local CSS/JS by appending ?v=<APP_VERSION>
  try{
    const ver = (window.APP_VERSION || 'dev');
    // Stylesheets
    document.querySelectorAll('link[rel="stylesheet"]').forEach(link => {
      const href = link.getAttribute('href');
      if(!href) return;
      if(/^\/?(assets|styles)\//.test(href) || href.startsWith('/')){
        const url = new URL(href, location.origin);
        url.searchParams.set('v', ver);
        link.href = url.pathname + '?' + url.searchParams.toString();
      }
    });
    // Scripts (defer ones)
    document.querySelectorAll('script[src]').forEach(script => {
      const src = script.getAttribute('src');
      if(!src) return;
      if(src.startsWith('/') || !/^https?:/i.test(src)){
        const url = new URL(src, location.origin);
        url.searchParams.set('v', ver);
        script.src = url.pathname + '?' + url.searchParams.toString();
      }
    });
  }catch(e){
    console.warn('Cache bust skipped:', e);
  }
});
