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
      link.classList.add('text-white');
    }
  }
});
