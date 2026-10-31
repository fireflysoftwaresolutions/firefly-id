function addCopyright() {
  if (!document.body) return;
  let footer = document.getElementById('ffid-copyright');
  if (!footer) {
    footer = document.createElement('footer');
    footer.id = 'ffid-copyright';
    document.body.append(footer);
  }
  let attribution = footer.querySelector('a');
  if (!attribution) {
    attribution = document.createElement('a');
    attribution.href = 'https://www.keycloak.org';
    footer.replaceChildren('© 2026 Firefly Software Foundation Inc. · ', attribution);
  }
  attribution.textContent = document.documentElement.lang.toLowerCase().startsWith('es')
    ? 'Con tecnología de Keycloak' : 'Powered by Keycloak';
}

new MutationObserver(addCopyright).observe(document.documentElement, { attributes: true, attributeFilter: ['lang'] });

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', addCopyright, { once: true });
} else {
  addCopyright();
}
