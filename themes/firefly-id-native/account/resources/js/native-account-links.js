function addNativeAccountLink() {
  if (document.body?.dataset.pageId !== 'account') return;
  const realm = location.pathname.match(/^(\/realms\/[^/]+)\/account(?:\/|$)/);
  const footer = document.getElementById('ffid-copyright');
  if (!realm || !footer?.querySelector('a[href="https://www.keycloak.org"]')) return;
  let link = document.getElementById('ffid-support-pin-link');
  if (!link) {
    const row = document.createElement('span');
    row.className = 'ffid-native-account-link';
    link = document.createElement('a');
    link.id = 'ffid-support-pin-link';
    link.href = `${location.origin}${realm[1]}/firefly-recovery/support-pin`;
    row.append(link);
    footer.append(row);
  }
  const label = document.documentElement.lang.toLowerCase().startsWith('es')
    ? 'PIN de atención al cliente' : 'Customer support PIN';
  if (link.textContent !== label) link.textContent = label;
  nativeFooterObserver.disconnect();
}

const nativeFooterObserver = new MutationObserver(addNativeAccountLink);
nativeFooterObserver.observe(document.documentElement, { childList: true, subtree: true });
new MutationObserver(addNativeAccountLink).observe(document.documentElement, { attributes: true, attributeFilter: ['lang'] });
addNativeAccountLink();
