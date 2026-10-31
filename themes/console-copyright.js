function addCopyright() {
  if (document.getElementById('ffid-copyright')) return;
  const footer = document.createElement('footer');
  footer.id = 'ffid-copyright';
  footer.textContent = '© 2026 Firefly Software Foundation Inc.';
  document.body.append(footer);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', addCopyright, { once: true });
} else {
  addCopyright();
}
