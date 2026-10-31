const visibilityControls = [
  'button[data-password-toggle]',
  'button[aria-label="Show password"]',
  'button[aria-label="Hide password"]',
  'button[aria-label="showPassword"]',
  'button[aria-label="hidePassword"]',
].join(',');

function enforceMaskedPasswords() {
  for (const button of document.querySelectorAll(visibilityControls)) {
    if (!button.disabled) button.disabled = true;
    if (!button.hidden) button.hidden = true;
    if (button.getAttribute('aria-hidden') !== 'true') button.setAttribute('aria-hidden', 'true');
    if (button.tabIndex !== -1) button.tabIndex = -1;
    const input = button.closest('.pf-v5-c-input-group')?.querySelector('input');
    if (input && input.type !== 'password') input.type = 'password';
  }
}

enforceMaskedPasswords();
new MutationObserver(enforceMaskedPasswords).observe(document.documentElement, {
  subtree: true, childList: true, attributes: true,
  attributeFilter: ['type', 'aria-label', 'disabled', 'hidden'],
});
