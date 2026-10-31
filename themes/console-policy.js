const visibilityControls = [
  'button[data-password-toggle]',
  'button[aria-label="Show password"]',
  'button[aria-label="Hide password"]',
  'button[aria-label="showPassword"]',
  'button[aria-label="hidePassword"]',
  'button[aria-label="Show password field in clear text"]',
  'button[aria-label="Hide password field in clear text"]',
  'button[aria-label="Mostrar contraseña"]',
  'button[aria-label="Ocultar contraseña"]',
  'button[aria-label="Mostrar campo de contraseña en texto claro"]',
  'button[aria-label="Ocultar campo de contraseña en texto claro"]',
].join(',');

const errorTitles = new Set(['Something went wrong', "We couldn't complete your request",
  'No hemos podido completar tu solicitud', 'Ha ocurrido un error', 'Algo ha salido mal']);

function presentErrorDialogs() {
  const spanish = document.documentElement.lang.toLowerCase().startsWith('es');
  for (const dialog of document.querySelectorAll('.pf-v5-c-modal-box')) {
    const title = dialog.querySelector('.pf-v5-c-modal-box__title-text');
    if (!title || !errorTitles.has(title.textContent.trim())) continue;
    if (!dialog.classList.contains('ffid-error-dialog')) dialog.classList.add('ffid-error-dialog');
    let brand = dialog.querySelector('.ffid-error-brand');
    if (!brand) {
      brand = document.createElement('img');
      brand.className = 'ffid-error-brand';
      brand.alt = 'Firefly Identity';
      dialog.querySelector('.pf-v5-c-modal-box__header')?.prepend(brand);
    }
    const variant = document.documentElement.classList.contains('pf-v5-theme-dark') ? 'dark' : 'light';
    const source = new URL(`../img/wordmark-${variant}.svg`, import.meta.url).href;
    if (brand.src !== source) brand.src = source;
    const detail = dialog.querySelector('.pf-v5-c-modal-box__body p');
    const copy = spanish
      ? 'Inténtalo de nuevo en unos instantes. Si el problema continúa, contacta con tu equipo de soporte.'
      : 'Try again in a moment. If the problem continues, contact your support team.';
    if (detail && detail.textContent !== copy) detail.textContent = copy;
  }
}

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

function applyPresentationPolicy() {
  enforceMaskedPasswords();
  presentErrorDialogs();
}

applyPresentationPolicy();
new MutationObserver(applyPresentationPolicy).observe(document.documentElement, {
  subtree: true, childList: true, attributes: true,
  attributeFilter: ['type', 'aria-label', 'disabled', 'hidden', 'class', 'lang'],
});
