// Keycloak 26.8.1's realm-independent WelcomeResource supplies no locale or message formatter.
const languages = navigator.languages?.length ? navigator.languages : [navigator.language];
const language = languages.map(value => (value || '').toLowerCase().split('-')[0])
  .find(value => value === 'en' || value === 'es') || 'en';
if (language === 'es') {
  for (const element of document.querySelectorAll('[data-ffid-es]')) {
    element.textContent = element.dataset.ffidEs;
  }
}
document.documentElement.lang = language;
