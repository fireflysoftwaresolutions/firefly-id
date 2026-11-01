import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const script = await readFile(new URL('../themes/firefly-id/welcome/resources/js/welcome-locale.js', import.meta.url), 'utf8');

function render(navigator, withAdmin = true) {
  const elements = [
    { textContent: 'Identity and access,', dataset: { ffidEs: 'Identidad y acceso,' } },
    { textContent: 'Powered by Keycloak', dataset: { ffidEs: 'Con tecnología de Keycloak' } },
  ];
  if (withAdmin) elements.push({ textContent: 'Open administration', dataset: { ffidEs: 'Abrir administración' } });
  const document = { documentElement: { lang: 'en' }, querySelectorAll: () => elements };
  vm.runInNewContext(script, { navigator, document });
  return { language: document.documentElement.lang, text: elements.map(element => element.textContent) };
}

test('welcome selects the first supported browser preference including regional Spanish', () => {
  assert.deepEqual(render({ languages: ['fr-FR', 'es-MX', 'en-US'] }), {
    language: 'es', text: ['Identidad y acceso,', 'Con tecnología de Keycloak', 'Abrir administración'],
  });
  assert.equal(render({ languages: ['en-US', 'es-ES'] }).text[0], 'Identity and access,');
});

test('welcome falls back to English for unsupported or missing browser languages', () => {
  for (const navigator of [{ languages: ['fr-FR', 'de-DE'] }, { languages: [] }, {}]) {
    assert.deepEqual(render(navigator), {
      language: 'en', text: ['Identity and access,', 'Powered by Keycloak', 'Open administration'],
    });
  }
});

test('welcome supports navigator.language fallback and an unavailable admin console', () => {
  assert.deepEqual(render({ language: 'es-ES' }, false), {
    language: 'es', text: ['Identidad y acceso,', 'Con tecnología de Keycloak'],
  });
});
