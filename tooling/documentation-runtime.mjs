import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, stat, mkdir, writeFile } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';
import { chromium } from 'playwright';

const site = resolve('.work/documentation/site');
const evidence = resolve('.work/documentation/browser');
await mkdir(evidence, { recursive: true });
const mime = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.png': 'image/png' };
const server = createServer(async (req, res) => {
  try {
    let path = resolve(site, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname));
    if (!path.startsWith(site + sep) && path !== site) { res.writeHead(403); res.end(); return; }
    if ((await stat(path)).isDirectory()) path = resolve(path, 'index.html');
    res.writeHead(200, { 'Content-Type': mime[extname(path)] || 'application/octet-stream' });
    res.end(await readFile(path));
  } catch { res.writeHead(404); res.end(); }
});
await new Promise(done => server.listen(0, '127.0.0.1', done));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ headless: true });
const manifest = JSON.parse(await readFile(resolve(site, 'documentation-provenance.json'), 'utf8'));
const routes = manifest.pages.filter(path => path !== '404.html').map(path => path === 'index.html' ? '' : path.replace(/index\.html$/, ''));
const summary = { scope: 'Actual static documentation browser; no identity-service or regulatory acceptance', source: manifest.source_revision, surfaces: [], search: [], navigation: [], themePersistence: false, externalRuntimeRequests: 0, failures: [] };
let stage = 'launch';
let activePage;
try {
  for (const mode of ['light', 'dark']) {
    for (const width of [1440, 390]) {
      const context = await browser.newContext({ viewport: { width, height: width === 390 ? 844 : 1000 }, colorScheme: mode, reducedMotion: 'reduce' });
      context.on('request', request => {
        const url = new URL(request.url());
        if (['http:', 'https:'].includes(url.protocol) && url.origin !== base) summary.externalRuntimeRequests++;
      });
      const page = await context.newPage();
      activePage = page;
      for (const route of routes) {
        stage = `render-${width}-${mode}:${route || 'home'}`;
        const response = await page.goto(`${base}/${route}`, { waitUntil: 'networkidle' });
        assert.equal(response.status(), 200);
        await page.evaluate(() => document.fonts.ready);
        const measured = await page.evaluate(() => {
          const link = document.querySelector('main .md-typeset p a:not(.headerlink), main .md-typeset td a:not(.headerlink)');
          const active = document.querySelector('.md-sidebar--primary .md-nav__link--active');
          return {
          font: getComputedStyle(document.body).fontFamily,
          fontLoaded: document.fonts.check('16px Manrope'),
          width: document.documentElement.clientWidth,
          scrollWidth: Math.max(document.documentElement.scrollWidth, document.body.scrollWidth),
          background: getComputedStyle(document.body).backgroundColor,
          h1: document.querySelector('main h1')?.textContent?.trim(),
          footer: document.querySelector('.md-copyright')?.textContent,
          brokenImages: [...document.images].filter(img => !img.complete || img.naturalWidth === 0).length,
          linkColor: link ? getComputedStyle(link).color : null,
          activeLinkColor: active ? getComputedStyle(active).color : null,
        }; });
        summary.lastObservation = { route, width, mode, ...measured };
        assert.match(measured.font, /Manrope/); assert.ok(measured.fontLoaded);
        assert.ok(measured.h1 && measured.scrollWidth <= measured.width + 1, 'Reading surface overflows its viewport');
        assert.equal(measured.background, mode === 'dark' ? 'rgb(16, 17, 15)' : 'rgb(243, 241, 235)');
        const linkColor = mode === 'dark' ? 'rgb(255, 179, 74)' : 'rgb(133, 84, 20)';
        if (measured.linkColor) assert.equal(measured.linkColor, linkColor, 'Body links drifted from the canonical Firefly palette');
        if (measured.activeLinkColor) assert.equal(measured.activeLinkColor, linkColor, 'Active navigation drifted from the canonical Firefly palette');
        assert.equal(measured.brokenImages, 0);
        assert.ok(await page.locator('.md-header__button.md-logo').isVisible(), 'Product branding is missing from the masthead');
        if (route) assert.ok(await page.locator('.md-path').isVisible(), 'Inner page has no breadcrumb trail');
        assert.match(measured.footer, /Firefly Software Foundation Inc\./); assert.match(measured.footer, /Keycloak/);
        summary.surfaces.push({ route, width, mode, fontLoaded: measured.fontLoaded, horizontalOverflow: false });
        if (['', 'controls-matrix/', 'configuration-reference/'].includes(route)) {
          await page.screenshot({ path: resolve(evidence, `${route.replaceAll('/', '') || 'home'}-${width}-${mode}.png`) });
        }
      }
      stage = `search-${width}-${mode}`;
      await page.goto(base, { waitUntil: 'networkidle' });
      if (width === 390) await page.locator('.md-header__button[for="__search"]').click();
      await page.locator('[data-md-component="search-query"]').pressSequentially('notification');
      await page.locator('.md-search-result__link[href*="notification-operations"]').first().waitFor();
      await page.keyboard.press('Escape');
      summary.search.push({ width, mode, result: 'notification-operations' });
      stage = `navigation-${width}-${mode}`;
      if (width === 390) {
        await page.locator('.md-header label[for="__drawer"]').click();
        await page.locator('.md-sidebar--primary .md-nav__item--active > .md-nav > label.md-nav__title').first().click();
        await page.locator('.md-sidebar--primary label.md-nav__link').filter({ hasText: /^\s*Configure\s*$/ }).click();
        await page.locator('.md-sidebar--primary').getByRole('link', { name: 'Configuration reference', exact: true }).click();
      } else {
        await page.locator('.md-tabs').getByRole('link', { name: 'Configure', exact: true }).click();
        await page.locator('.md-sidebar--primary').getByRole('link', { name: 'Configuration reference', exact: true }).click();
      }
      await page.waitForURL('**/configuration-reference/');
      assert.equal(await page.locator('main h1').evaluate(element => {
        const title = element.cloneNode(true);
        title.querySelectorAll('.headerlink').forEach(link => link.remove());
        return title.textContent.trim();
      }), 'Configuration reference');
      summary.navigation.push({ width, mode, result: 'configuration-reference' });
      if (width === 1440 && mode === 'light') {
        stage = 'theme-persistence';
        for (let count = 0; count < 3 && await page.locator('body').getAttribute('data-md-color-scheme') !== 'slate'; count++) {
          await page.locator('[data-md-component="palette"] label:visible').first().click();
        }
        assert.equal(await page.locator('body').getAttribute('data-md-color-scheme'), 'slate');
        await page.reload({ waitUntil: 'networkidle' });
        assert.equal(await page.locator('body').getAttribute('data-md-color-scheme'), 'slate');
        summary.themePersistence = true;
      }
      await context.close();
    }
  }
  assert.equal(summary.externalRuntimeRequests, 0, 'Documentation requests an external runtime asset');
} catch {
  summary.failures.push({ stage, message: 'Documentation browser assertion failed; inspect the bounded stage and credential-free captures.' });
  if (activePage && !activePage.isClosed()) await activePage.screenshot({ path: resolve(evidence, 'failure.png') }).catch(() => {});
  process.exitCode = 1;
} finally {
  await writeFile(resolve(evidence, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
  await browser.close();
  await new Promise(done => server.close(done));
}
console.log(JSON.stringify({ source: summary.source, surfaces: summary.surfaces.length, searchChecks: summary.search.length, navigationChecks: summary.navigation.length, themePersistence: summary.themePersistence, externalRuntimeRequests: summary.externalRuntimeRequests, failures: summary.failures }));
