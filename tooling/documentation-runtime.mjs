import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, stat, mkdir, writeFile, readdir } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';
import { chromium } from 'playwright';
import { inspectDiagram, measureDiagram } from './documentation-diagram-quality.mjs';

const site = resolve('.work/documentation/site');
const evidence = resolve('.work/documentation/browser');
const projectPath = '/firefly-id/';
await mkdir(evidence, { recursive: true });
const mime = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.png': 'image/png' };
const server = createServer(async (req, res) => {
  try {
    const pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    if (!pathname.startsWith(projectPath)) { res.writeHead(404); res.end(); return; }
    let path = resolve(site, pathname.slice(projectPath.length));
    if (!path.startsWith(site + sep) && path !== site) { res.writeHead(403); res.end(); return; }
    if ((await stat(path)).isDirectory()) path = resolve(path, 'index.html');
    res.writeHead(200, { 'Content-Type': mime[extname(path)] || 'application/octet-stream' });
    res.end(await readFile(path));
  } catch { res.writeHead(404); res.end(); }
});
await new Promise(done => server.listen(0, '127.0.0.1', done));
const origin = `http://127.0.0.1:${server.address().port}`;
const base = `${origin}${projectPath}`;
const browser = await chromium.launch({ headless: true });
const manifest = JSON.parse(await readFile(resolve(site, 'documentation-provenance.json'), 'utf8'));
const routes = manifest.pages.filter(path => path !== '404.html').map(path => path === 'index.html' ? '' : path.replace(/index\.html$/, ''));
const summary = { scope: 'Actual static documentation browser; no identity-service or regulatory acceptance', source: manifest.source_revision, basePath: projectPath, surfaces: [], diagrams: [], authoredDiagrams: [], search: [], navigation: [], themePersistence: false, externalRuntimeRequests: 0, failures: [] };
const generated = (await readdir(resolve(site, 'assets/diagrams/generated'))).filter(name => name.endsWith('.svg'));
let stage = 'launch';
let activePage;
try {
  for (const mode of ['light', 'dark']) {
    for (const width of [1440, 390]) {
      const context = await browser.newContext({ viewport: { width, height: width === 390 ? 844 : 1000 }, colorScheme: mode, reducedMotion: 'reduce' });
      context.on('request', request => {
        const url = new URL(request.url());
        if (['http:', 'https:'].includes(url.protocol) && url.origin !== origin) summary.externalRuntimeRequests++;
      });
      const diagramCoverage = new Map();
      const page = await context.newPage();
      activePage = page;
      for (const route of routes) {
        stage = `render-${width}-${mode}:${route || 'home'}`;
        const response = await page.goto(`${base}${route}`, { waitUntil: 'networkidle' });
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
          repeatedHeaderTitles: [...document.querySelectorAll('.md-header__title .md-header__topic')].filter(title => title.getClientRects().length > 0).length,
        }; });
        summary.lastObservation = { route, width, mode, ...measured };
        assert.match(measured.font, /Manrope/); assert.ok(measured.fontLoaded);
        assert.ok(measured.h1 && measured.scrollWidth <= measured.width + 1, 'Reading surface overflows its viewport');
        assert.equal(measured.background, mode === 'dark' ? 'rgb(16, 17, 15)' : 'rgb(243, 241, 235)');
        const linkColor = mode === 'dark' ? 'rgb(255, 179, 74)' : 'rgb(133, 84, 20)';
        if (measured.linkColor) assert.equal(measured.linkColor, linkColor, 'Body links drifted from the canonical Firefly palette');
        if (measured.activeLinkColor) assert.equal(measured.activeLinkColor, linkColor, 'Active navigation drifted from the canonical Firefly palette');
        assert.equal(measured.brokenImages, 0);
        assert.equal(measured.repeatedHeaderTitles, 0, 'The masthead repeats the identity already present in the logo');
        assert.equal(await page.locator('pre code.language-mermaid').count(), 0, 'A product diagram remained unrendered source');
        const figures = page.locator('.flow-figure');
        for (const figure of await figures.all()) {
          const variant = figure.locator(`.diagram-${mode}`);
          assert.ok(await variant.isVisible(), 'Diagram does not match the reading appearance');
          assert.equal(await figure.locator(`.diagram-${mode === 'light' ? 'dark' : 'light'}`).isVisible(), false);
          const scroll = figure.locator('.flow-scroll');
          const observation = await scroll.evaluate(element => {
            const image = [...element.querySelectorAll('img')].find(item => item.getClientRects().length);
            const link = image.closest('a');
            return { file: new URL(image.currentSrc).pathname.split('/').at(-1),
              accessible: Boolean(image.alt.trim() && element.getAttribute('aria-label')?.trim() && link.getAttribute('aria-label')?.trim()),
              opensSameAsset: link.href === image.currentSrc, scrollable: getComputedStyle(element).overflowX === 'auto' && element.tabIndex === 0,
              imageWidth: image.getBoundingClientRect().width, naturalWidth: image.naturalWidth,
              clientWidth: element.clientWidth, scrollWidth: element.scrollWidth };
          });
          assert.ok(observation.accessible && observation.opensSameAsset, 'Diagram lacks an accessible full-size link');
          assert.ok(observation.scrollable, 'Wide diagram has no keyboard-focusable scroll region');
          assert.ok(observation.imageWidth >= observation.naturalWidth - 1, 'Diagram text is shrunk below its authored size');
          assert.ok(observation.clientWidth <= width, 'Diagram scroll region escapes the viewport');
          diagramCoverage.set(observation.file, (diagramCoverage.get(observation.file) || 0) + 1);
          const capture = `inline-${observation.file.replace('.svg', '')}-${width}.png`;
          await scroll.screenshot({ path: resolve(evidence, capture) });
          if (observation.scrollWidth > observation.clientWidth + 1) {
            await scroll.focus();
            await page.keyboard.press('ArrowRight');
            await page.waitForFunction(element => element.scrollLeft > 0, await scroll.elementHandle());
            await scroll.evaluate(element => { element.scrollLeft = element.scrollWidth; });
            const reachedEnd = await scroll.evaluate(element => element.scrollLeft + element.clientWidth >= element.scrollWidth - 1);
            assert.ok(reachedEnd, 'The end of a wide diagram is unreachable');
            await scroll.screenshot({ path: resolve(evidence, capture.replace('.png', '-end.png')) });
            await scroll.evaluate(element => { element.scrollLeft = 0; });
          }
          summary.diagrams.push({ route, width, mode, ...observation, capture });
        }
        for (const figure of await page.locator('.solution-figure').all()) {
          await figure.screenshot({ path: resolve(evidence, `solution-inline-${width}-${mode}.png`) });
        }
        assert.ok(await page.locator('.md-header__button.md-logo').isVisible(), 'Product branding is missing from the masthead');
        if (route) assert.ok(await page.locator('.md-path').isVisible(), 'Inner page has no breadcrumb trail');
        assert.match(measured.footer, /Firefly Software Foundation Inc\./); assert.match(measured.footer, /Keycloak/);
        summary.surfaces.push({ route, width, mode, fontLoaded: measured.fontLoaded, horizontalOverflow: false });
        if (['', 'architecture/', 'integration-contract/', 'access-recovery/', 'controls-matrix/', 'configuration-reference/'].includes(route)) {
          await page.evaluate(() => window.scrollTo(0, 0));
          await page.screenshot({ path: resolve(evidence, `${route.replaceAll('/', '') || 'home'}-${width}-${mode}.png`) });
        }
      }
      assert.deepEqual([...diagramCoverage.keys()].sort(), generated.filter(name => name.endsWith(`-${mode}.svg`)).sort(), 'Every packaged diagram must appear in the handbook at each reading width');
      for (const count of diagramCoverage.values()) assert.equal(count, 1, 'A diagram is duplicated instead of its intended source');
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
  const authoredPage = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  activePage = authoredPage;
  await authoredPage.route('**/*', route => {
    const url = new URL(route.request().url());
    if (['http:', 'https:'].includes(url.protocol) && url.origin !== origin) { summary.externalRuntimeRequests++; return route.abort(); }
    return route.continue();
  });
  for (const file of (await readdir(resolve(site, 'assets/diagrams'))).filter(name => name.endsWith('.svg')).sort()) {
    stage = `authored-diagram:${file}`;
    await authoredPage.goto(`${base}assets/diagrams/${file}`, { waitUntil: 'networkidle' });
    await authoredPage.evaluate(() => document.fonts.ready);
    const measured = await authoredPage.evaluate(measureDiagram, 'dark');
    const findings = inspectDiagram(measured);
    const capture = `diagram-authored-${file.replace('.svg', '.png')}`;
    await authoredPage.locator('svg').screenshot({ path: resolve(evidence, capture) });
    summary.authoredDiagrams.push({ file, labelsChecked: measured.labels.length, capture, findings });
    summary.failures.push(...findings.map(finding => ({ stage, ...finding })));
  }
  if (summary.failures.length) process.exitCode = 1;
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
console.log(JSON.stringify({ source: summary.source, surfaces: summary.surfaces.length, diagramSurfaces: summary.diagrams.length, authoredDiagrams: summary.authoredDiagrams.length, searchChecks: summary.search.length, navigationChecks: summary.navigation.length, themePersistence: summary.themePersistence, externalRuntimeRequests: summary.externalRuntimeRequests, failures: summary.failures }));
