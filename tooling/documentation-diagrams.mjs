import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, sep, extname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { chromium } from 'playwright';

const output = resolve('.work/documentation/diagrams');
await mkdir(output, { recursive: true });
const diagrams = JSON.parse(execFileSync('python3', ['tooling/documentation_diagrams.py'], { encoding: 'utf8' }));
assert.ok(diagrams.length >= 12, 'Core architecture and journeys need their diagrams');
const vendor = resolve('.work/docs-diagrams/node_modules/mermaid/dist');
assert.equal(JSON.parse(await readFile(resolve(vendor, '../package.json'), 'utf8')).version, '12.2.0');
const font = await readFile('assets/brand/fonts/manrope-latin-wght-normal.woff2');
const fontUri = 'data:font/woff2;base64,' + font.toString('base64');
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/') { res.setHeader('Content-Type', 'text/html'); res.end('<!doctype html><html lang="en"><head><meta charset="utf-8"></head><body></body></html>'); return; }
    if (!url.pathname.startsWith('/mermaid/')) { res.writeHead(404); res.end(); return; }
    const file = resolve(vendor, decodeURIComponent(url.pathname.slice('/mermaid/'.length)));
    if (!file.startsWith(vendor + sep)) { res.writeHead(403); res.end(); return; }
    res.setHeader('Content-Type', extname(file) === '.mjs' || extname(file) === '.js' ? 'text/javascript' : 'application/octet-stream');
    res.end(await readFile(file));
  } catch { res.writeHead(404); res.end(); }
});
await new Promise(done => server.listen(0, '127.0.0.1', done));
const origin = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1800, height: 1200 }, reducedMotion: 'reduce' });
const summary = { version: '12.2.0', diagrams: [], failures: [], externalRequests: 0 };
let active;
try {
  await page.route('**/*', route => {
    const url = new URL(route.request().url());
    if (['http:', 'https:'].includes(url.protocol) && url.origin !== origin) { summary.externalRequests++; return route.abort(); }
    return route.continue();
  });
  await page.goto(origin);
  await page.addStyleTag({ content: `@font-face{font-family:Manrope;font-style:normal;font-weight:200 800;src:url('${fontUri}')}body{font-family:Manrope}` });
  await page.evaluate(async base => {
    await document.fonts.load('16px Manrope');
    window.diagramEngine = (await import(base + '/mermaid/mermaid.esm.min.mjs')).default;
  }, origin);
  assert.equal(await page.evaluate(() => document.fonts.check('16px Manrope')), true);
  for (const diagram of diagrams) {
    for (const mode of ['light', 'dark']) {
      active = { page: diagram.page, id: diagram.id, mode };
      const rendered = await page.evaluate(async ({ diagram, mode }) => {
        const dark = mode === 'dark';
        const text = dark ? '#f3f1eb' : '#272820';
        const line = dark ? '#bfb8ab' : '#62645b';
        const surface = dark ? '#272820' : '#ffffff';
        window.diagramEngine.initialize({ startOnLoad: false, securityLevel: 'strict', theme: 'base',
          fontFamily: 'Manrope', fontSize: 16, htmlLabels: false,
          themeVariables: { fontFamily: 'Manrope', fontSize: '16px', background: dark ? '#10110f' : '#f3f1eb',
            primaryColor: surface, primaryTextColor: text, primaryBorderColor: line, lineColor: line,
            secondaryColor: dark ? '#474a42' : '#f3f1eb', tertiaryColor: surface, textColor: text,
            secondaryTextColor: text, tertiaryTextColor: text, nodeTextColor: text,
            edgeLabelBackground: surface, clusterBkg: surface, clusterBorder: line,
            actorBkg: surface, actorBorder: line, actorTextColor: text, actorLineColor: line,
            signalColor: line, signalTextColor: text, labelBoxBkgColor: surface, labelTextColor: text,
            noteBkgColor: dark ? '#474a42' : '#f3f1eb', noteTextColor: text, noteBorderColor: line },
          flowchart: { htmlLabels: false, useMaxWidth: false, padding: 20, nodeSpacing: 30, rankSpacing: 40 },
          sequence: { useMaxWidth: false, wrap: true, actorFontFamily: 'Manrope', noteFontFamily: 'Manrope', messageFontFamily: 'Manrope' } });
        const result = await window.diagramEngine.render('flow' + diagram.id + mode, diagram.source);
        document.body.innerHTML = result.svg;
        const svg = document.querySelector('svg');
        await document.fonts.ready;
        return { svg: result.svg, viewBox: svg.getAttribute('viewBox'), texts: svg.querySelectorAll('text').length,
          font: getComputedStyle(svg.querySelector('text') || svg).fontFamily };
      }, { diagram, mode });
      assert.ok(rendered.viewBox && rendered.texts > 0);
      assert.match(rendered.font, /Manrope/);
      const embedded = rendered.svg.replace('<style>', `<style>@font-face{font-family:Manrope;font-style:normal;font-weight:200 800;src:url('${fontUri}')}`);
      assert.ok(embedded.includes(fontUri));
      await writeFile(resolve(output, `${diagram.id}-${mode}.svg`), embedded);
      summary.diagrams.push({ ...active, viewBox: rendered.viewBox, texts: rendered.texts, font: 'Manrope' });
    }
  }
  assert.equal(summary.externalRequests, 0);
} catch {
  summary.failures.push({ ...active, message: 'Static diagram compilation or font validation failed' });
  process.exitCode = 1;
} finally {
  await writeFile(resolve(output, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
  await browser.close();
  await new Promise(done => server.close(done));
}
console.log(JSON.stringify({ diagrams: summary.diagrams.length, externalRequests: summary.externalRequests, failures: summary.failures }));
