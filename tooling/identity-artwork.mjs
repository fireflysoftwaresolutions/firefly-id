import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

export async function assertIdentityArtworkReady(page, mode) {
  assert.ok(mode === 'light' || mode === 'dark', 'An explicit appearance is required for artwork qualification');
  await page.waitForFunction(dark => document.documentElement.classList.contains('pf-v5-theme-dark') === dark, mode === 'dark');
  const measured = await page.evaluate(() => {
    const header = document.querySelector('#kc-header');
    const wordmark = document.querySelector('#kc-header-wrapper');
    if (!header || !wordmark) return null;
    const visible = element => {
      const box = element.getBoundingClientRect();
      if (box.width <= 0 || box.height <= 0) return false;
      for (let current = element; current; current = current.parentElement) {
        const style = getComputedStyle(current);
        if (style.display === 'none' || style.visibility !== 'visible' || Number(style.opacity) === 0) return false;
      }
      return true;
    };
    const artwork = getComputedStyle(header, '::after');
    const backgroundUrl = style => style.backgroundImage.match(/^url\("([^"]+)"\)$/)?.[1];
    return { origin: location.origin, mobile: innerWidth <= 900,
      wordmark: { url: backgroundUrl(getComputedStyle(wordmark)), visible: visible(wordmark) },
      artwork: { url: backgroundUrl(artwork), visible: visible(header)
        && artwork.display !== 'none' && artwork.visibility === 'visible' && Number(artwork.opacity) > 0
        && artwork.content !== 'none' && parseFloat(artwork.width) > 0 && parseFloat(artwork.height) > 0 } };
  });
  assert.ok(measured, 'Identity header and wordmark must be present');
  const variant = `${measured.mobile ? 'mobile-' : ''}${mode}`;
  const assets = [
    { ...measured.wordmark, file: `wordmark-${mode}.svg`, canonical: `../assets/brand/firefly-id-${mode}.svg` },
    { ...measured.artwork, file: `authentication-${variant}.svg`, canonical: `../assets/identity-backgrounds/authentication-${variant}.svg` },
  ];
  for (const asset of assets) {
    assert.ok(asset.visible && asset.url, 'Identity artwork must have a visible nonzero rendered box and CSS image');
    const address = new URL(asset.url);
    assert.ok(address.origin === measured.origin && address.pathname.endsWith(`/img/${asset.file}`)
      && !address.search && !address.hash, 'Identity artwork must use the expected same-origin responsive appearance');
    const response = await page.request.get(asset.url, { timeout: 10000, maxRedirects: 0 });
    assert.equal(response.status(), 200, 'Identity artwork must be served successfully');
    assert.ok(response.url() === asset.url, 'Identity artwork must not redirect');
    const canonical = await readFile(new URL(asset.canonical, import.meta.url));
    assert.ok((await response.body()).equals(canonical), 'Served identity artwork must match the canonical SVG bytes');
  }
  await page.evaluate(async urls => {
    let timer;
    try {
      await Promise.race([
        Promise.all(urls.map(async url => {
          const image = new Image();
          image.src = url;
          await image.decode();
          if (!image.naturalWidth || !image.naturalHeight) throw new Error();
        })),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error()), 10000); }),
      ]);
    } catch {
      throw new Error('Identity artwork must decode before capture');
    } finally {
      clearTimeout(timer);
    }
  }, assets.map(asset => asset.url));
}
