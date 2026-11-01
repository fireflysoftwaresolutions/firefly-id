export function contrastRatio(foreground, background) {
  const luminance = channels => channels.map(value => {
    const channel = value / 255;
    return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  }).reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0);
  const values = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

export function inspectDiagram(measured) {
  const failures = [];
  const inside = (inner, outer, tolerance = 1) => inner.x >= outer.x - tolerance && inner.y >= outer.y - tolerance &&
    inner.x + inner.width <= outer.x + outer.width + tolerance && inner.y + inner.height <= outer.y + outer.height + tolerance;
  const overlaps = (a, b) => Math.min(a.x + a.width, b.x + b.width) - Math.max(a.x, b.x) > 1 &&
    Math.min(a.y + a.height, b.y + b.height) - Math.max(a.y, b.y) > 1;
  if (!measured.labels.length) failures.push({ code: 'MISSING_TEXT' });
  for (const item of [...measured.shapes, ...measured.labels]) {
    if (!inside(item.bounds, measured.bounds)) failures.push({ code: 'CLIPPED_CONTENT', item: item.text || item.name, bounds: item.bounds });
  }
  for (const item of measured.labels) {
    if (!(item.bounds.width > 0 && item.bounds.height > 0)) failures.push({ code: 'INVISIBLE_LABEL', text: item.text });
    if (!/Manrope/.test(item.font)) failures.push({ code: 'FONT_FALLBACK', text: item.text, font: item.font });
    if (item.fontSize < 12) failures.push({ code: 'SMALL_TEXT', text: item.text, size: item.fontSize });
    if (item.container && !inside(item.bounds, item.container)) failures.push({ code: 'LABEL_OUTSIDE_NODE', text: item.text });
    const validColors = [item.fill, ...item.backgrounds].every(color => color.length === 3 && color.every(Number.isFinite));
    const ratio = !validColors ? NaN : Math.min(...item.backgrounds.map(background => contrastRatio(item.fill, background)));
    if (!Number.isFinite(ratio) || ratio < 4.5) failures.push({ code: 'LOW_TEXT_CONTRAST', text: item.text, ratio });
  }
  for (const [items, code] of [[measured.labels, 'LABEL_COLLISION'], [measured.nodes, 'NODE_COLLISION']]) {
    for (let a = 0; a < items.length; a++) {
      for (let b = a + 1; b < items.length; b++) {
        if (overlaps(items[a].bounds, items[b].bounds)) failures.push({ code, items: [items[a].text || items[a].name, items[b].text || items[b].name] });
      }
    }
  }
  return failures;
}

// Runs inside the hosted browser after the packaged font has finished loading.
export function measureDiagram(mode) {
  const svg = document.querySelector('svg');
  const bounds = element => {
    const { x, y, width, height } = element.getBoundingClientRect();
    return { x, y, width, height };
  };
  const visible = element => !element.closest('defs, marker, clipPath, mask, pattern, symbol') &&
    getComputedStyle(element).display !== 'none' && getComputedStyle(element).visibility !== 'hidden' && Number(getComputedStyle(element).opacity) > 0;
  const shapes = [...svg.querySelectorAll('path, line, rect, polygon, polyline, circle, ellipse')].filter(visible);
  const canvas = mode === 'dark' ? [39, 40, 32] : [255, 255, 255];
  const color = value => (value.match(/[\d.]+/g) || []).slice(0, 3).map(Number);
  const backdrop = element => {
    const area = bounds(element);
    const center = new DOMPoint(area.x + area.width / 2, area.y + area.height / 2);
    let result = canvas;
    for (const shape of shapes) {
      const style = getComputedStyle(shape);
      if (!(shape.compareDocumentPosition(element) & Node.DOCUMENT_POSITION_FOLLOWING) || style.fill === 'none' || !shape.getScreenCTM()) continue;
      if (!shape.isPointInFill(center.matrixTransform(shape.getScreenCTM().inverse()))) continue;
      const fill = color(style.fill);
      const alpha = Number(style.fillOpacity) * Number(style.opacity);
      if (fill.length === 3) result = fill.map((channel, index) => channel * alpha + result[index] * (1 - alpha));
    }
    return result;
  };
  const labels = [...svg.querySelectorAll('text')].filter(element => element.textContent.trim()).map(element => {
    const style = getComputedStyle(element);
    const node = element.closest('.node');
    const shape = node?.querySelector('rect, polygon, circle, ellipse, path');
    return { text: element.textContent.trim(), bounds: visible(element) ? bounds(element) : { x: 0, y: 0, width: 0, height: 0 },
      font: style.fontFamily, fontSize: parseFloat(style.fontSize), fill: color(style.fill),
      backgrounds: [backdrop(element)], container: shape ? bounds(shape) : null };
  });
  return { bounds: bounds(svg), labels,
    shapes: shapes.map(element => ({ name: element.id || element.getAttribute('class') || element.tagName, bounds: bounds(element) })),
    nodes: [...svg.querySelectorAll('.node')].filter(visible).map(element => ({ name: element.id, bounds: bounds(element) })) };
}
