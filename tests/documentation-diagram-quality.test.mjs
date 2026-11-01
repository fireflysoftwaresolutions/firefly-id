import assert from 'node:assert/strict';
import test from 'node:test';

import * as quality from '../tooling/documentation-diagram-quality.mjs';
const box = (x, y, width, height) => ({ x, y, width, height });
const label = (text, bounds, extra = {}) => ({ text, bounds, font: 'Manrope', fontSize: 16,
  fill: [39, 40, 32], backgrounds: [[255, 255, 255]], ...extra });
const valid = () => ({ bounds: box(0, 0, 300, 200), shapes: [], nodes: [],
  labels: [label('Start', box(20, 20, 60, 20)), label('Finish', box(180, 120, 70, 20))] });

test('diagram audit rejects clipped content even when viewBox and text exist', () => {
  assert.equal(typeof quality.inspectDiagram, 'function');
  const data = valid();
  data.shapes.push({ name: 'connector', bounds: box(-8, 30, 100, 2) });
  assert.ok(quality.inspectDiagram(data).some(item => item.code === 'CLIPPED_CONTENT'));
});

test('diagram audit catches overlapping labels but permits touching bounds', () => {
  assert.equal(typeof quality.inspectDiagram, 'function');
  const data = valid();
  data.labels.push(label('Overlapping', box(30, 25, 90, 20)));
  assert.ok(quality.inspectDiagram(data).some(item => item.code === 'LABEL_COLLISION'));
  data.labels[2].bounds = box(80, 20, 90, 20);
  assert.deepEqual(quality.inspectDiagram(data), []);
});

test('diagram audit checks actual font, contrast and node containment', () => {
  assert.equal(typeof quality.inspectDiagram, 'function');
  const data = valid();
  data.labels[0] = label('Unreadable', box(20, 20, 60, 20), {
    font: 'Arial', fill: [190, 190, 190], container: box(25, 25, 20, 10),
  });
  const codes = quality.inspectDiagram(data).map(item => item.code);
  for (const code of ['FONT_FALLBACK', 'LOW_TEXT_CONTRAST', 'LABEL_OUTSIDE_NODE']) assert.ok(codes.includes(code), code);
});

test('diagram audit rejects invisible or missing text and overlapping nodes', () => {
  assert.equal(typeof quality.inspectDiagram, 'function');
  const data = valid();
  data.labels[0].bounds.width = 0;
  data.nodes = [{ name: 'A', bounds: box(10, 10, 90, 60) }, { name: 'B', bounds: box(80, 50, 90, 60) }];
  const codes = quality.inspectDiagram(data).map(item => item.code);
  assert.ok(codes.includes('INVISIBLE_LABEL'));
  assert.ok(codes.includes('NODE_COLLISION'));
  assert.ok(quality.inspectDiagram({ ...valid(), labels: [] }).some(item => item.code === 'MISSING_TEXT'));
});

test('contrast uses WCAG luminance with canonical light and dark surfaces', () => {
  assert.equal(typeof quality.contrastRatio, 'function');
  assert.equal(quality.contrastRatio([0, 0, 0], [255, 255, 255]), 21);
  assert.equal(quality.contrastRatio([100, 100, 100], [100, 100, 100]), 1);
  assert.ok(quality.contrastRatio([243, 241, 235], [71, 74, 66]) >= 4.5);
  assert.deepEqual(quality.inspectDiagram(valid()), []);
});

test('painted runs determine contrast and collision when parent actor boxes overlap', () => {
  const data = valid();
  data.labels = [
    label('Customer', box(20, 20, 80, 24), { fill: [255, 255, 255], runs: [label('Customer', box(20, 25, 75, 12))] }),
    label('Domain', box(20, 36, 80, 24), { fill: [255, 255, 255], runs: [label('Domain', box(20, 41, 60, 12))] }),
  ];
  assert.deepEqual(quality.inspectDiagram(data), []);
  data.labels[1].runs[0].bounds.y = 30;
  assert.ok(quality.inspectDiagram(data).some(item => item.code === 'LABEL_COLLISION'));
  data.labels[1].runs[0].fill = [255, 255, 255];
  assert.ok(quality.inspectDiagram(data).some(item => item.code === 'LOW_TEXT_CONTRAST'));
});

test('overlapping painted spans inside one label still report a collision', () => {
  const data = valid();
  data.labels = [label('Two lines', box(20, 20, 100, 40), { runs: [
    label('First line', box(20, 20, 75, 12)),
    label('Second line', box(20, 26, 80, 12)),
  ] })];
  assert.ok(quality.inspectDiagram(data).some(item => item.code === 'LABEL_COLLISION'));
});
