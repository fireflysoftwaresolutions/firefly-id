import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, stat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { persistNativeFactor } from '../tooling/native-factor-fixture.mjs';

const first = '11111111-1111-4111-8111-111111111111';
const second = '22222222-2222-4222-8222-222222222222';
async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'native-factor-fixture-'));
  t.after(() => rm(directory, { recursive: true }));
  await mkdir(join(directory, 'secrets'));
  return directory;
}
test('distinct users in one population retain independent private factor files', async t => {
  const directory = await fixture(t);
  const a = await persistNativeFactor(directory, 'customers', first, 'synthetic-first');
  const b = await persistNativeFactor(directory, 'customers', second, 'synthetic-second');
  assert.notEqual(a, b);
  assert.deepEqual(JSON.parse(await readFile(a)), { secret: 'synthetic-first' });
  assert.deepEqual(JSON.parse(await readFile(b)), { secret: 'synthetic-second' });
  assert.equal((await stat(a)).mode & 0o777, 0o600);
  assert.equal((await stat(b)).mode & 0o777, 0o600);
});
test('re-enrollment cannot overwrite a retained factor for the same identity', async t => {
  const directory = await fixture(t);
  const path = await persistNativeFactor(directory, 'workforce', first, 'synthetic-original');
  await assert.rejects(persistNativeFactor(directory, 'workforce', first, 'synthetic-replacement'), { code: 'EEXIST' });
  assert.deepEqual(JSON.parse(await readFile(path)), { secret: 'synthetic-original' });
});
test('unowned identity cannot select a factor file path', async t => {
  const directory = await fixture(t);
  await assert.rejects(persistNativeFactor(directory, '../elsewhere', first, 'synthetic'));
  await assert.rejects(persistNativeFactor(directory, 'customers', '../../elsewhere', 'synthetic'));
});
