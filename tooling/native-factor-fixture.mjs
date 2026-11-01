import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export async function persistNativeFactor(directory, population, subject, secret) {
  if (!['customers', 'workforce'].includes(population) || !/^[0-9a-f-]{36}$/.test(subject)) {
    throw new Error('Owned synthetic factor identity required');
  }
  const path = join(directory, 'secrets', `totp-${population}-${subject}.json`);
  await writeFile(path, JSON.stringify({ secret }), { mode: 0o600, flag: 'wx' });
  return path;
}
