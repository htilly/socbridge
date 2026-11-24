import { randomBytes } from 'node:crypto';
import { mkdir, open, rename, unlink } from 'node:fs/promises';
import path from 'node:path';

/**
 * Write a file atomically: write to a temp file in the same directory, fsync,
 * then rename over the target. Readers never observe a half-written file.
 */
export async function writeFileAtomic(file: string, data: string | Buffer, mode = 0o600): Promise<void> {
  const dir = path.dirname(file);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const tmp = path.join(dir, `.${path.basename(file)}.${randomBytes(6).toString('hex')}.tmp`);
  const handle = await open(tmp, 'w', mode);
  try {
    await handle.writeFile(data);
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(tmp, file);
  } catch (err) {
    await unlink(tmp).catch(() => undefined);
    throw err;
  }
}
