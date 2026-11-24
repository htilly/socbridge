// Copies the self-hosted UI fonts from their npm packages into public/design/fonts.
// The woff2 files are committed so the UI works on networks without internet
// access; run `npm run fonts:update` after bumping the font packages.
import { copyFileSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(import.meta.url);
const out = new URL('../public/design/fonts/', import.meta.url);
mkdirSync(out, { recursive: true });

const fonts = [
  { pkg: '@fontsource-variable/instrument-sans', file: 'instrument-sans-latin-wght-normal.woff2', license: 'OFL-instrument-sans.txt' },
  { pkg: '@fontsource-variable/martian-mono', file: 'martian-mono-latin-wght-normal.woff2', license: 'OFL-martian-mono.txt' },
];

for (const f of fonts) {
  const dir = path.dirname(require.resolve(`${f.pkg}/package.json`));
  copyFileSync(path.join(dir, 'files', f.file), new URL(f.file, out));
  copyFileSync(path.join(dir, 'LICENSE'), new URL(f.license, out));
  const { version } = require(`${f.pkg}/package.json`);
  console.log(`${f.pkg}@${version} -> public/design/fonts/${f.file}`);
}
