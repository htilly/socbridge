import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const read = (p: string) => readFileSync(new URL(`../../public/design/${p}`, import.meta.url), 'utf8');

function token(css: string, name: string): string {
  const m = new RegExp(`${name}:\\s*([^;]+);`).exec(css);
  assert.ok(m, `token ${name} missing`);
  return m[1]!.trim();
}

test('logo and favicon geometry match the aperture tokens', () => {
  const tokens = read('tokens.css');
  const R = Number(token(tokens, '--aperture-radius'));
  const a = Number(token(tokens, '--aperture-open'));
  const expected = `M -${R} -${R} L ${R} -${R} L ${R} -${a} L -${a} -${a} Z`;
  for (const file of ['logo.svg', 'favicon.svg']) {
    const svg = read(file);
    const paths = [...svg.matchAll(/ d="([^"]+)"/g)].map((m) => m[1]);
    assert.ok(paths.length > 0, `${file} has no path`);
    for (const d of paths) assert.equal(d, expected, `${file} blade geometry`);
    assert.ok(svg.includes(`viewBox="-${R} -${R} ${2 * R} ${2 * R}"`), `${file} viewBox`);
    assert.ok(svg.includes(token(tokens, '--brass')) && svg.includes(token(tokens, '--brass-d')), `${file} blade colours`);
  }
});

test('component styles use tokens only', () => {
  const css = read('components.css').replace(/\/\*[\s\S]*?\*\//g, '');
  assert.equal(css.match(/#[0-9a-fA-F]{3,8}\b/g), null, 'raw hex colour in components.css');
  assert.equal(css.match(/rgba?\(|hsla?\(/g), null, 'raw colour function in components.css');
});

test('severity never uses the identity colour', () => {
  const css = read('components.css').replace(/\/\*[\s\S]*?\*\//g, '');
  for (const rule of css.matchAll(/([^{}]*\.sev[^{}]*)\{([^}]*)\}/g)) {
    assert.ok(!/--brass|--accent|--focus-ring/.test(rule[2]!), `severity rule "${rule[1]!.trim()}" uses the identity colour`);
  }
});
