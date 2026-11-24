import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setupBanner } from '../auth/setup-banner.js';

test('setup banner: generated token is on its own greppable line', () => {
  const b = setupBanner({ origin: 'https://mcp.example.com', generated: 'abc123TOKEN' });
  const line = b.split('\n').find((l) => l.includes('SETUP TOKEN'));
  assert.equal(line?.trim(), 'SETUP TOKEN:  abc123TOKEN');
  assert.match(b, /Open https:\/\/mcp\.example\.com/);
  assert.match(b, /every restart/);
  assert.match(b, /^={20,}$/m);
});

test('setup banner: a token from SETUP_TOKEN is never printed', () => {
  const b = setupBanner({ origin: 'https://mcp.example.com' });
  assert.match(b, /SETUP TOKEN:  the value of SETUP_TOKEN/);
  assert.doesNotMatch(b, /every restart/);
});
