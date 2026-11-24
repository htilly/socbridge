// Writes a tiny MaxMind-format database (IPv4, 24-bit records) for tests.
// Run: node scripts/e2e/mmdb.mjs <file>
import { writeFileSync } from 'node:fs';

const head = (type, n) => {
  const ext = type > 7;
  const size = n < 29 ? n : 29;
  return Buffer.from([(ext ? 0 : type) << 5 | size, ...(ext ? [type - 7] : []), ...(n < 29 ? [] : [n - 29])]);
};
function encode(v) {
  if (typeof v === 'string') return Buffer.concat([head(2, Buffer.byteLength(v)), Buffer.from(v)]);
  if (typeof v === 'number') { const b = Buffer.alloc(8); b.writeDoubleBE(v); return Buffer.concat([head(3, 8), b]); }
  if (Buffer.isBuffer(v)) return Buffer.concat([head(6, v.length), v]); // uint32
  if (Array.isArray(v)) return Buffer.concat([head(11, v.length), ...v.map(encode)]);
  const e = Object.entries(v);
  return Buffer.concat([head(7, e.length), ...e.flatMap(([k, x]) => [encode(k), encode(x)])]);
}
const uint = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };

/** networks: { '203.0.113.0/24': record } */
export function buildMmdb(networks, databaseType = 'GeoLite2-City') {
  const nodes = [[null, null]];
  const data = [];
  let offset = 0;
  for (const [cidr, record] of Object.entries(networks)) {
    const [ip, len] = cidr.split('/');
    const bits = ip.split('.').map((o) => Number(o).toString(2).padStart(8, '0')).join('').slice(0, Number(len));
    const enc = encode(record);
    let at = 0;
    [...bits].forEach((b, i) => {
      if (i === bits.length - 1) nodes[at][b] = { offset };
      else at = nodes[at][b] ??= nodes.push([null, null]) - 1;
    });
    data.push(enc);
    offset += enc.length;
  }
  const tree = Buffer.alloc(nodes.length * 6);
  nodes.forEach((n, i) => n.forEach((r, s) => tree.writeUIntBE(r === null ? nodes.length : typeof r === 'number' ? r : nodes.length + 16 + r.offset, i * 6 + s * 3, 3)));
  const meta = encode({
    binary_format_major_version: uint(2), binary_format_minor_version: uint(0), build_epoch: uint(1), database_type: databaseType,
    description: { en: 'test' }, ip_version: uint(4), languages: ['en'], node_count: uint(nodes.length), record_size: uint(24),
  });
  return Buffer.concat([tree, Buffer.alloc(16), ...data, Buffer.from('abcdef4d61784d696e642e636f6d', 'hex'), meta]);
}

export const SAMPLE = {
  '203.0.113.0/26': { country: { names: { en: 'Netherlands' } }, location: { latitude: 52.37, longitude: 4.9 } },
  '203.0.113.64/26': { country: { names: { en: 'Brazil' } }, location: { latitude: -23.5, longitude: -46.6 } },
};
if (process.argv[1]?.endsWith('mmdb.mjs')) writeFileSync(process.argv[2], buildMmdb(SAMPLE));
