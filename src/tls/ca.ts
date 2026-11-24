import { generateKeyPairSync, randomBytes, X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';
import forge from 'node-forge';

/**
 * Offline certificate authority. Creates a long-lived root once and issues
 * short-lived server certificates from it. Nothing here touches the network.
 */

export interface CaMaterial {
  caKeyPem: string;
  caCertPem: string;
  /** Names and addresses the CA may certify (name constraints). Absent on CAs made before they existed. */
  names?: string[];
}

export interface LeafMaterial {
  keyPem: string;
  certPem: string;
  sans: string[];
}

const CA_YEARS = 5;
export const LEAF_DAYS = 90;
/** Re-issue the leaf when less than this much validity remains. */
export const RENEW_BEFORE_DAYS = 30;

function rsaKeyPair(): { publicKeyPem: string; privateKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKeyPem: publicKey, privateKeyPem: privateKey };
}

function serial(): string {
  const b = randomBytes(16);
  b[0] = b[0]! & 0x7f; // keep the serial positive
  return b.toString('hex');
}

/**
 * RFC 5280 nameConstraints: only these hosts and addresses, and nothing else of
 * either kind, so a stolen CA key cannot impersonate other sites.
 */
function nameConstraints(names: string[]) {
  const a = forge.asn1;
  const tree = (tag: number, bytes: string) =>
    a.create(a.Class.UNIVERSAL, a.Type.SEQUENCE, true, [a.create(a.Class.CONTEXT_SPECIFIC, tag, false, bytes)]);
  const ip = (s: string) => {
    const b = (forge.util as unknown as { bytesFromIP(ip: string): string }).bytesFromIP(s);
    return b + '\xff'.repeat(b.length);
  };
  const permitted = names.map((n) => (isIP(n) ? tree(7, ip(n)) : tree(2, n)));
  const excluded: ReturnType<typeof tree>[] = [];
  // A kind with no permitted entry would be unrestricted, so rule it out entirely.
  if (!names.some((n) => isIP(n) === 4) && !names.some((n) => isIP(n) === 6)) excluded.push(tree(7, '\0'.repeat(8)), tree(7, '\0'.repeat(32)));
  if (!names.some((n) => !isIP(n))) excluded.push(tree(2, ''));
  const parts = [a.create(a.Class.CONTEXT_SPECIFIC, 0, true, permitted)];
  if (excluded.length) parts.push(a.create(a.Class.CONTEXT_SPECIFIC, 1, true, excluded));
  return { id: '2.5.29.30', critical: true, value: a.toDer(a.create(a.Class.UNIVERSAL, a.Type.SEQUENCE, true, parts)).getBytes() };
}

/** Names this CA cannot certify because of its name constraints. A DNS constraint covers subdomains. */
export function outsideConstraints(ca: Pick<CaMaterial, 'names'>, sans: string[]): string[] {
  const names = ca.names;
  if (!names) return [];
  return sans.filter((s) => !names.some((n) => s === n || (!isIP(s) && !isIP(n) && s.endsWith('.' + n))));
}

export function createCa(commonName: string, names: string[] = []): CaMaterial {
  const keys = rsaKeyPair();
  const pub = forge.pki.publicKeyFromPem(keys.publicKeyPem);
  const priv = forge.pki.privateKeyFromPem(keys.privateKeyPem);
  const cert = forge.pki.createCertificate();
  cert.publicKey = pub;
  cert.serialNumber = serial();
  const now = new Date();
  cert.validity.notBefore = new Date(now.getTime() - 60_000);
  cert.validity.notAfter = new Date(now);
  cert.validity.notAfter.setFullYear(now.getFullYear() + CA_YEARS);
  const subject = [
    { name: 'commonName', value: commonName },
    { name: 'organizationName', value: 'SocBridge local CA' },
  ];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, pathLenConstraint: 0, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
    ...(names.length ? [nameConstraints(names)] : []),
    { name: 'subjectKeyIdentifier' },
  ]);
  cert.sign(priv, forge.md.sha256.create());
  return { caKeyPem: keys.privateKeyPem, caCertPem: forge.pki.certificateToPem(cert), ...(names.length ? { names: [...names] } : {}) };
}

export function issueLeaf(ca: CaMaterial, sans: string[]): LeafMaterial {
  if (sans.length === 0) throw new Error('At least one subject alternative name is required');
  const caCert = forge.pki.certificateFromPem(ca.caCertPem);
  const caKey = forge.pki.privateKeyFromPem(ca.caKeyPem);
  const keys = rsaKeyPair();
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(keys.publicKeyPem);
  cert.serialNumber = serial();
  const now = Date.now();
  cert.validity.notBefore = new Date(now - 60_000);
  cert.validity.notAfter = new Date(now + LEAF_DAYS * 86_400_000);
  cert.setSubject([{ name: 'commonName', value: sans[0]! }]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false, critical: true },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
    { name: 'extKeyUsage', serverAuth: true },
    {
      name: 'subjectAltName',
      altNames: sans.map((s) => (isIP(s) ? { type: 7, ip: s } : { type: 2, value: s })),
    },
    { name: 'subjectKeyIdentifier' },
    { name: 'authorityKeyIdentifier', keyIdentifier: caCert.generateSubjectKeyIdentifier().getBytes() },
  ]);
  cert.sign(caKey, forge.md.sha256.create());
  return { keyPem: keys.privateKeyPem, certPem: forge.pki.certificateToPem(cert), sans: [...sans] };
}

/** Days until the certificate expires (negative if already expired). */
export function daysRemaining(certPem: string): number {
  const x = new X509Certificate(certPem);
  return (Date.parse(x.validTo) - Date.now()) / 86_400_000;
}

export function fingerprint256(certPem: string): string {
  return new X509Certificate(certPem).fingerprint256;
}
