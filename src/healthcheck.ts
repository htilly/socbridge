/**
 * Container HEALTHCHECK: GET /health on the local listener. The built-in CA's
 * certificate is not in the container trust store, and the check only talks
 * to 127.0.0.1, so certificate verification is skipped here.
 */
import http from 'node:http';
import https from 'node:https';

const tlsOff = process.env.TLS_MODE === 'off';
const port = Number(process.env.PORT ?? (tlsOff ? 8080 : 8443));
const client = tlsOff ? http : https;

const req = client.get(
  { host: '127.0.0.1', port, path: '/health', timeout: 4000, rejectUnauthorized: false },
  (res) => {
    res.resume();
    process.exit(res.statusCode === 200 ? 0 : 1);
  },
);
req.on('timeout', () => req.destroy());
req.on('error', () => process.exit(1));
