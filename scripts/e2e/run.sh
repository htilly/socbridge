#!/usr/bin/env bash
# Starts mock Wazuh/DefectDojo/Graylog, points Trivy at scripts/e2e/trivy-reports, and SocBridge (TLS off, temp data dir), runs the e2e checks, cleans up.
# Usage: npm run build && scripts/e2e/run.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
DATA=$(mktemp -d)
export DATA_DIR=$DATA PUBLIC_URL=https://localhost:18080 PORT=18080 HOST=127.0.0.1 TLS_MODE=off
export SETUP_TOKEN=e2e-setup-token-0123456789abcdef CONFIG_ENCRYPTION_KEY=$(openssl rand -hex 32)
node scripts/e2e/mock-wazuh.mjs & MOCK=$!
node scripts/e2e/mock-llm.mjs & LLM=$!
node scripts/e2e/mock-defectdojo.mjs & DD=$!
node scripts/e2e/mock-graylog.mjs & GL=$!
node scripts/e2e/mock-feeds.mjs & FD=$!
node scripts/e2e/mmdb.mjs "$DATA/geoip.mmdb"
export TRIVY_REPORTS=$PWD/scripts/e2e/trivy-reports
node --input-type=module -e "
const { ConfigStore } = await import('./dist/config/store.js');
const s = ConfigStore.forDataDir(process.env.DATA_DIR, Buffer.from(process.env.CONFIG_ENCRYPTION_KEY, 'hex'));
await s.load();
await s.mutate((d) => { d.backends.wazuh = { enabled: true, managerUrl: 'http://127.0.0.1:19200', managerUser: 'ro', managerPassword: 'x', indexerUrl: 'http://127.0.0.1:19200', indexerUser: 'ro', indexerPassword: 'x' }; d.backends.defectdojo = { enabled: true, url: 'http://127.0.0.1:19210', apiKey: 'dd-test-key', tlsVerify: true }; d.backends.trivy = { enabled: true, reportsDir: process.env.TRIVY_REPORTS }; d.backends.graylog = { enabled: true, url: 'http://127.0.0.1:19220', apiToken: 'gl-test-token', tlsVerify: true, mcpPassthrough: false }; d.backends.intel = { enabled: true, kevUrl: 'http://127.0.0.1:19230/kev.json', epssUrl: 'http://127.0.0.1:19230/epss.csv' }; });
" > /dev/null
ANTHROPIC_BASE_URL=http://127.0.0.1:19300 node dist/index.js > "$DATA/server.log" 2>&1 & SRV=$!
cleanup() {
  kill "$SRV" "$MOCK" "$LLM" "$DD" "$GL" "$FD" 2>/dev/null || true
  wait "$SRV" "$MOCK" "$LLM" "$DD" "$GL" "$FD" 2>/dev/null || true   # the server flushes its config on SIGTERM
  rm -rf "$DATA" || true
}
trap cleanup EXIT
for _ in $(seq 1 30); do curl -fs http://127.0.0.1:18080/health > /dev/null && break; sleep 0.3; done
node scripts/e2e/passkey.mjs "$@"
