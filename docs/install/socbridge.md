# Install SocBridge only

For LLM agents. Read the [rules](README.md) first. Result: one container,
`socbridge`, on port 8443. Backends are connected at the end, in the web UI.

Needs: Linux, 1 CPU, 512 MB RAM, git, openssl, Docker Engine with Compose 2.24
or newer, TCP 8443 free, and read access to this (private) repository.

## 1. Check the host

```bash
docker info --format '{{.ServerVersion}}' && docker compose version --short
ss -ltn | grep ':8443 ' && echo "PORT 8443 IN USE"
```

**Check:** Compose is 2.24+ and nothing uses 8443.

## 2. Fetch the code

```bash
sudo mkdir -p /opt/soc && sudo chown "$USER" /opt/soc
# skip the clone if this repository is already there
git clone https://github.com/htilly/socbridge.git /opt/soc/socbridge
cd /opt/soc/socbridge
```

**Check:** `ls docker-compose.yml Dockerfile` lists both.

## 3. Create the encryption key

Do this once. Never overwrite an existing key: without it the stored
configuration cannot be read.

```bash
cd /opt/soc/socbridge
mkdir -p secrets
test -s secrets/config_key || openssl rand -hex 32 > secrets/config_key
sudo chown 1000 secrets/config_key && sudo chmod 400 secrets/config_key
```

**Check:** `sudo wc -c < secrets/config_key` prints 65.

**[HUMAN]** Back up `/opt/soc/socbridge/secrets/config_key` somewhere safe.

## 4. Configure

Put local settings in an override file so `git pull` stays clean. Replace the
URL. The port in it must be the one browsers use: keep `:8443`, or map
`443:8443` in `ports` and leave it out.

```bash
cd /opt/soc/socbridge
cat > docker-compose.override.yml <<'YAML'
services:
  socbridge:
    environment:
      PUBLIC_URL: https://socbridge.example.com:8443
YAML
docker compose config --quiet && docker compose config | grep PUBLIC_URL
```

Leave `TLS_MODE` unset so the certificate is chosen in the setup guide. All
other variables: [README, Configuration](../../README.md#configuration).

**Check:** the printed `PUBLIC_URL` is the user's.

## 5. Start

```bash
cd /opt/soc/socbridge
docker compose up -d --build
until [ "$(docker inspect -f '{{.State.Health.Status}}' socbridge)" = healthy ]; do
  sleep 3; docker inspect -f '{{.State.Status}}' socbridge | grep -q running || break
done
curl -sk https://127.0.0.1:8443/health
```

`-k` is fine here: this only checks liveness on localhost.

**Check:** the reply contains `"status":"ok"`. Otherwise read
`docker compose logs --tail 50 socbridge`.

## 6. First administrator [HUMAN]

Ask the user to do this; the setup token must not pass through the chat.

1. On the host: `docker compose logs socbridge | grep "SETUP TOKEN" | tail -1`.
2. Open `PUBLIC_URL`, paste the token, choose the certificate, create the
   passkey. Details and the CA fingerprint check:
   [README, Quick start](../../README.md#quick-start-docker-compose).

**Check:** the user is signed in and sees the Admin menu.

## 7. Connect backends [HUMAN]

**Admin → Backends**: fill in, tick *Enabled*, **Save**, **Test connection**.
Any subset works. Use read-only accounts and leave *Allow write tools* off.

| Backend | Needs |
|---|---|
| Wazuh 4.8+ | Manager API URL (55000) and read-only user; indexer URL (9200) and a user with `read` on both index patterns and `cluster:monitor/main`; CA certificate |
| Graylog | URL and an access token of a Reader user |
| DefectDojo | URL and the API v2 key of a Reader user |
| Trivy | Directory of JSON reports, mounted read-only (below) |
| Threat intel | Nothing; outbound HTTPS to `www.cisa.gov` and `epss.empiricalsecurity.com` |

Settings in full: [README, Backends](../../README.md#backends). For Trivy, add
to the override file, then run `docker compose up -d` and use
`/reports/trivy` as the report directory:

```yaml
    volumes:
      - /opt/soc/trivy-reports:/reports/trivy:ro
```

`localhost` in a URL means the SocBridge container itself. Use a hostname the
container can resolve.

**Check:** every enabled backend passes *Test connection*.

## 8. Connect an MCP client [HUMAN]

**My account → Access tokens**: create a token and copy the `claude mcp add …`
line. Other clients: [README](../../README.md#connecting-claude-code).

**Check:** the client lists tools, and `socbridge_backends` reports the enabled
backends as healthy.

## Upgrade

```bash
cd /opt/soc/socbridge && git pull --ff-only && docker compose up -d --build
```
