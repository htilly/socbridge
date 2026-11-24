# Install the full stack

For LLM agents. Read the [rules](README.md) first. Result, on one host:

| Service | Version | Reached by SocBridge as | Published on the host |
|---|---|---|---|
| Wazuh (manager, indexer, dashboard) | 4.14.10 | `https://wazuh.manager:55000`, `https://wazuh.indexer:9200` | 1514, 1515 (agents); dashboard 127.0.0.1:5601 |
| Graylog (server, data node, MongoDB) | 7.2 | `http://graylog:9000` | 127.0.0.1 only |
| DefectDojo | 3.5.202 | `http://defectdojo:8080` | 127.0.0.1:8080 |
| Trivy | 0.76.2 | JSON files in `/reports/trivy` | – |
| SocBridge | this repo | – | 8443 |

Each service is its own Compose project under `/opt/soc`, joined by a Docker
network named `soc`. Graylog and DefectDojo speak plain HTTP on that network
only. Everything uses the upstream Compose files, which their authors describe
as a starting point: fine for a lab or a small site, but plan backups, TLS and
sizing with the user before relying on it.

Needs: Linux **x86_64**, 8 CPUs, 24 GB RAM, 150 GB disk (a starting point; log
volume decides), git, curl, jq, openssl, Docker Engine with Compose 2.24+.

Skip any service the user does not want; the rest still works.

## 1. Prepare the host

```bash
uname -m; nproc; free -g | head -2; df -h /
docker compose version --short; command -v git curl jq openssl
ss -ltn | grep -E ':(1514|1515|5601|8080|8443|8999|9000|9200|9300|5044|5140|5555|12201|13301|13302) ' && echo "PORT IN USE"

echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-soc.conf && sudo sysctl --system > /dev/null
sudo mkdir -p /opt/soc && sudo chown "$USER" /opt/soc
install -d -m 700 /opt/soc/secrets
docker network inspect soc > /dev/null 2>&1 || docker network create soc
```

**Check:** no port in use, `sysctl -n vm.max_map_count` is at least 262144, and
`docker network inspect soc` works.

## 2. Generate secrets

Creates them once and never overwrites. The fixed ending meets Wazuh's password
rules; there is no `$`, which Compose would expand.

```bash
test -e /opt/soc/secrets/stack.env || ( umask 077
pw() { printf '%sA.z9' "$(openssl rand -hex 16)"; }
cat > /opt/soc/secrets/stack.env <<EOF
WAZUH_ADMIN_PW=$(pw)
WAZUH_DASHBOARD_PW=$(pw)
WAZUH_WUI_PW=$(pw)
WAZUH_API_ADMIN_PW=$(pw)
WAZUH_SB_INDEXER_PW=$(pw)
WAZUH_SB_API_PW=$(pw)
GRAYLOG_ADMIN_PW=$(pw)
GRAYLOG_SECRET=$(openssl rand -hex 48)
DD_DB_PW=$(openssl rand -hex 24)
DD_SECRET=$(openssl rand -hex 32)
DD_AES=$(openssl rand -hex 16)
EOF
)
```

**Check:** `stat -c %a /opt/soc/secrets/stack.env` prints 600 and
`grep -c = /opt/soc/secrets/stack.env` prints 11.

**[HUMAN]** Copy the file to a password manager.

## 3. Wazuh

Default passwords and the demo indexer users are replaced before first start.

```bash
git clone --depth 1 -b v4.14.10 https://github.com/wazuh/wazuh-docker.git /opt/soc/wazuh
cd /opt/soc/wazuh/single-node
set -a; . /opt/soc/secrets/stack.env; set +a

sed -i -e "s/SecretPassword/$WAZUH_ADMIN_PW/" \
  -e "s/DASHBOARD_PASSWORD=kibanaserver/DASHBOARD_PASSWORD=$WAZUH_DASHBOARD_PW/" \
  -e "s/API_PASSWORD=.*/API_PASSWORD=$WAZUH_WUI_PW/" docker-compose.yml
sed -i "s/password: .*/password: \"$WAZUH_WUI_PW\"/" config/wazuh_dashboard/wazuh.yml
chmod o-r docker-compose.yml

hash() { docker run --rm -e "$1" wazuh/wazuh-indexer:4.14.10 \
  bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -env "$1" | grep -o '^\$2[^[:space:]]*' | tail -1; }
H_ADMIN=$(hash WAZUH_ADMIN_PW); H_DASH=$(hash WAZUH_DASHBOARD_PW); H_SB=$(hash WAZUH_SB_INDEXER_PW)
for h in "$H_ADMIN" "$H_DASH" "$H_SB"; do [ ${#h} -eq 60 ] || echo "HASHING FAILED - STOP"; done

cat > config/wazuh_indexer/internal_users.yml <<EOF
---
_meta:
  type: "internalusers"
  config_version: 2
admin:
  hash: "$H_ADMIN"
  reserved: true
  backend_roles: ["admin"]
kibanaserver:
  hash: "$H_DASH"
  reserved: true
socbridge:
  hash: "$H_SB"
  reserved: false
  description: "SocBridge, read only"
EOF

cat > docker-compose.override.yml <<'YAML'
services:
  wazuh.manager:
    ports: !override ["1514:1514", "1515:1515"]
    networks: { default: {}, soc: {} }
  wazuh.indexer:
    ports: !reset []
    networks: { default: {}, soc: {} }
  wazuh.dashboard:
    ports: !override ["127.0.0.1:5601:5601"]
networks:
  soc: { external: true }
YAML

docker compose -f generate-indexer-certs.yml run --rm generator
docker compose config --quiet && docker compose up -d
```

**Check:** no "HASHING FAILED"; after one to five minutes this prints 200 twice:

```bash
cd /opt/soc/wazuh/single-node; set -a; . /opt/soc/secrets/stack.env; set +a
docker compose exec -T -e P="$WAZUH_ADMIN_PW" wazuh.indexer bash -c \
  'curl -s -o /dev/null -w "%{http_code}\n" --cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem -u "admin:$P" https://wazuh.indexer:9200/'
docker compose exec -T -e P="$WAZUH_WUI_PW" wazuh.manager bash -c \
  'curl -sk -o /dev/null -w "%{http_code}\n" -u "wazuh-wui:$P" -X POST "https://localhost:55000/security/user/authenticate?raw=true"'
```

Give the indexer user `socbridge` read access to the alert and vulnerability
indices, plus the version call SocBridge's health check makes:

```bash
cd /opt/soc/wazuh/single-node; set -a; . /opt/soc/secrets/stack.env; set +a
docker compose exec -T -e P="$WAZUH_ADMIN_PW" wazuh.indexer bash -s <<'SH'
set -euo pipefail
api() { curl -sf --cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem -u "admin:$P" \
  -H 'Content-Type: application/json' -X PUT "https://wazuh.indexer:9200/_plugins/_security/api/$1" -d "$2" > /dev/null; }
api roles/socbridge_read '{"cluster_permissions":["cluster_composite_ops_ro","cluster:monitor/main"],"index_permissions":[{"index_patterns":["wazuh-alerts-*","wazuh-states-vulnerabilities-*"],"allowed_actions":["read"]}]}'
api rolesmapping/socbridge_read '{"users":["socbridge"]}'
echo DONE
SH
```

**Check:** it prints `DONE`, and this prints 200:

```bash
cd /opt/soc/wazuh/single-node; set -a; . /opt/soc/secrets/stack.env; set +a
docker compose exec -T -e P="$WAZUH_SB_INDEXER_PW" wazuh.indexer bash -c \
  'curl -s -o /dev/null -w "%{http_code}\n" --cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem -u "socbridge:$P" https://wazuh.indexer:9200/'
```

The manager API starts with a self-signed certificate for another name. Give it
the certificate issued by the stack's CA, so SocBridge can verify both services:

```bash
cd /opt/soc/wazuh/single-node
docker compose exec -T wazuh.manager bash -c '
  cd /var/ossec/api/configuration/ssl &&
  install -o wazuh -g wazuh -m 640 /etc/ssl/filebeat.pem server.crt &&
  install -o wazuh -g wazuh -m 640 /etc/ssl/filebeat.key server.key'
docker compose restart wazuh.manager
```

**Check** (after a minute; prints 401, meaning TLS verified and login required):

```bash
cd /opt/soc/wazuh/single-node
docker compose exec -T wazuh.manager curl -s -o /dev/null -w '%{http_code}\n' \
  --cacert /etc/ssl/root-ca.pem --resolve wazuh.manager:55000:127.0.0.1 https://wazuh.manager:55000/
```

Create the read-only API user, and change the password of the built-in `wazuh`
user:

```bash
cd /opt/soc/wazuh/single-node; set -a; . /opt/soc/secrets/stack.env; set +a
docker compose exec -T -e WUI="$WAZUH_WUI_PW" -e SB="$WAZUH_SB_API_PW" -e ADM="$WAZUH_API_ADMIN_PW" wazuh.manager bash -s <<'SH'
set -euo pipefail
A=https://localhost:55000
T=$(curl -sfk -u "wazuh-wui:$WUI" -X POST "$A/security/user/authenticate?raw=true")
req() { curl -sfk -H "Authorization: Bearer $T" -H 'Content-Type: application/json' "$@"; }
PY=/var/ossec/framework/python/bin/python3
id() { $PY -c "import sys,json;print([i['id'] for i in json.load(sys.stdin)['data']['affected_items'] if i['$1']=='$2'][0])"; }
ROLE=$(req "$A/security/roles" | id name readonly)
req -X POST "$A/security/users" -d "{\"username\":\"socbridge\",\"password\":\"$SB\"}" > /dev/null
U=$(req "$A/security/users" | id username socbridge)
req -X POST "$A/security/users/$U/roles?role_ids=$ROLE" > /dev/null
W=$(req "$A/security/users" | id username wazuh)
req -X PUT "$A/security/users/$W" -d "{\"password\":\"$ADM\"}" > /dev/null
echo DONE
SH
```

**Check:** it prints `DONE`.

Agents are enrolled from the dashboard (`ssh -L 5601:127.0.0.1:5601 <host>`,
then <https://localhost:5601>, user `admin`).

## 4. Graylog

```bash
git clone --depth 1 https://github.com/Graylog2/docker-compose.git /opt/soc/graylog
cd /opt/soc/graylog/open-core
set -a; . /opt/soc/secrets/stack.env; set +a
( umask 077; cat > .env <<EOF
GRAYLOG_IMAGE=graylog/graylog:7.2
DATANODE_IMAGE=graylog/graylog-datanode:7.2
GRAYLOG_PASSWORD_SECRET=$GRAYLOG_SECRET
GRAYLOG_ROOT_PASSWORD_SHA2=$(printf %s "$GRAYLOG_ADMIN_PW" | sha256sum | cut -d' ' -f1)
EOF
)
cat > docker-compose.override.yml <<'YAML'
services:
  graylog:
    networks: { graylog: {}, soc: { aliases: [graylog] } }
networks:
  soc: { external: true }
YAML
docker compose config --quiet && docker compose up -d
```

**Check:** `docker compose ps` shows `mongodb`, `datanode` and `graylog` running,
and `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9000` answers.

**[HUMAN]**

1. `ssh -L 9000:127.0.0.1:9000 <host>`, open <http://localhost:9000>. The
   first-run login is in `docker compose logs graylog` ("It seems you are
   starting Graylog for the first time").
2. Follow the setup UI: create the CA, set the renewal policy, provision the
   data node, resume startup. Then sign in as `admin` with `GRAYLOG_ADMIN_PW`.
3. **System → Users and Teams**: create user `socbridge` with role *Reader* and
   share the streams it may search with it.
4. On that user **More → Edit tokens**: create a token. Note its lifetime
   (30 days by default); SocBridge loses access when it expires. Keep it for
   step 7.

Inputs listen on 127.0.0.1 only. If other machines send logs, agree with the
user which port to open and override `ports` for it.

## 5. DefectDojo

```bash
git clone --depth 1 -b 3.5.202 https://github.com/DefectDojo/django-DefectDojo.git /opt/soc/defectdojo
cd /opt/soc/defectdojo
set -a; . /opt/soc/secrets/stack.env; set +a
( umask 077; cat > .env <<EOF
DJANGO_VERSION=3.5.202
NGINX_VERSION=3.5.202
DD_SECRET_KEY=$DD_SECRET
DD_CREDENTIAL_AES_256_KEY=$DD_AES
DD_DATABASE_PASSWORD=$DD_DB_PW
DD_DATABASE_URL=postgresql://defectdojo:$DD_DB_PW@postgres:5432/defectdojo
DD_ALLOWED_HOSTS=localhost,127.0.0.1,defectdojo
EOF
)
cat > docker-compose.override.yml <<'YAML'
services:
  nginx:
    ports: !override ["127.0.0.1:8080:8080"]
    networks: { default: {}, soc: { aliases: [defectdojo] } }
networks:
  soc: { external: true }
YAML
docker compose config --quiet && docker compose pull
docker compose up -d --no-build
```

**Check** (first start takes several minutes): `docker compose ps -a initializer`
shows `Exited (0)`, and
`curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/login` prints 200.

**[HUMAN]**

1. `ssh -L 8080:127.0.0.1:8080 <host>`, open <http://localhost:8080>. User
   `admin`; the password is in `docker compose logs initializer | grep "Admin password"`.
   Change it.
2. Create user `socbridge`, not staff or superuser, with global role *Reader*.
3. Sign in as that user, user menu → **API v2 Key**. Keep the key for step 7.

## 6. Trivy

A daily scan of the images running on this host. The container gets the Docker
socket (full control of Docker) to read local images; tell the user. Anything
else that writes Trivy JSON into the directory works too.

```bash
mkdir -p /opt/soc/trivy-reports /opt/soc/trivy-cache /opt/soc/bin
cat > /opt/soc/bin/trivy-scan.sh <<'SH'
#!/usr/bin/env bash
set -uo pipefail
OUT=/opt/soc/trivy-reports/$(date +%F); mkdir -p "$OUT"; chmod 755 /opt/soc/trivy-reports "$OUT"
rc=0
for img in $(docker ps --format '{{.Image}}' | sort -u); do
  f=$(printf %s "$img" | tr -c 'A-Za-z0-9._-' '_').json
  if docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro -v /opt/soc/trivy-cache:/root/.cache/trivy \
      aquasec/trivy:0.76.2 image --quiet --scanners vuln --format json "$img" > "$OUT/.$f"; then
    chmod 644 "$OUT/.$f"; mv "$OUT/.$f" "$OUT/$f"
  else rm -f "$OUT/.$f"; echo "scan failed: $img" >&2; rc=1; fi
done
find /opt/soc/trivy-reports -mindepth 1 -maxdepth 1 -type d -mtime +30 -exec rm -rf {} +
exit $rc
SH
chmod 755 /opt/soc/bin/trivy-scan.sh && /opt/soc/bin/trivy-scan.sh
echo "30 3 * * * $USER /opt/soc/bin/trivy-scan.sh 2>&1 | logger -t trivy-scan" | sudo tee /etc/cron.d/trivy-scan
```

**Check:** `ls /opt/soc/trivy-reports/*/*.json` lists one file per image.

## 7. SocBridge

Follow [socbridge.md](socbridge.md), with this override file in its step 4:

```yaml
services:
  socbridge:
    environment:
      PUBLIC_URL: https://socbridge.example.com:8443
    volumes:
      - /opt/soc/trivy-reports:/reports/trivy:ro
    networks: { default: {}, soc: {} }
networks:
  soc: { external: true }
```

In its step 7 the user enters these values. Passwords are in
`/opt/soc/secrets/stack.env`; they should read them there, not through you.

| Backend | Setting | Value |
|---|---|---|
| Wazuh | Manager API URL | `https://wazuh.manager:55000` |
| | Manager API user / password | `socbridge` / `WAZUH_SB_API_PW` |
| | Indexer URL | `https://wazuh.indexer:9200` |
| | Indexer user / password | `socbridge` / `WAZUH_SB_INDEXER_PW` |
| | Verify TLS | on |
| | CA certificate | contents of `/opt/soc/wazuh/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem` (not secret; read with `sudo cat`) |
| Graylog | URL / Access token | `http://graylog:9000` / from step 4 |
| DefectDojo | URL / API v2 key | `http://defectdojo:8080` / from step 5 |
| Trivy | Report directory | `/reports/trivy` |
| Threat intel | | just enable |

**Check:** all five pass *Test connection*.

## 8. Report to the user

List what runs (`docker ps`), where secrets are, what is still **[HUMAN]**, and
what they must back up: `/opt/soc/secrets`, `/opt/soc/socbridge/secrets` and the
Docker volumes. Anything that failed or was skipped goes at the top.
