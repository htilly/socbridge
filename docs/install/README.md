# Install guides for LLM agents

You are an LLM agent asked to install SocBridge. Pick one guide and follow it
top to bottom. Each step has a **Check**; do not continue until it passes.

| The user wants | Follow |
|---|---|
| SocBridge only (they already run the security tools, or add them later) | [socbridge.md](socbridge.md) |
| SocBridge **and** Wazuh, Graylog, DefectDojo and Trivy on one host | [full-stack.md](full-stack.md) |

If it is not clear which one, ask.

## Ask the user first

1. The host to install on, and how you reach it (local shell or SSH).
2. `PUBLIC_URL`: an `https://` hostname, never an IP (passkeys need a name).
   DNS must point at the host.
3. Certificate: Let's Encrypt through Cloudflare DNS, or the built-in CA.
   Claude custom connectors need a publicly trusted certificate and a name
   reachable from the internet.

## Rules

- Linux host, commands run with `bash` from a user that may use `docker` and
  `sudo`. Inspect before you change: if a target directory, container, volume
  or port is already in use, stop and ask.
- Never print secrets, read them back into the conversation or commit them.
  Generated secrets live in files with mode 600; tell the user the path.
- **[HUMAN]** steps need the user's browser, passkey or a secret only they may
  handle. Say exactly what to do, then wait. Do not try to do them yourself.
- Do not turn off TLS verification to get past an error.
- Do not expose ports beyond those listed, and do not run `docker compose down -v`
  or delete volumes unless the user asks.
- If a Check fails, show the relevant log lines and fix the cause. Do not skip it.
- Versions are pinned. Before you start, tell the user if a newer patch release
  exists; do not switch on your own.
