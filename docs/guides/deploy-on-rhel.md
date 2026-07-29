# Deploy the MCP Agent Gateway on RHEL 8 or 9

> Status: DRAFT. This gets a RHEL 8/9 admin from a fresh box to a running, DPoP-capable gateway sitting in front of an MCP server. Two parts of the data plane are licensed Vault features and are called out where they land.

You will end with three services: the gateway on `127.0.0.1:3014`, your upstream (or the bundled naive) MCP on `127.0.0.1:3015`, and, optionally, the demo UI. The gateway adds IBM Verify token exchange, RFC 9396 RAR, Vault verify-rar ephemeral Postgres credentials, SSF session-kill, and optional DPoP. Your MCP server changes not at all.

## Before you begin

Pick your topology. Path A is the fastest way to see it work. Path B is what you ship.

- Path A, local eval stack. podman brings up Postgres, the naive MCP, and the gateway in containers. Good for a first green run.
- Path B, production. The gateway runs under systemd in front of your own MCP and your own Postgres. This is the rest of the guide.

Two things are licensed Vault features, not standard OSS: the OAuth-Resource-Server profile (Step 6) and, only if you choose `AUTH_METHOD=spiffe`, the native Vault SPIFFE loop (skipped here). Everything else is standard.

Use `AUTH_METHOD=verify` for your first bring-up. The gateway presents the user's exchanged token straight to Vault as the Vault token for both the credential mint and the revoke, so verify mode needs no AppRole and no SPIFFE-to-Vault login. You can move to spiffe mode later.

## Step 1. Install Node 20

Do not trust the default AppStream stream. It is often 18 or lower, below the repo floor of Node 20.

```bash
sudo dnf module reset nodejs
sudo dnf module enable nodejs:20
sudo dnf install -y nodejs git jq
node -v   # expect v20.x or v22.x
```

If your minor has no nodejs:20 module, use the NodeSource RPM instead. Do not use nvm on the systemd path, since a per-user nvm is not on the service account's PATH.

## Step 2. Get the code and install on the host

Install a dedicated service account and put the app in `/opt`, not a home directory (that avoids systemd ProtectHome surprises later).

```bash
sudo useradd --system --home-dir /opt/mcp-gateway --shell /sbin/nologin mcpgw
sudo mkdir -p /opt/mcp-gateway
sudo chown mcpgw:mcpgw /opt/mcp-gateway
sudo -u mcpgw git clone <this-repo> /opt/mcp-gateway
cd /opt/mcp-gateway
sudo -u mcpgw npm ci
```

Run `npm ci` on the box. Never copy `node_modules` from a Mac. tsx pulls esbuild, whose native binary is per-platform, and the lockfile already records the linux binaries.

## Step 3. Build and register the verify-rar Vault plugin

Neither bootstrap script builds this. You do it once on the Vault host.

Install Go 1.25 or newer. The RHEL go-toolset may lag, so the upstream tarball is safest.

```bash
curl -sSLO https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.25.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version
```

Build a static linux binary. The driver is pure-Go lib/pq with CGO off, so there is nothing to compile against.

```bash
cd /path/to/vault-plugin-secrets-verify-rar
make build-linux            # writes bin/vault-plugin-secrets-verify-rar-linux-amd64
```

Place it in Vault's plugin directory on the Vault host and register it. Confirm `plugin_directory` is set in your Vault config HCL first.

```bash
sudo install -o vault -g vault -m 0755 \
  bin/vault-plugin-secrets-verify-rar-linux-amd64 \
  /opt/vault/plugins/vault-plugin-secrets-verify-rar

export VAULT_ADDR=https://your-vault:8200
export VAULT_TOKEN=<admin-token>
PLUGIN_SHA=$(sha256sum /opt/vault/plugins/vault-plugin-secrets-verify-rar | cut -d' ' -f1)
vault plugin register -sha256="$PLUGIN_SHA" secret vault-plugin-secrets-verify-rar
vault secrets enable -path=verify-rar vault-plugin-secrets-verify-rar
```

SELinux note. The HashiCorp Vault RPM commonly runs largely unconfined, so no relabel is needed. If you run Vault under a targeted policy, label the plugin directory so vault can exec it: `sudo semanage fcontext -a -t bin_t '/opt/vault/plugins(/.*)?' && sudo restorecon -Rv /opt/vault/plugins`.

## Step 4. Prepare Postgres

Order matters. Create the management login FIRST, because `vault-roles.sql` only grants ADMIN OPTION to `vault_rar_admin` if that role already exists.

```bash
# On a host that can reach Postgres, as a superuser:
psql "$ADMIN_DSN" -c "CREATE ROLE vault_rar_admin LOGIN CREATEROLE PASSWORD 'choose-a-strong-password';"

psql "$ADMIN_DSN" -f examples/db/schema.sql
psql "$ADMIN_DSN" -f examples/db/seed.sql
psql "$ADMIN_DSN" -f examples/db/naive-admin-role.sql
psql "$ADMIN_DSN" -f examples/db/vault-roles.sql
```

The `vault_rar_admin` login is the plugin's management connection user. It needs CREATEROLE to mint ephemeral users, and it must hold `records_read`, `records_read_elevated`, and `records_write` WITH ADMIN OPTION so it can re-grant them. The SQL above wires the grants once the role exists.

Reachability. Postgres must be reachable from two places: your upstream MCP host, and the Vault host (Vault connects to Postgres to mint users). Open the path and list both client hosts in `pg_hba.conf`. Prefer `sslmode=require`.

## Step 5. Configure the Vault data plane

Two writes and one activation. Do them before you run bootstrap:vault.

First, the Postgres connection. bootstrap:vault does NOT create this, and without it every mint fails.

```bash
vault write verify-rar/config/db \
  name=records \
  connection_url='postgresql://{{username}}:{{password}}@PGHOST:5432/records?sslmode=require' \
  username=vault_rar_admin \
  password='the-password-from-step-4' \
  allowed_roles='records,records-elevated,records-write'
```

Keep `name` equal to `VAULT_RAR_DB_NAME` (default `records`).

Second, activate the OAuth-Resource-Server profile. This is the licensed Vault feature that lets the gateway present the user's exchanged token directly as the Vault token. If it is not active, bootstrap:vault will run but silently SKIP the identity entities, and real tool calls will 403. The activation shape is `sys/activation-flags/.../activate` plus a `sys/config/oauth-resource-server/<id>` profile pointed at your Verify tenant JWKS. This recipe is licensed and is not shipped in this repo, so treat it as a required prerequisite and confirm the mount accessor and issuer match the tenant that issues the token. See Open Questions.

Actor identity. Stay with `AUTH_METHOD=verify`. In that mode the gateway authenticates its actor leg with the Agent OIDC app's client_credentials, and it needs no AppRole and no native SPIFFE engine. Set `GATEWAY_ACTOR_SUB` to the Agent app clientId so the Vault ACTOR entity matches.

## Step 6. Fill in .env

```bash
cp .env.example .env
sudo chown mcpgw:mcpgw .env
sudo chmod 600 .env
```

Set at least these, keeping every value plain `KEY=VALUE` with no surrounding quotes (systemd's EnvironmentFile is not a shell and does no unquoting or expansion):

```bash
VERIFY_TENANT_URL=https://your-tenant.verify.ibm.com
GATEWAY_EXCHANGE_CLIENT_ID=...            # printed by bootstrap:verify
GATEWAY_EXCHANGE_CLIENT_SECRET=...        # env mode, for first bring-up
SECRETS_BACKEND=env                       # move to vault before you ship (see below)
AUTH_METHOD=verify
GATEWAY_AGENT_CLIENT_ID=...               # the Agent OIDC app
GATEWAY_AGENT_CLIENT_SECRET=...
GATEWAY_ACTOR_SUB=<the Agent app clientId>
VAULT_ADDR=https://your-vault:8200
UPSTREAM_MCP_URL=http://127.0.0.1:3015/mcp
```

If Vault uses a private CA, the gateway's Node fetch must trust it. Add the CA to the system trust and point Node at it in the unit (Step 8): `NODE_EXTRA_CA_CERTS=/etc/pki/ca-trust/source/anchors/vault-ca.pem`.

Ship-time posture. `SECRETS_BACKEND=env` is local-eval only. Move to `SECRETS_BACKEND=vault` so the gateway reads the rotating client secret live and nothing sits on disk.

## Step 7. Bootstrap Verify then Vault, in that order

```bash
# Verify tenant: OIDC apps, CELX attributes, access policy.
VERIFY_TENANT_URL=https://your-tenant.verify.ibm.com \
VERIFY_ADMIN_CLIENT_ID=<admin-id> \
VERIFY_ADMIN_SECRET=<admin-secret> \
VERIFY_IDENTITY_SOURCE_ID=<source-id> \
npm run bootstrap:verify
# Paste the printed GATEWAY_EXCHANGE_CLIENT_ID (and secret) back into .env.

# Vault: verify-rar roles, runtime ACL policy, OAuth-RS subject and actor entities.
VAULT_ADDR=https://your-vault:8200 \
VAULT_TOKEN=<token-that-can-write-roles-policies-entities> \
VERIFY_TENANT_URL=https://your-tenant.verify.ibm.com \
GATEWAY_AGENT_ID_CLAIM=mcp-gateway-agent \
GATEWAY_ACTOR_SUB=<the Agent app clientId> \
npm run bootstrap:vault
```

bootstrap:verify runs an entitlement preflight and fails naming any missing admin entitlement, so a half-provisioned tenant is impossible. If bootstrap:vault warns that it skipped the OAuth-RS entities, your OAuth-RS profile from Step 5 is not active. Fix that and re-run. Both scripts are idempotent.

## Step 8. Run the gateway under systemd

Write three units. Use an absolute interpreter, never `npx tsx`, and set WorkingDirectory so any relative config path resolves.

`/etc/systemd/system/mcp-gateway.service`:

```ini
[Unit]
Description=MCP Agent Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mcpgw
WorkingDirectory=/opt/mcp-gateway/gateway
EnvironmentFile=/opt/mcp-gateway/.env
Environment=PORT=3014
Environment=NODE_EXTRA_CA_CERTS=/etc/pki/ca-trust/source/anchors/vault-ca.pem
ExecStart=/opt/mcp-gateway/gateway/node_modules/.bin/tsx src/index.ts
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

Write a matching `mcp-naive.service` for the upstream (WorkingDirectory `/opt/mcp-gateway/examples/naive-mcp`, ExecStart the same tsx pattern) if you use the bundled MCP. For your own MCP, run it however it already runs. Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mcp-naive mcp-gateway
sudo systemctl status mcp-gateway
journalctl -u mcp-gateway -f
```

The gateway binds `127.0.0.1:3014` by design, so it is not reachable off-box. Put a reverse proxy or tunnel in front of it for real traffic.

## Step 9. Alternative, the podman eval stack

For Path A only. RHEL ships podman, not docker.

```bash
sudo dnf install -y podman podman-compose
```

Two edits make the compose file RHEL-safe. First, SELinux. Add `,Z` to each Postgres init bind mount in `docker-compose.yml` (for example `.../schema.sql:/docker-entrypoint-initdb.d/01-schema.sql:ro,Z`), or run `chcon -Rt container_file_t examples/db` first. Without the relabel the container cannot read the SQL, the init scripts silently never run, and you get an empty database that looks healthy. Second, older podman-compose mis-parses the long-form `env_file` object and `depends_on: service_healthy`, so either simplify `env_file` to `env_file: [.env]` or pass `--env-file .env` on the CLI.

```bash
podman compose --env-file .env up --build
```

Rootless podman is fine here. Every port is above 1024 and the bindings are loopback.

## Step 10. SELinux and firewalld

Good news on the firewall. The gateway, the naive MCP, and Postgres all bind loopback, and firewalld never filters loopback, so the secured stack needs zero firewall changes. Open a port only when you expose something.

```bash
# Only if a 443 reverse proxy fronts the gateway or UI:
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

If you front the gateway with httpd, SELinux blocks httpd from reaching the loopback service until you allow it:

```bash
sudo setsebool -P httpd_can_network_connect 1
```

## Step 11. The demo UI, if you use it

The UI is a SvelteKit adapter-node app. Built, it runs `node build`, which binds `0.0.0.0:3000` and honors PORT, HOST, and ORIGIN. That breaks the OIDC redirect, because the gateway bootstrap registered `http://localhost:5173/api/oidc-callback`. Two ways to fix it.

- Keep the registered redirect. Serve on 5173 with a matching ORIGIN:

```bash
cd /opt/gateway-agent-demo
npm ci
npm run build
PORT=5173 ORIGIN=http://your-host:5173 node build
```

- Or re-run bootstrap:verify with `GATEWAY_UI_ORIGIN=https://your-real-origin` so the redirect_uri is registered for your real hostname.

Behind a TLS-terminating proxy also set `PROTOCOL_HEADER=x-forwarded-proto` and `HOST_HEADER=x-forwarded-host`, and open only the proxy's port. Keep adapter-node behind the proxy, not raw on the Internet.

## Step 12. Turn on DPoP, in stages

DPoP is off by default and `none` mode is byte-identical to not having it. Turn it on in stages, and get time sync in place first because proofs carry a timestamp with a five-minute window on both sides.

```bash
sudo systemctl enable --now chronyd
```

Stage 1, bind the OBOs. Re-run the Verify bootstrap with the flag, then restart the gateway in outbound mode.

```bash
ENABLE_DPOP=true npm run bootstrap:verify
# This PUT rotates ALL THREE client secrets: exchange, agent, and UI.
# Re-read them (GET /v1.0/applications/{id} -> providers.oidc.properties.clientSecret)
# and update GATEWAY_EXCHANGE_CLIENT_SECRET, GATEWAY_AGENT_CLIENT_SECRET, and the
# demo VERIFY_UI_CLIENT_SECRET, or use SECRETS_BACKEND=vault so nothing goes stale.
# Then set TOKEN_BINDING_MODE=outbound in .env and restart.
sudo systemctl restart mcp-gateway
npm run smoke:dpop
```

Stage 2 and 3, full mode. Full mode also requires caller-signed proofs, which means DPoP-binding the UI app (`ENABLE_DPOP=true ENABLE_DPOP_UI=true`) and a DPoP-capable client. Set `GATEWAY_PUBLIC_URL` to the exact host string your callers use, and make the client's base URL identical. `http://localhost:3014` and `http://127.0.0.1:3014` are different values and mismatch returns 401 on every call. Only move to full mode after `npm run smoke:dpop` passes both legs. If the host runs in FIPS mode, validate this path specifically before trusting it.

## Step 13. The two smoke checks

Check one, liveness:

```bash
curl -sS localhost:3014/healthz     # expect {"status":"ok"}
```

Check two, the end-to-end proof. Grab a user access token from an OIDC login on your tenant (browser devtools, copy the `Authorization: Bearer` value), then:

```bash
GATEWAY_URL=http://127.0.0.1:3014 \
SMOKE_SUBJECT_TOKEN=<user-access-token> \
npm run smoke
```

This asserts, positive and negative: a tier-1 read returns 200 with a real token and ephemeral cred in `_diagnostic`; a restricted read returns 202 pending with a txId; a tier-4 delete returns 403 before Verify is contacted; an unknown tool returns 403. The restricted-read assertion parks a real MFA challenge, so the smoke user needs a registered push factor to complete it. It exits non-zero on any failure.

## Quick troubleshooting

- 200 but `_diagnostic: {}`. The call did not go through exchange plus mint. You are likely looking at a denied or killed result. Check `ok` and `denied`.
- Every mint 500s. `verify-rar/config/db` is missing or `vault_rar_admin` lacks CREATEROLE or the ADMIN OPTION grants (Steps 4 and 5).
- bootstrap:vault warned it skipped entities. The OAuth-RS profile is not active. Real calls will 403 until you activate it.
- CSIAQ0155E or invalid_client, one retry, then fine. The Verify Vault plugin rotated the client secret on read. Expected. A "waiting Ns for propagation" log line would be the bug.
- Login redirect loop after a DPoP bootstrap. A stale UI client secret. Re-read and update it.
- Cannot reach Vault, TLS error. A private CA the Node process does not trust. Set NODE_EXTRA_CA_CERTS in the unit.