# Configuration reference

Every environment variable, grouped by component, with its default and which mode requires it.
Runtime config is entirely environment-driven - copy [`.env.example`](../../.env.example) to `.env`
(gitignored) and fill it in. The gateway binds `127.0.0.1:PORT`; put a tunnel/ingress in front if it
must be public, and remember a [tunnel is not a security layer](../concepts/architecture.md#two-mcp-faces).

**"Required in which mode" legend:** _always_ · _env_ (`SECRETS_BACKEND=env`) · _vault_
(`SECRETS_BACKEND=vault`) · _spiffe_ (`AUTH_METHOD=spiffe`) · _verify_ (`AUTH_METHOD=verify`) ·
_bootstrap_ (only the `bootstrap/` scripts, never the running gateway) · _optional_.

## Gateway host

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `PORT` | `3014` | optional | North-face listen port (binds `127.0.0.1`). |
| `GATEWAY_SERVICE_NAME` | `mcp-gateway` | optional | Log prefixes, audit `actChain` actor, MCP server identity, dashboard event `source`. Override when running multiple gateways. |

## Secrets backend (`SECRETS_BACKEND`)

Selects where the **two Verify client secrets** (Token-Exchange app, always; agent app, verify-mode)
are read from. Scopes *only* those two secrets - Vault is used regardless for ephemeral DB creds and
(spiffe-mode) the actor SVID. Full treatment: [secrets guide](../guides/secrets.md).

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `SECRETS_BACKEND` | `env` | optional | `env` (plaintext from the vars below) or `vault` (rotating IBM Verify plugin roles). |
| `GATEWAY_EXCHANGE_CLIENT_SECRET` | *(empty)* | env | Token-Exchange app `client_secret`. Missing → named `MissingSecretError` at first exchange. |
| `GATEWAY_AGENT_CLIENT_SECRET` | *(empty)* | env **+** verify | Agent app `client_secret`. Only needed in env mode when `AUTH_METHOD=verify`. |
| `GATEWAY_EXCHANGE_ROLE` | `gateway-exchange` | vault | `ibm-verify` plugin role holding the rotating TE-app secret. |
| `GATEWAY_AGENT_ROLE` | `gateway-agent` | vault | `ibm-verify` plugin role for the agent-app secret. |

## IBM Verify tenant + OAuth clients

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `VERIFY_TENANT_URL` | `https://tenant.verify.ibm.com` | always | Your tenant base URL. Drives introspect, token exchange, factors, verifications; the SPIFFE actor audience is derived from its host. |
| `GATEWAY_EXCHANGE_CLIENT_ID` | *(empty)* | always | Token-Exchange app clientId (printed by `bootstrap:verify`). Its secret comes via `SECRETS_BACKEND`, never this line. |

## Agent actor identity (`AUTH_METHOD`)

How the gateway proves **its own** (actor) identity in the exchange.

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `AUTH_METHOD` | `spiffe` | optional | `spiffe` (Vault-native JWT-SVID) or `verify` (agent client-credentials grant). |
| `GATEWAY_ACTOR_TOKEN_TYPE` | `SPIFFE` | optional | `actor_token_type` sent for the SVID - must match the custom token type on the tenant. |
| `GATEWAY_AGENT_CLIENT_ID` | `0000…0000` | verify | Agent Identity OIDC app clientId (verify-mode actor). Secret via `SECRETS_BACKEND`. |

## HashiCorp Vault

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `VAULT_ADDR` | `http://127.0.0.1:8200` | always | Vault address (the OBO is POSTed here as `X-Vault-Token`). Also read as `VAULT_BASE_URI`. |
| `VAULT_KEY` | *(unset)* | optional | **Dev override** - used directly as the Vault client token, skipping the whole SPIFFE login. **Never set in a real deployment.** |
| `GATEWAY_APPROLE_ROLE_ID` | `__set_me__` | spiffe | AppRole role_id bootstrapping the workload identity (not secret, but deployment-specific). |
| `GATEWAY_APPROLE_SECRET_ID` | `__set_me__` | spiffe | AppRole secret_id (**secret** - local `.env` only). |
| `GATEWAY_SPIFFE_MINT_ROLE` | `mcp-gateway` | spiffe | Vault SPIFFE mint role (`/v1/spiffe/role/<role>/mintjwt`). |
| `GATEWAY_SPIFFE_AUTH_ROLE` | `mcp-gateway` | spiffe | Vault role on the native `auth/spiffe` login mount. |

## Upstream MCP server

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `UPSTREAM_MCP_URL` | `http://127.0.0.1:3015/mcp` | always | The unmodified MCP server the gateway fronts. The gateway injects `Authorization: Bearer <obo>` + `X-DB-Username`/`X-DB-Password` per call. **Swap seam #1** for [bring your own MCP](../guides/bring-your-own-mcp.md). |

## SSF/CAEP transmitter + events dashboard

Both optional, both about the [session kill](../guides/session-kill.md). The CAEP source is required
for the kill to actually happen; the dashboard is observability only.

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `ANTENNA_SOURCE_URL` | `https://localhost:9042/sources/agentic/events` | optional | CAEP source endpoint on the transmitter. `source_id` segment must match a configured source or the ingester 404s. |
| `WEBHOOK_URL` | `http://127.0.0.1:3003` | optional | Events-dashboard base URL. Kills are pushed to `<WEBHOOK_URL>/api/events`. |
| `WEBHOOK_API_KEY` | *(unset)* | optional | Enables the dashboard push. Unset → the push is skipped (local dev / tests). |

## Tunables (defaults shown; usually leave unset)

| Variable | Default | Purpose |
|---|---|---|
| `MFA_POLL_INTERVAL_MS` | `3000` | Step-up poll cadence. |
| `MFA_POLL_TIMEOUT_MS` | `120000` | Overall step-up poll timeout. |
| `HITL_PENDING_TTL_MS` | `130000` | TTL for a parked `mfa_challenge` transaction. |
| `SSF_KILLED_SESSION_TTL_MS` | `300000` | Local kill-gate TTL (covers the 30–75s transmitter→Verify revoke-propagation window). |

## Dev/test only

| Variable | Default | Purpose |
|---|---|---|
| `GATEWAY_ALLOW_TEST_VERDICT` | *(unset)* | When `1`, `POST /hitl/complete` honours a request-body `verdict` override so integration scripts can drive HITL without a phone. **Never enable outside local dev/CI** - see the [API reference](api.md#post-hitlcomplete). |

## Example stack (docker-compose)

Only used by the bundled example (`examples/naive-mcp` + `examples/db`). Your real upstream MCP +
database are configured however that server already is.

| Variable | Default | Purpose |
|---|---|---|
| `POSTGRES_PASSWORD` | `postgres_local_dev` | Postgres superuser password for the compose DB. |
| `NAIVE_PG_HOST` / `NAIVE_PG_PORT` / `NAIVE_PG_DB` | `127.0.0.1` / `5432` / `records` | The example naive MCP's DB connection. |
| `NAIVE_PG_USER` / `NAIVE_PG_PASSWORD` | `naive_admin` / `naive_admin_local_dev` | The naive MCP's static admin login (the control-condition credential the gateway replaces). |

## Bootstrap-only variables

Read **only** by the `bootstrap/` scripts, never by the running gateway. Full run order:
[bootstrap/README.md](../../bootstrap/README.md).

### `bootstrap:verify`

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `VERIFY_ADMIN_CLIENT_ID` | *(empty)* | bootstrap | Admin API client (client_credentials) that manages apps/attributes/policies. See [entitlements](verify-api-entitlements.md). |
| `VERIFY_ADMIN_SECRET` | *(empty)* | bootstrap | Admin API client secret. |
| `VERIFY_IDENTITY_SOURCE_ID` | *(none)* | recommended | The identity source the UI login authenticates against. Without it, sign-in loops at Verify. |
| `VERIFY_LOGIN_THEME_ID` | *(none)* | optional | Branded login theme (`customization.themeId`). |
| `GATEWAY_APP_PREFIX` | `MCP Gateway` | optional | App display-name prefix. |
| `GATEWAY_UI_ORIGIN` | `http://localhost:5173` | optional | UI redirect URIs. |
| `GATEWAY_COMPANY_NAME` | `Example` | optional | SAML company name. |
| `GATEWAY_AGENT_ID_CLAIM` | `mcp-gateway-agent` | optional | Static `agent_id` claim stamped on every OBO = Vault SUBJECT `external_id` (one entity covers all users). Keep verify+vault in sync. |
| `GATEWAY_ACTOR_SPIFFE_SUB` | `spiffe://example.org/mcp-gateway` | optional | The `may_act` constraint + Vault ACTOR `external_id` (spiffe mode). |
| `GATEWAY_ACTOR_SUB` | *(empty)* | optional | ACTOR `external_id` in **verify** mode - set to the Agent Identity clientId instead of the SPIFFE sub. |

### `bootstrap:vault`

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `VAULT_TOKEN` | *(empty)* | bootstrap | A Vault token allowed to write verify-rar roles, ACL policies, and identity entities. |
| `VAULT_RAR_DB_NAME` | `records` | optional | `db_name` on the verify-rar roles (the Vault DB-secrets connection name). |
| `VERIFY_ISSUER` | `VERIFY_TENANT_URL` + `/oauth2` | optional | Entity-alias issuer (tracks the OBO's `iss`). |
| `VAULT_OAUTH_RS_MOUNT_ACCESSOR` | auto-looked-up | optional | The OAuth-RS auth mount accessor. Auto-resolved from `sys/auth` if unset. |
| `VAULT_RUNTIME_POLICY` | `records-gateway` | optional | Runtime ACL policy name attached to the subject + actor entities. |
| `GATEWAY_EXCHANGE_APP_ID` / `GATEWAY_AGENT_APP_ID` | *(empty)* | optional | Only for `bootstrap:vault --with-ibm-verify` (creates the plugin roles that rotate the TE/agent client secrets). |

### `smoke`

| Variable | Default | Required | Purpose |
|---|---|---|---|
| `GATEWAY_URL` | `http://127.0.0.1:3014` | optional | The running gateway's base URL. |
| `SMOKE_SUBJECT_TOKEN` | *(empty)* | smoke | A user access_token (the RFC 8693 subject token). See the [smoke header](../../bootstrap/smoke.ts) for how to obtain one. |
| `SMOKE_NONVIP_ID` / `SMOKE_VIP_ID` / `SMOKE_DELETE_ID` | `REC-1001` / `REC-9001` / `REC-1001` | optional | Override the seed ids the smoke test uses. |
