# Quickstart

Get the whole chain running end-to-end, then prove it with two curls. Budget ~15 minutes the
first time (most of it is filling in Verify + Vault values). The
[README quickstart](../../README.md#5-minute-quickstart) is the condensed version; this is the one
with the *why* and the troubleshooting.

## What is local vs. external

`docker compose up` stands up the **local** pieces only:

| Service | Port (loopback) | What it is |
|---|---|---|
| `postgres` | 5432 | The seeded `records` database + roles (applied from `examples/db/*.sql`). |
| `naive-mcp` | 3015 | The deliberately insecure example MCP - works fully on its own. |
| `gateway` | 3014 | The gateway. Serves `/healthz` and proxies to `naive-mcp`. |

The gateway's security chain calls **two systems compose does not create**: your **IBM Verify
tenant** (token exchange + policy) and a **HashiCorp Vault** with the `verify-rar` plugin
(ephemeral DB creds). So:

- `docker compose up` **alone** → the naive MCP works; the gateway is healthy, but a *secured* tool
  call needs Verify + Vault.
- `docker compose up` **+ the bootstrap scripts** pointed at your tenant + Vault → the full secured
  chain.

This is stated plainly in the [compose header](../../docker-compose.yml) too. See
[requirements & licensing](../../README.md#requirements--licensing) for the one licensed component
(Vault's OAuth-RS/SPIFFE features).

## Step 1 - install

```bash
git clone <this-repo> && cd mcp-gateway-verify-vault
npm install                     # installs the gateway, examples, and bootstrap workspaces
```

## Step 2 - configure `.env`

```bash
cp .env.example .env
```

Fill in, at minimum:

- `VERIFY_TENANT_URL` - your tenant base URL.
- `GATEWAY_EXCHANGE_CLIENT_ID` - printed by `bootstrap:verify` (Step 3), so you may run bootstrap
  first and paste it back.
- `GATEWAY_EXCHANGE_CLIENT_SECRET` - in `env` mode (the default). Or set `SECRETS_BACKEND=vault`
  and skip it ([secrets guide](secrets.md)).
- `VAULT_ADDR` - your Vault address.
- The `bootstrap:*` admin credentials (`VERIFY_ADMIN_CLIENT_ID/SECRET`, `VAULT_TOKEN`) - used only
  by the scripts, never by the running gateway.

Every variable is documented in the [configuration reference](../reference/configuration.md).

## Step 3 - bootstrap the trust (idempotent)

These create, on **your** tenant and **your** Vault, exactly what the chain needs - all generated
from `gateway/config/{tools,rar}.json`, so they can never drift from what the gateway sends. Full
run order and rollback: [bootstrap/README.md](../../bootstrap/README.md).

```bash
npm run bootstrap:verify        # 3 OIDC apps + CELX attributes + access policy, bound to the TE app
#   → prints GATEWAY_EXCHANGE_CLIENT_ID / GATEWAY_AGENT_CLIENT_ID + the values bootstrap:vault needs

npm run bootstrap:vault         # verify-rar roles + runtime policy + the two OAuth-RS entities
```

`bootstrap:verify` runs an **entitlement preflight** first: it probes each admin API family and
**fails naming the missing entitlement** if your admin client is under-provisioned, so a
half-configured tenant is impossible. The exact least-privilege floor is
[verify-api-entitlements.md](../reference/verify-api-entitlements.md).

## Step 4 - bring up the stack

```bash
docker compose up --build
```

Compose applies `examples/db/{schema,seed,naive-admin-role,vault-roles}.sql` automatically. For an
**external** Postgres, apply them yourself in that order (see the
[bootstrap README](../../bootstrap/README.md), Step 3) - the `verify-rar` DB connection user must
hold `records_read` + `records_write` **WITH ADMIN OPTION** so it can re-grant them to each
ephemeral user.

Sanity check:

```bash
curl -sS localhost:3014/healthz        # → {"status":"ok"}
```

## Step 5 - prove it, two curls

You need a **user access token** - a normal access token from an OIDC login on your tenant (the
RFC 8693 subject token). Two ways to grab one, from the [smoke script header](../../bootstrap/smoke.ts):

- **Browser devtools** - sign in to your UI, open Network, copy the `Authorization: Bearer …` value
  off any request the UI sends to the gateway.
- **ROPC** - only if you enabled the password grant on the UI app (off by default):
  ```bash
  curl -s -X POST "$VERIFY_TENANT_URL/v1.0/endpoint/default/token" \
    -d grant_type=password -d username=<u> -d password=<p> \
    -d client_id=<ui_client_id> -d client_secret=<ui_secret> \
    -d scope="openid records:read records:write" | jq -r .access_token
  ```

The token must belong to a user with a registered **push factor**, or the elevated step-up cannot
park a real challenge.

**A - a routine read.** Public `REC-1001` returns the row *and* the ephemeral cred that fetched it:

```bash
curl -sS -X POST localhost:3014/tool \
  -H "Authorization: Bearer <user-access-token>" \
  -H 'Content-Type: application/json' \
  -d '{"name":"get_record","arguments":{"recordId":"REC-1001"}}'
```
```jsonc
// 200
{ "ok": true,
  "data": { "record_id": "REC-1001", "display_name": "Dana Reyes", "classification": "public", "...": "..." },
  "_diagnostic": { "oboJti": "…", "cred": { "username": "v-token-records-…", "path": "verify-rar/creds/records" } } }
```

**B - a step-up read.** Restricted `REC-9001` returns `202 pending` with a push to your phone. **The
caller never requested elevation** - the gateway [derived it](../concepts/human-in-the-loop.md):

```bash
curl -sS -X POST localhost:3014/tool \
  -H "Authorization: Bearer <user-access-token>" \
  -H 'Content-Type: application/json' \
  -d '{"name":"get_record","arguments":{"recordId":"REC-9001"}}'
# → 202 { "ok": false, "pending": true, "txId": "…", "pushInfo": { "title": "…", "message": "…" } }
```

Approve the push, then resume with the **same bearer**:

```bash
curl -sS -X POST localhost:3014/hitl/complete \
  -H "Authorization: Bearer <user-access-token>" \
  -H 'Content-Type: application/json' -d '{"txId":"<from above>"}'
# → 200 { "ok": true, "data": { …restricted record… }, "_diagnostic": { "cred": { "path": "verify-rar/creds/records-elevated" } } }
```

## Step 6 - the automated proof

```bash
GATEWAY_URL=http://127.0.0.1:3014 \
SMOKE_SUBJECT_TOKEN=<user-access-token> \
npm run smoke
```

`smoke` asserts, positive **and** negative: tier-1 read → `200` + real OBO/cred; restricted read →
`202 pending` + `txId`; tier-4 delete → `403` *before Verify is contacted*; unknown tool → `403`. It
exits non-zero on any failure.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `401 { "error": "missing_bearer" }` | No `Authorization` header. | Every user route is bearer-gated; add `-H "Authorization: Bearer …"`. |
| `401 { "ok": false, "error": "inactive_session" }` | Introspection failed - expired token, or the gateway can't reach Verify (fail-closed). | Refresh the token; confirm `VERIFY_TENANT_URL` and network reachability. |
| `200` but `_diagnostic: {}` | The call did not go through exchange+mint. | You're likely looking at a denied/killed result - check `ok`/`denied`. See [observability](../concepts/observability.md). |
| Restricted record returns `200` immediately (no push) | `shouldStepUp` isn't finding `classification` - usually the upstream envelope shape. | Confirm the naive MCP returns the record inside `content[0].text`; check `config/rar.json → stepUp.elevateWhen`. |
| `403 denied` on a tool you expected to work | It's tier 4 (blocked) or an unknown tool name. | Check `config/tools.json`; see [add a tool](add-a-tool.md). |
| Step-up push never arrives | The user has no registered push factor, or policy didn't fire `mfa_challenge`. | Register a push factor; verify the access policy is ACTIVE/fedSSO and bound to the TE app ([step-up policies](step-up-policies.md)). |
| `CSIAQ0155E` / `invalid_client` in logs, one retry, then fine | Verify Vault plugin rotated the client secret on read; the cache was briefly stale. | Expected - the single narrow-invalidation retry handles it. A "waiting Ns for propagation" log line would be the bug. |
| Session-kill "fires" but sessions live | CAEP payload shape wrong - the transmitter 201s and drops it. | `sub_id` top-level, `event_timestamp` in epoch **seconds**. See [session kill](session-kill.md). |

The full error ladder - with the exact codes and the reasoning behind each - is
[troubleshooting.md](../reference/troubleshooting.md).

## Testing (offline)

The whole suite runs with **zero network** - dependency injection everywhere lets tests drive the
full pipeline with mocked Verify/Vault/upstream responses and deterministic clocks/ids.

```bash
npm test           # vitest run across all workspaces
npm run typecheck  # strict tsc --noEmit
npm run lint:words # the customer-shareable forbidden-words scan CI enforces
```
