# Phase 0 wire-check - the "everything" server, no Vault

Before you point the gateway at a real database-backed MCP, prove the two hardest
parts in isolation: **the MCP transport works**, and **the no-DB security chain
runs end to end** - introspect -> tier gate -> Token Exchange + RAR -> HITL
step-up -> SSF -> audit - with **zero Vault** and **zero credentials on the
upstream**. This is the Phase 0 wire-check.

It fronts the reference
[`@modelcontextprotocol/server-everything`](https://www.npmjs.com/package/@modelcontextprotocol/server-everything),
a stock MCP server with no database, using the ready-made config in
[`examples/upstreams/everything/`](../../examples/upstreams/everything/) and
`UPSTREAM_DB_BACKED=false`. Because that upstream has no database, the Vault
ephemeral-credential leg is skipped entirely: you need a Verify tenant, but **no
Vault**.

## What you need

- An IBM Verify tenant (`VERIFY_TENANT_URL`) and admin credentials for the
  bootstrap (`VERIFY_ADMIN_CLIENT_ID` / `VERIFY_ADMIN_SECRET`).
- A user on that tenant with a registered **push factor** (for the optional
  tier-2 step-up in step 6).
- Node 20+. No Vault, no Postgres, no Docker.

## Step 1 - start the everything server

```bash
npx -y @modelcontextprotocol/server-everything streamableHttp
```

Note the port it prints (commonly `3001`). Its MCP endpoint is
`http://localhost:<port>/mcp`.

## Step 2 - point the gateway at the everything config

In the gateway `.env` (repo root):

```bash
VERIFY_TENANT_URL=https://your-tenant.verify.ibm.com
GATEWAY_EXCHANGE_CLIENT_ID=...            # printed by bootstrap:verify (step 3)
GATEWAY_EXCHANGE_CLIENT_SECRET=...        # printed by bootstrap:verify (env mode)

UPSTREAM_MCP_URL=http://localhost:<port>/mcp
GATEWAY_CONFIG_DIR=examples/upstreams/everything
UPSTREAM_DB_BACKED=false
```

`GATEWAY_CONFIG_DIR` makes BOTH the gateway runtime AND the bootstrap load
`tools.json` + `rar.json` from `examples/upstreams/everything/` instead of the
shipped `records` config, so they cannot diverge. A relative path resolves from
the process working directory - run the gateway and the bootstrap from the repo
root, or use an absolute path. `UPSTREAM_DB_BACKED=false` skips the Vault
mint/revoke leg and the `X-DB-*` headers; the everything config's actions carry
no `credsPath`, which is valid ONLY in this no-DB mode (see the fixture
[README](../../examples/upstreams/everything/README.md)).

The two tools this config secures:

| Tool | Tier | RAR action | Enforcement |
|---|---|---|---|
| `echo` | 1 (read) | `everything_read` | Token Exchange only, no step-up. |
| `printEnv` | 2 (write) | `everything_write` | Token Exchange + RAR; one policy push. |

## Step 3 - bootstrap Verify (no Vault)

With `GATEWAY_CONFIG_DIR` set, this generates the Token-Exchange app, the CELX
attributes, and the access policy for the `everything_read` / `everything_write`
actions - not the `records` ones:

```bash
npm run bootstrap:verify
```

It prints `GATEWAY_EXCHANGE_CLIENT_ID` / `GATEWAY_EXCHANGE_CLIENT_SECRET` - paste
them back into `.env`. **Do not run `bootstrap:vault`**: there is no Vault leg in
a no-DB wire-check.

## Step 4 - start the gateway and get a user token

```bash
cd gateway && npm run dev        # serves 127.0.0.1:3014
```

Grab a **user access token** - a normal access token from an OIDC login on your
tenant (the RFC 8693 subject token). The fastest way is browser devtools: sign in
to any UI app on the tenant, open Network, copy the `Authorization: Bearer ...`
value. (Full details in the [quickstart, step 5](quickstart.md#step-5---prove-it-two-curls).)

```bash
TOK=<user-access-token>
```

## Step 5 - call a tier-1 read (`echo`)

```bash
curl -sS -X POST localhost:3014/tool \
  -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"name":"echo","arguments":{"message":"hello"}}'
```

Expect `200` with the echoed text, and a `_diagnostic` that carries the OBO
correlation (`oboJti`, `oboScope`) but **no `cred`** - there is no database, so
no ephemeral credential was minted:

```jsonc
// 200
{ "ok": true,
  "data": { "content": [ { "type": "text", "text": "Echo: hello" } ] },
  "_diagnostic": { "oboJti": "...", "oboScope": "everything:read" } }   // NO cred key
}
```

A `_diagnostic` with `oboJti`/`oboScope` and no `cred` is the correct no-DB
shape. There is **no Vault call anywhere** in this path - confirm it in the
gateway log (no `mint` / `verify-rar` lines).

## Step 6 - (optional) trigger the tier-2 step-up (`printEnv`)

`printEnv` is tier 2, so the access policy fires an MFA push:

```bash
curl -sS -X POST localhost:3014/tool \
  -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"name":"printEnv","arguments":{}}'
# -> 202 { "ok": false, "pending": true, "txId": "...", "pushInfo": { ... } }
```

Approve the push on your phone, then resume with the **same bearer**:

```bash
curl -sS -X POST localhost:3014/hitl/complete \
  -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"txId":"<from above>"}'
# -> 200 { "ok": true, "data": { ... }, "_diagnostic": { "oboScope": "everything:write" } }   // still NO cred
```

## What this proves

With zero Vault and zero credentials on the upstream, you have exercised:

- **the transport** - the gateway speaks the MCP Streamable HTTP protocol to a
  stock, unmodified upstream it has never seen;
- **the full no-DB chain** - introspect -> tier gate -> RFC 8693 Token Exchange
  + RFC 9396 RAR -> HITL step-up (tier 2) -> SSF kill-gate -> audit, every step
  running exactly as it does in a DB-backed deployment, minus the one leg (Vault
  mint/revoke + `X-DB-*` headers) that a non-database upstream does not need.

That is the honest smallest proof that the gateway's security core is upstream-
and database-agnostic. Once it is green, swapping to your real database-backed
MCP is `GATEWAY_CONFIG_DIR` -> your domain's config, `UPSTREAM_DB_BACKED=true`,
and `bootstrap:vault` - covered in [bring your own MCP](bring-your-own-mcp.md).
