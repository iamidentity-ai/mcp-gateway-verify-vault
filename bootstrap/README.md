# `bootstrap/` - stand up the Verify + Vault trust the gateway needs

These idempotent scripts create, on **your** IBM Verify tenant and **your** HashiCorp
Vault, the exact apps / attributes / policy / roles / entities the gateway's security
chain depends on - all **generated from the gateway's own `gateway/config/{tools.json,
rar.json}`**, so they can never drift from what the gateway actually sends. This is what
makes the gateway drop-in: clone → fill `.env` → run these → the chain works.

Everything domain-specific (the `records` example - CELX action names, Postgres roles,
RAR type, scopes) is derived from those two config files. Retarget the gateway at a new
domain by editing `gateway/config/*.json`; re-run these scripts; done. No edits here.

## Run order

```bash
# 0. one-time: install the workspace
npm install

# 1. Verify tenant - apps, CELX attributes, access policy (idempotent)
VERIFY_TENANT_URL=https://your-tenant.verify.ibm.com \
VERIFY_ADMIN_CLIENT_ID=<admin-api-client-id> \
VERIFY_ADMIN_SECRET=<admin-api-client-secret> \
VERIFY_IDENTITY_SOURCE_ID=<your-identity-source-id> \
npm run bootstrap:verify
#   -> prints GATEWAY_EXCHANGE_CLIENT_ID / GATEWAY_AGENT_CLIENT_ID / the UI clientId,
#      plus GATEWAY_AGENT_ID_CLAIM + GATEWAY_ACTOR_SPIFFE_SUB to feed step 2.

# 2. Vault - verify-rar roles, runtime policy, OAuth-RS subject+actor entities
VAULT_ADDR=https://your-vault:8200 \
VAULT_TOKEN=<token-that-can-write-roles-policies-entities> \
VERIFY_TENANT_URL=https://your-tenant.verify.ibm.com \
GATEWAY_AGENT_ID_CLAIM=mcp-gateway-agent \
GATEWAY_ACTOR_SPIFFE_SUB=spiffe://example.org/mcp-gateway \
npm run bootstrap:vault
#   Add --with-ibm-verify to also create the ibm-verify plugin roles that rotate
#   the TE/agent client secrets (SECRETS_BACKEND=vault).

# 3. Database - the schema, seed rows, naive-admin login, and the pre-baked
#    NOLOGIN Postgres roles the verify-rar plugin grants. For the bundled local
#    stack, `docker compose up` (step 4) applies these automatically via the
#    postgres init dir. For an EXTERNAL Postgres, apply them yourself, in order:
psql "$DATABASE_URL" -f ../examples/db/schema.sql
psql "$DATABASE_URL" -f ../examples/db/seed.sql
psql "$DATABASE_URL" -f ../examples/db/naive-admin-role.sql
psql "$DATABASE_URL" -f ../examples/db/vault-roles.sql
#   IMPORTANT: the verify-rar plugin's DB connection user must hold records_read
#   + records_write WITH ADMIN OPTION so it can re-grant them to each ephemeral
#   user. (vault-roles.sql grants them to `vault_rar_admin` if that role exists.)

# 4. Bring up the stack (local example)
cp ../.env.example ../.env    # fill in the values printed by steps 1-2
docker compose -f ../docker-compose.yml up --build

# 5. Prove it end-to-end against the running gateway
GATEWAY_URL=http://127.0.0.1:3014 \
SMOKE_SUBJECT_TOKEN=<a user access_token from an OIDC login> \
npm run smoke
```

## `bootstrap:verify` - what it asks / what it creates

| Env | Required | Default | Notes |
|---|---|---|---|
| `VERIFY_TENANT_URL` | yes | - | `https://your-tenant.verify.ibm.com` |
| `VERIFY_ADMIN_CLIENT_ID` | yes | - | admin API client (client_credentials) |
| `VERIFY_ADMIN_SECRET` | yes | - | admin API client secret |
| `VERIFY_IDENTITY_SOURCE_ID` | recommended | *(none)* | without it the UI app has no login source and sign-in loops |
| `GATEWAY_APP_PREFIX` | no | `MCP Gateway` | app display-name prefix |
| `GATEWAY_UI_ORIGIN` | no | `http://localhost:5173` | UI redirect URIs |
| `GATEWAY_ACTOR_TOKEN_TYPE` | no | `SPIFFE` | custom actor token type name |
| `GATEWAY_AGENT_ID_CLAIM` | no | `mcp-gateway-agent` | static `agent_id` claim on every OBO (= Vault SUBJECT external_id) |
| `GATEWAY_ACTOR_SPIFFE_SUB` | no | `spiffe://example.org/mcp-gateway` | may_act constraint (= Vault ACTOR external_id) |
| `GATEWAY_COMPANY_NAME` | no | `Example` | SAML company name |
| `VERIFY_LOGIN_THEME_ID` | no | *(none)* | optional branded login theme |

**Creates:** an **entitlement preflight** first (probes each admin API family; on a `403`
it FAILS naming the missing entitlement, so a half-provisioned tenant is impossible),
then: a **Token Exchange app** (RFC 8693 + RFC 9396, `jwtBearer`+`tokenExchange`, the
`authz` RAR plumbing, `agent_id` claim, `records:read`/`records:write` scopes), an **Agent
Identity app** (client_credentials actor for `AUTH_METHOD=verify`), a **UI app** (OIDC
PKCE, `may_act`), the **4 CELX attributes** (id == name), and the **access policy** (DENY
→ MFA_ALWAYS → MFA_ALWAYS → MFA_PER_SESSION → ALLOW), **bound** to the TE app.
Prints every id + the exact `.env` lines to set. Re-run safe (GET-first, PUT full body).
`--rollback` deletes everything it creates, by name.

Client **secrets are not printed** - a GET rarely returns them and a PUT can regenerate
them. Get them from the Admin console, or (better) read them live via the Vault
`ibm-verify` plugin so nothing sits on disk.

## `bootstrap:vault` - what it asks / what it creates

| Env | Required | Default | Notes |
|---|---|---|---|
| `VAULT_ADDR` | no | `http://127.0.0.1:8200` | |
| `VAULT_TOKEN` | yes | - | must write verify-rar roles, ACL policies, identity entities |
| `VAULT_RAR_DB_NAME` | no | `records` | `db_name` on the verify-rar roles |
| `VERIFY_ISSUER` | no | derived from `VERIFY_TENANT_URL` + `/oauth2` | entity-alias issuer (tracks the OBO's `iss`) |
| `VAULT_OAUTH_RS_MOUNT_ACCESSOR` | no | auto-looked-up from `sys/auth` | the OAuth-RS auth mount accessor |
| `GATEWAY_AGENT_ID_CLAIM` | no | `mcp-gateway-agent` | SUBJECT external_id (from step 1) |
| `GATEWAY_ACTOR_SUB` / `GATEWAY_ACTOR_SPIFFE_SUB` | no | `spiffe://example.org/mcp-gateway` | ACTOR external_id (from step 1) |
| `VAULT_RUNTIME_POLICY` | no | `records-gateway` | ACL policy name |
| `--with-ibm-verify` flag | no | off | also create the `ibm-verify` plugin roles (needs `GATEWAY_EXCHANGE_APP_ID`/`_CLIENT_ID` + `GATEWAY_AGENT_APP_ID`/`_CLIENT_ID`) |

**Creates:** one **verify-rar role** per non-blocked creds path (`records`, `records-elevated`,
`records-write`) with `rar_mappings` keyed `<rarType>|<action>` → GRANT the matching
Postgres role, 5-min lease; a **runtime ACL policy** (read+update on every
`verify-rar/creds/*` + `sys/leases/revoke`); and the **two OAuth-RS entities** the OBO
resolves against - SUBJECT (external_id = `agent_id` claim, so one entity covers all
users) and ACTOR (external_id = the OBO `act.sub`), both attached to the runtime policy and
registered in agent-registry. `external_id` + `issuer` are **immutable** after creation -
an existing alias is left as-is (change = delete + re-run).

The Vault-native SPIFFE issuer/validator loop that mints the gateway's actor SVID in
`AUTH_METHOD=spiffe` is a distinct, licensed Vault feature and is **not** provisioned here
- see the SPIFFE block in `.env.example` and `docs/guides/`.

## `smoke` - what it proves

Runs against a **running** gateway with `GATEWAY_URL` + `SMOKE_SUBJECT_TOKEN` (a user
access_token - see the script header for how to grab one from browser devtools or ROPC).
Asserts, positive **and** negative, exiting non-zero on any failure:

1. **Tier-1 read** on a public id → `200 ok` + a real OBO + ephemeral cred in `_diagnostic`.
2. **Restricted read** → `202 pending` + a `txId` (the gateway forces a step-up the agent can't
   skip; approve the push on your phone, then `POST /hitl/complete {txId}` to finish).
3. **Tier-4 delete** → `403 denied` before Verify is ever contacted.
4. **Unknown tool** → `403 denied` (`unknown_tool`).
