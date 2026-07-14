# Secrets: `SECRETS_BACKEND=env` vs `vault`

The gateway authenticates to IBM Verify's `/oauth2/token` endpoint with **two
OAuth client secrets**:

| Secret | Used for | When |
| --- | --- | --- |
| Token-Exchange app `client_secret` | every RFC 8693 exchange (and the leg-2 `jwt_bearer` after MFA) | always |
| Agent app `client_secret` | the actor `client_credentials` grant | only when `AUTH_METHOD=verify` |

`SECRETS_BACKEND` decides **where those two secrets are read from**. Everything
else about the gateway is unchanged between the two modes - the token-exchange
and pipeline code go through one seam (`gateway/src/auth/secrets.ts`) and never
read a secret directly.

> `SECRETS_BACKEND` scopes **only** these two Verify client secrets. Vault is
> still used regardless for the verify-rar ephemeral Postgres credential (the
> OBO is presented as `X-Vault-Token`) and, under `AUTH_METHOD=spiffe`, for the
> actor JWT-SVID. "env mode" does **not** mean "no Vault".

## What an attacker gets in each posture

| | `SECRETS_BACKEND=env` (default) | `SECRETS_BACKEND=vault` (recommended) |
| --- | --- | --- |
| Where the secret lives | plaintext in `GATEWAY_EXCHANGE_CLIENT_SECRET` / `GATEWAY_AGENT_CLIENT_SECRET` (process env, your `.env`, your process manager's unit file) | in Vault; the gateway reads it live from the IBM Verify plugin role `ibm-verify/creds/<role>` |
| On disk / in `ps -Eww` / in a config-store leak | the long-lived client secret, usable until you manually rotate it in Verify | nothing - no client secret is stored by the gateway |
| Rotation | manual: rotate in Verify, then update the env var and restart | automatic: the plugin **rotates `client_secret` on every read**; a leaked value is stale almost immediately |
| Blast radius of a stolen value | full Verify client auth until manual rotation | one read window; the next read has already rotated it |
| Extra infrastructure | none - drop-in for local evaluation | Vault + the IBM Verify secrets-engine plugin, AppRole/SPIFFE for the gateway to authenticate to Vault |

**Use `env` only for local evaluation.** It is the zero-infrastructure path so
you can see the gateway working before you stand up Vault. For anything shared
or production-facing, use `vault`: it keeps the client secret off disk and
turns a leak into a near-non-event.

## `env` mode (default)

```bash
SECRETS_BACKEND=env
GATEWAY_EXCHANGE_CLIENT_SECRET=<the exchange app client_secret>
# only if AUTH_METHOD=verify:
GATEWAY_AGENT_CLIENT_SECRET=<the agent app client_secret>
```

- A missing required var fails fast with a named `MissingSecretError` naming the
  exact variable - e.g. `GATEWAY_EXCHANGE_CLIENT_SECRET is not set. ... switch
  to SECRETS_BACKEND=vault`.
- `invalidate*()` is a **no-op**: a static env value never rotates, so the
  stale-secret retry ladder (below) simply re-reads the same value. Harmless -
  the retry can't help a static secret, but it also can't loop.

## `vault` mode

```bash
SECRETS_BACKEND=vault
GATEWAY_EXCHANGE_ROLE=gateway-exchange   # ibm-verify plugin role for the TE app secret
GATEWAY_AGENT_ROLE=gateway-agent         # ibm-verify plugin role for the agent app secret
```

The gateway reads `ibm-verify/creds/<role>` through the existing
`auth/vault-secret.ts` machinery (1-hour cache, narrow per-role invalidation).
This mode requires the gateway to be able to authenticate to Vault - the
AppRole/SPIFFE bootstrap vars (`GATEWAY_APPROLE_ROLE_ID` / `_SECRET_ID`,
`GATEWAY_SPIFFE_*`) apply here.

## Migrating `env` → `vault`

1. **Store each secret in the IBM Verify Vault plugin.** The plugin owns the
   client credential and rotates it on read; you register the app once, then
   read through a role. Sketch (exact plugin verbs per your `bootstrap/`):

   ```bash
   # Register the exchange app's OAuth client with the ibm-verify plugin…
   vault write ibm-verify/apps/gateway-exchange \
       client_id="$GATEWAY_EXCHANGE_CLIENT_ID" \
       client_secret="$GATEWAY_EXCHANGE_CLIENT_SECRET"
   # …and expose it as a role the gateway reads (rotates client_secret on read):
   vault write ibm-verify/roles/gateway-exchange app=gateway-exchange

   # Repeat for the agent app if AUTH_METHOD=verify:
   vault write ibm-verify/apps/gateway-agent \
       client_id="$GATEWAY_AGENT_CLIENT_ID" \
       client_secret="$GATEWAY_AGENT_CLIENT_SECRET"
   vault write ibm-verify/roles/gateway-agent app=gateway-agent
   ```

   If you are keeping secrets in Vault KV instead of the rotating plugin (a
   weaker posture - no rotation), it is simply:

   ```bash
   vault kv put secret/gateway/exchange client_secret="$GATEWAY_EXCHANGE_CLIENT_SECRET"
   ```

   but the plugin path above is the recommended one and is what the seam's
   `vault` mode reads.

2. **Flip the backend and drop the plaintext:**

   ```bash
   SECRETS_BACKEND=vault
   GATEWAY_EXCHANGE_ROLE=gateway-exchange
   GATEWAY_AGENT_ROLE=gateway-agent
   # remove GATEWAY_EXCHANGE_CLIENT_SECRET / GATEWAY_AGENT_CLIENT_SECRET
   ```

3. **Rotate in Verify** so any value that was ever in a plaintext env var is
   dead, then restart the gateway. From here the plugin re-rotates on every
   read.

## The rotation story (why the single-retry cache pattern exists)

In `vault` mode the IBM Verify plugin **rotates the `client_secret` on every
read**. The gateway caches the current value (1 hour) so it isn't reading Vault
on every request - but a rotation performed by another process, or the plugin's
own eventual-consistency window on Verify's token endpoint, can leave that cache
briefly stale. When Verify answers a token call with a stale-secret signal
(HTTP 401, `invalid_client`, or `CSIAQ0155E` in the body) the gateway:

1. invalidates **only that role's** cache entry (never a global flush - a
   global flush would cascade errors onto every concurrent caller),
2. reads a fresh secret,
3. retries the token call **once** - no sleep, no "waiting Ns for propagation".

Both legs of the flow use this: leg-1 in `auth/token-exchange.ts`, and leg-2
(`jwt_bearer` after MFA approval) in `pipeline.ts`'s `completePending`. In
`env` mode the same code runs, but `invalidate*()` is a no-op and the re-read
returns the same static value - correct behaviour for a secret that doesn't
rotate.
