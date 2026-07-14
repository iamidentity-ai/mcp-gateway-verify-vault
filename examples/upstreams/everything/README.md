# Upstream config: the reference "everything" server (Phase 0 wire-check)

This directory is a ready-made `GATEWAY_CONFIG_DIR` for putting the gateway in
front of the reference MCP server
[`@modelcontextprotocol/server-everything`](https://www.npmjs.com/package/@modelcontextprotocol/server-everything).
It is the **Phase 0 wire-check** config: the smallest possible setup that proves
the gateway's transport plus its NO-DB security chain end to end, with **zero
Vault** and **zero credentials on the upstream**.

Use it by pointing the gateway (and its bootstrap) at this directory and
declaring the upstream is not database-backed:

```bash
GATEWAY_CONFIG_DIR=examples/upstreams/everything UPSTREAM_DB_BACKED=false
```

The full step-by-step is [docs/guides/wire-check.md](../../../docs/guides/wire-check.md).

## Why it is NO-DB

The everything server has no database, so there is no Vault ephemeral-credential
leg to point a creds path at. Both actions therefore carry **no `credsPath`**:

| Tool | Tier | RAR action | Notes |
|---|---|---|---|
| `echo` | 1 (read) | `everything_read` (`default: true`) | Token Exchange only, no step-up. |
| `printEnv` | 2 (write) | `everything_write` | Token Exchange + RAR; one policy-driven push. |

Because these actions have **no `credsPath`**, `rar.json` here is valid ONLY
under the no-DB parse rule, i.e. `parseRarConfig(raw, { requireCredsPath: false })`
- which is exactly what the gateway singleton uses when
`UPSTREAM_DB_BACKED=false`. Parse it with the default (`requireCredsPath: true`)
and it throws a named `RarConfigError` on the missing creds path, by design: a
credsPath-less config MUST be run no-DB. There is a test proving both directions
in `gateway/src/rar/rar-config.test.ts`.

`idField` (`resource_id`) and `argIdKey` (`resourceId`) are present because the
config schema requires them to be non-empty strings, but they are **unused
here**: `echo` and `printEnv` take no domain id (`echo` takes `message`,
`printEnv` takes nothing), so no argument is ever mapped onto `operationDetails`.

There is **no `stepUp` block** - server-derived step-up discovery is disabled
for the wire-check. Tier 2 (`printEnv`) still triggers the standard Verify MFA
push via the access policy, which is enough to exercise the HITL leg.
