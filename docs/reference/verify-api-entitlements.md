# IBM Verify API-client entitlements

A customer security team will (rightly) demand least privilege for the admin API client the gateway
is provisioned with. This page is the exact entitlement floor: what the client that runs
`bootstrap:verify` needs, what the session-kill transmitter needs, and - the headline - what the
**running gateway** needs from an admin client (**nothing**).

## The bottom line

**Everything the gateway uses is standard Verify** - OIDC apps, the token-exchange grant, access
policies, CELX custom attributes, introspection. No premium Verify add-on is required; the licensed
component lives on the Vault side (OAuth-RS/SPIFFE). And the two operational phases have very
different privilege needs:

- **Bootstrap** (one-time, `bootstrap/verify.ts`) needs a broad-ish admin client to *create* the
  apps, attributes, and policy.
- **Runtime** (the gateway serving tool calls) needs **none of those admin entitlements**. Token
  exchange, `/oauth2/userinfo` introspection, and the push factors/verifications all ride the
  **OIDC apps and the user/agent tokens**, not the admin client. The gateway never holds the admin
  credential.

## The entitlement table

Ported from the standalone-repo plan and cross-checked against what `bootstrap/verify.ts` (and the
transmitter) actually call. The **"exercised by this repo"** column is the honest part - some rows
are in the family blueprint but are not touched by this repo's current code.

| # | Phase | Endpoints called | Entitlement (Verify console name) | Exercised by this repo |
|---|---|---|---|---|
| 1 | Bootstrap | `GET/POST/PUT/DELETE /v1.0/applications` (list under `_embedded.applications`) | **Manage application lifecycle** (`manageApplications`) | ✅ `bootstrap/verify.ts` - **preflight-checked, required** |
| 2 | Bootstrap | `GET/POST /v1.0/owner/applications/{id}/entitlements` | **Manage application entitlements** | ⚠️ Not called by the current `verify.ts`. The closest thing it probes is the optional **group-entitlement fixup** (row below). |
| 3 | Bootstrap | `GET/POST/PUT/DELETE /v1.0/attributes` (CELX custom attributes, `id == name`) | **Manage attributes** (`manageAttributes`) | ✅ `bootstrap/verify.ts` - **preflight-checked, required** |
| 4 | Bootstrap | `GET/POST/PUT/DELETE /v5.0/policyvault/accesspolicy` | **Manage access policies** (`managePolicies`) | ✅ `bootstrap/verify.ts` - **preflight-checked, required** |
| 4a | Bootstrap (optional) | `GET /v2.0/Groups` | **Manage user groups** (`manageUserGroups`) | ⚠️ `bootstrap/verify.ts` - **preflight-checked, non-fatal** (only the optional group-entitlement fixup needs it) |
| 5 | Ops (optional) | `GET /v1.0/grants` (+ optional `DELETE /v1.0/grants/{id}`) | **Manage grants** (read; delete only if grant-cleanup is enabled) | ❌ Not in this repo - listed for the wider blueprint; add only if you script grant cleanup |
| 6 | SSF kill | `DELETE /v1.0/auth/sessions/{userId}` | **Manage sessions / user session deletion** | 🔶 Belongs to the **Antenna transmitter**, not the gateway or bootstrap (see below) |
| - | **Runtime (gateway)** | `POST /oauth2/token` (exchange + `jwt_bearer`), `GET /oauth2/userinfo`, `GET /v2.0/factors`, `POST /v1.0/authenticators/{id}/verifications`, `GET /v1.0/authnpolicy/transactions/{txId}` | **None** | ✅ These ride the **OIDC apps + user/agent tokens**, never the admin client |

### Reading the table

- Rows **1, 3, 4** are the hard floor for `bootstrap:verify` - the script's **preflight** probes each
  and **fails, naming the missing entitlement**, before it writes anything (so a half-provisioned
  tenant is impossible). Row **4a** is preflight-checked but **non-fatal**.
- Rows **2 and 5** appear in the broader cookbook-family blueprint but are **not exercised by this
  repo's code today**. Grant them only if you extend the bootstrap (app-entitlement assignment) or add
  grant-cleanup ops.
- Row **6** (session delete) is what makes the [session kill](../guides/session-kill.md) actually
  terminate sessions - but the **transmitter** calls it with its own credential; the gateway only
  *emits* the CAEP event. Provision this on whatever principal your transmitter uses, not on the
  gateway.

## The preflight names any missing entitlement

`bootstrap/verify.ts` opens with an entitlement preflight (`preflightEntitlements`). For each required
family it issues a cheap `GET` and interprets the status:

- **`401` anywhere** → the admin **credentials themselves** are invalid (fatal, distinct from a
  missing grant) - the script stops.
- **`403` on a required family** → the client is **missing that entitlement**; the script prints the
  exact console name to grant and stops **before any write**.
- **`403` on the optional Groups family** → warned, non-fatal.

So provisioning is self-checking: the admin client either has every required grant, or the run halts
with a named remedy and nothing created.

## Building the least-privilege client

1. Create an admin API client with **only** rows 1, 3, and 4 (Manage application lifecycle, Manage
   attributes, Manage access policies).
2. Run `bootstrap:verify` - the preflight passes and the apps/attributes/policy are created.
3. Run `bootstrap:vault`, then `smoke` - a green smoke run proves the client floor is sufficient for
   the whole chain.
4. If you later see a `403` in a bootstrap re-run, the preflight tells you exactly which of rows 2/4a
   to add - grant it and re-run. That's "shrink until it breaks," documented.

## Final row list (what a security team must grant)

- **Applications R/W** - Manage application lifecycle *(required, bootstrap)*
- **Application entitlements** - Manage application entitlements *(blueprint; not exercised by this
  repo - grant only if you extend the bootstrap; the optional group-entitlement fixup uses **Manage
  user groups** instead)*
- **Attributes** - Manage attributes *(required, bootstrap)*
- **Access policies** - Manage access policies *(required, bootstrap)*
- **Grants read** - Manage grants *(optional/ops; not in this repo)*
- **Session delete** - Manage sessions / user session deletion *(the SSF-kill transmitter, not the
  gateway or bootstrap)*
- **Runtime** - **None** *(exchange / userinfo / push ride the OIDC apps + user/agent tokens)*
