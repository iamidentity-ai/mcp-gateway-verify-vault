# Token exchange and Rich Authorization Requests

This is the heart of the gateway. Everything else - the tier gate, the step-up, the audit chain -
exists to feed or enforce this one exchange. If you read only one concept page, read this one.

## The question every tool call has to answer

When an agent asks the gateway to run `get_record`, three facts must be true *at the same time*,
and provably so:

1. **Identity** - *for whom* is this being done? (a specific signed-in user)
2. **Authorization** - *what exactly* is allowed? (read this one record, not write, not delete)
3. **Credential** - *with what* does the query actually run? (a database credential)

The naive failure mode collapses all three into one static admin credential: whoever can reach the
server queries the database as everyone. The gateway keeps them separate and **cryptographically
binds them together** for the duration of a single call. That binding - credential ⇄ authorization
⇄ identity - is the whole game.

## RFC 8693: token exchange with a subject and an actor

`auth/token-exchange.ts` performs an [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) token
exchange against Verify's `/oauth2/token`:

- **`subject_token`** = the *user's* access token (the bearer the agent presented). This carries
  the identity - the "for whom."
- **`actor_token`** = the *gateway's own* identity - a **SPIFFE JWT-SVID** by default
  (`AUTH_METHOD=spiffe`), or an agent app's `client_credentials` JWT (`AUTH_METHOD=verify`). This
  carries the "by what workload."
- **`scope`** = the tier's coarse OAuth scope (`records:read` / `records:write`).
- **`authorization_details`** = the fine-grained RFC 9396 RAR (below).

Verify returns an **OBO** ("on-behalf-of") token whose claims encode the delegation: a `sub` (the
user), an `act` chain naming the actor, and the `authorization_details` it approved. Delegation is
constrained on the tenant by a **`may_act`** claim on the user's login - only the configured
actor(s) may act on that user's behalf. This is real RFC 8693 `act`/`may_act`, not an ad-hoc
header the gateway invents.

Why an *actor* token at all? Because "the user did this" and "the user's agent did this on the
user's behalf" are different facts, and downstream systems (and the audit trail) deserve to tell
them apart. The `act` chain records *both* - the affirmative deliverable no per-server topology can
produce (see [observability](observability.md)).

## RFC 9396: Rich Authorization Requests

A coarse scope like `records:read` says "this token may read records." It does **not** say "read
*this* record." [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396) `authorization_details` closes
that gap. `rar/build-rar.ts` builds a **three-element** array:

```jsonc
[
  {
    "type": "urn:example:agent:records",          // config/rar.json → rarType
    "operationDetails": {
      "action": "record_read",                     // the collapsed Vault-role-mapping action
      "subaction": "record_read",                  // the original action, preserved for audit
      "record_id": "REC-1001"                       // the domain id, nested under config.idField
    }
  },
  { "type": "vault:path_access", "path_constraint": "verify-rar/creds/records", "action": "update" },
  { "type": "vault:path_access", "path_constraint": "sys/leases/revoke",        "action": "update" }
]
```

Element 1 is the **business RAR**. Its fields live **nested under `operationDetails`** - a
load-bearing shape: Verify's CELX access-policy navigation reads
`requestContext.authorizationDetails[...].operationDetails.<field>`. Put a field at the wrong level
and the policy silently never matches. Elements 2 and 3 are **`vault:path_access`** grants that
give the OBO explicit Vault path-level authority - the credentials path it will mint from, and
`sys/leases/revoke` so the gateway can hand the lease back.

The vocabulary - `rarType`, `idField`, the actions, the creds paths - is **entirely
[`config/rar.json`](../../gateway/config/rar.json)**, never hardcoded. That is what lets you point
the gateway at tickets, orders, or shipments by editing config, not code
([bring your own MCP](../guides/bring-your-own-mcp.md)).

### `resolveRar()` - one source of truth, and the bug it prevents

Callers that need *both* the `authorization_details` **and** the Vault creds path for the same call
(the pipeline does) must use `resolveRar()` - never compute them separately. The reason is a real
security-review finding: the RAR builder **elevates** a `vip: true` read to the configured step-up
action (`record_read` → `record_read_vip`) and its `-vip` creds path. If you derived the creds path
from the *raw* action independently, a VIP read would claim the elevated action to Verify while
minting from the *non-elevated* role - the credential unbound from the approved authorization.
`resolveRar()` runs the elevation-collapse **exactly once** and derives both outputs from that
single collapsed action, so they can never disagree. This is the credential ⇄ authorization binding
made concrete in one function.

## No standing database credentials - ever

The gateway holds **no long-lived database secret**. The OBO minted above is POSTed to Vault as
`X-Vault-Token` (`vault/mint.ts`); the `verify-rar` plugin validates it against the tenant JWKS,
matches its `authorization_details` against the role's `rar_mappings`, and only then mints a
**fresh Postgres credential** - a distinct username/password, TTL ~5 minutes, revoked in a
`finally` the moment the one call completes. Contrast the naive server's single static admin
credential shared by everyone.

The practical consequence: **compromising the gateway mid-call yields at most one short-lived
credential for one operation** - not a durable foothold. There is nothing at rest to steal. The
credential exists only for the window in which an *approved* authorization for a *specific* user
was live.

## Two legs, when a human is involved

When the IdP policy demands step-up, the exchange comes back `mfa_challenge` (a **200 OK**, not an
error) and the flow splits into two legs. The critical rule: the second (jwt-bearer,
[RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)) leg **re-sends `authorization_details`** -
Verify does not propagate RAR through it by default, and an OBO minted without the RAR would let
Vault mint a credential unbound from the approved transaction. The full sequence is in
[human-in-the-loop](human-in-the-loop.md); the mechanics are why it exists.

## The takeaway

Coarse scope alone is "can read records." RAR turns it into "may read *this* record, *for this
user*, *minting from this Vault role*, *right now*." The gateway's job is to assemble that binding
honestly and enforce it - not to decide the policy behind it.
