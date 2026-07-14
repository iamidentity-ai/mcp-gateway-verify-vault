# Threat model & security properties

The gateway is a **policy-enforcement point**. Its guarantees are meant to hold **even against an
attacker who holds the user's currently-valid session bearer** - the hardest case, because
introspection alone would pass. This page states what that attacker still cannot do, and - just as
importantly - what the gateway does *not* claim.

## What a valid-bearer attacker still cannot do

- **Obtain standing database credentials.** There is no long-lived DB secret on disk or in the
  gateway. Every credential is minted per call, scoped by the RAR-matched Vault role, ~5-minute TTL,
  and **revoked in a `finally`** on completion. Compromising the gateway mid-call yields at most one
  short-lived credential for one operation - not a durable foothold. (Contrast the naive server's
  fallback: a single static admin credential for everyone.)
- **Read a restricted record without a live human approval.** Classification is detected
  **server-side**; the agent can't request elevation, and the gateway re-runs a restricted record
  through the elevated RAR that makes IdP policy require a push. A compromised agent with a valid
  bearer still lights up the real user's phone.
- **Write without approval.** Tier 2 requires a policy-driven push; tier 3 requires a push on **every**
  call - enforced by IdP policy on the RAR, not by gateway code that could be edited around.
- **Invoke a blocked operation.** Tier 4 (`delete_record`) is denied at the gate, before the IdP is
  ever contacted.
- **Escape a report of abuse.** Three denials in five minutes, or one "suspicious" report from the
  phone, emit a CAEP event → transmitter → IdP session-delete across **every federated app**, and the
  local kill-gate 401s the next call immediately during propagation.
- **Weaponize step-up against another user.** `/hitl/complete` is identity-bound; a bearer holder who
  learns a victim's `txId` cannot complete or kill the victim's transaction (`403 forbidden`, before
  any side effect).
- **Strip the RAR at approval.** The second (`jwt_bearer`) leg **re-sends** `authorization_details`, so
  an approved OBO always carries the RAR Vault matches against - a credential is never minted unbound
  from the approved transaction.
- **Ride a dead IdP.** Introspection **fails closed**: any non-200 or network/TLS error is treated as
  an inactive session.
- **Slip past the bearer gate.** Every user route checks bearer presence first; unauthenticated calls
  `401` before any body parse or tool lookup.

## Secretless workload identity

In the reference posture the gateway holds **no static Vault token**: it bootstraps AppRole → SPIFFE
JWT-SVID → native `auth/spiffe` login → scoped Vault token, and presents an SVID as the RFC 8693 actor
token. (`VAULT_KEY` is a dev-only override; never set it in a real deployment.) Under
`SECRETS_BACKEND=vault` the Verify client secret is also never at rest - it rotates on every read (see
[secrets](guides/secrets.md)).

## Honest boundaries - what the gateway does *not* claim

- With a valid live bearer, an attacker **can** perform tier-1 reads of public records the user is
  entitled to (Token-Exchange only, no human check). The gateway enforces IdP policy; it is not an
  anomaly detector on reads.
- In-memory state (deny counter, kill-gate, pending store, audit ring buffer) is **per-process and
  non-persistent** - correct for a single-instance deploy; horizontal scaling needs shared state or
  sticky routing.
- The `_diagnostic` envelope **carries the full OBO** in the response - a deliberate observability
  choice for a demo/reference build. A raw OBO is a bearer token; redact it before any external trust
  boundary. See [observability](concepts/observability.md).
- The gateway is the highest-value box on the path. Its safety rests on **never becoming the source of
  truth about identity** - it transforms tokens and brokers credentials, and propagates identity
  downstream cryptographically (the OBO's `sub` + `act` chain + `authorization_details`), not as
  gateway-vouched plain headers. Keep it thin: the moment it absorbs authorization semantics, it
  becomes a confused deputy.
- The stable RFC floor (8693 / 9396 / 7523) is well-understood, but the composed agent-identity stack
  above it has no published formal security proof. Treat the thin-PEP discipline as the hedge.

## The affirmative deliverable

The property no per-server topology can produce is the **audit chain**: a per-call, per-user record of
*who* acted *for whom*, with *which* approved `authorization_details`, yielding *which* Vault lease,
and *which* CAEP events. That trail (`audit/chain.ts`, surfaced at `GET /me/audit`) is the gateway's
strongest, most defensible claim. See [observability](concepts/observability.md#the-audit-chain--the-affirmative-deliverable).
