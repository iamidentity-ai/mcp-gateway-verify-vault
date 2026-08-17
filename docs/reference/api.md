# API reference

The gateway's north face (`gateway/src/index.ts`), bound to `127.0.0.1:PORT` (default 3014). Every
user-facing route runs a **bearer-presence check first** - an unauthenticated call returns `401
{ error: "missing_bearer" }` before any body parse or tool lookup.

## Routes

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `/healthz` | GET | none | Liveness - `{ "status": "ok" }`. |
| `/mcp` | POST | bearer | Real MCP protocol over Streamable HTTP (stateless). `tools/call` → `runPipeline`. |
| `/tool` | POST | bearer | REST `{ name, arguments }` → `runPipeline`. Curl-friendly. |
| `/hitl/complete` | POST | bearer (**identity-bound**) | Resume a parked `mfa_challenge`. |
| `/me/audit` | GET | bearer | The caller's own audit records, most-recent-first. |
| `/me/session-status` | GET | bearer | Introspect + local kill-gate check. |

All bearer routes take `Authorization: Bearer <user-access-token>` (the RFC 8693 subject token).

**`X-User-Email`** (optional, `POST /tool` and `POST /mcp` only) is a trusted server-to-server
subject-email hint. It is used **only** as the transient-OTP delivery address when
`HITL_METHOD=transient_email` needs one, and it takes priority over both the introspected `email`
claim and the `preferred_username` fallback - Verify's `/oauth2/userinfo` reflects a
JIT-provisioned attribute that is set once and never refreshes on later logins, so a caller-supplied
value sourced from the *current* subject token is fresher. See
[human-in-the-loop](../concepts/human-in-the-loop.md#no-enrolled-push-factor-hitl_methodtransient_email).
The header is **ignored unless its value contains `@`**. This is the same trust model as bearer
forwarding: it must be set by a trusted caller (a UI backend that already decoded the user's real
IdP token at sign-in) - never by the browser or the model - and a deployment that exposes the
gateway beyond trusted callers must strip it at its edge.

---

## The envelope contract

`/tool` returns this envelope as its JSON body; `/mcp` returns the **same** envelope JSON-stringified
into the MCP `CallToolResult` text block (`content[0].text`). The two transports never drift -
`pipelineResultToEnvelope` is shared. **Read the envelope, not the HTTP status**, for the verdict.

### Success

```jsonc
// HTTP 200
{
  "ok": true,
  "data": { /* the upstream record, unwrapped from the MCP CallToolResult */ },
  "_diagnostic": {
    "oboJti": "b1c2…",                 // the OBO's jti - correlates to Verify's grant + Vault's audit log (the OBO token itself is never exposed)
    "oboTtl": 300,                     // seconds
    "oboScope": "records:read",
    "cred": {                          // the EPHEMERAL Postgres credential that ran the query
      "username": "v-token-records-x7…",
      "leaseId": "verify-rar/creds/records/…",
      "path": "verify-rar/creds/records"
    },
    "credRevoked": true,               // did the post-call lease revoke succeed? absent when nothing was minted (NO-DB upstream); `false` means that credential is still live until its TTL
    "elevated": false                  // true iff this went through the elevated step-up path
  }
}
```

When the pipeline supplies no diagnostics (denied / killed / error), `_diagnostic` is `{}` - the
mapper never fabricates values. An empty `_diagnostic` on a "200" is itself
[diagnostic](../concepts/observability.md#_diagnostic--is-a-signal-not-a-bug). `data` is the
**unwrapped** record - the gateway parses the upstream MCP `CallToolResult`'s `content[0].text` JSON
string so consumers see the record, not `{ content: [{ text }] }`.

### Pending (step-up in flight)

```jsonc
// HTTP 202
{
  "ok": false,
  "pending": true,
  "txId": "3f8c…",                     // resume via POST /hitl/complete { txId }
  "requestState": "v1.…",              // optional SEP-2322 integrity blob - echo it back on completion (below)
  "pushInfo": { "title": "Approve: view a restricted record", "message": "…", "transactionUri": "…" }
}
```

**`202` is not a failure.** A human approval push has landed on the user's phone; resolve it with
`/hitl/complete` using the same bearer. See [any-agent](../guides/any-agent.md).

`requestState` is an HMAC-bound blob (SEP-2322 pre-adoption; see
[human-in-the-loop](../concepts/human-in-the-loop.md#requeststate-integrity-sep-2322)) binding the
transaction's principal, an expiry, and a digest of the originating tool call. Echoing it back is
**optional** - a completer that sends only `txId` is unaffected, since the pending store's
single-use semantics and `/hitl/complete`'s identity check already enforce who may resume a
transaction. A completer that does present a `requestState` gets it verified **before** the
pending entry is consumed: a bad one returns `error: "invalid_request_state"` (`403`, the entry
survives - retry with just `txId`). A wrong one-time code on a `transient_email`-mode transaction
re-parks the same `txId` and mints a **fresh** `requestState` on the resulting `otp_invalid` error
envelope, because the re-park refreshes the pending entry's TTL but does not retroactively extend
the original blob's `exp` - a client should always echo the most-recently-received `requestState`,
never a cached first one.

### Denied

```jsonc
// HTTP 403
{ "ok": false, "denied": true, "reason": "policy_deny" }   // or "unknown_tool", or the MFA-deny reason
```

### Killed (suspicious)

```jsonc
// HTTP 401
{ "ok": false, "killed": true, "reason": "suspicious" }
```

### Error

```jsonc
// HTTP 401 (inactive_session / session_killed),
// 403 (forbidden / access_denied / invalid_request_state), or 500 (everything else)
{ "ok": false, "error": "inactive_session" }
```

`invalid_request_state` is `/hitl/complete`'s (and the `complete_hitl` MCP tool's) SEP-2322
requestState-verification failure - given the **same** shape and status as the owner-mismatch
`forbidden` case, since a rejected `requestState` is treated exactly like the wrong caller trying
to resume the transaction. See
[human-in-the-loop](../concepts/human-in-the-loop.md#requeststate-integrity-sep-2322).

A Token-Exchange-level `access_denied` (Verify itself rejected the exchange -
a real policy hard-cap deny, CSIAQ0278E, or a fresh-tenant entitlement gap,
CSIAQ0279E) gets the `denied` shape too, so a caller doesn't need to know
which layer produced the deny to handle it the same way:

```jsonc
// HTTP 403
{ "ok": false, "denied": true, "error": "access_denied" }
```

Note this is `denied: true` proving "Verify said no" - not proof the policy
itself is correctly configured. A fresh, incorrectly-entitled tenant and a
deliberate hard-cap policy both produce this exact response.

### Status-code mapping (`statusCodeFor`)

| Pipeline result | HTTP | Envelope |
|---|---|---|
| `ok` | 200 | `{ ok: true, data, _diagnostic }` |
| `pending` | 202 | `{ ok: false, pending: true, txId, pushInfo }` |
| `denied` | 403 | `{ ok: false, denied: true, reason }` |
| `session_killed_suspicious` | 401 | `{ ok: false, killed: true, reason: "suspicious" }` |
| `error: inactive_session` / `session_killed` | 401 | `{ ok: false, error }` |
| `error: forbidden` | 403 | `{ ok: false, error: "forbidden" }` |
| `error: access_denied` | 403 | `{ ok: false, denied: true, error: "access_denied" }` |
| `error: invalid_request_state` | 403 | `{ ok: false, error: "invalid_request_state" }` |
| `error: <other>` | 500 | `{ ok: false, error }` |

---

## `POST /tool`

Simple REST. Body:

```jsonc
{ "name": "get_record", "arguments": { "recordId": "REC-1001" } }
```

`name` (or `toolName`) is required - missing → `400 { error: "missing_name" }`. `arguments` (or
`args`) defaults to `{}`. Returns the [envelope](#the-envelope-contract) with the mapped status code.
Accepts the optional [`X-User-Email`](#routes) header.

```bash
curl -sS -X POST localhost:3014/tool \
  -H "Authorization: Bearer <user-access-token>" \
  -H 'Content-Type: application/json' \
  -d '{"name":"get_record","arguments":{"recordId":"REC-1001"}}'
```

## `POST /mcp`

Real MCP protocol over Streamable HTTP, **stateless** - a fresh `McpServer` + transport per request
(`sessionIdGenerator: undefined`). The advertised tools mirror
[`config/tools.json`](../../gateway/config/tools.json): `get_record`, `list_records`,
`get_record_history`, `get_record_detail`, `update_record`, `update_contact`, `delete_record`. Each
`tools/call` routes into the same `runPipeline`; the response envelope is JSON-stringified into the
result's text block. Connect with an MCP client and set the bearer on the transport request headers -
see [any-agent, Adapter 2](../guides/any-agent.md#adapter-2--the-mcp-sdk-client-mcp). Accepts the
optional [`X-User-Email`](#routes) header, same contract as `/tool`.

**`Mcp-Method` / `Mcp-Name` headers (SEP-2243, validate-if-present).** The gateway stays on MCP
protocol 2025-11-25, where neither header exists, so a legacy client that sends neither sees no
change in behavior. If a caller (or a 2026-07-28 client) sends `Mcp-Method` and/or `Mcp-Name`, the
gateway checks it against the JSON-RPC body underneath it - `Mcp-Method` against `body.method`;
`Mcp-Name` against `params.name` (`tools/call`, `prompts/get`) or `params.uri` (`resources/read`) -
**before** the request ever reaches the MCP transport. A header that disagrees with the body it is
attached to, or that fails to decode (malformed `=?base64?...?=` sentinel, or a decoded value
containing a control character), gets the spec-required rejection:

```jsonc
// HTTP 400
{ "jsonrpc": "2.0", "id": <echoed request id, or null>, "error": { "code": -32020, "message": "…" } }
```

This is validation, not enforcement of a REQUIRED header - the gateway never rejects a request for
*omitting* either header.

**`server/discover` (SEP-2575).** A well-formed `server/discover` JSON-RPC *request* (has an `id`;
a notification with no `id` falls through unchanged to the SDK) is answered directly at the route
layer, before the SDK ever sees it - the installed SDK has no `server/discover` handler and would
otherwise reply `-32601 Method not found`:

```jsonc
// HTTP 200
{
  "jsonrpc": "2.0",
  "id": "<echoed>",
  "result": {
    "resultType": "complete",
    "supportedVersions": ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05", "2024-10-07"],
    "capabilities": { "tools": {} },
    "_meta": { "io.modelcontextprotocol/serverInfo": { "name": "mcp-gateway", "version": "0.1.0" } },
    "instructions": "…",
    "ttlMs": 3600000,
    "cacheScope": "public"
  }
}
```

`supportedVersions` is sourced from the installed SDK's own version list, so it can never claim
`2026-07-28`. See [the adoption-status page](mcp-2026-07-28.md) for the full picture.

## `POST /hitl/complete`

Resume a parked `mfa_challenge`. Body:

```jsonc
{ "txId": "3f8c…", "requestState": "v1.…" }   // requestState optional; "verdict" is a gated dev/test escape hatch (below)
```

**Identity-bound (security-critical):** the caller's own bearer is introspected first, and its
`verifyUserId` must match the pending transaction's owner (checked off a *non-destructive* peek)
**before** any poll, deny-count, or session-kill side effect runs. A mismatch returns `403 forbidden`.
Without this, any bearer holder who learned a victim's `txId` could force a session-kill on the
victim - a zero-Verify-interaction DoS. See [human-in-the-loop](../concepts/human-in-the-loop.md#the-parked-transaction-is-identity-bound).

**`requestState`** is optional and verified, when present, **before** the pending entry is
consumed - off the entry's own stored owner and a digest recomputed from its own stored tool
name/arguments, never from anything the caller sends. A mismatched, expired, malformed, or
badly-signed value returns `403 { ok: false, error: "invalid_request_state" }` and leaves the
pending entry intact for a retry with just `txId`. The `complete_hitl` MCP tool (the `/mcp`-side
equivalent of this route) accepts the identical `requestState` argument. See
[human-in-the-loop](../concepts/human-in-the-loop.md#requeststate-integrity-sep-2322).

Missing `txId` → `400 { error: "missing_txId" }`. Unknown/expired → `{ error: "unknown_or_expired_tx" }`.
Normal completion polls the real Verify verification transaction and returns the terminal
[envelope](#the-envelope-contract) (`ok` after approval, `denied`/`killed` after denial, `error:
mfa_timeout` on timeout).

**The `verdict` escape hatch** (`approved` | `denied` | `denied_suspicious` | `timeout`) lets
integration scripts drive HITL without a phone, but is **gated behind `GATEWAY_ALLOW_TEST_VERDICT=1`**.
Outside that flag the request-body `verdict` is ignored entirely and the verdict always comes from
the live Verify poll. Never enable it outside local dev/CI.

## `GET /me/audit`

Returns the caller's own audit records (`audit/chain.ts`), most-recent-first, capped at `?limit=`
(default 50). Requires an active session (`401 { error: "inactive_session" }` otherwise).

```jsonc
// 200
{ "records": [
  { "ts": 1750000000000, "userId": "…", "tool": "get_record", "tier": 1,
    "sub": "…", "actChain": ["mcp-gateway", "…"], "authorizationDetails": [ /* RAR */ ],
    "decision": "ok", "leaseId": "…", "oboJti": "…", "latencyMs": 240 }
] }
```

`decision` values: `ok`, `tier4_deny`, `unknown_tool_deny`, `stepup_discovery`, `mfa_deny`,
`suspicious_deny_killed`. The audit chain is an in-memory ring buffer (500 records, oldest-evicted,
non-persistent - see [observability](../concepts/observability.md#the-audit-chain--the-affirmative-deliverable)).

## `GET /me/session-status`

Introspect + local kill-gate liveness check.

```jsonc
// 200 - active
{ "active": true, "email": "…", "sub": "…" }
// 401 - session revoked at the IdP
{ "active": false, "reason": "session_revoked" }
// 401 - locally killed (within the kill-gate TTL, before tenant-wide propagation completes)
{ "active": false, "reason": "session_killed" }
// 503 - Verify unreachable
{ "active": false, "reason": "verify_unreachable", "message": "…" }
```
