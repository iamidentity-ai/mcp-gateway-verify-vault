# Troubleshooting

The real error ladder - every entry is a gate this chain hit for real, with the fix and the reasoning.
Grouped by where the symptom shows up. For the happy-path quickstart troubleshooting table, see the
[quickstart](../guides/quickstart.md#troubleshooting).

## Token exchange / secrets

### `CSIAQ0155E` / `invalid_client` - one retry, then fine

**Symptom:** a token call logs `CSIAQ0155E`, `invalid_client`, or a `401`, then a single narrow retry
succeeds. **Cause:** in `SECRETS_BACKEND=vault` mode the IBM Verify Vault plugin **rotates the
`client_secret` on every read**; a rotation by another process (or the plugin's eventual-consistency
window) can leave the gateway's 1-hour role cache briefly stale. **Fix (already built in):** the
gateway invalidates **only that role's** cache entry, reads a fresh secret, and retries the token call
**once** - no sleep, no global flush. Both legs use it: leg-1 in `auth/token-exchange.ts`, leg-2
(`jwt_bearer`) in `pipeline.ts`'s `completePending`.

**Anti-pattern to grep for:** any `"waiting Ns for propagation"` log line. That is stale code - the fix
is a single narrow-invalidation retry, never a sleep. A global cache flush is also wrong: it cascades
errors onto every concurrent caller.

In `env` mode the same retry code runs, but `invalidate*()` is a no-op and the re-read returns the same
static value - correct for a secret that doesn't rotate.

### `MissingSecretError: GATEWAY_EXCHANGE_CLIENT_SECRET is not set`

**Cause:** `SECRETS_BACKEND=env` but the plaintext secret isn't set. **Fix:** set it, or switch to
`SECRETS_BACKEND=vault`. The error names the exact variable. See [secrets](../guides/secrets.md).

## Step-up (HITL)

### `mfa_challenge` treated as an error - it's a 200 OK

**Symptom:** the exchange "fails" whenever policy requires step-up. **Cause:** Verify returns
`scope=mfa_challenge` as a **200 OK** with a challenge token, *not* an error. Treating the 200 as
success (passing the challenge token downstream) or as an error (aborting) both break the flow.
**Fix:** branch on `exchangeResult.status === 'mfa_challenge'` - park the transaction, trigger the
push, and complete the second (`jwt_bearer`) leg. Never pass the challenge token to Vault or the
upstream. The gateway does this in `runExchangeAndCall`.

### Step-up completes but Vault denies the mint

**Cause:** the second (`jwt_bearer`) leg didn't **re-send `authorization_details`**. Verify does not
propagate RAR through the second leg by default, so the approved OBO carries no attested RAR and Vault
mints nothing (or the wrong role). **Fix (built in):** `exchangeMfaAssertionWithRAR` re-sends the RAR.
This is mandatory, not optional - see [token exchange & RAR](../concepts/token-exchange-and-rar.md#two-legs-when-a-human-is-involved).

### `/hitl/complete` returns `403 forbidden`

**Cause:** the bearer completing the transaction isn't the user who started it. `/hitl/complete` is
**identity-bound** - the caller's `verifyUserId` must match the pending transaction's owner. **Fix:**
resume with the **same user's bearer** that got the `202 pending`. This is a security guarantee, not a
bug: it stops a bearer holder who learned a victim's `txId` from forcing a session-kill on the victim.

### `/hitl/complete` returns `403 invalid_request_state`

**Cause:** the caller sent a `requestState` (SEP-2322) that failed verification - it doesn't match the
pending transaction's own owner/tool/arguments digest, has expired, is badly signed, or is malformed.
A JSON `null` is treated as an omitted key, not a failure; this error only fires for a `requestState`
that was actually present and didn't check out. **Fix:** echo back the **most recent** `requestState`
you received for this transaction (an `otp_invalid` re-park mints a fresh one with a new expiry - an
older blob from the same transaction can legitimately have expired), or simply retry with `txId` alone
and omit `requestState` entirely - the pending entry is untouched by a failed check, so nothing is
lost. See [human-in-the-loop](../concepts/human-in-the-loop.md#requeststate-integrity-sep-2322).

### `202 pending` handled as a failure

**Cause:** a client treating `ok: false` / HTTP 202 as "the call failed." **Fix:** `202 { pending }` is
`res.ok` semantically - a human approval is in flight. Surface the push and poll `/hitl/complete`. See
[the consumer contract](../concepts/human-in-the-loop.md#the-consumer-contract-202-pending-is-resok)
and [any-agent](../guides/any-agent.md).

## Classification discovery

### Every record looks public; the step-up never fires

**Cause:** `shouldStepUp` isn't finding the classification. In production `callUpstreamTool` returns
the MCP `CallToolResult` envelope verbatim - `{ content: [{ type: 'text', text: '<json string>' }] }`
- so the record (and its `classification`) lives **inside** that JSON string, not at the top level.
Reading the field off the envelope directly makes every record look public, so the gateway never
elevates and the `RecordsElevatedRead` policy rule never fires - the "policy isn't being applied" bug
that is actually a parsing bug. **Fix (built in):** `shouldStepUp` unwraps `content[0].text` before
evaluating `config/rar.json → stepUp.elevateWhen`. If you changed the upstream response shape, update
the unwrap.

### Every record now forces a step-up (the opposite)

**Cause:** `shouldStepUp` **fails closed** - with the shipped `notIn` safe-list, only a value
explicitly listed (`public` / `internal`) bypasses; anything else, and any result it can't parse into
a record carrying that field, forces the step-up. If you pointed the gateway at a **different
upstream** whose read result doesn't carry the `elevateWhen.field` at the top level of the unwrapped
record, every read over-protects into a step-up. **Fix:** make the `probeTool` read (`get_record` by
default) return the classification at the top level of its record, or set `elevateWhen.field` to where
your upstream actually puts it. Over-protection is the *intended* failure mode - it never leaks
sensitive data. (See [the elevateWhen match rule](../guides/step-up-policies.md#the-elevatewhen-match-rule).)

### `Error: config/tools.json: tool "…" uses rarAction "…" which is not a defined action` at startup

**Cause (as designed):** the gateway (and `bootstrap:verify`) now **cross-validate** `tools.json`
against `rar.json` at startup. A tool whose `rarAction` isn't a defined, non-blocked action in
`rar.json` would silently collapse to the default (read) action at exchange time and skip its tier's
step-up - so this is a hard, named crash instead. **Fix:** add the missing action to
`config/rar.json` (with its `credsPath`), or correct the `rarAction` typo in `config/tools.json`.
Only a tier-4 tool may map to a `blocked` action.

## Verify policy provisioning

These are the CELX/access-policy gotchas `bootstrap/verify.ts` already embeds - they bite only if you
hand-edit the policy in the Admin console.

### Policy is `ACTIVE` but never evaluates

**Cause:** `enforcementType` set at the **top level**. Verify silently strips it; the policy lands
`ACTIVE` but never fires. **Fix:** `enforcementType` lives **under `meta`**. `bootstrap:verify` reads
the policy back and warns if it didn't land `ACTIVE`/`fedSSO`.

### A policy condition silently never matches - `restrictScopes` drop

**Cause 1 (`EQ` vs `IN`):** a condition using `EQ` against a value list never matches - use `IN`.
**Cause 2 (`restrictScopes`):** with `restrictScopes` on, a condition keyed to a scope **not registered
on the TE app** silently never fires. **Fix:** register every scope the policy references
(`records:read` + `records:write`); the bootstrap does this.

### Policy bind doesn't stick

**Cause:** binding via `PUT /v1.0/applications/{id}/authPolicy` (empty-body 400s). **Fix:** set the
app-level `authPolicy` field and PUT the **whole app body**. The bootstrap reads back
`app.authPolicy.id` to confirm.

### Custom attribute condition points at a dead id after a rename

**Cause:** the attribute was POSTed without an explicit `id`, so Verify assigned a UUID; a later rename
leaves policy conditions pointing at the old id. **Fix:** POST attributes with explicit `id == name`.

## Observability / envelope

### `200` but `_diagnostic: {}` - invisible security

**Cause:** the call didn't go through the exchange+mint path (it was denied/killed/errored, or you're
misreading a non-`ok` envelope). The mapper **never fabricates** diagnostics, so an empty
`_diagnostic` on what you thought was a secured success is a red flag. **Fix:** check `ok`/`denied`/
`killed`/`error` - a populated `_diagnostic` is the confirmation the security chain actually ran. See
[observability](../concepts/observability.md#_diagnostic--is-a-signal-not-a-bug). *Invisible security
reads as broken* - that's the point of the envelope.

## Session kill

### Kill "fires" but the session stays alive

**Cause:** the CAEP payload shape is wrong, so the transmitter's ingester returns **`201` and silently
drops** the event. The two traps: `sub_id` must be **top-level** (not nested under `events`), and
`event_timestamp` must be **epoch seconds** (not milliseconds). **Fix:** match the exact shape in
[session kill](../guides/session-kill.md#2-the-caep-payload-shape-is-exact--and-unforgiving). Also
confirm `ANTENNA_SOURCE_URL`'s `source_id` segment matches a configured source (a mismatch 404s at the
ingester), and - if your transmitter JIT-caches handlers - that you **hard-restarted** it after a
handler/config change.

### The dashboard shows nothing after a real kill

**Cause:** `WEBHOOK_API_KEY` unset, so the observability push is skipped. The security kill still
happened (transmitter → Verify session delete); it's just invisible. **Fix:** set `WEBHOOK_URL` +
`WEBHOOK_API_KEY` if you want the dashboard badge. This channel is fire-and-forget and never affects
the real kill.

## Deploy / transport

### MCP calls intermittently fail with transport errors

**Cause:** a reused MCP client on the south face. The gateway builds a **per-call** MCP `Client` +
transport on purpose - reuse is the documented "MCP transport desync" failure mode. **Fix:** don't
cache the upstream client; `proxy/upstream.ts` already creates one per call.

### Unauthenticated calls return `500` instead of `401`

**Cause:** a route doing body/tool work before checking the bearer. **Fix:** every user route runs
`requireBearer` **first** - presence checked before any body parse. If you add a route, keep that
ordering; the bearer gate is the exposure boundary, and a tunnel in front is **not** a security layer.
