# Wire the session kill

The gateway escalates repeated denials (or one "suspicious" verdict) to a **tenant-wide session
kill**. It does this by *emitting a CAEP event* - a separate **SSF transmitter** ("Antenna") owns
the actual session-delete call. This guide wires the transmitter and the optional observability
dashboard. For the *why* (two channels, the 3-strike window, the local kill-gate), read
[concepts/session-kill](../concepts/session-kill.md) first.

## The two things you wire

```
gateway  ──CAEP session-revoked──▶  Antenna (SSF transmitter)  ──DELETE /v1.0/auth/sessions/{id}──▶  Verify
   │                                                                                                    │
   └──agent:session_revoked──▶  events dashboard (optional, observability only)          tenant-wide session revoke
```

1. **The CAEP source on the transmitter** (required for the kill to actually happen).
2. **The events dashboard webhook** (optional - so a real kill is *visible*).

## 1. Point the gateway at the transmitter source

The gateway POSTs its CAEP event to a **source endpoint** on the transmitter. Set it in `.env`:

```bash
# The source_id path segment must match a source configured on the transmitter.
ANTENNA_SOURCE_URL=https://your-transmitter:9042/sources/agentic/events
```

The `source_id` segment (`agentic` here) must match a source you configured on the transmitter - any
other value 404s at the ingester. If the transmitter serves self-signed HTTPS on localhost, the
gateway's service env may need `NODE_TLS_REJECT_UNAUTHORIZED=0` to connect.

## 2. The CAEP payload shape is exact - and unforgiving

The gateway sends exactly this shape (from `gateway/src/ssf/antenna.ts`). If your transmitter's
`session_revoked` handler expects anything different, the ingester returns **`201` and silently
drops the event** - the session is never killed and nothing tells you:

```jsonc
{
  "sub_id": {                          // TOP-LEVEL, not nested under events
    "format": "email",                 // or "opaque" when email is unknown
    "verifyUserId": "<internal Verify uid>",   // REQUIRED - the handler reads this
    "email": "<user-email>"            // rides along; older handlers fall back to SCIM-by-email
  },
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
      "event_timestamp": 1750000000,   // epoch SECONDS, not milliseconds
      "initiatingEntity": "policy",
      "reasonAdmin": { "en": "<reason>" },
      "reasonUser":  { "en": "<reason>" }
    }
  }
}
```

The two silent-drop traps: **`sub_id` is top-level** (not inside `events`), and **`event_timestamp`
is epoch seconds** (not ms). Getting either wrong 201s and drops.

## 3. The transmitter handler calls the session-delete API

The transmitter's `session_revoked` action handler reads `sub_id.verifyUserId` and calls Verify's
**`DELETE /v1.0/auth/sessions/{verifyUserId}`**, which terminates the user's sessions across **every
app federated to the tenant** - that tenant-wide blast radius is the point. The API-client
entitlement this handler needs (session delete) is in
[verify-api-entitlements](../reference/verify-api-entitlements.md) - note it belongs to the
**transmitter**, not the gateway's runtime and not the bootstrap admin client.

> If your transmitter JIT-caches its action handlers at container start, a handler or
> rendered-config change needs a **hard restart** (`docker restart`), not just `up -d` - a common
> "my kill stopped working" cause.

## 4. Optional: make the kill visible (events dashboard)

A real tenant-wide kill is otherwise *invisible* - the transmitter 201s, the Verify session dies,
and nothing shows on a dashboard. The gateway (the single kill choke point) also fire-and-forgets an
`agent:session_revoked` event to a webhook dashboard when a key is set:

```bash
WEBHOOK_URL=http://your-dashboard:3003
WEBHOOK_API_KEY=<the dashboard's ingest key>   # leave unset to disable
```

This is **observability only** - it never delays or fails the real CAEP kill (it runs first,
fire-and-forget). Leave `WEBHOOK_API_KEY` unset in local dev and it's a no-op. See
[observability](../concepts/observability.md) for why invisible security reads as broken.

## 5. What triggers a kill (recap)

From `completePending` (`gateway/src/pipeline.ts`), on the MFA verdict of a gated call:

- **3 normal denials in a 5-minute rolling window** → kill.
- **1 "suspicious"/fraud verdict** → kill immediately (terminal - the user reported the agent, don't
  keep pushing).
- **An approval** → clears the deny counter (a fresh slate; MFA-gated tiers only).

On a kill, the gateway *also* sets a **local kill-gate** (`markKilled`) so the very next call from
that user 401s immediately - covering the 30–75s window before the tenant-wide revoke fully
propagates. That gate is automatic; there's nothing to wire.

## 6. Prove it

Trigger three denials (deny the push three times within five minutes) on a tier-2/3 tool, or send
one "suspicious" verdict, then confirm:

- the next call from that user returns **`401 { killed: ... }`** (local kill-gate), and
- `GET /me/session-status` returns `{ active: false, reason: "session_killed" }`, and
- (if wired) the dashboard shows a **Session Revoked** badge for that user.

Tuning the thresholds (`SSF_KILLED_SESSION_TTL_MS`, the deny window) is in the
[configuration reference](../reference/configuration.md).
