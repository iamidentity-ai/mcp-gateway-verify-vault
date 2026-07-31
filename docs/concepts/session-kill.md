# Session kill - CAEP/SSF, two channels

A single denied step-up is a normal event; the user says no and the record is withheld. But
**repeated** denials, or an explicit "this is fraud" from the user's phone, are a different signal:
something is driving the agent that the user does not want. At that point the gateway escalates
from "deny this call" to "**kill this user's sessions, everywhere**."

The critical design point: the gateway only ever *emits* a CAEP event. It does **not** call the
IdP's session-delete API itself. A separate CAEP/SSF transmitter ("Antenna") owns that call. Two
channels, two jobs - keep them distinct.

```mermaid
flowchart TD
    START["MFA verdict on a gated tool call<br/>(completePending)"] --> Q{"push verdict, or<br/>emailed-code result?"}
    Q -->|"approved"| OK["clearDeny -> mint -> call -> revoke -> ok"]
    Q -->|"denied (normal)"| REC["recordDeny(user)"]
    Q -->|"wrong one-time code<br/>(otp_invalid)"| REC
    Q -->|"denied_suspicious / fraud"| SUS["suspicious - 1 strike is terminal"]
    B4["tier-4 tool call<br/>(runPipeline, BLOCKED_ACTION_KILL=true)"] --> REC

    REC --> THRESH{"3rd strike inside<br/>5-min window?"}
    THRESH -->|"no"| DENY["403 denied<br/>session survives"]
    THRESH -->|"yes"| KILL["Session kill"]
    SUS --> KILL

    KILL --> EMIT["emitSessionRevoked<br/>CAEP session-revoked event"]
    KILL --> MARK["markKilled(user)<br/>local 5-min kill-gate<br/>covers 30-75s propagation"]

    EMIT --> ANT["Antenna session_revoked.js"]
    ANT --> DEL["Verify DELETE<br/>/v1.0/auth/sessions/{user}"]
    DEL --> TENANT["Tenant-wide revoke:<br/>every app federated to the tenant"]
```

## What escalates

- **Normal denial** (`ssf/deny-counter.ts`) - `recordDeny()` increments a per-user counter in a
  **5-minute rolling window**. The **3rd strike** trips the threshold. A user who legitimately
  fat-fingers one approval is not punished; a loop hammering step-up is.
- **A wrong one-time code** (`HITL_METHOD=transient_email`) counts as a normal denial against the
  same counter, with the same 3-strike threshold. The person typing codes into the approval box did
  not prove they are the approver, which is the same signal a denied push carries. An **expired**
  code (`otp_expired`) does **not** count: that is a slow human, not a wrong one, and must never
  cost someone their session. A wrong code that still leaves attempts **re-parks** the same
  transaction so the box can be retried under the same `txId` - the counter is per *user*, not per
  transaction, so three wrong codes trip the kill whether they were typed into one parked step-up
  or three.
- **Suspicious / fraud** - a "report suspicious" verdict from the phone is a **1-strike,
  immediately terminal** kill. The reasoning: a user who reports the agent as fraudulent should not
  be pestered with more pushes - take the strong action at once.
- **Repeated blocked-action attempts** (`BLOCKED_ACTION_KILL=true`, default off). A **tier-4**
  deny - an identity asking for an action this deployment grants to *nobody* - feeds the same
  counter with the same 3-strike threshold. One attempt is noise. Three in five minutes is an
  identity reaching outside its grant over and over, which is what a client under someone else's
  influence looks like from the server side.

  **This is not detection.** The gateway does not read content, does not inspect prompts, and
  cannot tell you *why* the identity asked. It reacts to the consequence, not the cause - and it
  does not need the cause, because the blast radius was already bounded by the grant before the
  first attempt. Say it that way; the weaker claim is the true one and it is also the stronger
  argument.

  Deliberately narrow: only `policy_deny` counts. `unknown_tool` does **not** - a hallucinated tool
  name is a mistake, not an escalation attempt. Nor does a Verify-side `access_denied` at Token
  Exchange: a correctly-scoped read-only identity being refused a write is a normal, expected
  outcome (it is literally a demo scenario), and counting it would turn a working authorization
  boundary into a self-inflicted outage.
- **Approval clears the counter.** Proving the user still holds the MFA factor is a fresh slate -
  the counter resets (`clearDeny`). Note this only clears on **MFA-gated** tiers (2/3): a tier-1
  read succeeding must *not* reset the counter, or an agent could launder its strike count through
  harmless lookups between write attempts.

## Channel 1 - the security channel (the actual kill)

On a kill, `emitSessionRevoked()` (`ssf/antenna.ts`) POSTs a **CAEP `session-revoked` event** to
the transmitter. The transmitter's `session_revoked` handler is what calls Verify's
`DELETE /v1.0/auth/sessions/{verifyUserId}`, which terminates the user's sessions across **every
app federated to the tenant** - not just this gateway. That tenant-wide blast radius is the point:
if the agent is compromised, revoking only *this* app's session leaves the attacker holding the
user's session everywhere else.

The CAEP payload shape is exact and unforgiving. `sub_id` is **top-level** (not nested under
`events`); `event_timestamp` is **epoch seconds** (not milliseconds); `reasonAdmin.en` /
`reasonUser.en` must be present. Get any of these wrong and the ingester returns `201` and
**silently drops** the event - the session is never actually killed, and nothing tells you. The
handler reads `sub_id.verifyUserId` (older handlers fall back to SCIM-by-email, which is why the
email rides along when known). The exact shape lives in the `antenna.ts` header and
[step-up policies](../guides/session-kill.md).

## Channel 2 - the observability channel (and the local kill-gate)

Two more things happen in parallel with the CAEP emit, and both are about not-being-blind:

- **`markKilled(user)`** sets a **local 5-minute kill-gate**. A tenant-wide revoke is not
  instantaneous - there is a **30–75s propagation window** where Verify's `/oauth2/userinfo` might
  still 200 the just-revoked token. During that window the local gate 401s the *very next call*
  from that user immediately (pipeline step 0), so the gateway does not keep serving a session it
  just asked to have killed. Without this gate, the kill would have a several-second hole.
- **The central events dashboard push** (fire-and-forget). A real tenant-wide kill is otherwise
  *invisible*: the transmitter 201s, the Verify session dies, and nothing shows on a dashboard. So
  the gateway - the single kill choke point - also pushes an `agent:session_revoked` event to the
  webhook dashboard when `WEBHOOK_API_KEY` is set. This is the same principle as the
  [`_diagnostic` envelope](observability.md): **security you cannot see reads as broken.** A
  dashboard hiccup must never delay the real kill, so this push runs first and fire-and-forget.

## Why two channels, restated

The gateway *decides to escalate* (deny-counter + suspicious logic) and *emits*; the transmitter
*acts* (the session DELETE). Splitting them means the kill semantics (which app, which sessions, in
what order) live in one auditable transmitter handler you can reason about, and the gateway stays a
thin PEP that never becomes the tenant's session-management authority. Wiring the transmitter and
the dashboard is a task-shaped [guide](../guides/session-kill.md).
