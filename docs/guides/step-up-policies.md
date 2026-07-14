# Design step-up policies

Step-up (the human approval push) is enforced by **IBM Verify access policy**, not by gateway code.
This guide shows how the gateway's tiers and `config/rar.json` actions map to the Verify policy
rules that `bootstrap:verify` generates - and how to change the step-up behaviour by editing that
policy, not the gateway.

## The chain of custody

```
config/tools.json  ──▶  RAR authorization_details  ──▶  CELX attribute  ──▶  policy rule  ──▶  action
   tier + rarAction        operationDetails.action        matches action        first match      MFA / ALLOW / DENY
```

The gateway sends the RAR; Verify's policy reads `operationDetails.action` off it (via a CELX
custom attribute), matches a rule, and returns a verdict. The gateway *enforces* that verdict - it
never invents it. This is why step-up you configure in Verify can't be edited around in the
gateway.

## What `bootstrap:verify` generates

From the shipped `config/tools.json` + `config/rar.json`, the bootstrap derives (via
`bootstrap/lib/generate.ts`) one **access policy** and up to **four CELX attributes**, all named
from your RAR type's last segment (`records` → prefix `Records`):

| CELX attribute | Fires `true` when the RAR carries… | Policy rule | Verdict |
|---|---|---|---|
| `RecordsDeleteDeny` | a blocked (tier 4) action (`record_delete`) | `Records blocked-action hard deny` | `ACTION_DENY` |
| `RecordsVipRead` | `operationDetails.action == record_read_vip` | `Records VIP read step-up` | `ACTION_MFA_ALWAYS` |
| `RecordsSensitiveWrite` | a write action (tier 3) | `Records sensitive write` | `ACTION_MFA_ALWAYS` |
| `RecordsStandardWrite` | a write action (tier 2) | `Records standard write` | `ACTION_MFA_PER_SESSION` |
| *(none - default rule)* | anything unmatched (tier-1 reads) | `Default rule` | `ACTION_ALLOW` |

The policy is `Records-RAR-HITL`, **rule order is first-match-wins**: DENY → VIP read → sensitive
write → standard write → default allow. It is bound to the Token-Exchange app via the app-level
`authPolicy` field.

### How each tier lands on a verdict

- **Tier 1 (read)** → `record_read` action → no CELX attribute matches → **default `ACTION_ALLOW`**.
  Token Exchange succeeds with no push.
- **Tier 1 VIP read** → the gateway [derives](../concepts/human-in-the-loop.md) the elevated
  `record_read_vip` action → `RecordsVipRead` fires → **`ACTION_MFA_ALWAYS`** (push every VIP read).
  This covers **every** record-scoped read tool, not just `get_record`: the gateway probes the
  parent record's VIP status with `vipElevation.probeTool` (a flag-carrying read), so
  `get_record_detail` / `get_record_history` on a VIP record are gated too - an agent cannot dodge
  the step-up by calling a sibling read. `list_records` returns **no PII** (identifiers + `vip_flag`
  only), so bulk listing can't leak a VIP record's personal data either. And the check **fails
  closed**: a probe result the gateway can't parse forces the step-up rather than delivering. A
  **data-layer backstop** reinforces all of this - the base `records_read` Postgres role is
  Row-Level-Security-restricted to non-VIP rows, so VIP data is physically unreadable except through
  the `records_read_vip` role the gateway mints *only* after a completed step-up
  (see `examples/db/vault-roles.sql`).
- **Tier 2 / Tier 3 (write)** → `record_write` action → a write attribute fires → **MFA**. See the
  known-limitation note below on why both currently land on `ACTION_MFA_ALWAYS`.
- **Tier 4 (blocked)** → denied at the gateway's tier gate *before Verify is contacted*; the
  `RecordsDeleteDeny` rule is a **defense-in-depth backstop** for if that gate is ever bypassed.

### The write tiers - a documented known limitation

Tier 2 and tier 3 writes today send **identical** RAR content (`operationDetails.action ==
record_write`) - there is no field distinguishing which tool ran. So `RecordsSensitiveWrite` is
authored to match *every* write (forward-compatible: if a future `operationDetails.tool` field is
added it narrows to tier 3 only), and both write tiers fall through to `ACTION_MFA_ALWAYS`. That is
the **safe default** - tier 3's "push every call" is never accidentally relaxed. `RecordsStandardWrite`
(→ `ACTION_MFA_PER_SESSION`) exists so tier 2 auto-gets the lighter once-per-session treatment the
day a tool disambiguator lands in the RAR. Don't reorder these rules without reading the generated
attribute descriptions.

## Verify policy gotchas the bootstrap already handles

`bootstrap/verify.ts` embeds these hard-won invariants - you get them for free, but know them if you
hand-edit the policy in the Verify Admin console:

- **`enforcementType` lives under `meta`**, not top-level. A top-level value is silently stripped and
  the policy lands `ACTIVE` but never evaluates - the "policy isn't firing" trap.
- **Conditions use `IN`, never `EQ`.** `EQ` against a value list silently never matches.
- **Register every scope on the TE app.** With `restrictScopes` on, a policy condition keyed to an
  unregistered scope silently never fires. The bootstrap registers `records:read` + `records:write`.
- **Bind via the app-level `authPolicy` field**, then PUT the whole app - *not*
  `PUT /v1.0/applications/{id}/authPolicy` (empty-body 400s).
- **Custom attribute `id == name`.** A POST with an auto-generated UUID id leaves policy conditions
  pointing at a dead id after any rename.

The full list is in [troubleshooting](../reference/troubleshooting.md) and the `bootstrap/verify.ts`
header.

## Changing step-up behaviour

Because the verdict is the *policy's*, you tune step-up by editing the policy - regenerated from
config on the next `bootstrap:verify`, or by hand in the Admin console:

- **Make a tier-1 read require step-up unconditionally** → move that read's tool to a `rarAction`
  with its own CELX attribute + an `ACTION_MFA_ALWAYS` rule (edit `config/tools.json` +
  `config/rar.json`, re-run bootstrap).
- **Relax tier 2 to once-per-session** → this is what `RecordsStandardWrite` +
  `ACTION_MFA_PER_SESSION` is for; it activates once the RAR carries a tool disambiguator.
- **Protect a different "sensitive row" flag** → point `config/rar.json → vipElevation.vipField` at
  your flag; the `VipRead` rule then fires on your rows.

The runtime never changes for any of these. The gateway builds the RAR, sends the exchange, and
enforces whatever the policy returns. Wiring the **denial-escalation** side (three denials → session
kill) is a separate concern: [session kill](session-kill.md).
