# Observability - the `_diagnostic` envelope, and why invisible security reads as broken

Most security infrastructure has a demo problem: when it works perfectly, **nothing visible
happens.** The record comes back the same as it would from the naive server. The token exchange,
the RAR match, the ephemeral credential, the lease revoke - all of it is invisible, and invisible
security is indistinguishable from *no security* to anyone watching. Worse, it is indistinguishable
to *you* when you are debugging: "did the exchange actually happen, or did the call just fall
through?"

The gateway answers this deliberately. Every successful call carries a **`_diagnostic`** payload
that *shows the security working*.

## The envelope

`pipelineResultToEnvelope()` (`gateway/src/index.ts`) maps every pipeline result to a stable JSON
envelope. The success shape:

```jsonc
{
  "ok": true,
  "data": { "record_id": "REC-1001", "display_name": "Dana Reyes", "...": "..." },
  "_diagnostic": {
    "oboJti": "b1c2…",                   // the OBO's jti - correlates to Verify's grant + Vault's audit log. The OBO token itself is NEVER exposed (it is a live, replayable credential).
    "oboTtl": 300,                        // seconds
    "oboScope": "records:read",
    "cred": {
      "username": "v-token-records-x7…",  // the EPHEMERAL Postgres user that ran the query
      "leaseId": "verify-rar/creds/records/…",
      "path": "verify-rar/creds/records"
    },
    "elevated": false
  }
}
```

Every field is *evidence*. `oboJti` is the single value that ties this response to a specific
Verify token-exchange grant **and** to the Vault audit-log line that minted the credential - you
can follow one call across three systems. `cred.username` is a credential that **did not exist a
second ago and will not exist a few minutes from now**; seeing a fresh one per call is the visible
proof that there is no standing database secret. `elevated` shows whether this call went through
the [elevated step-up path](human-in-the-loop.md). A UI's agent log and audit-trace ribbon are built
to read exactly these fields.

Note what is **not** here: the raw OBO bearer token. The OBO is a live credential - it is what mints
the Vault database cred and authorizes the downstream call - so returning it to a client would hand
that client replayable authority until the token expires. The gateway exposes only the OBO's `jti`
(`oboJti`), which is enough to correlate the call across Verify and Vault but cannot be replayed.

The non-success shapes are equally explicit - `{ ok:false, pending:true, txId, pushInfo }`,
`{ ok:false, denied:true, reason }`, `{ ok:false, killed:true, reason }`, `{ ok:false, error }` -
so a consumer never has to guess *why* from an HTTP status alone. All of them are enumerated in the
[API reference](../reference/api.md).

## `_diagnostic: {}` is a signal, not a bug

The mapper **never fabricates** values it does not have. When the pipeline supplies no `diag` (a
denied call, a killed session, an error), `_diagnostic` is `{}`. An empty `_diagnostic` on what you
*thought* was a successful secured call is therefore diagnostic in its own right: it means the call
did **not** go through the exchange+mint path. Treat a populated `_diagnostic` as the confirmation
that the security chain actually ran - and an empty one on a "200" as a red flag worth
investigating (see [troubleshooting](../reference/troubleshooting.md)).

## The audit chain - the affirmative deliverable

The `_diagnostic` envelope is the per-*response* view. The per-*history* view is the **audit chain**
(`audit/chain.ts`), surfaced at `GET /me/audit`. Every dispatch appends a record: `ts`, `userId`,
`tool`, `tier`, `sub`, the `actChain` (`[service, user]`), the `authorizationDetails` sent, the
`decision`, the `leaseId` minted, the `oboJti`, and `latencyMs`.

This is the gateway's **strongest, most defensible claim** - the property no per-server topology
can produce. A scatter of individually-authorizing MCP servers cannot tell you, in one place, *who*
acted *for whom*, with *which* approved `authorization_details`, yielding *which* Vault lease, and
*which* CAEP events. A single thin PEP on the path can. That trail is the thing to point at when
someone asks "prove the agent only did what it was allowed to do."

Two honest caveats, both by design for a single-instance deploy:

- The audit chain is an in-memory **ring buffer** (bounded, oldest-evicted, non-persistent), like
  the deny counter and kill-gate. For production retention, tee it to durable storage; horizontal
  scaling needs shared state or sticky routing.
- The `_diagnostic` payload **carries the full OBO** in the response. That is a deliberate
  observability choice for a demo/reference build - it lets a UI *show* the token. Before any
  external trust boundary, decide whether to redact it: a raw OBO in a response body is a bearer
  token. The envelope makes the security visible; make sure you are the only one watching.

## The principle

Build the security so it can be *seen*. Not because opacity is insecure, but because unseeable
security cannot be trusted, demonstrated, or debugged - and a control nobody can verify is a
control nobody will keep.
