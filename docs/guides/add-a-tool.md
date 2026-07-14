# Add a tool

Adding a tool to an already-secured gateway is a **config edit plus, if you use the `/mcp`
transport, one schema declaration**. This guide walks the full checklist with a worked example:
adding a `get_record_notes` tier-1 read.

## The one question first: which tier?

Every tool gets a tier. The tier is the whole authorization posture:

| Tier | Meaning | Enforcement |
|---|---|---|
| 1 | Read | Token Exchange only - no step-up. |
| 2 | Write | Token Exchange + RAR; one policy-driven push. |
| 3 | Sensitive | Push on **every** call. |
| 4 | Blocked | Denied at the gate - Verify is never contacted. |

Pick the tier by blast radius, not by convenience. A read that exposes a sensitive row belongs in
tier 1 only if you rely on the [classification discovery probe](../concepts/human-in-the-loop.md) to
force step-up on the sensitive rows; otherwise consider the elevated path.

## ☐ 1. Add the tier-map entry - `config/tools.json`

```jsonc
{
  "...": "...",
  "get_record_notes": { "tier": 1, "rarAction": "record_read", "scope": "records:read" }
}
```

- **`tier`** - from the table above.
- **`rarAction`** - the RFC 9396 action this tool maps to. Reuse an existing action
  (`record_read` / `record_write`) unless the tool needs its own Vault role; a new action means a
  new `config/rar.json` entry and a new `verify-rar` role (see [bring your own MCP](bring-your-own-mcp.md)).
- **`scope`** - the coarse OAuth scope. Reuse the tier's scope; if it's a genuinely new scope, add
  it to the tool's registered scopes on the Verify Token-Exchange app (re-run `bootstrap:verify`).

That's it for the REST `/tool` transport - the tier gate reads this file, so the new tool is now
gated, exchanged, and minted-for exactly like its tier-mates. **No code.**

## ☐ 2. Register the MCP surface (only if clients use `/mcp`)

Clients on `/tool` need nothing more. For the real MCP transport, add the tool's `registerTool` +
zod schema in `gateway/src/index.ts` so the MCP server advertises it. This is a **schema
declaration, not logic** - the handler just routes into the same `runPipeline` dispatcher:

```ts
server.registerTool(
  "get_record_notes",
  {
    title: "Get notes for a record",
    description: "Tier 1 read - every note filed against a record id. Token Exchange only.",
    inputSchema: { recordId: z.string() },
  },
  async (args) => call("get_record_notes", args),
);
```

Keep the `inputSchema` argument names in sync with what your upstream MCP expects - and with
`config/rar.json`'s `argIdKey` (`recordId` under the default config), since the pipeline reads the
domain id off `args[argIdKey]`.

## ☐ 3. Make sure the upstream MCP actually has the tool

The gateway proxies to your naive MCP verbatim. If `get_record_notes` isn't a tool the upstream
server exposes, the call reaches the upstream and fails there. Add it upstream first (the
[example naive MCP](../../examples/naive-mcp/src/index.ts) shows the pattern - a pure-SQL function
plus a `registerTool`), then front it with the gateway.

## ☐ 4. If it's a genuinely new operation, not just a new tool

If the tool represents a new *kind* of operation (not just another read or write), you may need:

- a new **`config/rar.json` action** with its own `credsPath`, and
- a new **`verify-rar` Vault role** for that creds path (re-run `bootstrap:vault`), and
- possibly a new **CELX attribute + access-policy rule** if it should step up differently
  (re-run `bootstrap:verify`; see [step-up policies](step-up-policies.md)).

For a tool that reuses an existing action (the common case), none of this applies - step 1 (and
step 2 for `/mcp`) is the whole job.

## ☐ 5. Verify

```bash
npm test          # the tier map + RAR loader are covered by unit tests
npm run typecheck # catches an /mcp schema that doesn't match its handler
```

Then drive it against a running gateway with the same two-curl pattern from the
[quickstart](quickstart.md#step-5--prove-it-two-curls) - a `200` with a populated `_diagnostic`
confirms the new tool went through the full exchange+mint path.

## What you did *not* touch

The pipeline, the token exchange, the Vault mint, the HITL sequencing, the audit chain - untouched.
A new tier-1/2/3 tool inherits all of it from its tier. That is the payoff of the data-driven tier
map: the security is the stable part; the tool list is config.
