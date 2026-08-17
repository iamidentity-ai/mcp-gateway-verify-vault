# Any agent: client adapters

The gateway is **agent-agnostic by construction**. Nothing in the pipeline knows or cares what
reasoning loop sits north of it. This guide gives you copy-paste adapters for the common callers -
raw `fetch`, the MCP SDK client, a LangChain tool wrapper, a Claude custom-tool loop, a Strands
agent, and an OpenAI Agents SDK agent - all showing the one thing every caller must get right: the
**`202 pending` → `/hitl/complete`** handoff.

## The whole contract, restated

**North contract (two lines):**

1. Present the **user's OAuth bearer** (any access token from an OIDC login on your Verify tenant).
2. Speak **MCP** (`POST /mcp`, a real `tools/call`) *or* **REST** (`POST /tool { name, arguments }`).

**The one integration rule - read the envelope, not the HTTP status:**

| Envelope | HTTP | Meaning | What the caller does |
|---|---|---|---|
| `{ ok: true, data, _diagnostic }` | 200 | Success. | Use `data`. |
| `{ ok: false, pending: true, txId, requestState, pushInfo }` | 202 | **Human approval in flight.** | Surface the push; poll `POST /hitl/complete { txId }` with the **same bearer**. |
| `{ ok: false, denied: true, reason }` | 403 | Policy denied (tier 4 / unknown tool / MFA denied). | Stop; surface `reason`. |
| `{ ok: false, killed: true, reason }` | 401 | Session killed (suspicious). | Re-authenticate the user. |
| `{ ok: false, error }` | 403 | Forbidden (wrong bearer resuming a `txId`) or `invalid_request_state` (the echoed `requestState` failed verification). | Retry with the correct bearer, or retry with just `txId`. |
| `{ ok: false, error }` | 401 / 500 | Inactive session / server error. | Retry or re-auth per `error`. |

A caller that ignores `pending` does **not** break security - the record is withheld regardless. It
just can't complete step-up actions. See [the consumer contract](../concepts/human-in-the-loop.md#the-consumer-contract-202-pending-is-resok).

What the agent **never** receives: DB credentials, Vault tokens, or the OBO's signing authority.

---

## Five-minute checklist

1. Get a user bearer - any access token from an OIDC login on your Verify tenant.
2. Confirm reachability:
   ```bash
   curl -sS -X POST localhost:3014/tool -H "Authorization: Bearer <bearer>" -H 'Content-Type: application/json' \
     -d '{"name":"get_record","arguments":{"recordId":"REC-1001"}}'
   ```
3. Wire **one** tool with the adapter matching your stack: [1](#adapter-1---raw-fetch-the-reference) fetch · [2](#adapter-2---the-mcp-sdk-client-mcp) MCP SDK · [3](#adapter-3---a-langchain-tool-wrapper) LangChain · [4](#adapter-4---a-claude-custom-tool-loop) Claude · [5](#adapter-5---strands-python) Strands · [6](#adapter-6---openai-agents-sdk-python) OpenAI Agents SDK.
4. Handle `pending` per [the envelope table](#the-whole-contract-restated) above - read the envelope, not the HTTP status.
5. Stuck? See [troubleshooting](../reference/troubleshooting.md) - a real error ladder, not FAQ guesses.

---

## Adapter 1 - raw `fetch` (the reference)

This is the whole thing in ~40 lines. Every other adapter is a wrapper around this shape.

```ts
type Envelope =
  | { ok: true; data: unknown; _diagnostic: Record<string, unknown> }
  | { ok: false; pending: true; txId: string; requestState?: string; pushInfo?: { title: string; message: string } }
  | { ok: false; denied?: true; killed?: true; reason?: string; error?: string };

const GATEWAY = "http://127.0.0.1:3014";

/** Call a gateway tool. Resolves a `pending` step-up by polling /hitl/complete
 *  with the SAME bearer (identity-bound - a different user's bearer 403s). */
async function callGatewayTool(
  name: string,
  args: Record<string, unknown>,
  bearer: string,
): Promise<Envelope> {
  const res = await fetch(`${GATEWAY}/tool`, {
    method: "POST",
    headers: { Authorization: `Bearer ${bearer}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name, arguments: args }),
  });
  const body = (await res.json()) as Envelope;

  // 202 → human approval in flight. Surface the push, then resolve.
  if (!body.ok && "pending" in body && body.pending) {
    console.log(`Approve on your phone: ${body.pushInfo?.message ?? "step-up required"}`);
    // /hitl/complete polls the real Verify verification transaction until a
    // terminal verdict (approved / denied / timeout) - one call is enough.
    const done = await fetch(`${GATEWAY}/hitl/complete`, {
      method: "POST",
      headers: { Authorization: `Bearer ${bearer}`, "Content-Type": "application/json" },
      body: JSON.stringify({ txId: body.txId }),
    });
    return (await done.json()) as Envelope;
  }
  return body;
}
```

Because `/hitl/complete` is **identity-bound**, you must pass the *same* user's bearer that started
the call - the gateway introspects it and 403s a mismatch before touching the transaction.

---

## Adapter 2 - the MCP SDK client (`/mcp`)

The gateway's `/mcp` face speaks real MCP over Streamable HTTP. Use `@modelcontextprotocol/sdk`;
put the user's bearer on the transport's request headers. The tool result comes back as the MCP
`CallToolResult` - the gateway's envelope is the JSON string in `content[0].text`.

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

async function callViaMcp(name: string, args: Record<string, unknown>, bearer: string) {
  const transport = new StreamableHTTPClientTransport(new URL("http://127.0.0.1:3014/mcp"), {
    requestInit: { headers: { Authorization: `Bearer ${bearer}` } },
  });
  const client = new Client({ name: "my-agent", version: "1.0.0" });
  await client.connect(transport);
  try {
    const result = await client.callTool({ name, arguments: args });
    // The gateway's envelope is JSON-stringified into the first text block.
    const text = (result.content as Array<{ type: string; text?: string }>)[0]?.text ?? "{}";
    const envelope = JSON.parse(text);
    // Same pending handling as Adapter 1 - but /hitl/complete is REST, so most
    // callers resolve step-up over /tool + /hitl/complete even when reading via /mcp.
    return envelope;
  } finally {
    await client.close();
  }
}
```

The MCP tool list the gateway advertises (`get_record`, `list_records`, `update_record`,
`update_contact`, `delete_record`, …) mirrors [`config/tools.json`](../../gateway/config/tools.json).

---

## Adapter 3 - a LangChain tool wrapper

Wrap the gateway as a LangChain tool so any LangChain/LangGraph agent can call it. An **autonomous**
agent can't tap a phone, so the wrapper returns a clear signal on `pending` - either resolve it in
the orchestrator (as below) or surface it to a human-in-the-loop node.

```ts
import { DynamicStructuredTool } from "@langchain/core/tools";
import { z } from "zod";

/** One LangChain tool per gateway tool. The user's bearer is captured at
 *  construction (per-user agent instance) - never taken from model output. */
function makeGetRecordTool(bearer: string) {
  return new DynamicStructuredTool({
    name: "get_record",
    description: "Fetch a customer record by id. Restricted records require a human approval.",
    schema: z.object({ recordId: z.string() }),
    func: async ({ recordId }) => {
      const env = await callGatewayTool("get_record", { recordId }, bearer); // Adapter 1
      if (env.ok) return JSON.stringify(env.data);
      if ("pending" in env && env.pending) {
        // callGatewayTool already polled /hitl/complete once; if it's STILL
        // pending, tell the model a human must approve - it cannot proceed.
        return "APPROVAL_REQUIRED: a step-up push was sent to the user's phone. " +
          "This record cannot be read until the user approves.";
      }
      return `DENIED: ${("reason" in env && env.reason) || ("error" in env && env.error)}`;
    },
  });
}
```

The load-bearing choices: the **bearer is captured at construction** (one tool instance per signed-in
user), never read from the model's arguments; and a still-`pending` result becomes a plain string the
model can reason about rather than an exception that aborts the run.

---

## Adapter 4 - a Claude custom-tool loop

A manual [tool-use loop](https://docs.claude.com/en/docs/agents-and-tools/tool-use/overview) with the
Anthropic SDK. Claude decides when to call `get_record`; your loop executes it against the gateway
(resolving step-up), and feeds the result back as a `tool_result`.

```ts
import Anthropic from "@anthropic-ai/sdk";

const anthropic = new Anthropic();

async function runAgent(userPrompt: string, bearer: string) {
  const tools: Anthropic.Tool[] = [
    {
      name: "get_record",
      description: "Fetch a customer record by id. Restricted records trigger a human approval push.",
      input_schema: {
        type: "object",
        properties: { recordId: { type: "string" } },
        required: ["recordId"],
      },
    },
  ];
  const messages: Anthropic.MessageParam[] = [{ role: "user", content: userPrompt }];

  while (true) {
    const res = await anthropic.messages.create({
      model: "claude-opus-4-8",
      max_tokens: 1024,
      tools,
      messages,
    });
    if (res.stop_reason !== "tool_use") return res; // done

    messages.push({ role: "assistant", content: res.content });
    const toolResults: Anthropic.ToolResultBlockParam[] = [];
    for (const block of res.content) {
      if (block.type !== "tool_use") continue;
      // Execute against the gateway with the USER's bearer (not anything the
      // model produced). callGatewayTool resolves any step-up via /hitl/complete.
      const env = await callGatewayTool(block.name, block.input as Record<string, unknown>, bearer);
      toolResults.push({
        type: "tool_result",
        tool_use_id: block.id,
        content: JSON.stringify(env),
        is_error: !env.ok,
      });
    }
    messages.push({ role: "user", content: toolResults });
  }
}
```

Same discipline as the LangChain adapter: the **user's bearer is the gateway's identity**, passed by
your loop - never sourced from `block.input`. A `pending`/`denied` envelope goes back to Claude as a
`tool_result` (`is_error: true`) so it can respond appropriately, not as a thrown error.

---

## Adapter 5 - Strands (Python)

[Strands](https://strandsagents.com/) is AWS's Python agent SDK. Point its `MCPClient` at the
gateway's `/mcp` face over Streamable HTTP, put the user's bearer on the transport headers, and hand
the discovered tools to an `Agent`.

```python
import json
import os

import requests
from mcp.client.streamable_http import streamablehttp_client
from strands import Agent
from strands.tools.mcp import MCPClient

GATEWAY = os.environ.get("GATEWAY_URL", "http://127.0.0.1:3014")


# Strands' MCPClient.call_tool_sync/call_tool_async return an MCPToolResult - a
# TypedDict (it extends Strands' own ToolResult TypedDict, not a real class), so
# it's a plain dict at runtime. getattr(result, "content", []) silently returns
# the default instead of raising; the inner content blocks are TypedDicts too, so
# `.text` attribute access fails silently the same way. This has broken real
# integrations twice - always go through accessors that check both shapes.
def _content_blocks(r) -> list:
    if isinstance(r, dict):
        return r.get("content") or []
    return getattr(r, "content", None) or []


def _block_text(b) -> str:
    if isinstance(b, dict):
        return b.get("text") or ""
    return getattr(b, "text", "") or ""


def call_gateway_tool(mcp_client: MCPClient, name: str, arguments: dict, bearer: str) -> dict:
    """Call a gateway tool over MCP, then resolve a `pending` step-up over REST
    with the SAME bearer - /hitl/complete stays REST regardless of which
    transport started the call."""
    result = mcp_client.call_tool_sync(tool_use_id=name, name=name, arguments=arguments)
    blocks = _content_blocks(result)
    envelope = json.loads(_block_text(blocks[0])) if blocks else {}

    if not envelope.get("ok") and envelope.get("pending"):
        push = envelope.get("pushInfo") or {}
        print(f"Approve on your phone: {push.get('message', 'step-up required')}")
        resp = requests.post(
            f"{GATEWAY}/hitl/complete",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"txId": envelope["txId"]},
        )
        return resp.json()
    return envelope


bearer = os.environ["USER_BEARER"]
mcp_client = MCPClient(lambda: streamablehttp_client(
    url=f"{GATEWAY}/mcp",
    headers={"Authorization": f"Bearer {bearer}"},
))

with mcp_client:
    tools = mcp_client.list_tools_sync()
    agent = Agent(tools=tools)
    agent("Look up record REC-1001")  # autonomous loop, tool picked by the model

    # Direct call when your code - not the model - needs the envelope, e.g. to
    # resolve step-up deterministically instead of leaving it to the agent loop.
    envelope = call_gateway_tool(mcp_client, "get_record", {"recordId": "REC-9001"}, bearer)
```

The trap is easy to miss because it never raises: `getattr(result, "content", [])` on a dict quietly
returns `[]`, and code that "handles" an empty result drops every real tool response without an error
anywhere in the stack. Use the accessors above, or index the dict directly once you know its shape.

---

## Adapter 6 - OpenAI Agents SDK (Python)

The [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/) speaks MCP natively via
`MCPServerStreamableHttp`. Its `params` dict takes the URL and headers directly - same
bearer-on-headers shape as every other adapter, used as an async context manager.

```python
import asyncio
import json
import os

import httpx
from agents import Agent, Runner
from agents.mcp import MCPServerStreamableHttp

GATEWAY = os.environ.get("GATEWAY_URL", "http://127.0.0.1:3014")


async def call_gateway_tool(server: MCPServerStreamableHttp, name: str, arguments: dict, bearer: str) -> dict:
    """Call a gateway tool over MCP, then resolve a `pending` step-up over REST
    with the SAME bearer - /hitl/complete stays REST regardless of transport."""
    result = await server.call_tool(name, arguments)
    envelope = json.loads(result.content[0].text)

    if not envelope.get("ok") and envelope.get("pending"):
        push = envelope.get("pushInfo") or {}
        print(f"Approve on your phone: {push.get('message', 'step-up required')}")
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{GATEWAY}/hitl/complete",
                headers={"Authorization": f"Bearer {bearer}"},
                json={"txId": envelope["txId"]},
            )
        return resp.json()
    return envelope


async def main():
    bearer = os.environ["USER_BEARER"]
    async with MCPServerStreamableHttp(
        name="records gateway",
        params={"url": f"{GATEWAY}/mcp", "headers": {"Authorization": f"Bearer {bearer}"}},
    ) as server:
        agent = Agent(
            name="Records Assistant",
            instructions="Use the tools to answer questions about customer records.",
            mcp_servers=[server],
        )
        result = await Runner.run(agent, "Look up record REC-1001")
        print(result.final_output)

        # Direct call when your code needs the envelope deterministically.
        envelope = await call_gateway_tool(server, "get_record", {"recordId": "REC-9001"}, bearer)
        print(envelope)


if __name__ == "__main__":
    asyncio.run(main())
```

Unlike Strands, `server.call_tool()` here returns the MCP SDK's own `CallToolResult` - a real object,
not a TypedDict - so `result.content[0].text` is safe attribute access. The pending handoff is
identical either way: parse the envelope out of the text block, branch on `pending`, resolve over
REST with the same bearer.

---

## Why this works with anything

The six adapters differ only in *how the loop is driven*; the gateway call and the `pending` handoff
are identical in all of them. That is the point of a thin PEP on the path: the security contract is
the same two lines and one rule for `curl`, an MCP client, LangChain, Claude, Strands, or the OpenAI
Agents SDK - swap the reasoning loop freely. See [architecture](../concepts/architecture.md) for what
happens south of the call.
