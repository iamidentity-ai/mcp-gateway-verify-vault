/**
 * Gateway host — MCP gateway
 *
 * Express host that fronts an unmodified ("naive") upstream MCP server with
 * Token Exchange (RFC 8693) + RAR (RFC 9396) + Vault verify-rar ephemeral
 * Postgres creds + SSF/CAEP session-kill, all wired through pipeline.ts's
 * runPipeline / completePending. Two transports share one dispatcher, and
 * the MCP face uses a per-request stateless transport.
 *
 * Routes:
 *   GET  /healthz          -> { status: 'ok' }
 *   POST /mcp               south MCP face (real MCP protocol, Streamable
 *                            HTTP, stateless — fresh server+transport per
 *                            request). tools/call -> runPipeline.
 *   POST /tool               REST { name, arguments } -> runPipeline.
 *   POST /hitl/complete      { txId, verdict? } -> completePending, IDENTITY
 *                            BOUND: the caller's own bearer is introspected
 *                            and its verifyUserId must match the pending
 *                            transaction's owner or the call 403s before
 *                            touching pollOAuthMfaStatus/the deny counter/
 *                            session-kill (security-review CRITICAL fix —
 *                            previously any bearer could complete/kill ANY
 *                            known txId). `verdict` is a dev/test escape
 *                            hatch, GATED behind GATEWAY_ALLOW_TEST_VERDICT
 *                            === '1' (see below); normal operation always
 *                            polls the real Verify verification transaction
 *                            regardless of what the request body sends.
 *   GET  /me/audit           bearer -> getAuditForUser(verifyUserId).
 *   GET  /me/session-status  bearer -> introspectUser + local kill-gate.
 *
 * BEARER GATE FIRST on every user-facing route — presence checked before
 * any body parsing / tool lookup. If you put this host behind a tunnel or
 * reverse proxy, remember the tunnel is NOT a security layer: this bearer
 * gate is the exposure boundary.
 */

import 'dotenv/config';
import express, { type Request, type Response } from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { runPipeline, completePending, type PipelineResult } from './pipeline.js';
import { introspectUser } from './auth/introspect.js';
import { isSessionKilled } from './ssf/killed-sessions.js';
import { getAuditForUser } from './audit/chain.js';

const PORT = Number(process.env['PORT'] ?? 3014);
/** Service name — used in log prefixes and as the MCP server identity.
 *  Override via GATEWAY_SERVICE_NAME when running multiple gateways. */
const SERVICE = process.env['GATEWAY_SERVICE_NAME'] || 'mcp-gateway';

const app = express();
app.use(express.json({ limit: '1mb' }));

app.get('/healthz', (_req: Request, res: Response) => {
  res.json({ status: 'ok' });
});

// ── Bearer gate — presence check FIRST, before body/tool lookup ──────────
function requireBearer(req: Request, res: Response): string | undefined {
  const bearer = (req.header('authorization') || '').replace(/^Bearer /i, '');
  if (!bearer) {
    res.status(401).json({ error: 'missing_bearer' });
    return undefined;
  }
  return bearer;
}

/**
 * Map a PipelineResult to an HTTP response. Shared by both /mcp and /tool
 * so the two transports never drift on status-code semantics.
 */
function statusCodeFor(result: PipelineResult): number {
  switch (result.status) {
    case 'ok':
      return 200;
    case 'pending':
      return 202;
    case 'denied':
      return 403;
    case 'session_killed_suspicious':
      return 401;
    case 'error':
      if (result.error === 'forbidden') return 403;
      return result.error === 'inactive_session' || result.error === 'session_killed' ? 401 : 500;
  }
}

/** One MCP `CallToolResult` text-content block, as a typical naive MCP
 *  server's tool handlers return it (no `structuredContent` — every tool
 *  does literally
 *  `return { content: [{ type: 'text', text: JSON.stringify(result) }] }`). */
interface McpTextContent {
  type: 'text';
  text: string;
  [key: string]: unknown;
}

function looksLikeMcpTextResult(value: unknown): value is { content: McpTextContent[] } {
  if (typeof value !== 'object' || value === null) return false;
  const content = (value as { content?: unknown }).content;
  if (!Array.isArray(content) || content.length === 0) return false;
  const first = content[0] as { type?: unknown; text?: unknown } | undefined;
  return !!first && first.type === 'text' && typeof first.text === 'string';
}

/**
 * Unwrap the MCP `CallToolResult` envelope that `callUpstreamTool`
 * (proxy/upstream.ts) hands back verbatim from the real
 * `@modelcontextprotocol/sdk` `Client.callTool()` call.
 *
 * This is the actual "happy path breaks" bug, not just the top-level
 * status/ok naming: `PipelineResult['data']` for an `'ok'` result is, in
 * production, `{ content: [{ type: 'text', text: '<JSON string>' }] }` —
 * NOT the record object a UI route would destructure fields off of
 * directly (`record.display_name`, `.classification`, …). Left unwrapped, every
 * one of those reads would be `undefined`. `pipeline.test.ts`'s own mocks
 * for `callUpstreamTool`
 * return plain objects (e.g. `{ ok: true, record: {...} }`), so this stays
 * defensive: only unwraps a value that actually looks like an MCP
 * text-content result, and falls back to the value verbatim (never throws)
 * if `content[0].text` isn't valid JSON — e.g. a future tool that returns
 * `structuredContent` instead, or a genuinely non-JSON text reply.
 */
function unwrapToolData(data: unknown): unknown {
  if (!looksLikeMcpTextResult(data)) return data;
  try {
    return JSON.parse(data.content[0].text);
  } catch {
    return data;
  }
}

/**
 * Map a PipelineResult to the `{ ok, data, _diagnostic }` / `{ ok: false,
 * ... }` envelope that UI/agent clients read off the /tool JSON body
 * (`_diagnostic.oboJti/oboTtl/oboScope/cred` is the observability contract
 * downstream agent logs consume — all non-secret metadata; the raw OBO
 * bearer token is deliberately never included).
 *
 * Pure — takes only the PipelineResult, no I/O. Shared by /tool (JSON body
 * directly) and /mcp (JSON-stringified into the MCP text-content block) so
 * the two transports never drift. `statusCodeFor` is UNCHANGED and still
 * drives the HTTP status code on /tool — this only reshapes the body.
 *
 * When the pipeline supplies no `diag`, `_diagnostic` is `{}` — this mapper
 * never fabricates values it doesn't have. The populated case carries the
 * pipeline's OboDiag so a UI's audit-trace ribbon and elevated lease/cred
 * display can light up.
 */
export function pipelineResultToEnvelope(result: PipelineResult): Record<string, unknown> {
  switch (result.status) {
    case 'ok':
      // `diag` is the pipeline's OboDiag (oboJti/oboTtl/oboScope/cred/
      // elevated) — the `_diagnostic` contract a UI's agent log and
      // audit-trace ribbon read. All non-secret: the raw OBO bearer token
      // is never exposed to clients (it is a replayable credential).
      return { ok: true, data: unwrapToolData(result.data), _diagnostic: result.diag ?? {} };
    case 'pending':
      return { ok: false, pending: true, txId: result.txId, pushInfo: result.pushInfo };
    case 'denied':
      return { ok: false, denied: true, reason: result.reason };
    case 'session_killed_suspicious':
      return { ok: false, killed: true, reason: 'suspicious' };
    case 'error':
      return { ok: false, error: result.error };
  }
}

// ── Shared dispatcher both transports call ────────────────────────────────
async function dispatchTool(toolName: string, args: Record<string, unknown>, bearer: string): Promise<PipelineResult> {
  return runPipeline({ userToken: bearer, toolName, args });
}

// ── Transport 1: POST /tool (simple REST, curl-friendly) ─────────────────
app.post('/tool', async (req: Request, res: Response) => {
  const bearer = requireBearer(req, res);
  if (!bearer) return;

  const body = (req.body ?? {}) as Record<string, unknown>;
  const name = (body['name'] ?? body['toolName']) as string | undefined;
  const args = (body['arguments'] ?? body['args'] ?? {}) as Record<string, unknown>;
  if (!name) return res.status(400).json({ error: 'missing_name' });

  try {
    const result = await dispatchTool(name, args, bearer);
    res.status(statusCodeFor(result)).json(pipelineResultToEnvelope(result));
  } catch (err) {
    const e = err as Error;
    // Log the real error server-side ONLY; the client gets a stable generic
    // envelope. e.message can carry internal topology (Vault paths, tenant
    // error codes) or, via mint, secret material — never echo it to the caller.
    console.error(`[${SERVICE}] /tool dispatch failed:`, e.message);
    res.status(500).json(pipelineResultToEnvelope({ status: 'error', error: 'tool_error' }));
  }
});

/**
 * Resolve the dev/test verdict override from a /hitl/complete request body.
 * GATED behind `env.GATEWAY_ALLOW_TEST_VERDICT === '1'` — outside that
 * flag, a request-body `verdict` is unconditionally ignored (returns
 * `undefined`), forcing completePending to derive the verdict from the real
 * pollOAuthMfaStatus poll against Verify instead of trusting client input.
 *
 * Pure + exported (no I/O, `env` injectable) so this specific
 * security-relevant gating decision can be unit tested (see index.test.ts)
 * without booting the Express app.
 */
export function resolveTestVerdictOverride(
  body: Record<string, unknown>,
  env: NodeJS.ProcessEnv = process.env,
): 'approved' | 'denied' | 'denied_suspicious' | 'timeout' | undefined {
  if (env['GATEWAY_ALLOW_TEST_VERDICT'] !== '1') return undefined;
  return body['verdict'] as 'approved' | 'denied' | 'denied_suspicious' | 'timeout' | undefined;
}

// ── POST /hitl/complete — resume a parked mfa_challenge ───────────────────
//
// Body: { txId: string, verdict?: 'approved' | 'denied' | 'denied_suspicious'
//         | 'timeout', assertion?: string, reason?: string }
//
// IDENTITY BOUND (security-review CRITICAL fix): the caller's OWN bearer is
// introspected first — its verifyUserId is passed to completePending, which
// rejects (403 forbidden) unless it matches the pending transaction's owner.
// Without this, presence-only bearer checking let any caller who learned
// another user's txId force a session-kill on that victim via
// verdict:'denied_suspicious' with zero Verify interaction.
//
// `verdict` is a dev/test escape hatch for driving this route without a live
// phone (used by integration scripts) — but it is GATED behind
// process.env.GATEWAY_ALLOW_TEST_VERDICT === '1'. Outside that flag, the
// request body's `verdict` is ignored entirely and completePending always
// derives the verdict from the real pollOAuthMfaStatus poll against Verify.
app.post('/hitl/complete', async (req: Request, res: Response) => {
  const bearer = requireBearer(req, res);
  if (!bearer) return;

  const body = (req.body ?? {}) as Record<string, unknown>;
  const txId = body['txId'] as string | undefined;
  if (!txId) return res.status(400).json({ error: 'missing_txId' });

  const introspection = await introspectUser(bearer);
  const callerVerifyUserId = introspection.active ? introspection.verifyUserId : undefined;

  const verdict = resolveTestVerdictOverride(body);

  try {
    const result = verdict
      ? await completePending(txId, callerVerifyUserId, {
        pollOAuthMfaStatus: async () => {
          if (verdict === 'approved') {
            return { state: 'approved', assertion: (body['assertion'] as string) ?? 'test-assertion' };
          }
          if (verdict === 'timeout') return { state: 'timeout' };
          return { state: verdict, reason: (body['reason'] as string) ?? verdict };
        },
      })
      : await completePending(txId, callerVerifyUserId);
    // Return the SAME `{ ok, data, _diagnostic }` envelope as /tool and /mcp —
    // a consumer resuming a step-up must not get a different shape than the
    // one that parked it (statusCodeFor still drives the HTTP status off the
    // raw result). completePending's `ok` result carries `diag`, so the
    // approved elevated read surfaces its OBO + elevated-scoped cred here too.
    res.status(statusCodeFor(result)).json(pipelineResultToEnvelope(result));
  } catch (err) {
    const e = err as Error;
    console.error(`[${SERVICE}] /hitl/complete failed:`, e.message);
    res.status(500).json(pipelineResultToEnvelope({ status: 'error', error: 'hitl_complete_error' }));
  }
});

// ── GET /me/audit ───────────────────────────────────────────────────────
app.get('/me/audit', async (req: Request, res: Response) => {
  const bearer = requireBearer(req, res);
  if (!bearer) return;

  const introspection = await introspectUser(bearer);
  if (!introspection.active || !introspection.verifyUserId) {
    return res.status(401).json({ error: 'inactive_session' });
  }

  const limitRaw = req.query['limit'];
  const limit = typeof limitRaw === 'string' && Number.isFinite(Number(limitRaw)) ? Number(limitRaw) : undefined;

  res.json({ records: getAuditForUser(introspection.verifyUserId, limit) });
});

// ── GET /me/session-status — bearer liveness + local kill-gate check ─────
app.get('/me/session-status', async (req: Request, res: Response) => {
  const bearer = requireBearer(req, res);
  if (!bearer) return;

  try {
    const introspection = await introspectUser(bearer);
    if (!introspection.active) {
      return res.status(401).json({ active: false, reason: 'session_revoked' });
    }
    if (introspection.verifyUserId && isSessionKilled(introspection.verifyUserId)) {
      return res.status(401).json({ active: false, reason: 'session_killed' });
    }
    return res.json({ active: true, email: introspection.email, sub: introspection.verifyUserId });
  } catch (e) {
    const err = e as Error;
    console.error(`[${SERVICE}] /me/session-status failed:`, err.message);
    return res.status(503).json({ active: false, reason: 'verify_unreachable' });
  }
});

// ── Transport 2: POST /mcp (real MCP protocol over Streamable HTTP) ──────
//
// The tool surface (names + titles + descriptions + zod inputSchemas) is built
// ONCE at module load — `MCP_TOOL_SPECS` — so the per-request buildMcpServer
// does not reconstruct 7 zod schemas on every /mcp call.
//
// The McpServer itself is STILL created per request (not a shared global). This
// is deliberate: `server.connect(transport)` binds the server's Protocol to a
// SINGLE transport, and /mcp is stateless (`sessionIdGenerator: undefined`) with
// a fresh transport per request. Sharing one server across concurrent requests
// would clobber that per-connection binding — a known MCP transport-desync bug.
// So we amortize the schema construction (the real cost) but keep per-request
// isolation. Every tool routes through runPipeline — the gateway never talks to
// the database or the upstream MCP directly.
interface McpToolSpec {
  name: string;
  config: { title: string; description: string; inputSchema: z.ZodRawShape };
}

const MCP_TOOL_SPECS: McpToolSpec[] = [
  {
    name: 'get_record',
    config: {
      title: 'Get a record',
      description: 'Returns a single record by record id. Step-up on restricted records is gateway-derived; the caller never requests elevation.',
      inputSchema: { recordId: z.string() },
    },
  },
  {
    name: 'list_records',
    config: {
      title: "List an owner's records",
      description: 'Returns every record assigned to the given owner, by owner UPN.',
      inputSchema: { ownerUpn: z.string() },
    },
  },
  {
    name: 'get_record_history',
    config: {
      title: 'Get history for a record',
      description: 'Returns every history entry filed against a record id, most recent first.',
      inputSchema: { recordId: z.string() },
    },
  },
  {
    name: 'get_record_detail',
    config: {
      title: 'Get record detail lines',
      description:
        'Tier 1 read — every detail line under a record id with level and status. Token Exchange only. The read counterpart to update_record.',
      inputSchema: { recordId: z.string() },
    },
  },
  {
    name: 'update_record',
    config: {
      title: 'Update a record field',
      description: 'Sets a field on the record identified by record id. Tier 2 — one Verify-policy push.',
      inputSchema: { recordId: z.string(), field: z.string(), value: z.string() },
    },
  },
  {
    name: 'update_contact',
    config: {
      title: "Update a record's contact email",
      description: 'Sets the contact email on a record, by record id. Tier 3 — push every call.',
      inputSchema: { recordId: z.string(), email: z.string() },
    },
  },
  {
    name: 'delete_record',
    config: {
      title: 'Delete a record',
      description: 'Tier 4 — blocked by policy. Always denied before Verify is ever contacted.',
      inputSchema: { recordId: z.string() },
    },
  },
];

/** Test/introspection helper: the /mcp tool names, in registration order. */
export const mcpToolNames = (): string[] => MCP_TOOL_SPECS.map((s) => s.name);

function buildMcpServer(bearer: string): McpServer {
  const server = new McpServer({ name: SERVICE, version: '0.1.0' });

  const call = async (name: string, args: Record<string, unknown>) => {
    const result = await dispatchTool(name, args, bearer);
    return { content: [{ type: 'text' as const, text: JSON.stringify(pipelineResultToEnvelope(result)) }] };
  };

  for (const spec of MCP_TOOL_SPECS) {
    server.registerTool(spec.name, spec.config, async (args) => call(spec.name, args as Record<string, unknown>));
  }

  return server;
}

app.post('/mcp', async (req: Request, res: Response) => {
  const bearer = requireBearer(req, res);
  if (!bearer) return;

  const server = buildMcpServer(bearer);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on('close', () => {
    transport.close();
    server.close();
  });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`[${SERVICE}] listening on http://127.0.0.1:${PORT}`);
});
