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
 *   POST /hitl/complete      { txId, verdict?, otp? } -> completePending,
 *                            IDENTITY BOUND: the caller's own bearer is
 *                            introspected and its verifyUserId must match the
 *                            pending transaction's owner or the call 403s
 *                            before touching pollOAuthMfaStatus/the deny
 *                            counter/session-kill (security-review CRITICAL
 *                            fix — previously any bearer could complete/kill
 *                            ANY known txId). `verdict` is a dev/test escape
 *                            hatch, GATED behind GATEWAY_ALLOW_TEST_VERDICT
 *                            === '1' (see below); normal operation always
 *                            polls the real Verify verification transaction
 *                            regardless of what the request body sends. `otp`
 *                            is REQUIRED when HITL_METHOD=transient_email
 *                            parked the tx (400 otp_required if missing);
 *                            ignored for a push-parked tx.
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
import { isSessionKilled, readSubjectIssuedAt } from './ssf/killed-sessions.js';
import { getAuditForUser } from './audit/chain.js';
import { resolveBindingMode } from './auth/binding-mode.js';
import { verifyDpopProof } from './auth/dpop-verify.js';
import { validateMcpHeaders } from './mcp/header-validation.js';
import { tools as configuredToolPolicies, type ToolArgType, type ToolPolicy } from './policy/tiers.js';

const PORT = Number(process.env['PORT'] ?? 3014);
// Interface to bind. Defaults to loopback (safe for local dev). Set GATEWAY_BIND
// to 0.0.0.0 for container / systemd / reverse-proxied deploys where the port
// must be reachable off the loopback interface. See docs/guides/deploy-on-rhel.md.
const GATEWAY_BIND = process.env['GATEWAY_BIND'] || '127.0.0.1';
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

// ── Inbound DPoP enforcement (TOKEN_BINDING_MODE=full) ───────────────────
// htu binds to the URL the CALLER used. Behind a tunnel or LB that is the
// public hostname, so it must be configured; the local bind is the fallback
// for same-host development.
const PUBLIC_URL = (process.env['GATEWAY_PUBLIC_URL'] || `http://127.0.0.1:${PORT}`).replace(/\/+$/, '');

/** Gate a route on a valid caller proof in full mode. In none/outbound mode
 *  this is a no-op so the drop-in path stays untouched. Returns false after
 *  writing the 401, mirroring requireBearer's contract. */
async function requireDpopBound(req: Request, res: Response, bearer: string): Promise<boolean> {
  if (resolveBindingMode() !== 'full') return true;
  const proof = req.header('dpop');
  if (!proof) {
    res.status(401).json({ error: 'missing_dpop_proof' });
    return false;
  }
  const result = await verifyDpopProof({ proof, method: req.method, url: `${PUBLIC_URL}${req.path}`, accessToken: bearer });
  if (!result.ok) {
    res.status(401).json({ error: result.error });
    return false;
  }
  return true;
}

/**
 * Map a PipelineResult to an HTTP response. Shared by both /mcp and /tool
 * so the two transports never drift on status-code semantics. Exported
 * (like pipelineResultToEnvelope below) purely so this mapping is
 * unit-testable without booting a real HTTP round-trip — see index.test.ts.
 */
export function statusCodeFor(result: PipelineResult): number {
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
      // 'access_denied' is Verify's own Token Exchange rejecting the
      // request — a real policy hard-cap deny (CSIAQ0278E) OR a fresh-tenant
      // entitlement gap (CSIAQ0279E). Both come back as this exact error
      // string from auth/token-exchange.ts, so `denied: true` here proves
      // "Verify said no", not "the policy is correctly configured" — a
      // caller diagnosing a surprise deny still has to check which one.
      // No collision with any other TokenExchangeResult error string:
      // invalid_client/CSIAQ0155E is handled by the stale-secret retry
      // before this ever returns; invalid_scope/invalid_grant surface as
      // their own literal strings, distinct from 'access_denied'.
      if (result.error === 'forbidden' || result.error === 'access_denied') return 403;
      if (result.error === 'inactive_session' || result.error === 'session_killed') return 401;
      // transient_email HITL mode (HITL_METHOD=transient_email): caller-
      // correctable input errors, not server failures.
      if (
        result.error === 'otp_required' ||
        result.error === 'otp_invalid' ||
        result.error === 'otp_expired' ||
        result.error === 'mfa_no_email'
      ) {
        return 400;
      }
      // The pending tx's push/OTP trigger never actually fired (best-effort
      // trigger failed at park time) — nothing to complete. Not the caller's
      // fault and not a generic server error: 409 signals "this transaction
      // cannot be completed in its current state," distinct from the 500 a
      // genuinely unexpected exception still maps to.
      if (result.error === 'no_poll_url' || result.error === 'otp_init_failed') return 409;
      return 500;
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
      // `killed` rides along when this deny is the one that crossed the
      // deny-counter threshold and fired the session kill. Without it the
      // envelope was indistinguishable from an ordinary policy deny, so
      // every client — including this product's own reference UI, which
      // branches on `killed` to render a terminal "session ended" state —
      // treated the 3rd strike as a retryable deny and silently missed the
      // kill that had, in fact, already happened server-side. The HTTP
      // status stays 403 (see statusCodeFor): read the ENVELOPE, never the
      // status, is this product's contract, and moving the code would break
      // consumers that already special-case 401 for `inactive_session`.
      //
      // denyCount/denyThreshold appear on a tier-4 deny when
      // BLOCKED_ACTION_KILL is on, so a client can say "attempt 2 of 3 — at 3
      // this session is revoked" BEFORE the third one lands, instead of the
      // kill arriving as an unexplained surprise. Same two fields, same
      // meaning, as on the otp_invalid error case below.
      return {
        ok: false,
        denied: true,
        reason: result.reason,
        ...(result.killed ? { killed: true } : {}),
        ...(result.denyCount !== undefined ? { denyCount: result.denyCount } : {}),
        ...(result.denyThreshold !== undefined ? { denyThreshold: result.denyThreshold } : {}),
      };
    case 'session_killed_suspicious':
      return { ok: false, killed: true, reason: 'suspicious' };
    case 'error':
      // Mirrors the 403 in statusCodeFor: a Verify Token-Exchange
      // access_denied is a real deny, not a generic failure — give it the
      // same envelope shape ('denied: true') a caller already checks for
      // on the tier-4 local-gate 'denied' status, so both deny paths look
      // identical to a client. `error` stays present too (unlike the
      // tier-4 case, which has no error string) so a consumer that logs
      // the raw code for correlation still gets it.
      return result.error === 'access_denied'
        ? { ok: false, denied: true, error: result.error }
        : {
            ok: false,
            error: result.error,
            // transient_email HITL mode: how many tries are left on
            // otp_invalid, when Verify's response reported one.
            ...(result.attemptsRemaining !== undefined ? { attemptsRemaining: result.attemptsRemaining } : {}),
            // ...and how far this user is along THIS gateway's own
            // 3-strike kill threshold (a separate budget from Verify's
            // per-code retry count above). Present only on otp_invalid.
            ...(result.denyCount !== undefined ? { denyCount: result.denyCount } : {}),
            ...(result.denyThreshold !== undefined ? { denyThreshold: result.denyThreshold } : {}),
          };
  }
}

// ── Shared dispatcher both transports call ────────────────────────────────
async function dispatchTool(
  toolName: string,
  args: Record<string, unknown>,
  bearer: string,
  subjectEmail?: string,
): Promise<PipelineResult> {
  return runPipeline({ userToken: bearer, toolName, args, senderConstrained: resolveBindingMode() === 'full', subjectEmail });
}

/**
 * Server-to-server only — set by a trusted UI backend from the ORIGINAL IdP
 * subject token it already decoded at sign-in, never by the browser or the
 * model. See PipelineCtx.subjectEmail's doc in pipeline.ts. Shared by BOTH
 * transports (/tool and /mcp) so a caller-supplied subject email drives
 * transient-OTP delivery identically regardless of which one carried the
 * call — see buildMcpServer's use for /mcp, which previously had no path
 * for this header at all.
 */
function subjectEmailFromHeader(req: Request): string | undefined {
  const v = req.header('x-user-email');
  return v && v.includes('@') ? v : undefined;
}

// ── Transport 1: POST /tool (simple REST, curl-friendly) ─────────────────
app.post('/tool', async (req: Request, res: Response) => {
  const bearer = requireBearer(req, res);
  if (!bearer) return;
  if (!(await requireDpopBound(req, res, bearer))) return;

  const body = (req.body ?? {}) as Record<string, unknown>;
  const name = (body['name'] ?? body['toolName']) as string | undefined;
  const args = (body['arguments'] ?? body['args'] ?? {}) as Record<string, unknown>;
  if (!name) return res.status(400).json({ error: 'missing_name' });

  const subjectEmail = subjectEmailFromHeader(req);

  try {
    const result = await dispatchTool(name, args, bearer, subjectEmail);
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
//         | 'timeout', assertion?: string, reason?: string, otp?: string }
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
//
// `otp` is REQUIRED when HITL_METHOD=transient_email parked this tx
// (completePending 400s with otp_required if it's missing) — ignored for a
// push-parked tx. Passed straight through; completePending is what actually
// validates it against Verify's transient-verification endpoint.
app.post('/hitl/complete', async (req: Request, res: Response) => {
  const bearer = requireBearer(req, res);
  if (!bearer) return;
  if (!(await requireDpopBound(req, res, bearer))) return;

  const body = (req.body ?? {}) as Record<string, unknown>;
  const txId = body['txId'] as string | undefined;
  if (!txId) return res.status(400).json({ error: 'missing_txId' });
  const otp = body['otp'] as string | undefined;

  const introspection = await introspectUser(bearer);
  const callerVerifyUserId = introspection.active ? introspection.verifyUserId : undefined;

  const verdict = resolveTestVerdictOverride(body);

  try {
    const result = verdict
      ? await completePending(
        txId,
        callerVerifyUserId,
        {
          pollOAuthMfaStatus: async () => {
            if (verdict === 'approved') {
              return { state: 'approved', assertion: (body['assertion'] as string) ?? 'test-assertion' };
            }
            if (verdict === 'timeout') return { state: 'timeout' };
            return { state: verdict, reason: (body['reason'] as string) ?? verdict };
          },
        },
        otp,
      )
      : await completePending(txId, callerVerifyUserId, {}, otp);
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
  if (!(await requireDpopBound(req, res, bearer))) return;

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
  if (!(await requireDpopBound(req, res, bearer))) return;

  try {
    const introspection = await introspectUser(bearer);
    if (!introspection.active) {
      return res.status(401).json({ active: false, reason: 'session_revoked' });
    }
    // Same iat-aware gate the pipeline uses. Polling this endpoint with a
    // token minted AFTER the kill reports `active` again — without it a
    // user who has genuinely re-authenticated keeps seeing "Session ended"
    // and re-signing in forever (the login loop this gate caused live).
    if (
      introspection.verifyUserId &&
      isSessionKilled(introspection.verifyUserId, readSubjectIssuedAt(bearer))
    ) {
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
// does not reconstruct the zod schemas on every /mcp call.
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
  config: { title: string; description: string; inputSchema: z.ZodRawShape | z.ZodTypeAny };
}

/**
 * Hand-authored specs for the shipped reference tools (config/tools.json's
 * record_read/record_write vocabulary) — these get real per-field schemas
 * because this repo owns their argument shape.
 */
const KNOWN_TOOL_SPECS: McpToolSpec[] = [
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

/**
 * Every OTHER MCP tool call parks on a push and RETURNS the pending envelope
 * (`{ ok:false, pending:true, txId, pushInfo }`, unwrapped from the MCP
 * CallToolResult text block) instead of blocking the call — the `/mcp`
 * transport never polls Verify inline (see completeHitlForBearer's doc
 * comment for why). This tool is how an MCP client resumes that parked call
 * once the human has approved: it takes the txId and itself blocks until
 * pollOAuthMfaStatus reaches a terminal state, exactly like the REST
 * `/hitl/complete` route.
 */
const COMPLETE_HITL_TOOL_NAME = 'complete_hitl';
const COMPLETE_HITL_SPEC: McpToolSpec = {
  name: COMPLETE_HITL_TOOL_NAME,
  config: {
    title: 'Complete a pending human-in-the-loop approval',
    description:
      'Resumes a tool call that came back with pending:true and a txId (the human needs to approve a push or email code first — check pushInfo.method). Call this with that txId once the human says they approved it. If pushInfo.method was "email_otp", pass the 6-digit code the human read from their email as `otp` (REQUIRED in that case — omitting it returns otp_required). This call blocks until Verify\'s verification transaction reaches a terminal state (approved/denied/timeout) and then returns the SAME { ok, data, _diagnostic } envelope the original call would have returned had it not needed a step-up.',
    inputSchema: { txId: z.string(), otp: z.string().optional() },
  },
};

/** Maps policy/tiers.ts's ToolArgType strings to the real zod primitive —
 *  see buildToolSpecs' doc comment for why a REAL field-by-field schema
 *  (not a `z.record` catch-all) matters for a config-driven tool. */
const ZOD_ARG_TYPE: Record<ToolArgType, () => z.ZodTypeAny> = {
  string: () => z.string(),
  number: () => z.number(),
  boolean: () => z.boolean(),
};

/** Turn a ToolPolicy's optional `args` map into a real ZodRawShape (e.g.
 *  `{table: z.string(), note: z.string()}`) so the tool's advertised
 *  `tools/list` inputSchema has real named properties, not an empty
 *  object — and so tools/call actually validates them field-by-field. */
function shapeFromArgs(args: Record<string, ToolArgType>): z.ZodRawShape {
  const shape: z.ZodRawShape = {};
  for (const [field, type] of Object.entries(args)) {
    shape[field] = ZOD_ARG_TYPE[type]();
  }
  return shape;
}

/**
 * Build the /mcp tool surface from the SAME tools.json (tool name -> tier/
 * rarAction/scope/args) that gates the REST /tool transport
 * (policy/tiers.ts), instead of a fixed list that only ever matched the
 * shipped reference config/tools.json. Before this, a deployment pointed
 * at a different GATEWAY_CONFIG_DIR (a different upstream's tool names)
 * had a REST transport that worked and an MCP transport that silently
 * exposed the WRONG tools — /mcp advertised get_record/list_records/etc.
 * regardless of what tools.json actually configured. Found wiring the
 * OpenShell ARS demo's Claude Code sandbox onto this gateway over real
 * MCP: its jira_get_ticket/gitlab_get_file/databricks_write/
 * databricks_query tools were entirely invisible to `tools/list`.
 *
 * A configured name with a hand-authored spec in KNOWN_TOOL_SPECS (the
 * shipped record_read/record_write reference tools) gets that spec, with
 * its real per-field schema. Every other configured name gets its schema
 * from tools.json's optional `args` map (shapeFromArgs) when the config
 * author supplied one — a REAL per-field ZodRawShape, so `tools/list`
 * advertises real named properties and `tools/call` validates them, not
 * an empty `properties: {}` a real MCP client would call with `{}`
 * against (found live: the FIRST version of this fix used a bare
 * `z.record(...)` fallback for every config-driven tool, which the SDK's
 * schema normalizer can't turn into a non-empty JSON Schema — see
 * zod-compat.js's normalizeObjectSchema, which only recognizes an
 * object/record WITH a shape, not a bare record type). When `args` is
 * absent (an operator's tools.json genuinely doesn't know the upstream's
 * field names), the same `z.record` catch-all from before is still the
 * fallback — permissive on purpose, not a regression, just no longer the
 * ONLY option.
 *
 * `complete_hitl` is always appended UNLESS a configured tool already
 * uses that name — guarding against `server.registerTool` throwing on a
 * duplicate registration (every /mcp request would then fail) if some
 * future tools.json ever defines a tool literally called `complete_hitl`.
 */
// `policies` is parameterized (defaulting to the real module-level
// tools.json map) purely so index.test.ts can exercise the complete_hitl
// dedupe branch and the args-vs-passthrough schema choice directly, without
// needing a second process with a different GATEWAY_CONFIG_DIR.
export function buildToolSpecs(policies: Record<string, ToolPolicy> = configuredToolPolicies): McpToolSpec[] {
  const known = new Map(KNOWN_TOOL_SPECS.map((s) => [s.name, s]));
  const configured = Object.entries(policies).map(
    ([name, policy]) =>
      known.get(name) ?? {
        name,
        config: {
          title: name,
          description: policy.args
            ? `Configured tool (tier ${policy.tier}, RAR action "${policy.rarAction}"). Arguments are forwarded verbatim to this deployment's upstream MCP tool of the same name.`
            : `Configured tool (tier ${policy.tier}, RAR action "${policy.rarAction}"). Generic passthrough — arguments are forwarded verbatim to this deployment's upstream MCP tool of the same name; the gateway has no per-field schema for it (tools.json defines no "args" for it), only its tier/RAR policy.`,
          inputSchema: policy.args ? shapeFromArgs(policy.args) : z.record(z.string(), z.unknown()),
        },
      },
  );
  return configured.some((s) => s.name === COMPLETE_HITL_TOOL_NAME) ? configured : [...configured, COMPLETE_HITL_SPEC];
}

const MCP_TOOL_SPECS: McpToolSpec[] = buildToolSpecs();

/** Test/introspection helper: the /mcp tool names, in registration order. */
export const mcpToolNames = (): string[] => MCP_TOOL_SPECS.map((s) => s.name);

/**
 * Shared by the `complete_hitl` MCP tool. Mirrors POST /hitl/complete
 * (identity-bound: the caller's OWN bearer is introspected and its
 * verifyUserId must match the pending transaction's owner, or
 * completePending 403s before touching pollOAuthMfaStatus / the deny
 * counter / session-kill — see that route's doc comment for the full
 * rationale). Deliberately does NOT support the GATEWAY_ALLOW_TEST_VERDICT
 * escape hatch the REST route has for integration tests — an MCP client
 * always drives the real poll against Verify.
 */
async function completeHitlForBearer(txId: string, bearer: string, otp?: string): Promise<PipelineResult> {
  const introspection = await introspectUser(bearer);
  const callerVerifyUserId = introspection.active ? introspection.verifyUserId : undefined;
  return completePending(txId, callerVerifyUserId, {}, otp);
}

function buildMcpServer(bearer: string, subjectEmail?: string): McpServer {
  const server = new McpServer({ name: SERVICE, version: '0.1.0' });

  const call = async (name: string, args: Record<string, unknown>) => {
    const result =
      name === COMPLETE_HITL_TOOL_NAME
        ? await completeHitlForBearer(args['txId'] as string, bearer, args['otp'] as string | undefined)
        : await dispatchTool(name, args, bearer, subjectEmail);
    return { content: [{ type: 'text' as const, text: JSON.stringify(pipelineResultToEnvelope(result)) }] };
  };

  for (const spec of MCP_TOOL_SPECS) {
    server.registerTool(spec.name, spec.config, async (args: Record<string, unknown>) =>
      call(spec.name, args as Record<string, unknown>),
    );
  }

  return server;
}

app.post('/mcp', async (req: Request, res: Response) => {
  const bearer = requireBearer(req, res);
  if (!bearer) return;
  if (!(await requireDpopBound(req, res, bearer))) return;

  // SEP-2243 Mcp-Method/Mcp-Name validation, Phase 0 validate-if-present:
  // a legacy 2025-11-25 client sends neither header and this is a no-op; a
  // header that lies about the request underneath it gets the spec's
  // required 400 + JSON-RPC -32020, before the transport ever sees it.
  const verdict = validateMcpHeaders(
    { mcpMethod: req.header('mcp-method'), mcpName: req.header('mcp-name') },
    req.body,
  );
  if (!verdict.ok) {
    const id = req.body && typeof req.body === 'object' && 'id' in req.body ? (req.body as { id: unknown }).id : null;
    res.status(400).json({ jsonrpc: '2.0', id, error: { code: -32020, message: verdict.message } });
    return;
  }

  const subjectEmail = subjectEmailFromHeader(req);
  const server = buildMcpServer(bearer, subjectEmail);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on('close', () => {
    transport.close();
    server.close();
  });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(PORT, GATEWAY_BIND, () => {
  console.log(`[${SERVICE}] listening on http://${GATEWAY_BIND}:${PORT}`);
});
