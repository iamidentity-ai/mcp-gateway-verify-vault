/**
 * Six-step pipeline orchestrator — MCP gateway
 *
 * Wires every already-built gateway module into the single choke point
 * every tool call passes through:
 *
 *   0. isSessionKilled(verifyUserId) — local 5-min kill-gate, checked right
 *      after introspection resolves who the caller is (see the ordering
 *      note on runPipeline below).
 *   1. introspectUser(userToken) — is the token active? who is it for?
 *   2. gateTool(toolName) — tier map: tier 4 = policy_deny, unknown = deny.
 *   3. resolveRar + exchangeToken — RFC 8693 Token Exchange with RFC 9396
 *      RAR (resolveRar is the single source of truth for both the
 *      authorization_details and the Vault creds path — see
 *      rar/build-rar.ts). May come back 'ok' (continue), 'mfa_challenge'
 *      (park as pending + trigger a push) or 'error'.
 *   4. mintCred — Vault verify-rar mints an ephemeral Postgres credential.
 *   5. callUpstreamTool — the OBO + ephemeral creds actually run the tool
 *      against the upstream MCP server.
 *   6. revokeLease (best-effort) + appendAudit + clearDeny (MFA-gated
 *      tools only — see the deny-counter note below), return { status: 'ok' }.
 *
 * completePending() resumes step 3 onward after a push/OTP verdict comes
 * back for an mfa_challenge that runPipeline parked. Callers MUST supply the
 * caller's own (introspected) verifyUserId as `callerVerifyUserId` — it is
 * checked against the pending ctx's verifyUserId BEFORE anything else runs
 * (security-review CRITICAL fix; see completePending's own doc comment).
 *
 * Every module this orchestrator calls is injectable via `deps` (default:
 * the real imported functions) so unit tests never touch the network —
 * see pipeline.test.ts. End-to-end integration against a real Verify/Vault/
 * upstream-MCP stack lives outside this unit suite.
 */

import { randomUUID } from 'node:crypto';
import { introspectUser } from './auth/introspect.js';
import { getExchangeClientSecret, invalidateExchangeSecret } from './auth/secrets.js';
import {
  exchangeToken,
  triggerOAuthMfaPush,
  pollOAuthMfaStatus,
  exchangeMfaAssertionWithRAR,
  buildPushContext,
} from './auth/token-exchange.js';
import { gateTool } from './policy/tiers.js';
import { resolveRar, type AuthorizationDetail } from './rar/build-rar.js';
import { rarConfig, isElevatedCredsPath } from './rar/rar-config.js';
import { mintCred, revokeLease, type MintedCred } from './vault/mint.js';
import { callUpstreamTool } from './proxy/upstream.js';
import { recordDeny, clearDeny } from './ssf/deny-counter.js';
import { markKilled, isSessionKilled } from './ssf/killed-sessions.js';
import { emitSessionRevoked } from './ssf/antenna.js';
import { putPending, takePending, peekPending, type PendingCtx } from './hitl/pending.js';
import { appendAudit } from './audit/chain.js';

/** Service name recorded as the actor in audit actChains. */
const SERVICE_NAME = process.env.GATEWAY_SERVICE_NAME || 'mcp-gateway';

// ── Types ────────────────────────────────────────────────────

export interface PipelineCtx {
  /** The user's Verify access_token — the RFC 8693 subject_token. */
  userToken: string;
  toolName: string;
  args: Record<string, unknown>;
}

export interface PushInfo {
  title: string;
  message: string;
  transactionUri?: string;
}

/**
 * Discriminated union every route handler switches on. 'error' carries a
 * machine-readable `error` code ('inactive_session', 'session_killed',
 * 'mfa_timeout', or whatever exchangeToken/exchangeMfaAssertionWithRAR
 * surfaced) — index.ts maps these to HTTP status codes.
 */
/**
 * OBO/cred metadata attached to every successful pipeline result — the
 * `_diagnostic` envelope: index.ts maps this onto `{ok:true, data,
 * _diagnostic}` so a UI's agent log, audit-trace ribbon, and JWT viewer can
 * SHOW the token exchange actually happening (OBO + jti + ttl + scope + the
 * ephemeral Vault cred). DEMO-ONLY: carrying the full OBO in a response is a
 * deliberate observability choice — flag it before any external trust
 * boundary.
 */
export interface OboDiag {
  // The raw OBO bearer token is deliberately NOT a field here. It is a live
  // credential — it mints Vault DB creds and calls downstream APIs — so it must
  // never reach a client. `oboJti` (below) is the non-secret correlation id
  // that proves the exchange happened without being replayable.
  oboJti?: string;
  oboTtl?: number;
  oboScope?: string;
  cred?: { username: string; leaseId: string; path: string };
  elevated?: boolean;
}

export type PipelineResult =
  | { status: 'ok'; data: unknown; diag?: OboDiag }
  | { status: 'pending'; txId: string; pushInfo?: PushInfo }
  | { status: 'denied'; reason: string; killed?: boolean }
  | { status: 'session_killed_suspicious' }
  | { status: 'error'; error: string };

/** Extract the `jti` claim from a JWT without verifying it (display only). */
function decodeJwtJti(token: string): string | undefined {
  const parts = token.split('.');
  if (parts.length !== 3) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as Record<string, unknown>;
    return typeof payload['jti'] === 'string' ? payload['jti'] : undefined;
  } catch {
    return undefined;
  }
}

// ── runPipeline deps ─────────────────────────────────────────

export interface RunPipelineDeps {
  introspectUser?: typeof introspectUser;
  isSessionKilled?: typeof isSessionKilled;
  gateTool?: typeof gateTool;
  /** Single source of truth for BOTH authorization_details and the Vault
   *  creds path — see rar/build-rar.ts's resolveRar doc comment for why
   *  these must never be derived separately. */
  resolveRar?: typeof resolveRar;
  exchangeToken?: typeof exchangeToken;
  triggerOAuthMfaPush?: typeof triggerOAuthMfaPush;
  buildPushContext?: typeof buildPushContext;
  mintCred?: typeof mintCred;
  callUpstreamTool?: typeof callUpstreamTool;
  revokeLease?: typeof revokeLease;
  appendAudit?: typeof appendAudit;
  clearDeny?: typeof clearDeny;
  putPending?: typeof putPending;
  /** Injectable txId generator (tests want deterministic ids). */
  genTxId?: () => string;
  /** Injectable clock (tests want deterministic latency). */
  now?: () => number;
  /**
   * Whether the upstream MCP is database-backed. `true` (default) runs the
   * Vault ephemeral-cred leg (mint → X-DB-* headers → revoke) before every
   * upstream call. `false` (env UPSTREAM_DB_BACKED === 'false') fronts a
   * NON-database upstream (e.g. GitHub's MCP): the mint/revoke leg is skipped
   * and callUpstreamTool runs on the OBO alone. Everything else — introspect,
   * tier gate, Token Exchange + RAR, HITL step-up, SSF kill, audit — is
   * identical. Injectable so tests drive it without env. Security-safe DEFAULT:
   * unset env stays DB-backed (still mints a scoped, ephemeral Vault cred).
   */
  dbBacked?: boolean;
}

const defaultRunPipelineDeps: Required<RunPipelineDeps> = {
  introspectUser,
  isSessionKilled,
  gateTool,
  resolveRar,
  exchangeToken,
  triggerOAuthMfaPush,
  buildPushContext,
  mintCred,
  callUpstreamTool,
  revokeLease,
  appendAudit,
  clearDeny,
  putPending,
  genTxId: () => randomUUID(),
  now: () => Date.now(),
  dbBacked: process.env['UPSTREAM_DB_BACKED'] !== 'false',
};

/**
 * MFA-gated tiers (2 write / 3 sensitive). Tier 1 reads are Token-Exchange
 * only and NEVER gate clearDeny — an LLM agent runs harmless lookups before
 * every write attempt, and if a lookup's success cleared the counter, the
 * 3-strike chain could never accumulate across retries within one
 * conversation.
 */
function isMfaGatedTier(tier: number): boolean {
  return tier === 2 || tier === 3;
}

/**
 * Evaluate the configured step-up match rule (config/rar.json →
 * stepUp.elevateWhen) against a discovery-read result to decide whether the
 * gateway must force a step-up. In PRODUCTION callUpstreamTool
 * (proxy/upstream.ts) returns the MCP CallToolResult envelope verbatim —
 * `{ content: [{ type: 'text', text: '<json string>' }] }` — so the record,
 * and its classification field, lives inside that JSON string, NOT at the top
 * level. (pipeline.test.ts mocks may return the plain record; index.ts's
 * `unwrapToolData` does the same unwrap for the HTTP response.)
 *
 * FAILS CLOSED: any envelope we can't parse into a record object, or a record
 * missing the configured field, returns `true` (step up). The matchers:
 *   equals — value === equals
 *   in     — in.includes(value)      (allow-list)
 *   notIn  — !notIn.includes(value)  (fail-closed safe-list: elevate for
 *            anything NOT explicitly safe, including unknown/new levels)
 * A swapped upstream whose result doesn't carry the field therefore
 * over-protects (extra step-ups) instead of silently leaking sensitive data
 * with no challenge — the "policy isn't being applied" bug, closed.
 */
function shouldStepUp(data: unknown): boolean {
  const rule = rarConfig.stepUp.elevateWhen;
  let record: unknown = data;
  const envelope = data as { content?: Array<{ text?: unknown }> } | null;
  if (envelope && typeof envelope === 'object' && Array.isArray(envelope.content)) {
    const text = envelope.content[0]?.text;
    if (typeof text !== 'string') return true; // envelope we can't read → fail closed
    try {
      record = JSON.parse(text);
    } catch {
      return true; // unparseable upstream shape → fail closed (force step-up)
    }
  }
  if (!record || typeof record !== 'object') return true; // no record object → fail closed
  const value = (record as Record<string, unknown>)[rule.field];
  if (value === undefined) return true; // field missing → fail closed
  if (rule.equals !== undefined) return value === rule.equals;
  if (rule.in !== undefined) return rule.in.includes(value);
  if (rule.notIn !== undefined) return !rule.notIn.includes(value);
  return true; // no matcher configured → fail closed
}

// ── runPipeline ───────────────────────────────────────────────

export async function runPipeline(ctx: PipelineCtx, deps: RunPipelineDeps = {}): Promise<PipelineResult> {
  const d: Required<RunPipelineDeps> = { ...defaultRunPipelineDeps, ...deps };
  const startedAt = d.now();

  // Step 1: who is this? Introspection must run FIRST — the killed-session
  // check (nominally "step 0") needs verifyUserId, which only introspection
  // can give us.
  const introspection = await d.introspectUser(ctx.userToken);
  if (!introspection.active) {
    return { status: 'error', error: 'inactive_session' };
  }
  const verifyUserId = introspection.verifyUserId ?? '';
  const userEmail = introspection.email;

  // Step 0: local kill-gate, BEFORE any gate/exchange work. Covers the
  // 30-75s Antenna -> Verify session-revoke propagation window.
  if (d.isSessionKilled(verifyUserId)) {
    return { status: 'error', error: 'session_killed' };
  }

  // Step 2: tier gate — the single choke point before Verify is ever hit.
  const gate = d.gateTool(ctx.toolName);
  if (!gate.allowed) {
    d.appendAudit({
      ts: d.now(),
      userId: verifyUserId,
      tool: ctx.toolName,
      tier: gate.tier,
      decision: gate.reason === 'policy_deny' ? 'tier4_deny' : 'unknown_tool_deny',
    });
    return { status: 'denied', reason: gate.reason ?? 'policy_deny' };
  }

  // Step 2.5: GATEWAY-DERIVED STEP-UP (config/rar.json → stepUp).
  //
  // The caller NEVER supplies elevation — the GATEWAY decides. It runs a cheap
  // discovery read with the standard (non-elevated) RAR, which the Verify policy
  // allows with no push, purely to learn the record's classification. The probe
  // calls stepUp.probeTool (a classification-carrying read, e.g. get_record) on
  // the SAME record id, so record-scoped reads whose own result does NOT carry
  // the classification field (get_record_detail / get_record_history) are still
  // gated by the parent record's classification — not just get_record. A
  // restricted record is NOT returned from the probe: the gateway re-runs the
  // ACTUAL requested tool with the elevated-action RAR, which makes Verify's
  // elevated-read policy rule fire ACTION_MFA_ALWAYS. shouldStepUp FAILS CLOSED,
  // so an unreadable probe result forces the step-up. Because the agent can't
  // supply elevation, it cannot skip.
  if (rarConfig.stepUp.discoveryTools.includes(ctx.toolName)) {
    const probeTool = rarConfig.stepUp.probeTool ?? ctx.toolName;
    const probeIsDelivery = probeTool === ctx.toolName;
    // For get_record the probe IS the requested call; for detail/history it is a
    // separate classification-carrying read of the same record id.
    const probeCtx: PipelineCtx = probeIsDelivery
      ? ctx
      : { ...ctx, toolName: probeTool, args: { [rarConfig.argIdKey]: ctx.args[rarConfig.argIdKey] } };
    const probeGate = probeIsDelivery ? gate : d.gateTool(probeTool);
    const probe = await runExchangeAndCall({ ctx: probeCtx, gate: probeGate, verifyUserId, userEmail, startedAt, elevated: false, suppressAudit: true }, d);
    if (probe.result.status !== 'ok') return probe.result;
    // NB: probe.result.data is the MCP CallToolResult envelope in production —
    // shouldStepUp unwraps content[0].text before evaluating elevateWhen.
    const elevate = shouldStepUp(probe.result.data);

    if (!elevate) {
      if (probeIsDelivery) {
        // get_record on a public record — the discovery read IS the delivery.
        d.appendAudit({
          ts: d.now(), userId: verifyUserId, tool: ctx.toolName, tier: gate.tier,
          sub: verifyUserId, actChain: [SERVICE_NAME, verifyUserId],
          authorizationDetails: probe.authorizationDetails, decision: 'ok',
          leaseId: probe.leaseId, oboJti: probe.result.diag?.oboJti,
          latencyMs: d.now() - startedAt,
        });
        return probe.result;
      }
      // detail/history on a public record — the probe only told us it is not
      // restricted; run the ACTUAL requested tool with the standard RAR. That
      // call (suppressAudit:false) audits its own 'ok' result.
      const delivered = await runExchangeAndCall({ ctx, gate, verifyUserId, userEmail, startedAt, elevated: false, suppressAudit: false }, d);
      return delivered.result;
    }

    // Restricted — discard the probe data, audit the discovery, force the
    // step-up on the ACTUAL requested tool (get_record / detail / history) with
    // elevated creds.
    d.appendAudit({
      ts: d.now(), userId: verifyUserId, tool: ctx.toolName, tier: gate.tier,
      authorizationDetails: probe.authorizationDetails, decision: 'stepup_discovery',
      leaseId: probe.leaseId, oboJti: probe.result.diag?.oboJti,
    });
    const elevated = await runExchangeAndCall({ ctx, gate, verifyUserId, userEmail, startedAt, elevated: true, suppressAudit: false }, d);
    return elevated.result;
  }

  // Normal path — all other tools (list, history, writes). The caller can never
  // supply elevation; the gateway derives it (above) for discovery tools only,
  // so this path is always elevated: false. runExchangeAndCall audits the 'ok'
  // result and clears the deny counter for MFA-gated tiers itself
  // (suppressAudit:false).
  const normal = await runExchangeAndCall(
    { ctx, gate, verifyUserId, userEmail, startedAt, elevated: false, suppressAudit: false },
    d,
  );
  return normal.result;
}

/**
 * Steps 3–6 for a single tool call at a resolved elevation level: RAR + Token
 * Exchange → (mfa_challenge → park pending + push) → mint → upstream → revoke.
 * Returns the terminal result plus the authorization_details and leaseId used,
 * so the caller can audit. When suppressAudit is false it also writes the 'ok'
 * audit + clears the deny counter for MFA-gated tiers (the normal-path
 * behaviour); the gateway-derived step-up discovery flow passes suppressAudit:true
 * and audits at the runPipeline level once it knows whether the probe elevated.
 *
 * resolveRar is the single source of truth for BOTH authorizationDetails and
 * credsPath — deriving credsPath separately from the raw gate.rarAction would
 * miss the elevation collapse buildRAR applies (see build-rar.ts).
 */
async function runExchangeAndCall(
  params: {
    ctx: PipelineCtx;
    gate: ReturnType<typeof gateTool>;
    verifyUserId: string;
    /** Introspected email — parked in PendingCtx so completePending kills
     *  can put it in the CAEP sub_id (older Antenna handlers need it). */
    userEmail?: string;
    startedAt: number;
    elevated: boolean;
    suppressAudit: boolean;
  },
  d: Required<RunPipelineDeps>,
): Promise<{ result: PipelineResult; authorizationDetails: AuthorizationDetail[]; leaseId?: string }> {
  const { ctx, gate, verifyUserId, userEmail, startedAt, elevated, suppressAudit } = params;

  const { authorizationDetails, credsPath }: { authorizationDetails: AuthorizationDetail[]; credsPath: string | undefined } =
    d.resolveRar({
      rarAction: gate.rarAction,
      // The domain id rides on whatever tool-call argument config/rar.json
      // names (argIdKey; `recordId` under the default config).
      recordId: ctx.args[rarConfig.argIdKey] as string | undefined,
      elevated,
    });

  const exchangeResult = await d.exchangeToken({
    subjectToken: ctx.userToken,
    scope: gate.scope,
    authorizationDetails,
  });

  if (exchangeResult.status === 'mfa_challenge') {
    const txId = d.genTxId();
    const pushContext = d.buildPushContext(authorizationDetails);

    // Kick the push now so the pending record already carries a
    // transactionUri when the caller starts polling /hitl/complete.
    // Best-effort: if the push itself fails to fire, still park the
    // pending ctx (transactionUri left undefined) so the caller sees a
    // 'pending' result rather than a hard error — a retry can re-trigger.
    let transactionUri: string | undefined;
    try {
      transactionUri = await d.triggerOAuthMfaPush(exchangeResult.challengeToken, pushContext);
    } catch (err) {
      console.warn('[pipeline] triggerOAuthMfaPush failed (parking pending anyway):', (err as Error).message);
    }

    const pendingCtx: PendingCtx = {
      verifyUserId,
      email: userEmail,
      challengeToken: exchangeResult.challengeToken,
      transactionUri,
      scope: gate.scope,
      authorizationDetails,
      toolName: ctx.toolName,
      credsPath,
      startedAt,
      args: ctx.args,
    };
    d.putPending(txId, pendingCtx);

    return {
      result: { status: 'pending', txId, pushInfo: { ...pushContext, transactionUri } },
      authorizationDetails,
    };
  }

  if (exchangeResult.status === 'error') {
    return { result: { status: 'error', error: exchangeResult.error }, authorizationDetails };
  }

  const obo = exchangeResult.accessToken;

  // DB-backed (default): mint an ephemeral verify-rar Postgres credential, hand
  // it to the upstream as X-DB-*, and revoke the lease after the one call (the
  // revoke always runs, success or failure, so a lease never outlives its call).
  // NO-DB (UPSTREAM_DB_BACKED=false): the upstream has no database — SKIP the
  // whole Vault leg and call it on the OBO alone (no X-DB-* headers).
  let cred: MintedCred | undefined;
  let data: unknown;
  if (d.dbBacked) {
    // credsPath is guaranteed present in DB-backed mode — the rar-config parse
    // requires it on every non-blocked action when UPSTREAM_DB_BACKED !== 'false'.
    cred = await d.mintCred({ obo, authorizationDetails, credsPath: credsPath! });
    try {
      data = await d.callUpstreamTool({
        name: ctx.toolName,
        arguments: ctx.args,
        obo,
        dbUser: cred.username,
        dbPass: cred.password,
      });
    } finally {
      await d.revokeLease(cred.leaseId, obo);
    }
  } else {
    data = await d.callUpstreamTool({ name: ctx.toolName, arguments: ctx.args, obo });
  }

  // The observability payload — proves the exchange (+ mint, when DB-backed)
  // happened. Carries the OBO's jti (correlation), never the OBO itself (a live
  // credential). NO-DB: no `cred` field (there is no ephemeral credential).
  const diag: OboDiag = {
    oboJti: decodeJwtJti(obo),
    oboTtl: exchangeResult.expiresIn,
    oboScope: exchangeResult.scope ?? gate.scope,
    ...(cred ? { cred: { username: cred.username, leaseId: cred.leaseId, path: credsPath! } } : {}),
    elevated,
  };

  if (!suppressAudit) {
    d.appendAudit({
      ts: d.now(),
      userId: verifyUserId,
      tool: ctx.toolName,
      tier: gate.tier,
      sub: verifyUserId,
      actChain: [SERVICE_NAME, verifyUserId],
      authorizationDetails,
      decision: 'ok',
      leaseId: cred?.leaseId,
      oboJti: diag.oboJti,
      latencyMs: d.now() - startedAt,
    });
    if (isMfaGatedTier(gate.tier)) {
      d.clearDeny(verifyUserId);
    }
  }

  return { result: { status: 'ok', data, diag }, authorizationDetails, leaseId: cred?.leaseId };
}

// ── completePending deps ─────────────────────────────────────

export interface CompletePendingDeps {
  peekPending?: typeof peekPending;
  takePending?: typeof takePending;
  gateTool?: typeof gateTool;
  pollOAuthMfaStatus?: typeof pollOAuthMfaStatus;
  /** Exchange-app client secret via the secrets seam (env | vault). */
  getExchangeClientSecret?: typeof getExchangeClientSecret;
  invalidateExchangeSecret?: typeof invalidateExchangeSecret;
  exchangeMfaAssertionWithRAR?: typeof exchangeMfaAssertionWithRAR;
  mintCred?: typeof mintCred;
  callUpstreamTool?: typeof callUpstreamTool;
  revokeLease?: typeof revokeLease;
  appendAudit?: typeof appendAudit;
  clearDeny?: typeof clearDeny;
  recordDeny?: typeof recordDeny;
  emitSessionRevoked?: typeof emitSessionRevoked;
  markKilled?: typeof markKilled;
  isSessionKilled?: typeof isSessionKilled;
  now?: () => number;
  /** See RunPipelineDeps.dbBacked — same flag for the post-approval (leg-2)
   *  path, so a stepped-up call to a non-DB upstream also skips the Vault leg. */
  dbBacked?: boolean;
}

const defaultCompletePendingDeps: Required<CompletePendingDeps> = {
  peekPending,
  takePending,
  gateTool,
  pollOAuthMfaStatus,
  getExchangeClientSecret,
  invalidateExchangeSecret,
  exchangeMfaAssertionWithRAR,
  mintCred,
  callUpstreamTool,
  revokeLease,
  appendAudit,
  clearDeny,
  recordDeny,
  emitSessionRevoked,
  markKilled,
  isSessionKilled,
  now: () => Date.now(),
  dbBacked: process.env['UPSTREAM_DB_BACKED'] !== 'false',
};

/**
 * Narrow stale-secret detection for the leg-2 (jwt_bearer) exchange result.
 * exchangeMfaAssertionWithRAR's error variant carries no raw HTTP status
 * (unlike token-exchange.ts's internal isStaleSecretError, which sees the
 * numeric status) — so this checks the `error`/`errorDescription` strings
 * Verify's /oauth2/token error body maps onto for the same signals
 * (CSIAQ0155E, invalid_client, or a literal 401 echoed into the body).
 */
function isStaleSecretResult(result: { error: string; errorDescription?: string }): boolean {
  const haystack = `${result.error} ${result.errorDescription ?? ''}`;
  return (
    haystack.includes('CSIAQ0155E') ||
    haystack.includes('invalid_client') ||
    haystack.includes('401')
  );
}

/**
 * Resume a parked mfa_challenge after the push/OTP verdict is in. Called by
 * POST /hitl/complete once the caller believes the user has responded (or
 * to poll for a verdict — pollOAuthMfaStatus itself loops until a terminal
 * state or its own timeout).
 *
 * `callerVerifyUserId` is the introspected identity of whoever is making
 * THIS HTTP request (index.ts resolves it via introspectUser(bearer) before
 * calling in) — REQUIRED, and checked against the pending ctx's own
 * verifyUserId before anything else runs.
 *
 * FIX 1 (CRITICAL, security review): without this check, /hitl/complete only
 * verified bearer PRESENCE, not identity. Any caller holding ANY valid
 * bearer who learned another user's (unguessable, but leakable) txId could
 * POST {txId, verdict:'denied_suspicious'} and force
 * emitSessionRevoked+markKilled on the VICTIM (whose verifyUserId is in the
 * pending ctx) — a session-kill DoS needing zero Verify interaction. The
 * check runs off a non-destructive peekPending() FIRST, so a mismatched
 * (unauthorized) caller is rejected without burning the legitimate owner's
 * one-shot completion — and strictly BEFORE pollOAuthMfaStatus /
 * recordDeny / markKilled / emitSessionRevoked / the deny counter are ever
 * touched.
 */
export async function completePending(
  txId: string,
  callerVerifyUserId: string | undefined,
  deps: CompletePendingDeps = {},
): Promise<PipelineResult> {
  const d: Required<CompletePendingDeps> = { ...defaultCompletePendingDeps, ...deps };
  const startedAt = d.now();

  const peeked = d.peekPending(txId);
  if (!peeked) {
    return { status: 'error', error: 'unknown_or_expired_tx' };
  }

  if (!callerVerifyUserId || callerVerifyUserId !== peeked.verifyUserId) {
    return { status: 'error', error: 'forbidden' };
  }

  // Local kill-gate — same shield runPipeline applies at step 0. Without this,
  // a session killed WHILE a step-up is parked (e.g. a suspicious-deny or
  // 3-strike kill on another tx during the ~30-75s Antenna->Verify revocation
  // propagation window, while the bearer still introspects active) could resume
  // this parked tx, mint fresh Vault creds, and return the withheld data. Check
  // the tx OWNER's verifyUserId (== the identity-bound caller) before takePending.
  if (d.isSessionKilled(peeked.verifyUserId)) {
    return { status: 'error', error: 'session_killed' };
  }

  const ctx = d.takePending(txId);
  if (!ctx) {
    // Expired in the (vanishingly small, single-threaded-Node) window
    // between peek and take — treat exactly like a normal expiry.
    return { status: 'error', error: 'unknown_or_expired_tx' };
  }

  const args = ctx.args;
  const gate = d.gateTool(ctx.toolName);
  const authorizationDetails = ctx.authorizationDetails as AuthorizationDetail[];

  const verdict = await d.pollOAuthMfaStatus(ctx.transactionUri ?? '', ctx.challengeToken);

  if (verdict.state === 'denied_suspicious') {
    await d.emitSessionRevoked({ verifyUserId: ctx.verifyUserId, email: ctx.email, reason: 'suspicious' });
    d.markKilled(ctx.verifyUserId);
    d.appendAudit({
      ts: d.now(),
      userId: ctx.verifyUserId,
      tool: ctx.toolName,
      tier: gate.tier,
      authorizationDetails,
      decision: 'suspicious_deny_killed',
    });
    return { status: 'session_killed_suspicious' };
  }

  if (verdict.state === 'denied') {
    const denyResult = d.recordDeny(ctx.verifyUserId);
    d.appendAudit({
      ts: d.now(),
      userId: ctx.verifyUserId,
      tool: ctx.toolName,
      tier: gate.tier,
      authorizationDetails,
      decision: 'mfa_deny',
    });
    if (denyResult.thresholdReached) {
      await d.emitSessionRevoked({ verifyUserId: ctx.verifyUserId, email: ctx.email, reason: 'deny_threshold_reached' });
      d.markKilled(ctx.verifyUserId);
      return { status: 'denied', reason: verdict.reason, killed: true };
    }
    return { status: 'denied', reason: verdict.reason };
  }

  if (verdict.state === 'timeout') {
    return { status: 'error', error: 'mfa_timeout' };
  }

  // verdict.state === 'approved'
  let exchangeSecret = await d.getExchangeClientSecret();
  let assertionResult = await d.exchangeMfaAssertionWithRAR(
    verdict.assertion,
    ctx.scope,
    authorizationDetails,
    exchangeSecret,
  );

  // FIX 2 (security review): single-attempt narrow-invalidation retry on a
  // stale-secret signal, mirroring token-exchange.ts's leg-1 retry ladder.
  // This leg previously had none — a client_secret rotation landing between
  // leg-1 success and leg-2 completion failed the entire HITL resume. The
  // secrets seam decides what "invalidate" means (vault: drop the role cache;
  // env: no-op, since a static env secret does not rotate).
  if (assertionResult.status === 'error' && isStaleSecretResult(assertionResult)) {
    d.invalidateExchangeSecret();
    exchangeSecret = await d.getExchangeClientSecret();
    assertionResult = await d.exchangeMfaAssertionWithRAR(
      verdict.assertion,
      ctx.scope,
      authorizationDetails,
      exchangeSecret,
    );
  }

  if (assertionResult.status !== 'ok') {
    return {
      status: 'error',
      error: assertionResult.status === 'error' ? assertionResult.error : 'jwt_bearer_failed',
    };
  }
  const obo = assertionResult.accessToken;

  // Same DB-backed vs NO-DB branch as runExchangeAndCall — a stepped-up call to
  // a non-database upstream (UPSTREAM_DB_BACKED=false) skips the mint/revoke leg
  // and runs on the OBO alone.
  let cred: MintedCred | undefined;
  let data: unknown;
  if (d.dbBacked) {
    cred = await d.mintCred({ obo, authorizationDetails, credsPath: ctx.credsPath! });
    try {
      data = await d.callUpstreamTool({
        name: ctx.toolName,
        arguments: args,
        obo,
        dbUser: cred.username,
        dbPass: cred.password,
      });
    } finally {
      await d.revokeLease(cred.leaseId, obo);
    }
  } else {
    data = await d.callUpstreamTool({ name: ctx.toolName, arguments: args, obo });
  }

  // Same observability payload as runExchangeAndCall — this is the leg-2
  // (post-approval) OBO, the one actually minted after the human said yes.
  // NO-DB: no `cred` field (there is no ephemeral credential).
  const diag: OboDiag = {
    oboJti: decodeJwtJti(obo),
    oboTtl: assertionResult.expiresIn,
    oboScope: assertionResult.scope ?? ctx.scope,
    ...(cred ? { cred: { username: cred.username, leaseId: cred.leaseId, path: ctx.credsPath! } } : {}),
    // Elevated iff the parked creds path belongs to an `elevatedFrom` action
    // in config/rar.json — the config, not a path-suffix naming convention,
    // defines "elevated". A NO-DB call has no creds path, so it is never elevated.
    elevated: ctx.credsPath ? isElevatedCredsPath(ctx.credsPath) : false,
  };

  d.appendAudit({
    ts: d.now(),
    userId: ctx.verifyUserId,
    tool: ctx.toolName,
    tier: gate.tier,
    sub: ctx.verifyUserId,
    actChain: [SERVICE_NAME, ctx.verifyUserId],
    authorizationDetails,
    decision: 'ok',
    leaseId: cred?.leaseId,
    oboJti: diag.oboJti,
    latencyMs: d.now() - startedAt,
  });

  // Approval just proved the user holds the MFA factor — fresh slate.
  d.clearDeny(ctx.verifyUserId);

  return { status: 'ok', data, diag };
}
