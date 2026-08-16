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
 *      With BLOCKED_ACTION_KILL=true a tier-4 deny also feeds the per-user
 *      deny counter, and the third one in the rolling window revokes the
 *      session (see RunPipelineDeps.blockedActionKill for the scope + the
 *      "this is not detection" caveat).
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
  triggerTransientEmailOtp,
  submitTransientOtp,
  maskEmail,
} from './auth/token-exchange.js';
import { gateTool } from './policy/tiers.js';
import { resolveRar, type AuthorizationDetail } from './rar/build-rar.js';
import { rarConfig, isElevatedCredsPath } from './rar/rar-config.js';
import { mintCred, revokeLease, type MintedCred } from './vault/mint.js';
import { callUpstreamTool } from './proxy/upstream.js';
import { recordDeny, clearDeny } from './ssf/deny-counter.js';
import { markKilled, isSessionKilled, readSubjectIssuedAt } from './ssf/killed-sessions.js';
import { emitSessionRevoked } from './ssf/antenna.js';
import { putPending, takePending, peekPending, ttlMs, type PendingCtx } from './hitl/pending.js';
import { mintRequestState, verifyRequestState, requestDigest } from './hitl/request-state.js';
import { appendAudit } from './audit/chain.js';

/** Service name recorded as the actor in audit actChains. */
const SERVICE_NAME = process.env.GATEWAY_SERVICE_NAME || 'mcp-gateway';

// ── Types ────────────────────────────────────────────────────

export interface PipelineCtx {
  /** The user's Verify access_token — the RFC 8693 subject_token. */
  userToken: string;
  toolName: string;
  args: Record<string, unknown>;
  /** True when the inbound request passed full-mode DPoP validation. Pure
   *  observability: enforcement already happened at the route layer. */
  senderConstrained?: boolean;
  /**
   * Transient-OTP delivery address, sourced by the CALLER from the original
   * IdP subject token's own `email`/`preferred_username` claim (decoded
   * server-side at sign-in — see a sibling reference implementation's
   * `token-exchange.ts::selectTransientOtpChannel`, which decodes
   * `req.subjectToken` directly for this exact reason). Takes priority over
   * `introspection.email` below: Verify's `/oauth2/userinfo` reflects the
   * JIT-provisioned shadow user's persisted attribute, which is a snapshot
   * frozen at first provisioning (or a manual SCIM patch) and does NOT
   * refresh on later logins even when the current subject token's own claim
   * changed — see feedback_verify_transient_otp_no_directory_dependency.
   * Optional and backward-compatible: omitted, this behaves exactly as
   * before (introspection-derived fallback only).
   */
  subjectEmail?: string;
}

export interface PushInfo {
  /** Which HITL method parked this transaction. Absent on entries built
   *  before this field existed — callers should treat a missing method as
   *  'push' (the only method that existed then). */
  method?: 'push' | 'email_otp';
  title?: string;
  message?: string;
  transactionUri?: string;
  /** 'email_otp' only — masked destination for display, e.g. "s•••@example.com". */
  maskedDestination?: string;
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
  // The raw OBO bearer token is a LIVE credential — it mints Vault DB creds and
  // calls downstream APIs — so it is normally NOT sent to a client; `oboJti`
  // (below) is the non-secret correlation id that proves the exchange happened
  // without being replayable. It is populated here ONLY when GATEWAY_DEBUG_OBO=true
  // — a localhost demo affordance so the UI can decode it in a JWT viewer. NEVER
  // enable that flag in a shipped or networked deployment.
  obo?: string;
  oboJti?: string;
  oboTtl?: number;
  oboScope?: string;
  cred?: { username: string; leaseId: string; path: string };
  /**
   * Did the gateway's post-call `revokeLease` actually succeed? This is the
   * evidence for the claim the whole ephemeral-credential design rests on —
   * "the credential in `cred` does not exist any more." It is REPORTED, never
   * assumed: `false` means Vault did not accept the revoke and the credential
   * is still live until its TTL expires, which is a real signal a UI should
   * show rather than hide. Present only on DB-backed calls that actually
   * minted (there is nothing to revoke otherwise), and only when the injected
   * revokeLease reported an outcome — never fabricated as `true`.
   */
  credRevoked?: boolean;
  elevated?: boolean;
  /** "dpop" when the inbound request carried a validated DPoP proof. */
  tokenBinding?: 'dpop';
}

export type PipelineResult =
  | { status: 'ok'; data: unknown; diag?: OboDiag }
  /**
   * `requestState` — the HMAC-protected SEP-2322 (MRTR) blob minted at park
   * time (hitl/request-state.ts). Both transports' pending envelopes carry
   * it alongside `txId`; a completer MAY echo it back to `completePending`
   * for verify-before-consume integrity binding — see that function's own
   * doc comment. Required (not optional) because every park site mints one.
   */
  | { status: 'pending'; txId: string; requestState: string; pushInfo?: PushInfo }
  /**
   * denyCount / denyThreshold ride along on a tier-4 (blocked-action) deny
   * when BLOCKED_ACTION_KILL is on, for the same reason they ride along on
   * an `otp_invalid` error: so a caller can render "attempt 2 of 3" without
   * keeping its own counter. They describe THIS gateway's kill threshold.
   */
  | { status: 'denied'; reason: string; killed?: boolean; denyCount?: number; denyThreshold?: number }
  | { status: 'session_killed_suspicious' }
  /** attemptsRemaining is set only for error:'otp_invalid' when Verify's
   *  response reported a retries/attemptsRemaining count. denyCount /
   *  denyThreshold ride along on the same case so a caller can show
   *  "strike 2 of 3" without maintaining its own counter — they describe
   *  THIS gateway's own kill threshold, not Verify's per-code retry budget
   *  (which is what attemptsRemaining reports; the two are independent).
   *
   *  requestState is set ONLY on the otp_invalid re-park case (see
   *  completePending's email_otp branch): re-parking under the same txId
   *  refreshes the pending entry's TTL, so the ORIGINAL requestState minted
   *  at park time — whose `exp` is fixed at that original mint — would
   *  outlive its own claim without a matching refresh. A freshly minted
   *  requestState (same txId/sub/digest, new exp) rides along here so a
   *  SEP-2322-compliant client that always echoes the most recently
   *  received blob is never worse off than one that never echoes at all. */
  | {
      status: 'error';
      error: string;
      attemptsRemaining?: number;
      denyCount?: number;
      denyThreshold?: number;
      requestState?: string;
    };

// ── GATEWAY_NARRATE: one readable line per call ───────────────
//
// A demo/operations affordance in the same spirit as GATEWAY_DEBUG_OBO above,
// and gated the same way — DEFAULT OFF, opt in with GATEWAY_NARRATE=true.
// When off, this module logs exactly what it always did (nothing per-request):
// narrate() returns before touching console, so stdout is byte-identical.
//
// When on, every tool call emits ONE line summarizing the whole chain — who
// called, which tool, its tier, the RAR action, what Token Exchange said
// (including mfa_challenge and Verify policy denies), the Vault lease that got
// minted, and whether the post-call revoke succeeded — so `tail -F` on the
// gateway's log is legible on a projector while the pipeline runs.
//
// HARD RULE: this line NEVER carries a live credential. No OBO, no ephemeral DB
// password, no client secret, no MFA challenge token, no OTP. `oboJti` and the
// Vault `lease_id` are non-secret correlation ids and are the ONLY token-shaped
// values allowed here. The whole thesis of this gateway is that credentials
// stay out of view — a narration mode that leaked one would refute it.
//
// Unlike GATEWAY_DEBUG_OBO (which puts a replayable token in an HTTP response
// body and must never be enabled outside localhost), this flag only writes
// non-secret metadata to the gateway's own log. It is still off by default:
// per-call logging is a demo/debug posture, and the caller identity it prints
// is PII you should not emit into a shipped deployment's logs by accident.
const NARRATE_PREFIX = '[gateway:narrate]';

/** Non-secret facts a single tool call accumulates, rendered by narrate(). */
export interface NarrateFacts {
  /** Terminal PipelineResult status: ok | pending | denied | error | killed. */
  outcome: string;
  tool: string;
  /** Caller identity — the introspected email when there is one, else the
   *  Verify user id. Never a token. */
  user?: string;
  tier?: number;
  /** RFC 9396 action the RAR was built for (gate.rarAction). */
  rar?: string;
  /** Token Exchange verdict: ok | mfa_challenge | denied:<code> | error:<code>. */
  exchange?: string;
  /** Gateway-derived step-up marker: 'discovery' | 'elevated' | 'resumed'. */
  stepUp?: string;
  /** Vault lease id — a correlation id, NOT the credential it leased. */
  lease?: string;
  /** revokeLease outcome. Printed verbatim; `false` is a real signal. */
  revoked?: boolean;
  /** OBO jti — correlation id, not the token. */
  jti?: string;
  /** HITL transaction id for a parked step-up. */
  tx?: string;
  latencyMs?: number;
}

/** True when narration is enabled. Read per-call (not cached at module load)
 *  so a test can toggle the env var the same way the GATEWAY_DEBUG_OBO
 *  branches above are exercised. */
function narrateEnabled(): boolean {
  return process.env['GATEWAY_NARRATE'] === 'true';
}

/**
 * Emit the one-line-per-call narration. No-op unless GATEWAY_NARRATE=true.
 * Fields are printed in a fixed order and omitted when absent, so the lines
 * column-align well enough to read while scrolling.
 */
function narrate(f: NarrateFacts): void {
  if (!narrateEnabled()) return;
  const parts = [NARRATE_PREFIX, f.outcome.toUpperCase(), `tool=${f.tool}`];
  if (f.user) parts.push(`user=${f.user}`);
  if (f.tier !== undefined) parts.push(`tier=${f.tier}`);
  if (f.rar) parts.push(`rar=${f.rar}`);
  if (f.exchange) parts.push(`exchange=${f.exchange}`);
  if (f.stepUp) parts.push(`stepup=${f.stepUp}`);
  if (f.lease) parts.push(`lease=${f.lease}`);
  if (f.revoked !== undefined) parts.push(`revoked=${f.revoked}`);
  if (f.jti) parts.push(`jti=${f.jti}`);
  if (f.tx) parts.push(`tx=${f.tx}`);
  if (f.latencyMs !== undefined) parts.push(`${f.latencyMs}ms`);
  console.log(parts.join(' '));
}

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
  /** Reads the subject token's `iat` so a post-kill re-authentication clears
   *  the local kill-gate. Injectable purely so tests can drive the gate
   *  without minting JWTs. */
  readSubjectIssuedAt?: typeof readSubjectIssuedAt;
  gateTool?: typeof gateTool;
  /** Single source of truth for BOTH authorization_details and the Vault
   *  creds path — see rar/build-rar.ts's resolveRar doc comment for why
   *  these must never be derived separately. */
  resolveRar?: typeof resolveRar;
  exchangeToken?: typeof exchangeToken;
  triggerOAuthMfaPush?: typeof triggerOAuthMfaPush;
  buildPushContext?: typeof buildPushContext;
  /** transient_email HITL mode only — see hitlMethod below. */
  triggerTransientEmailOtp?: typeof triggerTransientEmailOtp;
  mintCred?: typeof mintCred;
  callUpstreamTool?: typeof callUpstreamTool;
  revokeLease?: typeof revokeLease;
  appendAudit?: typeof appendAudit;
  clearDeny?: typeof clearDeny;
  /** Blocked-action escalation kill — see `blockedActionKill` below. */
  recordDeny?: typeof recordDeny;
  emitSessionRevoked?: typeof emitSessionRevoked;
  markKilled?: typeof markKilled;
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
  /**
   * Which HITL method to use when Token Exchange returns mfa_challenge.
   * 'push' (default) is the original triggerOAuthMfaPush flow — zero
   * behavior change for existing deployments with HITL_METHOD unset.
   * 'transient_email' is for populations with no enrolled Verify factor
   * (Entra-anchored users JIT'd into the tenant): it mails a one-shot code
   * to the introspected user's email instead of pushing to a phone. Read
   * from env at module load, same pattern as dbBacked above.
   */
  hitlMethod?: 'push' | 'transient_email';
  /**
   * BLOCKED-ACTION ESCALATION KILL (env `BLOCKED_ACTION_KILL=true`, DEFAULT OFF).
   *
   * When on, a **tier-4** deny — an identity asking for an action this
   * deployment grants to nobody — feeds the SAME per-user deny counter and the
   * SAME 3-strike threshold an MFA denial feeds, and the third one inside the
   * rolling window revokes the session (CAEP → SSF → the directories) exactly
   * as a third wrong one-time code does.
   *
   * WHY this is worth having: repeated attempts to use an action outside the
   * grant is the observable CONSEQUENCE of an agent under someone else's
   * influence — a poisoned document, a hijacked prompt, a compromised client.
   * The gateway does not, and cannot, tell you WHY the identity asked; it does
   * not inspect content and it detects nothing semantic. It reacts to the
   * behaviour it can actually see. That is the entire claim — do not let a
   * README, a UI string, or a demo narration inflate it into detection.
   *
   * SCOPE, deliberately narrow:
   *   - ONLY `reason === 'policy_deny'` (tier 4) counts. `unknown_tool` does
   *     NOT: a model hallucinating a tool name is a mistake, not an
   *     escalation attempt, and must never cost anyone their session.
   *   - A Verify-side `access_denied` at Token Exchange does NOT count either.
   *     That deny is a legitimate, expected outcome of a correctly-scoped
   *     identity (a read-only agent proving it cannot write is a normal
   *     demonstration, and a normal application flow), and counting it would
   *     turn a working authorization boundary into a self-inflicted outage.
   *   - The counter is shared with the MFA path on purpose: it counts
   *     DENIALS THIS IDENTITY COLLECTED, whatever produced them.
   *
   * DEFAULT OFF because it changes what an existing deployment does on a path
   * that previously only ever returned 403 — opt in per instance, and only on
   * an instance whose tier-4 tools are genuinely blocked-for-everyone.
   */
  blockedActionKill?: boolean;
}

const defaultRunPipelineDeps: Required<RunPipelineDeps> = {
  introspectUser,
  isSessionKilled,
  readSubjectIssuedAt,
  gateTool,
  resolveRar,
  exchangeToken,
  triggerOAuthMfaPush,
  buildPushContext,
  triggerTransientEmailOtp,
  mintCred,
  callUpstreamTool,
  revokeLease,
  appendAudit,
  clearDeny,
  recordDeny,
  emitSessionRevoked,
  markKilled,
  putPending,
  genTxId: () => randomUUID(),
  now: () => Date.now(),
  dbBacked: process.env['UPSTREAM_DB_BACKED'] !== 'false',
  hitlMethod: process.env['HITL_METHOD'] === 'transient_email' ? 'transient_email' : 'push',
  blockedActionKill: process.env['BLOCKED_ACTION_KILL'] === 'true',
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
    narrate({ outcome: 'error', tool: ctx.toolName, exchange: 'error:inactive_session', latencyMs: d.now() - startedAt });
    return { status: 'error', error: 'inactive_session' };
  }
  const verifyUserId = introspection.verifyUserId ?? '';
  // Some STS custom token types (Okta, and Entra with certain claim
  // mappings) emit NO `email` claim at all — /oauth2/userinfo then has
  // nothing under `email` even though the token DOES carry
  // `preferred_username` (often the same address, e.g.
  // "operator@example.com"). Fall back to it, but ONLY when it looks like
  // an email (contains '@') — a UPN-shaped preferred_username with no '@'
  // must NOT be treated as a delivery address. Live-found: a
  // transient_email HITL deployment returned mfa_no_email for an identity
  // that plainly had a deliverable address, just not under the `email`
  // claim. Proven pattern: the same fallback used in the portfolio's Okta-
  // fronted token-exchange variant's selectTransientOtpChannel.
  //
  // `ctx.subjectEmail` (caller-supplied, decoded from the ORIGINAL IdP
  // subject token) is preferred over BOTH: Verify's userinfo reflects a
  // persisted, JIT-provisioned attribute that is set once and never
  // refreshed on later logins, so it silently drifts from the subject
  // token's actual current claim. See PipelineCtx.subjectEmail's doc.
  const userEmail =
    ctx.subjectEmail ??
    introspection.email ??
    (introspection.preferredUsername?.includes('@') ? introspection.preferredUsername : undefined);

  // Step 0: local kill-gate, BEFORE any gate/exchange work. Covers the
  // 30-75s Antenna -> Verify session-revoke propagation window.
  //
  // The token's `iat` is passed so a genuine re-authentication clears the
  // gate: only a subject token ISSUED AFTER the kill gets through, and one
  // can only exist if the human authenticated again at the IdP. This runs
  // after introspection deliberately — Verify has already vouched for this
  // exact token, so its `iat` is not something a caller can assert. See
  // ssf/killed-sessions.ts for why this is not a timer and not an un-kill API.
  const wasKilled = d.isSessionKilled(verifyUserId);
  if (d.isSessionKilled(verifyUserId, d.readSubjectIssuedAt(ctx.userToken))) {
    narrate({
      outcome: 'error', tool: ctx.toolName, ...(userEmail || verifyUserId ? { user: userEmail || verifyUserId } : {}),
      exchange: 'error:session_killed', latencyMs: d.now() - startedAt,
    });
    return { status: 'error', error: 'session_killed' };
  }
  if (wasKilled) {
    // The gate was in force a line ago and this token's `iat` just cleared
    // it — a real re-authentication. Reset the strike counter too, or the
    // very next deny lands on a counter that is already at the threshold
    // and kills the brand-new session instantly. A re-authenticated human
    // starts from zero strikes, which is the whole point of letting them
    // back in.
    d.clearDeny(verifyUserId);
    console.warn(
      `[${SERVICE_NAME}] kill-gate cleared for user=${verifyUserId} — subject token issued after the kill ` +
        `(re-authenticated at the identity provider); deny counter reset`,
    );
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

    // Blocked-action escalation kill (opt-in — see RunPipelineDeps.blockedActionKill).
    // Only a real tier-4 policy deny counts; `unknown_tool` never does.
    if (d.blockedActionKill && gate.reason === 'policy_deny') {
      const denyResult = d.recordDeny(verifyUserId);
      if (denyResult.thresholdReached) {
        await d.emitSessionRevoked({
          verifyUserId,
          email: userEmail,
          reason: 'blocked_action_threshold_reached',
        });
        d.markKilled(verifyUserId);
        d.appendAudit({
          ts: d.now(),
          userId: verifyUserId,
          tool: ctx.toolName,
          tier: gate.tier,
          decision: 'tier4_deny_threshold_killed',
        });
        narrate({
          outcome: 'killed', tool: ctx.toolName, ...(userEmail || verifyUserId ? { user: userEmail || verifyUserId } : {}),
          tier: gate.tier, exchange: 'denied:blocked_action_threshold_reached', latencyMs: d.now() - startedAt,
        });
        return {
          status: 'denied',
          reason: 'blocked_action_threshold_reached',
          killed: true,
          denyCount: denyResult.count,
          denyThreshold: denyResult.threshold,
        };
      }
      narrate({
        outcome: 'denied', tool: ctx.toolName, ...(userEmail || verifyUserId ? { user: userEmail || verifyUserId } : {}),
        tier: gate.tier, exchange: 'denied:policy_deny', latencyMs: d.now() - startedAt,
      });
      return {
        status: 'denied',
        reason: 'policy_deny',
        denyCount: denyResult.count,
        denyThreshold: denyResult.threshold,
      };
    }

    narrate({
      outcome: 'denied', tool: ctx.toolName, ...(userEmail || verifyUserId ? { user: userEmail || verifyUserId } : {}),
      tier: gate.tier, exchange: `denied:${gate.reason ?? 'policy_deny'}`, latencyMs: d.now() - startedAt,
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
    if (probe.result.status !== 'ok') {
      // The probe failed — that IS this inbound call's outcome. Narrate once,
      // marked as the discovery leg so the line is not mistaken for a delivery.
      narrate({ ...probe.facts, tool: ctx.toolName, stepUp: 'discovery', latencyMs: d.now() - startedAt });
      return probe.result;
    }
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
        narrate({ ...probe.facts, latencyMs: d.now() - startedAt });
        return probe.result;
      }
      // detail/history on a public record — the probe only told us it is not
      // restricted; run the ACTUAL requested tool with the standard RAR. That
      // call (suppressAudit:false) audits its own 'ok' result.
      const delivered = await runExchangeAndCall({ ctx, gate, verifyUserId, userEmail, startedAt, elevated: false, suppressAudit: false }, d);
      narrate({ ...delivered.facts, latencyMs: d.now() - startedAt });
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
    narrate({ ...elevated.facts, stepUp: 'elevated', latencyMs: d.now() - startedAt });
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
  narrate({ ...normal.facts, latencyMs: d.now() - startedAt });
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

/**
 * Mint the SEP-2322 requestState for a transaction about to be parked (or
 * RE-parked — see completePending's otp_invalid retry branch, which calls
 * this again on every re-put). Shared by every mint site so `sub` and
 * `digest` can never drift between them: `sub` is the SAME verifyUserId the
 * pending ctx stores (and that completePending's owner check at the top of
 * that function compares the caller against), and `digest` is computed over
 * the SAME toolName/args the pending ctx stores for the eventual re-run.
 *
 * `exp` is `now + ttlMs()` — it matches the pending entry's TTL AS OF THIS
 * MINT, not for the entry's lifetime. A re-park (putPending called again
 * under the same txId) refreshes the STORE's expiry to a new `now +
 * ttlMs()`; a blob minted before that re-park keeps its ORIGINAL (now
 * stale-relative-to-the-refreshed-entry) exp — it does NOT get retroactively
 * extended, and letting it verify past its own exp would be a lie about
 * what was actually signed. The re-park call site mints and returns a FRESH
 * blob for exactly this reason: the entry and its most-recently-issued
 * requestState always expire together; a stale (pre-re-park) blob does not,
 * by design — see the wiring rules in completePending's own doc comment.
 */
function mintPendingRequestState(
  txId: string,
  verifyUserId: string,
  toolName: string,
  args: Record<string, unknown>,
  now: number,
): string {
  return mintRequestState({ txId, sub: verifyUserId, exp: now + ttlMs(), digest: requestDigest(toolName, args) });
}

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
): Promise<{
  result: PipelineResult;
  authorizationDetails: AuthorizationDetail[];
  leaseId?: string;
  /** Non-secret narration facts accumulated by this leg. runPipeline (the
   *  choke point) renders them — this function never prints, so a
   *  discovery-probe leg cannot emit a second line for one inbound call. */
  facts: NarrateFacts;
}> {
  const { ctx, gate, verifyUserId, userEmail, startedAt, elevated, suppressAudit } = params;

  // Narration accumulator — non-secret metadata only (see narrate() above).
  const facts: NarrateFacts = {
    outcome: 'error',
    tool: ctx.toolName,
    ...(userEmail || verifyUserId ? { user: userEmail || verifyUserId } : {}),
    tier: gate.tier,
    ...(gate.rarAction ? { rar: gate.rarAction } : {}),
  };

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
    facts.exchange = 'mfa_challenge';
    facts.tx = txId;

    // ── transient_email HITL mode ─────────────────────────────────────
    // Entra-anchored users JIT'd into the tenant have no enrolled Verify
    // push factor (triggerOAuthMfaPush would 500 with mfa_no_factor) — mail
    // a one-shot code to the user's introspected email instead. The
    // destination is NEVER hardcoded or caller-supplied; it comes from
    // Token Exchange's own introspection result the same way push resolves
    // the user's factor from the challenge token — `userEmail` above
    // already folds in the `email`-claim-missing fallback to
    // `preferred_username`, so mfa_no_email below means BOTH sources came
    // up empty (or preferred_username wasn't email-shaped), not just that
    // one specific claim was absent.
    if (d.hitlMethod === 'transient_email') {
      if (!userEmail) {
        if (!suppressAudit) {
          d.appendAudit({
            ts: d.now(),
            userId: verifyUserId,
            tool: ctx.toolName,
            tier: gate.tier,
            authorizationDetails,
            decision: 'exchange_error',
          });
        }
        facts.outcome = 'error';
        facts.exchange = 'error:mfa_no_email';
        return { result: { status: 'error', error: 'mfa_no_email' }, authorizationDetails, facts };
      }

      // Best-effort, same rationale as the push trigger below: if sending
      // the code itself fails, still park the pending ctx (transactionUri
      // left undefined) so the caller sees 'pending' rather than a hard
      // error — completePending's no-poll-URL guard turns that into a
      // clear otp_init_failed instead of crashing.
      let transactionUri: string | undefined;
      try {
        const txn = await d.triggerTransientEmailOtp(exchangeResult.challengeToken, userEmail);
        transactionUri = txn.transactionUri;
      } catch (err) {
        console.warn('[pipeline] triggerTransientEmailOtp failed (parking pending anyway):', (err as Error).message);
      }

      const pendingCtx: PendingCtx = {
        verifyUserId,
        email: userEmail,
        challengeToken: exchangeResult.challengeToken,
        hitlMethod: 'email_otp',
        transactionUri,
        scope: gate.scope,
        authorizationDetails,
        toolName: ctx.toolName,
        credsPath,
        startedAt,
        args: ctx.args,
        senderConstrained: ctx.senderConstrained,
      };
      d.putPending(txId, pendingCtx);

      facts.outcome = 'pending';
      return {
        result: {
          status: 'pending',
          txId,
          requestState: mintPendingRequestState(txId, verifyUserId, ctx.toolName, ctx.args, d.now()),
          pushInfo: { method: 'email_otp', maskedDestination: maskEmail(userEmail) },
        },
        authorizationDetails,
        facts,
      };
    }

    // ── push HITL mode (default) ────────────────────────────────────────
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
      hitlMethod: 'push',
      transactionUri,
      scope: gate.scope,
      authorizationDetails,
      toolName: ctx.toolName,
      credsPath,
      startedAt,
      args: ctx.args,
      senderConstrained: ctx.senderConstrained,
    };
    d.putPending(txId, pendingCtx);

    facts.outcome = 'pending';
    return {
      result: {
        status: 'pending',
        txId,
        requestState: mintPendingRequestState(txId, verifyUserId, ctx.toolName, ctx.args, d.now()),
        pushInfo: { method: 'push', ...pushContext, transactionUri },
      },
      authorizationDetails,
      facts,
    };
  }

  if (exchangeResult.status === 'error') {
    // AUDIT PARITY with the tier-4 local deny above: that gate always
    // audits before returning 'denied'; this Token-Exchange-level failure
    // — most importantly a real Verify policy deny (access_denied,
    // CSIAQ0278E hard-cap or CSIAQ0279E entitlement gap) — previously
    // returned with NO audit row at all, so a caller reconstructing "who
    // got denied what" from the audit chain alone would silently miss
    // every deny that made it past the tier gate and got rejected by
    // Verify itself. suppressAudit still governs this (matches the 'ok'
    // path below): the gateway-derived step-up discovery probe audits its
    // own outcome one level up in runPipeline, so a probe-only failure here
    // must not double-audit.
    if (!suppressAudit) {
      d.appendAudit({
        ts: d.now(),
        userId: verifyUserId,
        tool: ctx.toolName,
        tier: gate.tier,
        authorizationDetails,
        decision: exchangeResult.error === 'access_denied' ? 'exchange_denied' : 'exchange_error',
      });
    }
    facts.outcome = 'error';
    facts.exchange =
      exchangeResult.error === 'access_denied' ? 'denied:access_denied' : `error:${exchangeResult.error}`;
    return { result: { status: 'error', error: exchangeResult.error }, authorizationDetails, facts };
  }

  const obo = exchangeResult.accessToken;
  facts.exchange = 'ok';

  // DB-backed (default): mint an ephemeral verify-rar Postgres credential, hand
  // it to the upstream as X-DB-*, and revoke the lease after the one call (the
  // revoke always runs, success or failure, so a lease never outlives its call).
  // NO-DB (UPSTREAM_DB_BACKED=false): the upstream has no database — SKIP the
  // whole Vault leg and call it on the OBO alone (no X-DB-* headers).
  let cred: MintedCred | undefined;
  let data: unknown;
  // revokeLease REPORTS whether Vault accepted the revoke (it still never
  // throws). Left undefined when nothing was minted, or when an injected test
  // double returns void — the diag below only carries a real boolean, so it
  // can never claim "revoked" without evidence.
  let credRevoked: boolean | undefined;
  if (d.dbBacked) {
    // credsPath is guaranteed present in DB-backed mode — the rar-config parse
    // requires it on every non-blocked action when UPSTREAM_DB_BACKED !== 'false'.
    cred = await d.mintCred({ obo, authorizationDetails, credsPath: credsPath! });
    facts.lease = cred.leaseId;
    try {
      data = await d.callUpstreamTool({
        name: ctx.toolName,
        arguments: ctx.args,
        obo,
        dbUser: cred.username,
        dbPass: cred.password,
      });
    } finally {
      const revoked = await d.revokeLease(cred.leaseId, obo);
      if (typeof revoked === 'boolean') {
        credRevoked = revoked;
        facts.revoked = revoked;
      }
    }
  } else {
    data = await d.callUpstreamTool({ name: ctx.toolName, arguments: ctx.args, obo });
  }

  // The observability payload — proves the exchange (+ mint, when DB-backed)
  // happened. Carries the OBO's jti (correlation), never the OBO itself (a live
  // credential). NO-DB: no `cred` field (there is no ephemeral credential).
  const diag: OboDiag = {
    ...(process.env['GATEWAY_DEBUG_OBO'] === 'true' ? { obo } : {}),
    oboJti: decodeJwtJti(obo),
    oboTtl: exchangeResult.expiresIn,
    oboScope: exchangeResult.scope ?? gate.scope,
    ...(cred ? { cred: { username: cred.username, leaseId: cred.leaseId, path: credsPath! } } : {}),
    ...(typeof credRevoked === 'boolean' ? { credRevoked } : {}),
    elevated,
    ...(ctx.senderConstrained ? { tokenBinding: 'dpop' as const } : {}),
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

  facts.outcome = 'ok';
  if (diag.oboJti) facts.jti = diag.oboJti;

  return { result: { status: 'ok', data, diag }, authorizationDetails, leaseId: cred?.leaseId, facts };
}

// ── completePending deps ─────────────────────────────────────

export interface CompletePendingDeps {
  peekPending?: typeof peekPending;
  takePending?: typeof takePending;
  /** Re-park a transaction whose one-shot entry takePending already consumed
   *  — used by the transient_email retry path (a wrong code that still has
   *  attempts left must stay resumable under the same txId). */
  putPending?: typeof putPending;
  gateTool?: typeof gateTool;
  pollOAuthMfaStatus?: typeof pollOAuthMfaStatus;
  /** transient_email HITL mode only — verifies the caller-supplied otp
   *  against the pending ctx's transactionUri (the transient-verification
   *  submit URL). Not used on the push path. */
  submitTransientOtp?: typeof submitTransientOtp;
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
  putPending,
  gateTool,
  pollOAuthMfaStatus,
  submitTransientOtp,
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
 *
 * `otp` is REQUIRED when the parked transaction's hitlMethod is 'email_otp'
 * (transient_email HITL mode) — validated off the same non-destructive peek,
 * BEFORE takePending, so a caller who simply omitted the field doesn't burn
 * the one-shot pending entry. It is ignored for 'push' transactions (the
 * push path has no code to submit).
 *
 * `requestState` is OPTIONAL — SEP-2322 (MRTR) integrity binding, Phase 0
 * validate-if-present (see hitl/request-state.ts's own doc comment). Absent:
 * behavior is unchanged from before this parameter existed — the identity
 * check above and the single-use pending store already enforce who may
 * resume a transaction. Present: it is verified against the entry's own
 * owner and a digest recomputed from the entry's own stored toolName/args
 * (never from anything the caller sends) — off the same non-destructive
 * `peeked` read the identity check uses, BEFORE takePending, so a bad
 * requestState never burns the legitimate owner's one-shot completion
 * attempt. A failure returns the SAME shape as the owner-mismatch path
 * above, with `error: 'invalid_request_state'`.
 */
export async function completePending(
  txId: string,
  callerVerifyUserId: string | undefined,
  deps: CompletePendingDeps = {},
  otp?: string,
  requestState?: string,
): Promise<PipelineResult> {
  const d: Required<CompletePendingDeps> = { ...defaultCompletePendingDeps, ...deps };
  const startedAt = d.now();

  const peeked = d.peekPending(txId);
  if (!peeked) {
    narrate({ outcome: 'error', tool: 'complete_hitl', stepUp: 'resumed', tx: txId, exchange: 'error:unknown_or_expired_tx' });
    return { status: 'error', error: 'unknown_or_expired_tx' };
  }

  if (!callerVerifyUserId || callerVerifyUserId !== peeked.verifyUserId) {
    narrate({ outcome: 'error', tool: peeked.toolName, stepUp: 'resumed', tx: txId, exchange: 'error:forbidden' });
    return { status: 'error', error: 'forbidden' };
  }

  // SEP-2322 requestState — validate-if-present (see completePending's own
  // doc comment above). Runs off the same non-destructive `peeked` read as
  // the identity check just above, strictly BEFORE takePending: a bad
  // requestState must not consume the pending entry, so a completer that
  // retries with just txId can still succeed. The digest is recomputed from
  // the ENTRY's own stored toolName/args — never from anything the caller
  // presents — so a completer cannot mint its own digest to match a
  // tampered claim.
  if (requestState !== undefined) {
    const verdict = verifyRequestState(
      requestState,
      { txId, sub: peeked.verifyUserId, digest: requestDigest(peeked.toolName, peeked.args) },
      d.now(),
    );
    if (!verdict.ok) {
      narrate({ outcome: 'error', tool: peeked.toolName, stepUp: 'resumed', tx: txId, exchange: 'error:invalid_request_state' });
      return { status: 'error', error: 'invalid_request_state' };
    }
  }

  // Local kill-gate — same shield runPipeline applies at step 0. Without this,
  // a session killed WHILE a step-up is parked (e.g. a suspicious-deny or
  // 3-strike kill on another tx during the ~30-75s Antenna->Verify revocation
  // propagation window, while the bearer still introspects active) could resume
  // this parked tx, mint fresh Vault creds, and return the withheld data. Check
  // the tx OWNER's verifyUserId (== the identity-bound caller) before takePending.
  if (d.isSessionKilled(peeked.verifyUserId)) {
    narrate({ outcome: 'error', tool: peeked.toolName, user: peeked.email ?? peeked.verifyUserId, stepUp: 'resumed', tx: txId, exchange: 'error:session_killed' });
    return { status: 'error', error: 'session_killed' };
  }

  // Back-compat: entries parked before hitlMethod existed have no field —
  // treat as 'push' (the only method that existed then).
  const hitlMethod = peeked.hitlMethod ?? 'push';

  if (hitlMethod === 'email_otp' && !otp) {
    narrate({ outcome: 'error', tool: peeked.toolName, user: peeked.email ?? peeked.verifyUserId, stepUp: 'resumed', tx: txId, exchange: 'error:otp_required' });
    return { status: 'error', error: 'otp_required' };
  }

  const ctx = d.takePending(txId);
  if (!ctx) {
    // Expired in the (vanishingly small, single-threaded-Node) window
    // between peek and take — treat exactly like a normal expiry.
    narrate({ outcome: 'error', tool: peeked.toolName, stepUp: 'resumed', tx: txId, exchange: 'error:unknown_or_expired_tx' });
    return { status: 'error', error: 'unknown_or_expired_tx' };
  }

  const args = ctx.args;
  const gate = d.gateTool(ctx.toolName);
  const authorizationDetails = ctx.authorizationDetails as AuthorizationDetail[];

  // Narration accumulator for the resumed leg — same non-secret contract as
  // runExchangeAndCall's. `stepUp: 'resumed'` is what distinguishes this line
  // from the original call's `pending` line carrying the same tx id.
  const facts: NarrateFacts = {
    outcome: 'error',
    tool: ctx.toolName,
    ...(ctx.email || ctx.verifyUserId ? { user: ctx.email || ctx.verifyUserId } : {}),
    tier: gate.tier,
    ...(gate.rarAction ? { rar: gate.rarAction } : {}),
    stepUp: 'resumed',
    tx: txId,
  };
  /** Render `facts` with the terminal outcome + this leg's elapsed time. */
  const narrateFinish = (outcome: string, exchange?: string): void => {
    narrate({ ...facts, outcome, ...(exchange ? { exchange } : {}), latencyMs: d.now() - startedAt });
  };

  // Hardening fix: a pending tx whose push/OTP trigger never actually fired
  // (runExchangeAndCall's best-effort trigger failed, parked anyway so the
  // caller still sees 'pending') has no transactionUri. This used to fall
  // straight into pollOAuthMfaStatus('', ...), which threw a raw "Failed to
  // parse URL from ?returnJwt=true" — a 500 with no actionable diagnostic —
  // instead of a clean envelope the caller can act on (e.g. retry the
  // original call to get a fresh mfa_challenge).
  if (!ctx.transactionUri) {
    const err = hitlMethod === 'email_otp' ? 'otp_init_failed' : 'no_poll_url';
    narrateFinish('error', `error:${err}`);
    return { status: 'error', error: err };
  }

  let assertion: string;

  if (hitlMethod === 'email_otp') {
    const otpResult = await d.submitTransientOtp(ctx.transactionUri, otp!, ctx.challengeToken);

    if (otpResult.status === 'otp_invalid') {
      // A wrong one-time code is a DENIAL, exactly like a denied push — the
      // person on the other end of the step-up did not prove they are the
      // approver. It therefore feeds the SAME per-user deny counter the push
      // path feeds, with the SAME 3-strike threshold and the SAME kill.
      //
      // This wire did not exist until 2026-07-31. `recordDeny`/`markKilled`/
      // `emitSessionRevoked` were only reachable from the push branch below,
      // so a deployment running HITL_METHOD=transient_email had a fully-built
      // kill chain that nothing could ever trigger. Counting only `otp_invalid`
      // (never `otp_expired`) is deliberate: an expired code means a slow
      // human, not a wrong one, and must not cost anyone their session.
      const denyResult = d.recordDeny(ctx.verifyUserId);
      d.appendAudit({
        ts: d.now(),
        userId: ctx.verifyUserId,
        tool: ctx.toolName,
        tier: gate.tier,
        authorizationDetails,
        decision: 'otp_invalid',
      });

      if (denyResult.thresholdReached) {
        await d.emitSessionRevoked({
          verifyUserId: ctx.verifyUserId,
          email: ctx.email,
          reason: 'otp_deny_threshold_reached',
        });
        d.markKilled(ctx.verifyUserId);
        d.appendAudit({
          ts: d.now(),
          userId: ctx.verifyUserId,
          tool: ctx.toolName,
          tier: gate.tier,
          authorizationDetails,
          decision: 'otp_deny_threshold_killed',
        });
        narrateFinish('killed', 'denied:otp_deny_threshold_reached');
        return { status: 'denied', reason: 'otp_deny_threshold_reached', killed: true };
      }

      // Attempts remain — RE-PARK the transaction under the same txId so the
      // caller can genuinely retry. takePending() above was destructive, so
      // without this re-put the very next attempt on this txId returns
      // `unknown_or_expired_tx`: every consumer's documented "wrong code, N
      // attempts remaining, try again" flow was unreachable, and a 3-strike
      // threshold could never be walked to on a single parked step-up.
      // Re-putting also refreshes the entry's TTL, which is correct — the
      // clock a retry should race is the OTP's own validity, which Verify
      // enforces itself and reports back as `otp_expired`.
      d.putPending(txId, ctx);

      // The requestState minted at the ORIGINAL park has an `exp` fixed to
      // that original mint (see mintPendingRequestState's doc comment) — it
      // does NOT get retroactively extended by the re-put above. Mint and
      // return a FRESH one (same txId/sub/digest inputs, off the SAME ctx
      // the store now holds, new exp = this re-park's now + ttlMs()) so a
      // client that always echoes the most-recently-received requestState
      // is never worse off than one that never echoes at all — a client
      // still holding the stale original blob past its exp is rejected by
      // design (invalid_request_state), but can retry with just the txId,
      // or with THIS fresh one.
      const requestState = mintPendingRequestState(txId, ctx.verifyUserId, ctx.toolName, ctx.args, d.now());

      narrateFinish('error', 'error:otp_invalid');
      return {
        status: 'error',
        error: 'otp_invalid',
        ...(otpResult.attemptsRemaining !== undefined ? { attemptsRemaining: otpResult.attemptsRemaining } : {}),
        denyCount: denyResult.count,
        denyThreshold: denyResult.threshold,
        requestState,
      };
    }
    if (otpResult.status === 'otp_expired') {
      d.appendAudit({
        ts: d.now(),
        userId: ctx.verifyUserId,
        tool: ctx.toolName,
        tier: gate.tier,
        authorizationDetails,
        decision: 'otp_expired',
      });
      narrateFinish('error', 'error:otp_expired');
      return { status: 'error', error: 'otp_expired' };
    }
    if (otpResult.status === 'error') {
      narrateFinish('error', `error:${otpResult.error}`);
      return { status: 'error', error: otpResult.error };
    }
    assertion = otpResult.assertion;
  } else {
    const verdict = await d.pollOAuthMfaStatus(ctx.transactionUri, ctx.challengeToken);

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
      narrateFinish('killed', 'denied:suspicious');
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
        narrateFinish('denied', 'denied:deny_threshold_reached');
        return { status: 'denied', reason: verdict.reason, killed: true };
      }
      narrateFinish('denied', `denied:${verdict.reason ?? 'mfa_deny'}`);
      return { status: 'denied', reason: verdict.reason };
    }

    if (verdict.state === 'timeout') {
      narrateFinish('error', 'error:mfa_timeout');
      return { status: 'error', error: 'mfa_timeout' };
    }

    // verdict.state === 'approved'
    assertion = verdict.assertion;
  }

  let exchangeSecret = await d.getExchangeClientSecret();
  let assertionResult = await d.exchangeMfaAssertionWithRAR(
    assertion,
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
      assertion,
      ctx.scope,
      authorizationDetails,
      exchangeSecret,
    );
  }

  if (assertionResult.status !== 'ok') {
    const err = assertionResult.status === 'error' ? assertionResult.error : 'jwt_bearer_failed';
    narrateFinish('error', `error:${err}`);
    return { status: 'error', error: err };
  }
  const obo = assertionResult.accessToken;
  facts.exchange = 'ok:jwt_bearer';

  // Same DB-backed vs NO-DB branch as runExchangeAndCall — a stepped-up call to
  // a non-database upstream (UPSTREAM_DB_BACKED=false) skips the mint/revoke leg
  // and runs on the OBO alone.
  let cred: MintedCred | undefined;
  let data: unknown;
  // Same reported-not-assumed revoke outcome as runExchangeAndCall. This site
  // MUST populate it too: an approved step-up is exactly the call a presenter
  // points at, and a diag that silently drops a field on the HITL path is the
  // `_diagnostic: {}` class of bug this repo has already been bitten by.
  let credRevoked: boolean | undefined;
  if (d.dbBacked) {
    cred = await d.mintCred({ obo, authorizationDetails, credsPath: ctx.credsPath! });
    facts.lease = cred.leaseId;
    try {
      data = await d.callUpstreamTool({
        name: ctx.toolName,
        arguments: args,
        obo,
        dbUser: cred.username,
        dbPass: cred.password,
      });
    } finally {
      const revoked = await d.revokeLease(cred.leaseId, obo);
      if (typeof revoked === 'boolean') {
        credRevoked = revoked;
        facts.revoked = revoked;
      }
    }
  } else {
    data = await d.callUpstreamTool({ name: ctx.toolName, arguments: args, obo });
  }

  // Same observability payload as runExchangeAndCall — this is the leg-2
  // (post-approval) OBO, the one actually minted after the human said yes.
  // NO-DB: no `cred` field (there is no ephemeral credential).
  const diag: OboDiag = {
    ...(process.env['GATEWAY_DEBUG_OBO'] === 'true' ? { obo } : {}),
    oboJti: decodeJwtJti(obo),
    oboTtl: assertionResult.expiresIn,
    oboScope: assertionResult.scope ?? ctx.scope,
    ...(cred ? { cred: { username: cred.username, leaseId: cred.leaseId, path: ctx.credsPath! } } : {}),
    ...(typeof credRevoked === 'boolean' ? { credRevoked } : {}),
    // Elevated iff the parked creds path belongs to an `elevatedFrom` action
    // in config/rar.json — the config, not a path-suffix naming convention,
    // defines "elevated". A NO-DB call has no creds path, so it is never elevated.
    elevated: ctx.credsPath ? isElevatedCredsPath(ctx.credsPath) : false,
    ...(ctx.senderConstrained ? { tokenBinding: 'dpop' as const } : {}),
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

  if (diag.oboJti) facts.jti = diag.oboJti;
  narrateFinish('ok');

  return { status: 'ok', data, diag };
}
