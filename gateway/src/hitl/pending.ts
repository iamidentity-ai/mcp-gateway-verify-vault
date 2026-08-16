// hitl/pending.ts — pending-transaction store.
//
// In-memory map keyed by txId, backing the gateway's HITL step-up flow
// with a putPending/takePending single-use pattern.
//
// When Token Exchange returns `scope=mfa_challenge`, the gateway needs to
// remember everything required to resume the second (jwt_bearer) leg once
// the user approves the push/OTP: the challenge token, the tool call being
// gated, and the scoped RAR (authorizationDetails) that must be re-sent.
// This module provides that store.
//
// Design constraints:
//   - One process, no distributed state — Map<string, Entry> is fine
//     (matches the gateway's single systemd-instance deploy).
//   - TTL enforced lazily: takePending() drops expired entries; opportunistic
//     sweep on every put() removes entries that have already expired.
//     Default TTL is 130s, overridable via HITL_PENDING_TTL_MS, read at
//     call time (not module load) so tests can inject a tiny TTL.
//   - takePending() is a destructive read: it deletes the entry on hit so a
//     transaction can only be resumed once (retries must re-putPending).
//   - peekPending() is a NON-destructive read: same lookup + TTL check as
//     takePending() but never deletes. Added for pipeline.ts's completePending
//     identity-binding check (security-review CRITICAL fix) — the caller's
//     verifyUserId must be compared against ctx.verifyUserId BEFORE the
//     one-shot entry is consumed, so a mismatched (unauthorized) caller can
//     be rejected without burning the legitimate owner's only completion
//     attempt.
//   - __resetForTests() empties the store; only for test isolation.

export interface PendingCtx {
  verifyUserId: string;
  /** The user's email from introspection — carried so a kill fired from
   *  completePending can include it in the CAEP sub_id (older transmitter
   *  session_revoked handlers fall back to SCIM-by-email and reject
   *  "No email in sub_id" without it). */
  email?: string;
  challengeToken: string;
  /** Which HITL method parked this transaction — decides how completePending
   *  resumes it: 'push' (default, back-compat with entries parked before
   *  this field existed) polls pollOAuthMfaStatus; 'email_otp' requires an
   *  `otp` from the caller and calls submitTransientOtp instead. Set once at
   *  park time by pipeline.ts's runExchangeAndCall off HITL_METHOD — never
   *  chosen by the caller completing the transaction. */
  hitlMethod?: 'push' | 'email_otp';
  /** For 'push': the transactionUri polled for a verdict. For 'email_otp':
   *  the transient-verification submit URL built from triggerTransientEmailOtp's
   *  response id. Absent when the trigger call itself failed (best-effort —
   *  the tx is still parked so the caller sees 'pending' rather than a hard
   *  error) — completePending MUST treat an absent value as "nothing to
   *  resume" rather than pass '' into a URL-parsing fetch call. */
  transactionUri?: string;
  scope: string;
  authorizationDetails: unknown[];
  toolName: string;
  /** verify-rar creds path the parked step-up will mint from. Absent in a
   *  NO-DB deployment (UPSTREAM_DB_BACKED=false) — there is no Vault leg, so
   *  completePending skips the mint and calls the upstream on the OBO alone. */
  credsPath?: string;
  startedAt: number;
  /** Original tool-call arguments, round-tripped through the txId so
   *  completePending can re-invoke callUpstreamTool once the push/OTP is
   *  approved. Folded directly into PendingCtx (review FIX 3) —
   *  previously lived in a pipeline-local `pendingArgs` side-channel Map
   *  that was only cleared on successful completion, leaking one entry per
   *  abandoned/timed-out mfa_challenge for the lifetime of the process. */
  args: Record<string, unknown>;
  /** True when the request that parked this transaction passed full-mode
   *  DPoP validation at the route layer. Carried through to completePending's
   *  diag so a resumed step-up still surfaces `tokenBinding: 'dpop'`. */
  senderConstrained?: boolean;
}

const DEFAULT_TTL_MS = 130 * 1000;

/** Exported so pipeline.ts's mint sites (park AND re-park — see
 *  completePending's otp_invalid retry branch) can compute a SEP-2322
 *  requestState (hitl/request-state.ts) `exp` matching THIS store's TTL as
 *  of that mint. A single mint's `exp` tracks the entry's TTL at mint time,
 *  not for the entry's whole lifetime: putPending (called again on a
 *  re-park) refreshes the STORE entry's own expiry independently, so an
 *  earlier requestState does not get retroactively extended — the re-park
 *  call site mints a fresh one instead, and a stale blob presented past its
 *  own exp is rejected by design (see completePending). */
export function ttlMs(): number {
  const raw = process.env.HITL_PENDING_TTL_MS;
  if (!raw) return DEFAULT_TTL_MS;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_TTL_MS;
}

interface Entry {
  ctx: PendingCtx;
  expiresAt: number;
}

const store = new Map<string, Entry>();

/**
 * Store a pending transaction ctx keyed by `txId`. Sweeps expired entries
 * opportunistically on every call so the Map does not grow unbounded.
 */
export function putPending(txId: string, ctx: PendingCtx): void {
  const now = Date.now();
  for (const [key, entry] of store) {
    if (entry.expiresAt <= now) store.delete(key);
  }
  store.set(txId, { ctx, expiresAt: now + ttlMs() });
}

/**
 * Retrieve AND delete the pending ctx for `txId`. Returns undefined when
 * the key is missing or the entry has expired. Callers that want to allow
 * a retry must call `putPending` again with the original ctx.
 */
export function takePending(txId: string): PendingCtx | undefined {
  const entry = store.get(txId);
  if (!entry) return undefined;
  store.delete(txId);
  if (entry.expiresAt <= Date.now()) return undefined;
  return entry.ctx;
}

/**
 * Retrieve the pending ctx for `txId` WITHOUT deleting it. Returns undefined
 * under the same conditions as takePending (missing or expired key) but
 * leaves the entry in place so a subsequent takePending can still consume it
 * exactly once. Use this to inspect a pending transaction (e.g. to
 * identity-bind the caller against ctx.verifyUserId) before deciding whether
 * the request is even entitled to consume it.
 */
export function peekPending(txId: string): PendingCtx | undefined {
  const entry = store.get(txId);
  if (!entry) return undefined;
  if (entry.expiresAt <= Date.now()) return undefined;
  return entry.ctx;
}

/**
 * Reset the store. Only for test isolation — never call in production code.
 */
export function __resetForTests(): void {
  store.clear();
}
