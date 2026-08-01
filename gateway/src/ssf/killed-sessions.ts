// ssf/killed-sessions.ts — local kill-gate.
//
// Local kill-gate that short-circuits subsequent tool calls during the
// 30-75s transmitter → Verify session-revoke propagation window. TTL
// configurable via SSF_KILLED_SESSION_TTL_MS (default 5 min).
//
// Without this, attempts 2+ after a 1-strike suspicious-deny (or after a 3rd
// consecutive normal deny) still go through Token Exchange, fire MFA pushes
// to the user's phone, and generally pester someone who has already
// reported the agent's activity as suspicious. Verify-side propagation
// takes 17-75s; this local gate covers that window with zero extra
// roundtrips.
//
// ── CLEARING THE GATE ON A GENUINE RE-AUTHENTICATION ──────────────────────
//
// The gate is per-process and in-memory. Left as a bare "is this user id in
// the map" check it produces a demo-breaking dead end: the human signs back
// in at the IdP, gets a brand-new session, and STILL gets `session_killed`
// on every call until the TTL lapses or an operator restarts the service.
// Observed live — the UI shows "Session ended", the user clicks "Sign in
// again", authenticates successfully, and lands straight back on the same
// modal. The only reset was SSH.
//
// The fix is NOT a shorter timer and NOT a client-assertable un-kill. It is
// to make the gate answer the question it actually means to ask: "has this
// human re-authenticated SINCE the kill?" A token's `iat` answers that, and
// it answers it unforgeably:
//
//   * the kill records the wall-clock second at which it happened;
//   * a call is let through only if the presented subject token was ISSUED
//     STRICTLY AFTER that instant;
//   * `iat` is a claim in a Verify-signed JWT that runPipeline has ALREADY
//     confirmed is active (introspection runs before this gate — see
//     pipeline.ts step 1), so a caller cannot mint, doctor or replay one. A
//     tampered token fails its signature and userinfo 401s it before this
//     code is ever reached.
//
// To obtain a token with a later `iat` the human must complete a fresh
// authorization at the IdP, which is exactly the bar we want: the killed
// session stays dead until a real re-authentication, and no amount of
// retrying, waiting, or client-side assertion moves it.
//
// FAILS CLOSED: no `iat`, an unparseable token, or an `iat` at-or-before the
// kill all keep the user gated. An opaque (non-JWT) subject token therefore
// never silently bypasses a kill — such a deployment keeps the original
// TTL-only behaviour.

interface KillRecord {
  /** Wall-clock ms after which the local gate lapses regardless (propagation-window backstop). */
  expiry: number;
  /** Wall-clock SECONDS at which the kill was recorded — compared against the subject token's `iat`. */
  killedAtSec: number;
}

const killed = new Map<string, KillRecord>();

const DEFAULT_TTL_MS = 5 * 60 * 1000;

function ttlMs(): number {
  const raw = process.env.SSF_KILLED_SESSION_TTL_MS;
  if (!raw) return DEFAULT_TTL_MS;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_TTL_MS;
}

/**
 * Mark a user's session as killed locally. Tool dispatches for this user
 * short-circuit until either the TTL expires or the user presents a subject
 * token issued after this moment. Called after a 1-strike suspicious-deny
 * OR a 3-strike threshold-reached deny.
 */
export function markKilled(verifyUserId: string): void {
  const now = Date.now();
  killed.set(verifyUserId, {
    expiry: now + ttlMs(),
    // Floor to whole seconds: JWT `iat` has second granularity, so a token
    // minted in the same second as the kill must NOT count as "after" it.
    // Flooring makes the comparison `iat > killedAtSec` reject that tie.
    killedAtSec: Math.floor(now / 1000),
  });
}

/**
 * Is this user's session locally killed and still gated?
 *
 * `subjectIssuedAtSec` is the `iat` of the subject token presented on THIS
 * call (see readSubjectIssuedAt). Supplying an `iat` strictly greater than
 * the kill instant clears the gate — the human has re-authenticated at the
 * IdP since the kill. Omitting it (or passing an older one) leaves the gate
 * in force. Lazy TTL expiry: cleans up the entry on miss.
 */
export function isSessionKilled(verifyUserId: string, subjectIssuedAtSec?: number): boolean {
  const record = killed.get(verifyUserId);
  if (record === undefined) return false;

  if (Date.now() >= record.expiry) {
    killed.delete(verifyUserId);
    return false;
  }

  // A subject token minted AFTER the kill can only exist if the human
  // completed a fresh authorization — honour it and drop the gate.
  if (typeof subjectIssuedAtSec === 'number' && Number.isFinite(subjectIssuedAtSec) && subjectIssuedAtSec > record.killedAtSec) {
    killed.delete(verifyUserId);
    return false;
  }

  return true;
}

/**
 * Read the `iat` (in seconds) out of a subject token, or undefined for a
 * non-JWT / missing / non-numeric claim.
 *
 * NO signature check here on purpose, and none is needed: the only caller
 * runs this AFTER Verify has confirmed the very same token is active, so an
 * `iat` this function can read is one Verify has already vouched for.
 * Anything it cannot read returns undefined, which keeps the gate closed.
 */
export function readSubjectIssuedAt(token: string | undefined): number | undefined {
  const parts = (token ?? '').split('.');
  if (parts.length !== 3) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as Record<string, unknown>;
    return typeof payload['iat'] === 'number' ? (payload['iat'] as number) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Manually clear a kill (operator reset). Idempotent.
 */
export function unmarkKilled(verifyUserId: string): void {
  killed.delete(verifyUserId);
}

/**
 * Test-only: wipe the kill map between tests so process-singleton state
 * doesn't leak across test cases.
 */
export function __resetForTests(): void {
  killed.clear();
}
