// ssf/killed-sessions.ts — local kill-gate.
//
// Local 5-min kill-gate that 401s subsequent tool calls during the 30-75s
// transmitter → Verify session-revoke propagation window. TTL configurable
// via SSF_KILLED_SESSION_TTL_MS env var (default 5 min).
//
// Without this, attempts 2+ after a 1-strike suspicious-deny (or after a 3rd
// consecutive normal deny) still go through Token Exchange, fire MFA pushes
// to the user's phone, and generally pester someone who has already
// reported the agent's activity as suspicious. Verify-side propagation
// takes 17-75s; this local gate covers that window with zero extra
// roundtrips.

const killed = new Map<string, number>();

const DEFAULT_TTL_MS = 5 * 60 * 1000;

function ttlMs(): number {
  const raw = process.env.SSF_KILLED_SESSION_TTL_MS;
  if (!raw) return DEFAULT_TTL_MS;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_TTL_MS;
}

/**
 * Mark a user's session as killed locally. Tool dispatches for this user
 * will short-circuit until the TTL expires. Called after a 1-strike
 * suspicious-deny OR a 3-strike threshold-reached normal-deny.
 */
export function markKilled(verifyUserId: string): void {
  killed.set(verifyUserId, Date.now() + ttlMs());
}

/**
 * Check whether a user's session has been locally killed and is still
 * within the TTL window. Lazy expiry: cleans up the entry on miss.
 */
export function isSessionKilled(verifyUserId: string): boolean {
  const expiry = killed.get(verifyUserId);
  if (expiry === undefined) return false;
  if (Date.now() >= expiry) {
    killed.delete(verifyUserId);
    return false;
  }
  return true;
}

/**
 * Manually clear a kill (e.g. on /unkill or re-auth). Idempotent.
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
