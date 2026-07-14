// ssf/deny-counter.ts — per-user MFA denial counter.
//
// In-memory per-user MFA denial counter for the
// "3 denials = session kill" scenario. Resets on a successful MFA-gated
// tool call (so a legitimate user who accidentally denies once doesn't
// compound across sessions). Resets when the rolling window expires
// (5 minutes). Single-process, non-persistent — fine for the demo where the
// gateway runs as one systemd service.
//
// Tested behavior contract (see deny-counter.test.ts):
//
//   recordDeny('A') → { count: 1, thresholdReached: false }
//   recordDeny('A') → { count: 2, thresholdReached: false }
//   recordDeny('A') → { count: 3, thresholdReached: true  }  ← threshold
//   clearDeny('A')  → getDenyCount('A') === 0
//   After WINDOW_MS expires → next recordDeny resets to count=1
//   Different user IDs are tracked independently.

const WINDOW_MS = 5 * 60 * 1000; // 5-minute rolling window
const THRESHOLD = 3;

interface Entry {
  count: number;
  firstSeen: number;
}

// Module-level singleton — one map per process (matches systemd single-instance deploy).
const entries = new Map<string, Entry>();

export interface DenyResult {
  count: number;
  thresholdReached: boolean;
  windowMs: number;
  threshold: number;
}

/**
 * Record a denial for the given user. Returns the new count and whether
 * the threshold has been reached.
 *
 * If the prior entry is outside the rolling window, the counter resets to 1
 * (this denial starts a new window). The threshold is INCLUSIVE: count === 3
 * triggers the session-kill.
 */
export function recordDeny(verifyUserId: string): DenyResult {
  const now = Date.now();
  const existing = entries.get(verifyUserId);

  if (!existing || now - existing.firstSeen > WINDOW_MS) {
    // No prior entry or window expired — start fresh.
    entries.set(verifyUserId, { count: 1, firstSeen: now });
    return { count: 1, thresholdReached: false, windowMs: WINDOW_MS, threshold: THRESHOLD };
  }

  existing.count += 1;
  return {
    count: existing.count,
    thresholdReached: existing.count >= THRESHOLD,
    windowMs: WINDOW_MS,
    threshold: THRESHOLD,
  };
}

/**
 * Clear the counter for a user. Call after:
 *   - A successful MFA approval (legit user; reset so accidental denies don't
 *     compound across sessions).
 *   - A threshold-triggered session kill (next sign-in starts fresh).
 */
export function clearDeny(verifyUserId: string): void {
  entries.delete(verifyUserId);
}

/**
 * Read-only count inspector for diagnostics.
 */
export function getDenyCount(verifyUserId: string): number {
  return entries.get(verifyUserId)?.count ?? 0;
}
