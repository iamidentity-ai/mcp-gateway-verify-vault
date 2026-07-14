// audit/chain.ts — per-call audit-chain ring buffer.
//
// Feeds a UI stepper with a per-user, most-recent-first trail of every
// tool dispatch: tier, decision, RAR sent, lease minted, latency. One
// process, non-persistent — fine for the demo where the gateway runs as a
// single systemd service (matches deny-counter.ts / killed-sessions.ts).
//
// Design constraints:
//   - Fixed-capacity ring buffer (CAP records total, across all users) so
//     memory is bounded regardless of traffic; oldest record is evicted
//     first once the cap is reached.
//   - getAuditForUser filters by userId and returns newest-first, capped at
//     `limit` (default 50) — the stepper only ever renders a handful of
//     recent steps per user.
//   - __resetForTests() empties the buffer; only for test isolation.

export interface AuditRecord {
  ts: number;
  userId: string;
  tool: string;
  tier: number;
  sub?: string;
  actChain?: string[];
  authorizationDetails?: unknown[];
  decision: string;
  leaseId?: string;
  /** jti of the OBO that authorized this call — correlates the audit record
   *  with Verify's token-exchange grant and Vault's audit log. */
  oboJti?: string;
  latencyMs?: number;
}

const CAP = 500;
const DEFAULT_LIMIT = 50;

// Oldest-first insertion order; index 0 is evicted first once length > CAP.
const records: AuditRecord[] = [];

/**
 * Append an audit record to the ring buffer. When the buffer is at
 * capacity, the oldest record (across all users) is dropped to make room.
 */
export function appendAudit(rec: AuditRecord): void {
  records.push(rec);
  if (records.length > CAP) {
    records.shift();
  }
}

/**
 * Return this user's audit records, most-recent-first, capped at `limit`
 * (default 50).
 */
export function getAuditForUser(userId: string, limit: number = DEFAULT_LIMIT): AuditRecord[] {
  const out: AuditRecord[] = [];
  for (let i = records.length - 1; i >= 0 && out.length < limit; i--) {
    const rec = records[i];
    if (rec.userId === userId) out.push(rec);
  }
  return out;
}

/**
 * Reset the buffer. Only for test isolation — never call in production
 * code.
 */
export function __resetForTests(): void {
  records.length = 0;
}
