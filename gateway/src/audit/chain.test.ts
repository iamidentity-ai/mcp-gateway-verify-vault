/**
 * Tests for chain.ts.
 *
 * appendAudit/getAuditForUser back a UI
 * stepper's per-call audit trail. Ring buffer capped at a module const
 * (500) total entries across all users; getAuditForUser filters by userId
 * and returns newest-first, capped at `limit` (default 50).
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { appendAudit, getAuditForUser, __resetForTests, type AuditRecord } from './chain.js';

function makeRecord(overrides: Partial<AuditRecord> = {}): AuditRecord {
  return {
    ts: Date.now(),
    userId: 'user-123',
    tool: 'update_record',
    tier: 2,
    decision: 'allow',
    ...overrides,
  };
}

describe('audit/chain', () => {
  beforeEach(() => {
    __resetForTests();
  });

  it('appendAudit then getAuditForUser returns it', () => {
    const rec = makeRecord();
    appendAudit(rec);
    expect(getAuditForUser('user-123')).toEqual([rec]);
  });

  it('returns newest-first ordering', () => {
    const first = makeRecord({ ts: 1, tool: 'first' });
    const second = makeRecord({ ts: 2, tool: 'second' });
    const third = makeRecord({ ts: 3, tool: 'third' });
    appendAudit(first);
    appendAudit(second);
    appendAudit(third);
    expect(getAuditForUser('user-123').map((r) => r.tool)).toEqual(['third', 'second', 'first']);
  });

  it('filters by userId — other users are excluded', () => {
    appendAudit(makeRecord({ userId: 'user-A', tool: 'a-tool' }));
    appendAudit(makeRecord({ userId: 'user-B', tool: 'b-tool' }));
    appendAudit(makeRecord({ userId: 'user-A', tool: 'a-tool-2' }));

    const forA = getAuditForUser('user-A');
    expect(forA).toHaveLength(2);
    expect(forA.every((r) => r.userId === 'user-A')).toBe(true);

    const forB = getAuditForUser('user-B');
    expect(forB).toHaveLength(1);
    expect(forB[0].tool).toBe('b-tool');
  });

  it('respects the limit parameter', () => {
    for (let i = 0; i < 10; i++) {
      appendAudit(makeRecord({ tool: `tool-${i}`, ts: i }));
    }
    const limited = getAuditForUser('user-123', 3);
    expect(limited).toHaveLength(3);
    expect(limited.map((r) => r.tool)).toEqual(['tool-9', 'tool-8', 'tool-7']);
  });

  it('defaults the limit to 50', () => {
    for (let i = 0; i < 60; i++) {
      appendAudit(makeRecord({ tool: `tool-${i}`, ts: i }));
    }
    expect(getAuditForUser('user-123')).toHaveLength(50);
  });

  it('caps the total ring buffer length — appending past the cap drops the oldest', () => {
    // Cap is 500, spread across two users so we can prove the *oldest*
    // record (from user-old) is the one evicted, not merely truncated
    // per-user.
    appendAudit(makeRecord({ userId: 'user-old', tool: 'oldest', ts: 0 }));
    for (let i = 1; i <= 500; i++) {
      appendAudit(makeRecord({ userId: 'user-fill', tool: `fill-${i}`, ts: i }));
    }
    // Total appended = 501 > cap of 500, so the very first (oldest) entry
    // must have been evicted.
    expect(getAuditForUser('user-old')).toHaveLength(0);
    expect(getAuditForUser('user-fill', 500)).toHaveLength(500);
  });

  it('carries the full AuditRecord shape through unchanged, including optional fields', () => {
    const rec = makeRecord({
      sub: 'sub-claim-42',
      actChain: ['mcp-gateway', 'user-123'],
      authorizationDetails: [{ type: 'vault:path_access' }],
      leaseId: 'lease-xyz',
      latencyMs: 812,
    });
    appendAudit(rec);
    expect(getAuditForUser('user-123')[0]).toEqual(rec);
  });

  it('__resetForTests wipes all audit records', () => {
    appendAudit(makeRecord());
    __resetForTests();
    expect(getAuditForUser('user-123')).toEqual([]);
  });
});
