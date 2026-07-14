/**
 * Tests for pending.ts.
 *
 * putPending/takePending single-use pattern: keyed by txId, TTL default
 * 130s (HITL_PENDING_TTL_MS), takePending is a destructive read
 * (single-use — a second take returns undefined), and unknown/expired keys
 * return undefined (not null, to match this module's own
 * PendingCtx | undefined contract).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { putPending, takePending, peekPending, __resetForTests, type PendingCtx } from './pending.js';

function makeCtx(overrides: Partial<PendingCtx> = {}): PendingCtx {
  return {
    verifyUserId: 'user-123',
    challengeToken: 'challenge-abc',
    transactionUri: 'https://verify.example/transactions/abc',
    scope: 'records:write',
    authorizationDetails: [{ type: 'vault:path_access', locations: ['verify-rar/creds/records'] }],
    toolName: 'update_record',
    credsPath: 'verify-rar/creds/records',
    startedAt: Date.now(),
    args: { recordId: 'REC-1' },
    ...overrides,
  };
}

describe('hitl/pending', () => {
  const ORIGINAL_TTL = process.env.HITL_PENDING_TTL_MS;

  beforeEach(() => {
    vi.useFakeTimers();
    __resetForTests();
  });

  afterEach(() => {
    vi.useRealTimers();
    if (ORIGINAL_TTL === undefined) {
      delete process.env.HITL_PENDING_TTL_MS;
    } else {
      process.env.HITL_PENDING_TTL_MS = ORIGINAL_TTL;
    }
  });

  it('putPending then takePending returns the stored ctx', () => {
    const ctx = makeCtx();
    putPending('tx-1', ctx);
    expect(takePending('tx-1')).toEqual(ctx);
  });

  it('is single-use: a second takePending for the same txId returns undefined', () => {
    putPending('tx-2', makeCtx());
    expect(takePending('tx-2')).toBeDefined();
    expect(takePending('tx-2')).toBeUndefined();
  });

  it('unknown txId returns undefined', () => {
    expect(takePending('tx-never-put')).toBeUndefined();
  });

  it('entry past the TTL returns undefined (default 130s)', () => {
    putPending('tx-3', makeCtx());
    vi.advanceTimersByTime(130_000 + 1);
    expect(takePending('tx-3')).toBeUndefined();
  });

  it('entry within the default TTL is still retrievable', () => {
    putPending('tx-4', makeCtx());
    vi.advanceTimersByTime(130_000 - 1);
    expect(takePending('tx-4')).toBeDefined();
  });

  it('respects a custom HITL_PENDING_TTL_MS override', () => {
    process.env.HITL_PENDING_TTL_MS = '1000';
    putPending('tx-5', makeCtx());
    vi.advanceTimersByTime(1001);
    expect(takePending('tx-5')).toBeUndefined();
  });

  it('different txIds are tracked independently', () => {
    putPending('tx-6', makeCtx({ toolName: 'update_record' }));
    putPending('tx-7', makeCtx({ toolName: 'delete_record' }));
    expect(takePending('tx-6')?.toolName).toBe('update_record');
    expect(takePending('tx-7')?.toolName).toBe('delete_record');
  });

  it('__resetForTests wipes all pending entries', () => {
    putPending('tx-8', makeCtx());
    __resetForTests();
    expect(takePending('tx-8')).toBeUndefined();
  });

  it('putPending round-trips the args field on the stored ctx', () => {
    const ctx = makeCtx({ args: { recordId: 'REC-9', field: 'status', value: 'active' } });
    putPending('tx-args', ctx);
    expect(takePending('tx-args')?.args).toEqual({ recordId: 'REC-9', field: 'status', value: 'active' });
  });

  describe('peekPending', () => {
    it('returns the stored ctx WITHOUT consuming it — a subsequent takePending still succeeds', () => {
      const ctx = makeCtx();
      putPending('tx-peek-1', ctx);

      expect(peekPending('tx-peek-1')).toEqual(ctx);
      // Peeking again still works — peek never deletes.
      expect(peekPending('tx-peek-1')).toEqual(ctx);

      // The entry is still there for a real (destructive) take.
      expect(takePending('tx-peek-1')).toEqual(ctx);
      expect(takePending('tx-peek-1')).toBeUndefined();
    });

    it('returns undefined for an unknown txId', () => {
      expect(peekPending('tx-peek-never-put')).toBeUndefined();
    });

    it('returns undefined for an entry past the TTL, without deleting it out from under a caller', () => {
      putPending('tx-peek-2', makeCtx());
      vi.advanceTimersByTime(130_000 + 1);
      expect(peekPending('tx-peek-2')).toBeUndefined();
    });
  });
});
