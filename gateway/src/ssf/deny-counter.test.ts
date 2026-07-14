/**
 * Tests for deny-counter.ts.
 *
 * The module
 * uses a module-level singleton Map, so each test uses a distinct user ID
 * to avoid cross-test state, except where cross-test isolation is
 * explicitly being tested (clearDeny, window expiry).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { recordDeny, clearDeny, getDenyCount } from './deny-counter.js';

describe('deny-counter', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('increments count on successive calls; thresholdReached is false before 3', () => {
    const r1 = recordDeny('user-threshold-A');
    expect(r1.count).toBe(1);
    expect(r1.thresholdReached).toBe(false);

    const r2 = recordDeny('user-threshold-A');
    expect(r2.count).toBe(2);
    expect(r2.thresholdReached).toBe(false);
  });

  it('reaches threshold at count === 3 (inclusive)', () => {
    recordDeny('user-threshold-B');
    recordDeny('user-threshold-B');
    const r3 = recordDeny('user-threshold-B');
    expect(r3.count).toBe(3);
    expect(r3.thresholdReached).toBe(true);
  });

  it('DenyResult carries windowMs and threshold fields', () => {
    const r = recordDeny('user-fields-C');
    expect(typeof r.windowMs).toBe('number');
    expect(r.windowMs).toBeGreaterThan(0);
    expect(r.threshold).toBe(3);
  });

  it('clearDeny resets counter to 0', () => {
    recordDeny('user-clear-D');
    recordDeny('user-clear-D');
    clearDeny('user-clear-D');
    expect(getDenyCount('user-clear-D')).toBe(0);
  });

  it('next recordDeny after clearDeny starts at count=1, thresholdReached=false', () => {
    recordDeny('user-clear-E');
    recordDeny('user-clear-E');
    recordDeny('user-clear-E'); // threshold
    clearDeny('user-clear-E');
    const r = recordDeny('user-clear-E');
    expect(r.count).toBe(1);
    expect(r.thresholdReached).toBe(false);
  });

  it('window expiry: next recordDeny after WINDOW_MS resets to count=1, thresholdReached=false', () => {
    const WINDOW_MS = 5 * 60 * 1000;
    recordDeny('user-window-F');
    recordDeny('user-window-F');
    // Advance past the 5-minute window
    vi.advanceTimersByTime(WINDOW_MS + 1);
    const r = recordDeny('user-window-F');
    expect(r.count).toBe(1);
    expect(r.thresholdReached).toBe(false);
  });

  it('window expiry does not trigger before WINDOW_MS elapses', () => {
    const WINDOW_MS = 5 * 60 * 1000;
    recordDeny('user-window-G');
    recordDeny('user-window-G');
    // Advance to just before the window expires
    vi.advanceTimersByTime(WINDOW_MS - 1);
    const r = recordDeny('user-window-G');
    // Should be count=3 (within window), not reset to 1
    expect(r.count).toBe(3);
    expect(r.thresholdReached).toBe(true);
  });

  it('different user IDs are tracked independently', () => {
    recordDeny('user-indep-H');
    recordDeny('user-indep-H');
    recordDeny('user-indep-H');

    // 'user-indep-I' should start fresh regardless of 'user-indep-H'
    const r = recordDeny('user-indep-I');
    expect(r.count).toBe(1);
    expect(r.thresholdReached).toBe(false);
    expect(getDenyCount('user-indep-H')).toBe(3);
  });

  it('getDenyCount returns 0 for unknown user', () => {
    expect(getDenyCount('user-never-seen-Z')).toBe(0);
  });
});
