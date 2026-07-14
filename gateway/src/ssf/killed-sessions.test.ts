/**
 * Tests for killed-sessions.ts.
 *
 * Coverage:
 * markKilled → isSessionKilled true; TTL expiry → false (lazy expiry);
 * unmarkKilled clears; SSF_KILLED_SESSION_TTL_MS override respected;
 * independent users; __resetForTests wipes all state.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { markKilled, isSessionKilled, unmarkKilled, __resetForTests } from './killed-sessions.js';

describe('killed-sessions', () => {
  const ORIGINAL_TTL = process.env.SSF_KILLED_SESSION_TTL_MS;

  beforeEach(() => {
    vi.useFakeTimers();
    __resetForTests();
  });

  afterEach(() => {
    vi.useRealTimers();
    if (ORIGINAL_TTL === undefined) {
      delete process.env.SSF_KILLED_SESSION_TTL_MS;
    } else {
      process.env.SSF_KILLED_SESSION_TTL_MS = ORIGINAL_TTL;
    }
  });

  it('isSessionKilled is false for a user that was never marked', () => {
    expect(isSessionKilled('user-never-killed')).toBe(false);
  });

  it('markKilled then isSessionKilled returns true within the TTL window', () => {
    markKilled('user-A');
    expect(isSessionKilled('user-A')).toBe(true);
  });

  it('TTL expiry: isSessionKilled returns false after the TTL elapses (lazy expiry)', () => {
    process.env.SSF_KILLED_SESSION_TTL_MS = '300000'; // 5 min, matches default
    markKilled('user-B');
    expect(isSessionKilled('user-B')).toBe(true);
    vi.advanceTimersByTime(300_000 + 1);
    expect(isSessionKilled('user-B')).toBe(false);
  });

  it('does not expire before the TTL elapses', () => {
    process.env.SSF_KILLED_SESSION_TTL_MS = '300000';
    markKilled('user-C');
    vi.advanceTimersByTime(300_000 - 1);
    expect(isSessionKilled('user-C')).toBe(true);
  });

  it('respects a custom SSF_KILLED_SESSION_TTL_MS override', () => {
    process.env.SSF_KILLED_SESSION_TTL_MS = '1000';
    markKilled('user-D');
    vi.advanceTimersByTime(1001);
    expect(isSessionKilled('user-D')).toBe(false);
  });

  it('unmarkKilled clears the kill immediately', () => {
    markKilled('user-E');
    expect(isSessionKilled('user-E')).toBe(true);
    unmarkKilled('user-E');
    expect(isSessionKilled('user-E')).toBe(false);
  });

  it('unmarkKilled is idempotent for a user that was never killed', () => {
    expect(() => unmarkKilled('user-never-killed-2')).not.toThrow();
  });

  it('different user IDs are tracked independently', () => {
    markKilled('user-F');
    expect(isSessionKilled('user-F')).toBe(true);
    expect(isSessionKilled('user-G')).toBe(false);
  });

  it('__resetForTests clears all kills', () => {
    markKilled('user-H');
    __resetForTests();
    expect(isSessionKilled('user-H')).toBe(false);
  });
});
