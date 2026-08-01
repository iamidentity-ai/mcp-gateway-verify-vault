/**
 * Tests for killed-sessions.ts.
 *
 * Coverage:
 * markKilled → isSessionKilled true; TTL expiry → false (lazy expiry);
 * unmarkKilled clears; SSF_KILLED_SESSION_TTL_MS override respected;
 * independent users; __resetForTests wipes all state.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  markKilled,
  isSessionKilled,
  unmarkKilled,
  readSubjectIssuedAt,
  __resetForTests,
} from './killed-sessions.js';

/** Build a JWT-shaped string carrying just the claims a test needs. Never signed —
 *  readSubjectIssuedAt deliberately does no signature check (see its doc comment). */
function jwtWithClaims(claims: Record<string, unknown>): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64(claims)}.sig`;
}

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

  // ── Re-authentication clears the gate ──────────────────────────────────
  //
  // REGRESSION GUARD. A kill used to be a dead end: the human signed back
  // in at the IdP and every call still returned session_killed until the
  // TTL lapsed or an operator restarted the service. These pin the rule
  // that replaced it — only a subject token ISSUED AFTER the kill gets
  // through, which is unforgeable because the caller cannot mint one
  // without authenticating again.

  it('a subject token issued AFTER the kill clears the gate — a genuine re-authentication', () => {
    vi.setSystemTime(new Date('2026-08-01T12:00:00Z'));
    markKilled('user-reauth');
    expect(isSessionKilled('user-reauth')).toBe(true);

    const iatAfter = Math.floor(Date.parse('2026-08-01T12:00:30Z') / 1000);
    expect(isSessionKilled('user-reauth', iatAfter)).toBe(false);
  });

  it('the clear is sticky — once re-authenticated the user stays un-gated', () => {
    vi.setSystemTime(new Date('2026-08-01T12:00:00Z'));
    markKilled('user-sticky');
    const iatAfter = Math.floor(Date.parse('2026-08-01T12:00:30Z') / 1000);
    expect(isSessionKilled('user-sticky', iatAfter)).toBe(false);
    // A later call with no iat at all must NOT resurrect the kill.
    expect(isSessionKilled('user-sticky')).toBe(false);
  });

  it('a token issued BEFORE the kill does NOT clear it — replaying the old session stays dead', () => {
    vi.setSystemTime(new Date('2026-08-01T12:00:00Z'));
    const iatBefore = Math.floor(Date.parse('2026-08-01T11:59:00Z') / 1000);
    markKilled('user-replay');
    expect(isSessionKilled('user-replay', iatBefore)).toBe(true);
  });

  it('a token issued in the SAME second as the kill does NOT clear it (tie loses)', () => {
    vi.setSystemTime(new Date('2026-08-01T12:00:00Z'));
    markKilled('user-tie');
    const iatSameSecond = Math.floor(Date.parse('2026-08-01T12:00:00Z') / 1000);
    expect(isSessionKilled('user-tie', iatSameSecond)).toBe(true);
  });

  it('fails CLOSED on an unusable iat — undefined, NaN and Infinity all stay gated', () => {
    vi.setSystemTime(new Date('2026-08-01T12:00:00Z'));
    markKilled('user-closed');
    expect(isSessionKilled('user-closed', undefined)).toBe(true);
    expect(isSessionKilled('user-closed', Number.NaN)).toBe(true);
    expect(isSessionKilled('user-closed', Number.POSITIVE_INFINITY)).toBe(true);
  });

  describe('readSubjectIssuedAt', () => {
    it('reads a numeric iat out of a JWT-shaped token', () => {
      expect(readSubjectIssuedAt(jwtWithClaims({ sub: 'u', iat: 1785589249 }))).toBe(1785589249);
    });

    it('returns undefined for an opaque (non-JWT) token, so the gate stays closed', () => {
      expect(readSubjectIssuedAt('an-opaque-reference-token')).toBeUndefined();
    });

    it('returns undefined for a missing or non-numeric iat', () => {
      expect(readSubjectIssuedAt(jwtWithClaims({ sub: 'u' }))).toBeUndefined();
      expect(readSubjectIssuedAt(jwtWithClaims({ sub: 'u', iat: 'yesterday' }))).toBeUndefined();
    });

    it('returns undefined for undefined / malformed input rather than throwing', () => {
      expect(readSubjectIssuedAt(undefined)).toBeUndefined();
      expect(readSubjectIssuedAt('a.b.c')).toBeUndefined();
    });
  });
});
