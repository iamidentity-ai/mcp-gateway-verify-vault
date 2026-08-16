/**
 * Tests for hitl/request-state.ts — the HMAC-protected SEP-2322 requestState
 * blob minted at HITL park time and verified on completion.
 *
 * Coverage:
 *   - mint/verify roundtrip: ok
 *   - tampered payload (claims mutated, original signature kept) -> bad_signature
 *   - expired exp -> expired
 *   - wrong txId / sub / digest in the verifier's `expect` -> mismatch
 *   - structurally garbage blobs -> malformed
 *   - requestDigest is key-order independent (canonical JSON)
 *   - HITL_STATE_SECRET env is honored: a blob minted under one secret fails
 *     once the env secret changes, and a fresh mint under the new secret
 *     verifies fine — proves the secret is read per-call, not cached.
 */
import { describe, it, expect } from 'vitest';
import { mintRequestState, verifyRequestState, requestDigest } from './request-state.js';

describe('mint/verify roundtrip', () => {
  it('a freshly minted blob verifies ok against the exact claims it was minted with', () => {
    const digest = requestDigest('update_record', { recordId: 'REC-1' });
    const claims = { txId: 'tx-1', sub: 'user-1', exp: Date.now() + 60_000, digest };
    const blob = mintRequestState(claims);

    expect(blob.startsWith('v1.')).toBe(true);
    expect(blob.split('.')).toHaveLength(3);

    const verdict = verifyRequestState(blob, { txId: claims.txId, sub: claims.sub, digest: claims.digest });
    expect(verdict).toEqual({ ok: true });
  });
});

describe('tampered payload -> bad_signature', () => {
  it('mutating a claim (without re-signing) fails signature verification, not claim comparison', () => {
    const digest = requestDigest('update_record', { recordId: 'REC-1' });
    const claims = { txId: 'tx-1', sub: 'user-1', exp: Date.now() + 60_000, digest };
    const blob = mintRequestState(claims);

    const [prefix, payload, sig] = blob.split('.');
    const decoded = JSON.parse(Buffer.from(payload!, 'base64url').toString('utf8')) as Record<string, unknown>;
    decoded['txId'] = 'tx-attacker-chosen';
    const tamperedPayload = Buffer.from(JSON.stringify(decoded), 'utf8').toString('base64url');
    // Re-attach the ORIGINAL signature — an attacker without the secret can
    // edit the payload but cannot produce a matching signature for it.
    const tamperedBlob = `${prefix}.${tamperedPayload}.${sig}`;

    const verdict = verifyRequestState(tamperedBlob, { txId: claims.txId, sub: claims.sub, digest: claims.digest });
    expect(verdict).toEqual({ ok: false, reason: 'bad_signature' });
  });

  it('mutating even a single byte of the signature itself fails', () => {
    const claims = { txId: 'tx-1', sub: 'user-1', exp: Date.now() + 60_000, digest: requestDigest('t', {}) };
    const blob = mintRequestState(claims);
    const flipped = blob.slice(0, -1) + (blob.endsWith('A') ? 'B' : 'A');

    const verdict = verifyRequestState(flipped, { txId: claims.txId, sub: claims.sub, digest: claims.digest });
    expect(verdict).toEqual({ ok: false, reason: 'bad_signature' });
  });
});

describe('expired -> expired', () => {
  it('nowMs at or after exp is rejected as expired', () => {
    const claims = { txId: 'tx-1', sub: 'user-1', exp: 5_000, digest: requestDigest('t', {}) };
    const blob = mintRequestState(claims);

    expect(verifyRequestState(blob, { txId: claims.txId, sub: claims.sub, digest: claims.digest }, 5_000)).toEqual({
      ok: false,
      reason: 'expired',
    });
    expect(verifyRequestState(blob, { txId: claims.txId, sub: claims.sub, digest: claims.digest }, 6_000)).toEqual({
      ok: false,
      reason: 'expired',
    });
    // Just before exp still verifies.
    expect(verifyRequestState(blob, { txId: claims.txId, sub: claims.sub, digest: claims.digest }, 4_999)).toEqual({
      ok: true,
    });
  });
});

describe('wrong txId/sub/digest -> mismatch', () => {
  const digest = requestDigest('update_record', { recordId: 'REC-1' });
  const claims = { txId: 'tx-1', sub: 'user-1', exp: Date.now() + 60_000, digest };
  const blob = mintRequestState(claims);

  it('wrong txId', () => {
    expect(verifyRequestState(blob, { txId: 'tx-other', sub: 'user-1', digest })).toEqual({
      ok: false,
      reason: 'mismatch',
    });
  });

  it('wrong sub', () => {
    expect(verifyRequestState(blob, { txId: 'tx-1', sub: 'attacker-999', digest })).toEqual({
      ok: false,
      reason: 'mismatch',
    });
  });

  it('wrong digest (e.g. a completer trying to replay this requestState against a re-run with different args)', () => {
    expect(verifyRequestState(blob, { txId: 'tx-1', sub: 'user-1', digest: 'deadbeef'.repeat(8) })).toEqual({
      ok: false,
      reason: 'mismatch',
    });
  });
});

describe('garbage blob -> malformed', () => {
  it.each([
    ['no dots at all', 'not-a-valid-request-state-blob'],
    ['wrong version prefix', 'v2.abc.def'],
    ['only two segments', 'v1.abc'],
    ['four segments', 'v1.abc.def.ghi'],
    ['empty payload segment', 'v1..def'],
    ['empty signature segment', 'v1.abc.'],
    ['empty string', ''],
  ])('%s -> malformed', (_label, blob) => {
    const verdict = verifyRequestState(blob, { txId: 'tx-1', sub: 'user-1', digest: 'x' });
    expect(verdict).toEqual({ ok: false, reason: 'malformed' });
  });
});

describe('requestDigest — canonical JSON (key-order independence)', () => {
  it('flat object: key order does not change the digest', () => {
    const d1 = requestDigest('update_record', { a: 1, b: 2 });
    const d2 = requestDigest('update_record', { b: 2, a: 1 });
    expect(d1).toBe(d2);
    expect(d1).toMatch(/^[0-9a-f]{64}$/);
  });

  it('nested object: key order at every level does not change the digest', () => {
    const d1 = requestDigest('update_record', { outer: { a: 1, b: { x: 1, y: 2 } }, z: true });
    const d2 = requestDigest('update_record', { z: true, outer: { b: { y: 2, x: 1 }, a: 1 } });
    expect(d1).toBe(d2);
  });

  it('a different tool name over the SAME args produces a different digest', () => {
    const d1 = requestDigest('update_record', { recordId: 'REC-1' });
    const d2 = requestDigest('delete_record', { recordId: 'REC-1' });
    expect(d1).not.toBe(d2);
  });

  it('array element order DOES change the digest (arrays are not sorted, only object keys)', () => {
    const d1 = requestDigest('bulk_update', { ids: ['a', 'b'] });
    const d2 = requestDigest('bulk_update', { ids: ['b', 'a'] });
    expect(d1).not.toBe(d2);
  });
});

describe('HITL_STATE_SECRET env honored', () => {
  it('a blob minted under secret A fails once the env secret rotates to B; a fresh mint under B verifies under B', () => {
    const prev = process.env['HITL_STATE_SECRET'];
    try {
      process.env['HITL_STATE_SECRET'] = 'test-secret-A-0123456789abcdef';
      const digest = requestDigest('update_record', {});
      const claims = { txId: 'tx-1', sub: 'user-1', exp: Date.now() + 60_000, digest };
      const blobA = mintRequestState(claims);
      expect(verifyRequestState(blobA, { txId: claims.txId, sub: claims.sub, digest })).toEqual({ ok: true });

      process.env['HITL_STATE_SECRET'] = 'test-secret-B-fedcba9876543210';
      // The SAME blob, minted under A, no longer verifies once the process's
      // configured secret has rotated to B — proves the secret is read
      // per-call (secretKey() is not cached at import/first-use for the env
      // path), matching hitl/pending.ts's ttlMs() per-call-read pattern.
      expect(verifyRequestState(blobA, { txId: claims.txId, sub: claims.sub, digest })).toEqual({
        ok: false,
        reason: 'bad_signature',
      });

      // A fresh mint under B verifies fine under B.
      const blobB = mintRequestState(claims);
      expect(verifyRequestState(blobB, { txId: claims.txId, sub: claims.sub, digest })).toEqual({ ok: true });
    } finally {
      if (prev === undefined) delete process.env['HITL_STATE_SECRET'];
      else process.env['HITL_STATE_SECRET'] = prev;
    }
  });
});
