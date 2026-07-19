/**
 * Inbound DPoP validation tests. Proofs are built with the same
 * sender-constraints layer the clients vendor, so both sides stay honest.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { generateDpopKey } from './sender-constraints/dpop-key.js';
import { buildDpopProof } from './sender-constraints/dpop-proof.js';
import { verifyDpopProof, accessTokenHash, tokenCnfJkt, __clearJtiCacheForTests } from './dpop-verify.js';
import { calculateJwkThumbprint } from 'jose';

const URL_ = 'http://127.0.0.1:3014/tool';

function fakeToken(cnfJkt?: string): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b64({ alg: 'RS256' })}.${b64({ sub: 'user-1', ...(cnfJkt ? { cnf: { jkt: cnfJkt } } : {}) })}.sig`;
}

async function boundSetup() {
  const key = await generateDpopKey();
  const jkt = await key.thumbprint();
  const token = fakeToken(jkt);
  const proof = await buildDpopProof({ key, htm: 'POST', htu: URL_, ath: accessTokenHash(token) });
  return { key, jkt, token, proof };
}

beforeEach(() => __clearJtiCacheForTests());

describe('verifyDpopProof', () => {
  it('accepts a well-formed bound proof and returns the key thumbprint', async () => {
    const { jkt, token, proof } = await boundSetup();
    const res = await verifyDpopProof({ proof, method: 'POST', url: URL_, accessToken: token });
    expect(res).toEqual({ ok: true, jkt });
  });

  it('rejects garbage and wrong typ', async () => {
    const { token } = await boundSetup();
    expect((await verifyDpopProof({ proof: 'not-a-jwt', method: 'POST', url: URL_, accessToken: token })).ok).toBe(false);
    // a plain JWT (typ defaults to JWT) must not pass as a proof
    const { key } = await boundSetup();
    const { SignJWT } = await import('jose');
    const plain = await new SignJWT({ htm: 'POST', htu: URL_, jti: 'x' })
      .setProtectedHeader({ alg: 'RS256', jwk: key.publicJwk })
      .setIssuedAt()
      .sign(key.privateKey);
    const res = await verifyDpopProof({ proof: plain, method: 'POST', url: URL_, accessToken: token });
    expect(res).toEqual({ ok: false, error: 'wrong_proof_typ' });
  });

  it('rejects htm and htu mismatches, and matches htu with query stripped', async () => {
    const { token, proof } = await boundSetup();
    expect(await verifyDpopProof({ proof, method: 'GET', url: URL_, accessToken: token })).toEqual({ ok: false, error: 'htm_mismatch' });
    expect(await verifyDpopProof({ proof, method: 'POST', url: 'http://127.0.0.1:3014/other', accessToken: token })).toEqual({ ok: false, error: 'htu_mismatch' });
    __clearJtiCacheForTests();
    expect((await verifyDpopProof({ proof, method: 'POST', url: `${URL_}?a=1`, accessToken: token })).ok).toBe(true);
  });

  it('rejects a stale iat via the injected clock', async () => {
    const { token, proof } = await boundSetup();
    const res = await verifyDpopProof(
      { proof, method: 'POST', url: URL_, accessToken: token },
      { now: () => Date.now() + 400_000 },
    );
    expect(res).toEqual({ ok: false, error: 'proof_iat_out_of_window' });
  });

  it('rejects a replayed jti', async () => {
    const { token, proof } = await boundSetup();
    expect((await verifyDpopProof({ proof, method: 'POST', url: URL_, accessToken: token })).ok).toBe(true);
    expect(await verifyDpopProof({ proof, method: 'POST', url: URL_, accessToken: token })).toEqual({ ok: false, error: 'proof_replayed' });
  });

  it('rejects a proof whose ath does not hash THIS access token', async () => {
    const { key, jkt } = { ...(await boundSetup()) };
    const token = fakeToken(jkt);
    const proof = await buildDpopProof({ key, htm: 'POST', htu: URL_, ath: accessTokenHash('some-other-token') });
    expect(await verifyDpopProof({ proof, method: 'POST', url: URL_, accessToken: token })).toEqual({ ok: false, error: 'ath_mismatch' });
  });

  it('rejects an unbound token and a token bound to a DIFFERENT key', async () => {
    const { key } = await boundSetup();
    const unbound = fakeToken();
    const p1 = await buildDpopProof({ key, htm: 'POST', htu: URL_, ath: accessTokenHash(unbound) });
    expect(await verifyDpopProof({ proof: p1, method: 'POST', url: URL_, accessToken: unbound })).toEqual({ ok: false, error: 'token_not_sender_constrained' });

    const otherKey = await generateDpopKey();
    const boundToOther = fakeToken(await otherKey.thumbprint());
    const p2 = await buildDpopProof({ key, htm: 'POST', htu: URL_, ath: accessTokenHash(boundToOther) });
    expect(await verifyDpopProof({ proof: p2, method: 'POST', url: URL_, accessToken: boundToOther })).toEqual({ ok: false, error: 'cnf_jkt_mismatch' });
  });

  it('returns malformed_target_url and never throws when the target url is invalid', async () => {
    const { token, proof } = await boundSetup();
    await expect(
      verifyDpopProof({ proof, method: 'POST', url: 'not-a-url', accessToken: token }),
    ).resolves.toEqual({ ok: false, error: 'malformed_target_url' });
    await expect(
      verifyDpopProof({ proof, method: 'POST', url: '', accessToken: token }),
    ).resolves.toEqual({ ok: false, error: 'malformed_target_url' });
  });
});

describe('helpers', () => {
  it('tokenCnfJkt reads cnf.jkt and tolerates non-JWTs', async () => {
    const key = await generateDpopKey();
    const jkt = await calculateJwkThumbprint(key.publicJwk, 'sha256');
    expect(tokenCnfJkt(fakeToken(jkt))).toBe(jkt);
    expect(tokenCnfJkt('opaque')).toBeUndefined();
  });
  it('accessTokenHash is base64url SHA-256', () => {
    expect(accessTokenHash('token')).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});
