/**
 * Tests for the sender-constraints layer: key shape, proof claims, htu
 * normalization, jti uniqueness, private-key hygiene, header attachment.
 */
import { describe, it, expect, vi } from 'vitest';
import { decodeJwt, decodeProtectedHeader, jwtVerify, EmbeddedJWK } from 'jose';
import { generateDpopKey } from './dpop-key.js';
import { buildDpopProof, normalizeHtu } from './dpop-proof.js';
import { dpopFetch } from './dpop-fetch.js';

describe('generateDpopKey', () => {
  it('produces an RSA public JWK with a stable thumbprint and no private material', async () => {
    const key = await generateDpopKey();
    expect(key.publicJwk.kty).toBe('RSA');
    expect(key.publicJwk).not.toHaveProperty('d');
    const t1 = await key.thumbprint();
    expect(t1).toBe(await key.thumbprint());
    expect(t1).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe('buildDpopProof', () => {
  it('signs a dpop+jwt with htm, normalized htu, iat, and a fresh jti per proof', async () => {
    const key = await generateDpopKey();
    const proof = await buildDpopProof({ key, htm: 'POST', htu: 'https://tenant.example.com/oauth2/token?x=1#f' });
    const header = decodeProtectedHeader(proof);
    expect(header.typ).toBe('dpop+jwt');
    expect(header.alg).toBe('RS256');
    expect(header.jwk).toBeDefined();
    expect(header.jwk).not.toHaveProperty('d');
    const payload = decodeJwt(proof);
    expect(payload['htm']).toBe('POST');
    expect(payload['htu']).toBe('https://tenant.example.com/oauth2/token');
    expect(typeof payload.iat).toBe('number');
    const proof2 = await buildDpopProof({ key, htm: 'POST', htu: 'https://tenant.example.com/oauth2/token' });
    expect(decodeJwt(proof2).jti).not.toBe(payload.jti);
  });

  it('verifies against its own embedded JWK and carries ath when provided', async () => {
    const key = await generateDpopKey();
    const proof = await buildDpopProof({ key, htm: 'GET', htu: 'https://g.example.com/me/audit', ath: 'abc123' });
    const { payload } = await jwtVerify(proof, EmbeddedJWK, { typ: 'dpop+jwt' });
    expect(payload['ath']).toBe('abc123');
  });
});

describe('normalizeHtu', () => {
  it('strips query and fragment, keeps scheme, host, and path', () => {
    expect(normalizeHtu('https://g.example.com:3014/tool?a=1#b')).toBe('https://g.example.com:3014/tool');
  });
});

describe('dpopFetch', () => {
  it('attaches a DPoP header and preserves existing headers', async () => {
    const key = await generateDpopKey();
    const fetchImpl = vi.fn<typeof fetch>(async () => new Response('{}'));
    await dpopFetch('https://tenant.example.com/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      key,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    const [, init] = fetchImpl.mock.calls[0]!;
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers['Content-Type']).toBe('application/x-www-form-urlencoded');
    expect(headers['DPoP']).toMatch(/^eyJ/);
    expect(decodeProtectedHeader(headers['DPoP']!).typ).toBe('dpop+jwt');
  });
});
