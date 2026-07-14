/**
 * Tests for introspect.ts.
 *
 * Coverage:
 *   - 200 from /oauth2/userinfo -> active:true with verifyUserId (sub) + email
 *   - 401 from /oauth2/userinfo -> active:false, no verifyUserId/email
 *   - a fetch rejection (network/TLS error) fails closed -> active:false
 *   - hits the injected tenantUrl, not the live default
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { introspectUser, __clearIntrospectCache } from './introspect.js';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** A JWT-shaped token whose payload carries `exp` (seconds). No signature. */
function fakeJwt(expSeconds: number): string {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b64({ alg: 'none' })}.${b64({ exp: expSeconds })}.sig`;
}

// The introspection cache is module-level; clear it between cases so an active
// token cached in one test never leaks into the next.
afterEach(() => __clearIntrospectCache());

describe('introspectUser', () => {
  it('200 -> active:true with verifyUserId (sub) and email from the userinfo body', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () =>
      jsonResponse({ sub: 'verify-user-abc123', email: 'agent@example.com' }),
    );

    const result = await introspectUser('user-access-token', {
      fetchImpl: fetchMock,
      tenantUrl: 'https://verify.test',
    });

    expect(result).toEqual({
      active: true,
      verifyUserId: 'verify-user-abc123',
      email: 'agent@example.com',
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://verify.test/oauth2/userinfo');
    const headers = init.headers as Record<string, string>;
    expect(headers['Authorization']).toBe('Bearer user-access-token');
  });

  it('401 -> active:false, no verifyUserId/email', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse({ error: 'invalid_token' }, 401));

    const result = await introspectUser('dead-token', { fetchImpl: fetchMock, tenantUrl: 'https://verify.test' });

    expect(result).toEqual({ active: false });
  });

  it('a fetch rejection (network/TLS error) fails closed to active:false', async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error('network down');
    });

    const result = await introspectUser('some-token', {
      fetchImpl: fetchMock as unknown as typeof fetch,
      tenantUrl: 'https://verify.test',
    });

    expect(result).toEqual({ active: false });
  });

  it('defaults to VERIFY_TENANT_URL / the tenant.verify.ibm.com host when no tenantUrl override is passed', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse({ sub: 'u1' }));

    await introspectUser('tok', { fetchImpl: fetchMock });

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url.startsWith('https://tenant.verify.ibm.com/oauth2/userinfo')).toBe(true);
  });

  it('a 200 body missing sub/email still reports active:true with undefined fields', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse({}));

    const result = await introspectUser('tok', { fetchImpl: fetchMock, tenantUrl: 'https://verify.test' });

    expect(result).toEqual({ active: true, verifyUserId: undefined, email: undefined });
  });
});

// ── Positive-only introspection cache (perf: 1 fewer /userinfo hop per call) ──
describe('introspectUser — cache', () => {
  const base = { tenantUrl: 'https://verify.test' as const };

  it('serves an ACTIVE result from cache within TTL (one fetch for two calls)', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse({ sub: 'u1', email: 'a@example.com' }));
    const deps = { ...base, fetchImpl: fetchMock, now: () => 1_000, cacheTtlMs: 15_000 };
    const r1 = await introspectUser('cache-token-1', deps);
    const r2 = await introspectUser('cache-token-1', deps);
    expect(r2).toEqual(r1);
    expect(r1).toEqual({ active: true, verifyUserId: 'u1', email: 'a@example.com' });
    expect(fetchMock).toHaveBeenCalledTimes(1); // second call served from cache
  });

  it('NEVER caches an inactive (401) result — re-checks every call', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse({ error: 'invalid_token' }, 401));
    const deps = { ...base, fetchImpl: fetchMock, cacheTtlMs: 15_000 };
    await introspectUser('dead-1', deps);
    await introspectUser('dead-1', deps);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('re-fetches after the TTL window elapses', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse({ sub: 'u2' }));
    let t = 1_000;
    const deps = { ...base, fetchImpl: fetchMock, now: () => t, cacheTtlMs: 15_000 };
    await introspectUser('ttl-token', deps); // cached until 16_000
    t = 20_000; // past the TTL
    await introspectUser('ttl-token', deps);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('caps the cache entry at the token JWT `exp` (exp sooner than TTL forces a re-check)', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse({ sub: 'u3' }));
    let t = 1_000;
    const jwt = fakeJwt(5); // exp = 5_000ms, sooner than now(1_000)+TTL(15_000)=16_000
    const deps = { ...base, fetchImpl: fetchMock, now: () => t, cacheTtlMs: 15_000 };
    await introspectUser(jwt, deps); // cached until min(16_000, 5_000) = 5_000
    t = 6_000; // past exp but within the raw TTL
    await introspectUser(jwt, deps);
    expect(fetchMock).toHaveBeenCalledTimes(2); // exp-capped, so re-fetched
  });

  it('cacheTtlMs:0 disables the cache (fetch every call)', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse({ sub: 'u4' }));
    const deps = { ...base, fetchImpl: fetchMock, cacheTtlMs: 0 };
    await introspectUser('no-cache', deps);
    await introspectUser('no-cache', deps);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
