/**
 * Tests for introspect.ts.
 *
 * Coverage:
 *   - 200 from /oauth2/userinfo -> active:true with verifyUserId (sub) + email
 *   - 401 from /oauth2/userinfo -> active:false, no verifyUserId/email
 *   - a fetch rejection (network/TLS error) fails closed -> active:false
 *   - hits the injected tenantUrl, not the live default
 */
import { describe, it, expect, vi } from 'vitest';
import { introspectUser } from './introspect.js';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

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
