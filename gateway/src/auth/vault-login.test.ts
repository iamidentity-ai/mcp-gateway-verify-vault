/**
 * Tests for vault-login.ts.
 *
 * All network calls go through injectable deps (fetchImpl/getSvidImpl) — no
 * live Vault call is ever made.
 *
 * Coverage:
 *   - VAULT_KEY env override is used directly (dev override)
 *   - login POST goes to /v1/auth/spiffe/login, SVID rides in the
 *     Authorization: Bearer header, body is exactly {"role": ...} — NO jwt key
 *   - getVaultToken() caches the client_token across calls within TTL
 *   - getVaultToken() refreshes when within 5 min of expiry
 *   - GATEWAY_SPIFFE_AUTH_ROLE env var overrides the default role
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getVaultToken, __resetCachesForTests } from './vault-login.js';

function vaultLoginResponse(token: string, leaseDurationSec: number): Response {
  return new Response(JSON.stringify({ auth: { client_token: token, lease_duration: leaseDurationSec } }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

const fetchMock = vi.fn();
const getSvidMock = vi.fn(async () => ({
  svid: 'test-svid-jwt',
  spiffeId: 'spiffe://gateway.example.com/mcp-gateway',
  expiresAt: Date.now() + 3600_000,
}));

beforeEach(() => {
  __resetCachesForTests();
  fetchMock.mockReset();
  getSvidMock.mockClear();
  delete process.env.VAULT_KEY;
  delete process.env.GATEWAY_SPIFFE_AUTH_ROLE;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('getVaultToken', () => {
  it('uses VAULT_KEY directly when set (dev override)', async () => {
    process.env.VAULT_KEY = 'static-dev-token';
    const token = await getVaultToken({ fetchImpl: fetchMock, addr: 'https://v', getSvidImpl: getSvidMock });
    expect(token).toBe('static-dev-token');
    expect(fetchMock).not.toHaveBeenCalled();
    expect(getSvidMock).not.toHaveBeenCalled();
  });

  it('POSTs to /v1/auth/spiffe/login with the SVID in the Authorization header and body {role} only (no jwt key)', async () => {
    fetchMock.mockResolvedValueOnce(vaultLoginResponse('vault-token-1', 3600));
    const token = await getVaultToken({ fetchImpl: fetchMock, addr: 'https://v', getSvidImpl: getSvidMock });

    expect(token).toBe('vault-token-1');
    expect(getSvidMock).toHaveBeenCalledWith('vault');
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toBe('https://v/v1/auth/spiffe/login');
    expect(options.method).toBe('POST');
    expect(options.headers.Authorization).toBe('Bearer test-svid-jwt');

    const parsedBody = JSON.parse(options.body);
    expect(parsedBody).toEqual({ role: 'mcp-gateway' });
    expect(parsedBody).not.toHaveProperty('jwt');
  });

  it('caches the token across calls within TTL', async () => {
    fetchMock.mockResolvedValueOnce(vaultLoginResponse('vault-token-1', 3600));
    const deps = { fetchImpl: fetchMock, addr: 'https://v', getSvidImpl: getSvidMock };
    const t1 = await getVaultToken(deps);
    const t2 = await getVaultToken(deps);
    expect(t1).toBe('vault-token-1');
    expect(t2).toBe('vault-token-1');
    // Only one Vault login round-trip
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(getSvidMock).toHaveBeenCalledTimes(1);
  });

  it('refreshes the token when within 5 min of expiry', async () => {
    // First login: very short lease. The 5-min refresh buffer means the token
    // is already considered "near expiry" and the cache miss triggers a
    // re-login on the next call.
    fetchMock.mockResolvedValueOnce(vaultLoginResponse('vault-token-A', 60));
    fetchMock.mockResolvedValueOnce(vaultLoginResponse('vault-token-B', 3600));
    const deps = { fetchImpl: fetchMock, addr: 'https://v', getSvidImpl: getSvidMock };

    const t1 = await getVaultToken(deps);
    const t2 = await getVaultToken(deps);

    expect(t1).toBe('vault-token-A');
    expect(t2).toBe('vault-token-B');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('respects a custom GATEWAY_SPIFFE_AUTH_ROLE env var', async () => {
    process.env.GATEWAY_SPIFFE_AUTH_ROLE = 'custom-role';
    fetchMock.mockResolvedValueOnce(vaultLoginResponse('vault-token-1', 3600));
    await getVaultToken({ fetchImpl: fetchMock, addr: 'https://v', getSvidImpl: getSvidMock });
    const [, options] = fetchMock.mock.calls[0];
    expect(JSON.parse(options.body)).toEqual({ role: 'custom-role' });
  });
});
