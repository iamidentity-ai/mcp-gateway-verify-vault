/**
 * Tests for vault-secret.ts.
 *
 * All network calls go through injectable deps (fetchImpl/getVaultTokenImpl)
 * — no live Vault call is ever made.
 *
 * Coverage:
 *   - getPluginSecret() returns the fetched value, sending X-Vault-Token
 *   - getPluginSecret() caches the secret across calls within TTL
 *   - invalidatePluginSecret() forces a refetch on the next call
 *   - invalidatePluginSecret() is narrow — only drops the named role
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getPluginSecret, invalidatePluginSecret, __resetCachesForTests } from './vault-secret.js';

function pluginSecretResponse(secret: string): Response {
  return new Response(JSON.stringify({ data: { client_secret: secret } }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

const fetchMock = vi.fn();
const getVaultTokenMock = vi.fn(async () => 'vault-token-1');

beforeEach(() => {
  __resetCachesForTests();
  fetchMock.mockReset();
  getVaultTokenMock.mockClear();
  getVaultTokenMock.mockResolvedValue('vault-token-1');
});

describe('getPluginSecret + invalidatePluginSecret', () => {
  it('fetches and returns the client_secret, sending the Vault token as X-Vault-Token', async () => {
    fetchMock.mockResolvedValueOnce(pluginSecretResponse('secret-v1'));
    const deps = { fetchImpl: fetchMock, addr: 'https://v', getVaultTokenImpl: getVaultTokenMock };

    const secret = await getPluginSecret('mcp-gateway', deps);
    expect(secret).toBe('secret-v1');

    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toBe('https://v/v1/ibm-verify/creds/mcp-gateway');
    expect(options.headers['X-Vault-Token']).toBe('vault-token-1');
  });

  it('caches the secret across calls within TTL', async () => {
    fetchMock.mockResolvedValueOnce(pluginSecretResponse('secret-v1'));
    const deps = { fetchImpl: fetchMock, addr: 'https://v', getVaultTokenImpl: getVaultTokenMock };

    const a = await getPluginSecret('mcp-gateway', deps);
    const b = await getPluginSecret('mcp-gateway', deps);

    expect(a).toBe(b);
    // Only one secret fetch — second call hit the cache
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('invalidatePluginSecret forces a refetch on the next call', async () => {
    fetchMock
      .mockResolvedValueOnce(pluginSecretResponse('secret-v1'))
      .mockResolvedValueOnce(pluginSecretResponse('secret-v2'));
    const deps = { fetchImpl: fetchMock, addr: 'https://v', getVaultTokenImpl: getVaultTokenMock };

    const a = await getPluginSecret('mcp-gateway', deps);
    invalidatePluginSecret('mcp-gateway');
    const b = await getPluginSecret('mcp-gateway', deps);

    expect(a).toBe('secret-v1');
    expect(b).toBe('secret-v2');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('invalidatePluginSecret is narrow — only drops the named role', async () => {
    fetchMock
      .mockResolvedValueOnce(pluginSecretResponse('exchange-secret'))
      .mockResolvedValueOnce(pluginSecretResponse('agent-secret'));
    const deps = { fetchImpl: fetchMock, addr: 'https://v', getVaultTokenImpl: getVaultTokenMock };

    await getPluginSecret('gateway-exchange', deps);
    await getPluginSecret('gateway-agent', deps);

    invalidatePluginSecret('gateway-exchange');

    // Third call to gateway-agent should hit the cache, NOT trigger a fetch
    const cached = await getPluginSecret('gateway-agent', deps);
    expect(cached).toBe('agent-secret');
    // 2 secret fetches; no extra fetch for the still-cached agent role
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
