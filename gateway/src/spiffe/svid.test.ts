import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getSvid, __resetSvidCacheForTests } from './svid.js';

const fakeSvid = (aud: string, expSec: number) => {
  const p = Buffer.from(JSON.stringify({ sub: 'spiffe://gateway.example.com/mcp-gateway', aud, exp: expSec, jti: 'j1' })).toString('base64url');
  return `h.${p}.s`;
};

describe('getSvid', () => {
  beforeEach(() => __resetSvidCacheForTests());
  it('logs in via AppRole then mints a JWT-SVID for the audience', async () => {
    const now = Math.floor(Date.now()/1000);
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ auth: { client_token: 'approle-tok' } }) })          // approle login
      .mockResolvedValueOnce({ ok: true, json: async () => ({ data: { token: fakeSvid('vault', now+600) } }) });    // mintjwt
    const r = await getSvid('vault', { fetchImpl, addr: 'https://v', roleId: 'r', secretId: 's' } as any);
    expect(r.spiffeId).toContain('mcp-gateway');
    expect(fetchImpl.mock.calls[0][0]).toContain('/v1/auth/approle/login');
    expect(fetchImpl.mock.calls[1][0]).toContain('/v1/spiffe/role/mcp-gateway/mintjwt');
  });
  it('caches within TTL (no second mint)', async () => {
    const now = Math.floor(Date.now()/1000);
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ auth: { client_token: 't' } }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ data: { token: fakeSvid('vault', now+600) } }) });
    const deps = { fetchImpl, addr: 'https://v', roleId: 'r', secretId: 's' } as any;
    await getSvid('vault', deps); await getSvid('vault', deps);
    expect(fetchImpl).toHaveBeenCalledTimes(2); // login+mint once, cache hit second
  });
});
