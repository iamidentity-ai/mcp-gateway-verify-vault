import { describe, it, expect, afterEach, vi } from 'vitest';
import { resolveBindingMode, getGatewayDpopKey, __resetBindingForTests } from './binding-mode.js';

afterEach(() => {
  __resetBindingForTests();
  vi.unstubAllEnvs();
});

describe('resolveBindingMode', () => {
  it('defaults to none on unset and unknown values', () => {
    expect(resolveBindingMode({})).toBe('none');
    expect(resolveBindingMode({ TOKEN_BINDING_MODE: 'bogus' })).toBe('none');
  });
  it('accepts outbound and full, case-insensitively', () => {
    expect(resolveBindingMode({ TOKEN_BINDING_MODE: 'outbound' })).toBe('outbound');
    expect(resolveBindingMode({ TOKEN_BINDING_MODE: 'FULL' })).toBe('full');
  });
});

describe('getGatewayDpopKey', () => {
  it('throws in none mode', async () => {
    vi.stubEnv('TOKEN_BINDING_MODE', 'none');
    await expect(getGatewayDpopKey()).rejects.toThrow(/TOKEN_BINDING_MODE/);
  });
  it('returns the same key across calls in outbound mode', async () => {
    vi.stubEnv('TOKEN_BINDING_MODE', 'outbound');
    const a = await getGatewayDpopKey();
    const b = await getGatewayDpopKey();
    expect(await a.thumbprint()).toBe(await b.thumbprint());
  });
});
