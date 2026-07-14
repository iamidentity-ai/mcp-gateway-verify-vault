/**
 * Tests for auth/secrets.ts — the SECRETS_BACKEND=env|vault seam.
 *
 * Coverage:
 *   env mode (default):
 *     - getExchange/AgentClientSecret return the env-var values
 *     - a missing var throws a NAMED MissingSecretError naming the exact var
 *     - invalidate*() is a no-op and never touches the Vault machinery
 *   vault mode:
 *     - getExchange/AgentClientSecret route to getPluginSecret with the
 *       configured role; invalidate*() routes to invalidatePluginSecret
 *   backend selection:
 *     - default is 'env'; an unknown SECRETS_BACKEND throws SecretsConfigError
 *
 * The Vault plugin machinery (vault-secret.js) is mocked at the module level
 * so vault-mode routing is asserted without a live Vault call.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const vaultMocks = vi.hoisted(() => ({
  getPluginSecret: vi.fn(),
  invalidatePluginSecret: vi.fn(),
}));
vi.mock('./vault-secret.js', () => ({
  getPluginSecret: vaultMocks.getPluginSecret,
  invalidatePluginSecret: vaultMocks.invalidatePluginSecret,
}));
const { getPluginSecret, invalidatePluginSecret } = vaultMocks;

import {
  getExchangeClientSecret,
  getAgentClientSecret,
  invalidateExchangeSecret,
  invalidateAgentSecret,
  secretsBackend,
  MissingSecretError,
  SecretsConfigError,
} from './secrets.js';

// Snapshot + restore the env vars this suite mutates.
const ENV_KEYS = [
  'SECRETS_BACKEND',
  'GATEWAY_EXCHANGE_CLIENT_SECRET',
  'GATEWAY_AGENT_CLIENT_SECRET',
  'GATEWAY_EXCHANGE_ROLE',
  'GATEWAY_AGENT_ROLE',
] as const;
const saved: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const k of ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  getPluginSecret.mockReset();
  invalidatePluginSecret.mockReset();
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

describe('secretsBackend', () => {
  it('defaults to "env" when SECRETS_BACKEND is unset', () => {
    expect(secretsBackend()).toBe('env');
  });

  it('accepts "vault" (case-insensitive)', () => {
    process.env.SECRETS_BACKEND = 'VAULT';
    expect(secretsBackend()).toBe('vault');
  });

  it('throws a named SecretsConfigError on an unknown value', () => {
    process.env.SECRETS_BACKEND = 'aws-secrets-manager';
    expect(() => secretsBackend()).toThrow(SecretsConfigError);
    expect(() => secretsBackend()).toThrow(/must be "env" or "vault"/);
  });
});

describe('env mode (default)', () => {
  it('returns the exchange + agent secrets from process.env', async () => {
    process.env.GATEWAY_EXCHANGE_CLIENT_SECRET = 'env-exchange-secret';
    process.env.GATEWAY_AGENT_CLIENT_SECRET = 'env-agent-secret';

    await expect(getExchangeClientSecret()).resolves.toBe('env-exchange-secret');
    await expect(getAgentClientSecret()).resolves.toBe('env-agent-secret');

    // Vault is never consulted in env mode.
    expect(getPluginSecret).not.toHaveBeenCalled();
  });

  it('throws a named MissingSecretError naming the exact exchange var', async () => {
    await expect(getExchangeClientSecret()).rejects.toBeInstanceOf(MissingSecretError);
    await expect(getExchangeClientSecret()).rejects.toThrow(/GATEWAY_EXCHANGE_CLIENT_SECRET is not set/);
    await expect(getExchangeClientSecret()).rejects.toThrow(/switch to SECRETS_BACKEND=vault/);
  });

  it('throws a named MissingSecretError naming the exact agent var', async () => {
    await expect(getAgentClientSecret()).rejects.toBeInstanceOf(MissingSecretError);
    await expect(getAgentClientSecret()).rejects.toThrow(/GATEWAY_AGENT_CLIENT_SECRET is not set/);
  });

  it('invalidate*() is a no-op and never touches the Vault machinery', () => {
    expect(() => invalidateExchangeSecret()).not.toThrow();
    expect(() => invalidateAgentSecret()).not.toThrow();
    expect(invalidatePluginSecret).not.toHaveBeenCalled();
  });
});

describe('vault mode', () => {
  beforeEach(() => {
    process.env.SECRETS_BACKEND = 'vault';
  });

  it('routes getExchangeClientSecret to getPluginSecret with the default exchange role', async () => {
    getPluginSecret.mockResolvedValueOnce('vault-exchange-secret');
    await expect(getExchangeClientSecret()).resolves.toBe('vault-exchange-secret');
    expect(getPluginSecret).toHaveBeenCalledWith('gateway-exchange');
  });

  it('routes getAgentClientSecret to getPluginSecret with the default agent role', async () => {
    getPluginSecret.mockResolvedValueOnce('vault-agent-secret');
    await expect(getAgentClientSecret()).resolves.toBe('vault-agent-secret');
    expect(getPluginSecret).toHaveBeenCalledWith('gateway-agent');
  });

  it('honors GATEWAY_EXCHANGE_ROLE / GATEWAY_AGENT_ROLE overrides', async () => {
    process.env.GATEWAY_EXCHANGE_ROLE = 'te-role';
    process.env.GATEWAY_AGENT_ROLE = 'agent-role';
    getPluginSecret.mockResolvedValue('x');

    await getExchangeClientSecret();
    await getAgentClientSecret();

    expect(getPluginSecret).toHaveBeenCalledWith('te-role');
    expect(getPluginSecret).toHaveBeenCalledWith('agent-role');
  });

  it('routes invalidate*() to invalidatePluginSecret with the configured role', () => {
    invalidateExchangeSecret();
    invalidateAgentSecret();
    expect(invalidatePluginSecret).toHaveBeenCalledWith('gateway-exchange');
    expect(invalidatePluginSecret).toHaveBeenCalledWith('gateway-agent');
  });

  it('does NOT read the env-var secrets in vault mode', async () => {
    process.env.GATEWAY_EXCHANGE_CLIENT_SECRET = 'should-be-ignored';
    getPluginSecret.mockResolvedValueOnce('vault-wins');
    await expect(getExchangeClientSecret()).resolves.toBe('vault-wins');
  });
});
