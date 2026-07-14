/**
 * IBM Verify plugin-secret cache — MCP gateway
 *
 * Reads secrets from the IBM Verify Vault plugin (dynamic — rotated on every
 * read). A short cache TTL under concurrent load triggers CSIAQ0155E
 * cascades because every rotation has an eventual-consistency window on
 * Verify's token endpoint. We use a 1h cache and rely on narrow per-role
 * invalidation (invalidatePluginSecret) on stale-secret retry — never a
 * global flush, which would cascade errors to concurrent callers.
 *
 * Environment:
 *   VAULT_ADDR — Vault address, defaults to http://127.0.0.1:8200
 */

import { getVaultToken } from './vault-login.js';

const DEFAULT_VAULT_ADDR = 'http://127.0.0.1:8200';
const SECRET_CACHE_TTL = 3600; // seconds

export interface VaultSecretDeps {
  /** Injectable fetch — tests pass a mock so no live Vault call is ever made. */
  fetchImpl?: typeof fetch;
  addr?: string;
  /** Injectable getVaultToken — tests pass a mock so no live login happens. */
  getVaultTokenImpl?: typeof getVaultToken;
}

// ── Secret cache (1h TTL) ────────────────────────────────────
interface CachedSecret {
  value: string;
  fetchedAt: number; // ms
  ttl: number; // seconds
}
const secretCache = new Map<string, CachedSecret>();

/**
 * Reset the module-level secret cache. For tests only.
 * Not exported as part of the public API on purpose.
 */
export function __resetCachesForTests(): void {
  secretCache.clear();
}

/**
 * Read a secret from the IBM Verify plugin (dynamic — rotated on read).
 * Path format: ibm-verify/creds/<role-name>
 */
export async function getPluginSecret(roleName: string, deps: VaultSecretDeps = {}): Promise<string> {
  const cacheKey = `ibm-verify/creds/${roleName}`;
  const cached = secretCache.get(cacheKey);

  if (cached && Date.now() - cached.fetchedAt < cached.ttl * 1000) {
    return cached.value;
  }

  const fetchImpl = deps.fetchImpl ?? fetch;
  const addr = deps.addr ?? process.env.VAULT_ADDR ?? DEFAULT_VAULT_ADDR;
  const getVaultTokenImpl = deps.getVaultTokenImpl ?? getVaultToken;

  const token = await getVaultTokenImpl();
  const response = await fetchImpl(`${addr}/v1/${cacheKey}`, {
    headers: { 'X-Vault-Token': token },
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`Vault secret fetch failed for ${roleName}: ${text}`);
  }

  const data = (await response.json()) as { data?: { client_secret?: string } };
  const secret = data?.data?.client_secret;
  if (!secret) throw new Error(`No client_secret in Vault response for ${roleName}`);

  secretCache.set(cacheKey, {
    value: secret,
    fetchedAt: Date.now(),
    ttl: SECRET_CACHE_TTL,
  });
  return secret;
}

/**
 * Narrow per-role invalidation. Drops a single ibm-verify/creds/<role> cache
 * entry — leaves all other role caches AND the Vault client token intact.
 *
 * Use on CSIAQ0155E or invalid_client signals from IBM Verify. A global
 * cache flush would blow away every role cache, cascading errors to
 * concurrent callers.
 */
export function invalidatePluginSecret(roleName: string): void {
  const cacheKey = `ibm-verify/creds/${roleName}`;
  secretCache.delete(cacheKey);
}
