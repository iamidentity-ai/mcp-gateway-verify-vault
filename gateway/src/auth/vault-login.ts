/**
 * Vault native auth/spiffe login — MCP gateway
 *
 * This is Vault's native SPIFFE auth method (no SPIRE agent), tuned on the
 * Vault host with `-passthrough-request-headers=Authorization`. That means
 * the SVID rides in the **Authorization: Bearer** request header, and the
 * JSON body carries ONLY the role — there is no `jwt` body field. Putting
 * the SVID in the body silently fails against this mount.
 *
 *   1. Mint a `vault`-audience JWT-SVID via getSvid('vault')
 *   2. POST /v1/auth/spiffe/login, header `Authorization: Bearer <svid>`,
 *      body `{"role": "mcp-gateway"}` → auth.client_token
 *   3. Cache the resulting client_token until ~5 min before
 *      auth.lease_duration expiry
 *
 * Everything Vault-facing goes through an injectable `deps` object so tests
 * never make a live network call.
 *
 * Environment:
 *   VAULT_ADDR                 — Vault address, defaults to http://127.0.0.1:8200
 *   VAULT_KEY                  — dev override; if set, used directly as the client token
 *   GATEWAY_SPIFFE_AUTH_ROLE   — Vault role on the native auth/spiffe mount, "mcp-gateway" by default
 */

import { getSvid } from '../spiffe/svid.js';

const DEFAULT_VAULT_ADDR = 'http://127.0.0.1:8200';
const DEFAULT_AUTH_ROLE = 'mcp-gateway';
const REFRESH_BUFFER_MS = 5 * 60 * 1000; // 5 min

export interface VaultLoginDeps {
  /** Injectable fetch — tests pass a mock so no live Vault call is ever made. */
  fetchImpl?: typeof fetch;
  addr?: string;
  /** Injectable getSvid — tests pass a mock so no live SVID mint happens. */
  getSvidImpl?: typeof getSvid;
}

// ── Vault token cache ────────────────────────────────────────
let cachedVaultToken: string | null = null;
let cachedVaultTokenExpiry = 0;

/**
 * Reset the module-level Vault token cache. For tests only.
 * Not exported as part of the public API on purpose.
 */
export function __resetCachesForTests(): void {
  cachedVaultToken = null;
  cachedVaultTokenExpiry = 0;
}

async function loginToVaultWithSvid(
  addr: string,
  svid: string,
  fetchImpl: typeof fetch,
): Promise<{ token: string; ttlMs: number }> {
  const role = process.env.GATEWAY_SPIFFE_AUTH_ROLE || DEFAULT_AUTH_ROLE;
  const endpoint = `${addr}/v1/auth/spiffe/login`;
  const res = await fetchImpl(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${svid}`,
    },
    body: JSON.stringify({ role }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Vault native SPIFFE login failed (${res.status}): ${body}`);
  }

  const data = (await res.json()) as { auth?: { client_token?: string; lease_duration?: number } };
  const token = data?.auth?.client_token;
  const ttl = data?.auth?.lease_duration || 3600;
  if (!token) throw new Error('No client_token in Vault login response');
  return { token, ttlMs: ttl * 1000 };
}

/**
 * Resolve a Vault client token via the native auth/spiffe login. Cached
 * until ~5 min before expiry.
 */
export async function getVaultToken(deps: VaultLoginDeps = {}): Promise<string> {
  // Dev override
  if (process.env.VAULT_KEY) {
    return process.env.VAULT_KEY;
  }

  // Cached token still valid? (5-min refresh buffer)
  if (cachedVaultToken && Date.now() < cachedVaultTokenExpiry - REFRESH_BUFFER_MS) {
    return cachedVaultToken;
  }

  const fetchImpl = deps.fetchImpl ?? fetch;
  const addr = deps.addr ?? process.env.VAULT_ADDR ?? DEFAULT_VAULT_ADDR;
  const getSvidImpl = deps.getSvidImpl ?? getSvid;

  // Mint a fresh vault-audience SVID and exchange it for a Vault token
  const { svid } = await getSvidImpl('vault');
  const { token, ttlMs } = await loginToVaultWithSvid(addr, svid, fetchImpl);
  cachedVaultToken = token;
  cachedVaultTokenExpiry = Date.now() + ttlMs;
  return token;
}
