/**
 * Thin fetch wrapper that attaches a fresh DPoP proof on every call. The
 * caller passes the key plus an optional fetchImpl injection for tests, so
 * nothing here monkey-patches the global.
 */
import { buildDpopProof } from './dpop-proof.js';
import type { DpopKey } from './dpop-key.js';

export interface DpopFetchOptions extends RequestInit {
  key: DpopKey;
  /** base64url SHA-256 of an access token riding along in Authorization. */
  ath?: string;
  fetchImpl?: typeof fetch;
}

export async function dpopFetch(url: string | URL, options: DpopFetchOptions): Promise<Response> {
  const { key, ath, fetchImpl, ...init } = options;
  const method = init.method ?? 'GET';
  const proof = await buildDpopProof({ key, htm: method, htu: String(url), ...(ath ? { ath } : {}) });
  const headers: Record<string, string> = {
    ...((init.headers as Record<string, string> | undefined) ?? {}),
    DPoP: proof,
  };
  const fetchToUse = fetchImpl ?? globalThis.fetch;
  return fetchToUse(url, { ...init, headers });
}
