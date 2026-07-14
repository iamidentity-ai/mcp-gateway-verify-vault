/**
 * Session introspection — MCP gateway
 *
 * Every gateway request carries a user access_token (the RFC 8693 subject
 * token). Before the pipeline gates a tool call or spends a Token Exchange
 * round-trip, it needs to know: is this token still active, and who is it
 * for (verifyUserId / email)? We answer that with a single
 * GET /oauth2/userinfo call using the token itself as the bearer — no
 * separate client-credentialed /oauth2/introspect call needed, since
 * userinfo already 401s a dead/revoked token and 200s an active one with
 * the claims we need (sub -> verifyUserId, email -> email). Fully
 * injectable for tests.
 *
 * A short, POSITIVE-ONLY cache removes one /oauth2/userinfo round-trip from
 * the hot path of every call. It is safe by construction:
 *   - only ACTIVE (200) results are ever cached — a 401/network error is
 *     never cached, so a revoked/expired token is always re-checked;
 *   - an entry never outlives the token's own JWT `exp`, and the TTL is short
 *     (default 15s), so a revocation that does NOT flow through SSF/CAEP (a
 *     plain Verify session-delete, a user logout) is honored for at most
 *     min(TTL, exp);
 *   - the SSF/CAEP kill-gate runs in runPipeline AFTER introspection, so a
 *     cached-active token is STILL denied the instant an abuse kill lands —
 *     the cache never weakens the kill path, only the non-CAEP window.
 *
 * Environment:
 *   VERIFY_TENANT_URL        — your IBM Verify tenant base URL
 *   INTROSPECT_CACHE_TTL_MS  — positive-cache TTL in ms (default 15000; 0 disables)
 */

import { createHash } from 'node:crypto';

const VERIFY_TENANT_URL = process.env.VERIFY_TENANT_URL || 'https://tenant.verify.ibm.com';
const CACHE_TTL_MS = Number(process.env['INTROSPECT_CACHE_TTL_MS'] ?? 15_000);
const CACHE_MAX_ENTRIES = 5_000;

export interface IntrospectResult {
  active: boolean;
  verifyUserId?: string;
  email?: string;
}

export interface IntrospectDeps {
  /** Injectable fetch — tests pass a mock so no live Verify call is ever made. */
  fetchImpl?: typeof fetch;
  /** Injectable tenant base URL override (tests / non-default infra). */
  tenantUrl?: string;
  /** Injectable clock (tests). */
  now?: () => number;
  /** Cache TTL override in ms; 0 disables the cache (tests / opt-out). */
  cacheTtlMs?: number;
}

interface CacheEntry {
  result: IntrospectResult;
  cacheUntil: number;
}
const introspectCache = new Map<string, CacheEntry>();

/** Test-only: drop all cached entries so cases don't leak into each other. */
export function __clearIntrospectCache(): void {
  introspectCache.clear();
}

/** Key on a hash of the token — never hold raw bearer tokens as map keys. */
function tokenKey(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/** The JWT `exp` in ms, or undefined for a non-JWT / missing exp. No signature check. */
function jwtExpMs(token: string): number | undefined {
  const parts = token.split('.');
  if (parts.length !== 3) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as Record<string, unknown>;
    return typeof payload['exp'] === 'number' ? (payload['exp'] as number) * 1000 : undefined;
  } catch {
    return undefined;
  }
}

/**
 * GET /oauth2/userinfo with the caller's bearer.
 *   200 -> { active: true, verifyUserId: <sub>, email: <email> }
 *   anything else (401, network error, ...) -> { active: false }
 *
 * Never throws — a network failure or non-200 is treated the same as an
 * inactive session so callers can fail closed without a try/catch of their
 * own. Active results are served from a short positive cache (see file header).
 */
export async function introspectUser(token: string, deps: IntrospectDeps = {}): Promise<IntrospectResult> {
  const now = deps.now ?? Date.now;
  const ttlMs = deps.cacheTtlMs ?? CACHE_TTL_MS;
  const key = tokenKey(token);

  if (ttlMs > 0) {
    const hit = introspectCache.get(key);
    if (hit && hit.cacheUntil > now()) return hit.result;
  }

  const fetchImpl = deps.fetchImpl ?? fetch;
  const tenantUrl = deps.tenantUrl ?? VERIFY_TENANT_URL;

  try {
    const res = await fetchImpl(`${tenantUrl}/oauth2/userinfo`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (res.status !== 200) {
      return { active: false }; // never cache a negative
    }

    const data = (await res.json()) as Record<string, unknown>;
    const result: IntrospectResult = {
      active: true,
      verifyUserId: typeof data['sub'] === 'string' ? (data['sub'] as string) : undefined,
      email: typeof data['email'] === 'string' ? (data['email'] as string) : undefined,
    };
    if (ttlMs > 0) cachePut(key, result, now, ttlMs, token);
    return result;
  } catch {
    // Network / TLS error reaching Verify — fail closed, same as a 401. Never cached.
    return { active: false };
  }
}

/** Cache an ACTIVE result, capped at min(now+TTL, token exp). */
function cachePut(key: string, result: IntrospectResult, now: () => number, ttlMs: number, token: string): void {
  const expMs = jwtExpMs(token);
  const cacheUntil = expMs !== undefined ? Math.min(now() + ttlMs, expMs) : now() + ttlMs;
  if (cacheUntil <= now()) return; // already-expired token: don't cache

  if (introspectCache.size >= CACHE_MAX_ENTRIES) {
    const t = now();
    for (const [k, v] of introspectCache) if (v.cacheUntil <= t) introspectCache.delete(k);
  }
  introspectCache.set(key, { result, cacheUntil });
}
