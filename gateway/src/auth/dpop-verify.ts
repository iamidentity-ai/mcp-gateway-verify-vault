/**
 * Inbound DPoP proof validation (RFC 9449). This is the gateway acting as a
 * DPoP resource server in TOKEN_BINDING_MODE=full.
 *
 * Runs BEFORE introspection in the request path and spends no network: one
 * signature verification against the JWK embedded in the proof itself, plus
 * local checks. The chain of trust:
 *   - the proof's signature proves the caller HOLDS the key in the header;
 *   - ath proves the proof was built for THIS access token;
 *   - the token's cnf.jkt (stamped by Verify at issuance) proves the token
 *     was ISSUED to that same key.
 * cnf.jkt is decoded without signature verification here. That is sound
 * because the token's authenticity is separately established by the
 * introspection call that follows (Verify 401s a tampered token), the same
 * trust model introspect.ts already applies to the exp claim.
 *
 * The jti replay cache is in-memory and capped, the same idiom as the
 * introspection cache: expired entries are swept when the cap is reached.
 * A gateway restart clears it; the iat window bounds what a restart forgives.
 */
import { jwtVerify, EmbeddedJWK, calculateJwkThumbprint, decodeProtectedHeader } from 'jose';
import type { JWK } from 'jose';
import { createHash } from 'node:crypto';
import { normalizeHtu } from './sender-constraints/dpop-proof.js';

const IAT_WINDOW_SEC = 300;
const JTI_CACHE_MAX = 50_000;

export type DpopVerifyResult = { ok: true; jkt: string } | { ok: false; error: string };

export interface DpopVerifyDeps {
  now?: () => number;
}

const jtiCache = new Map<string, number>(); // jti -> expiresAtMs

export function __clearJtiCacheForTests(): void {
  jtiCache.clear();
}

function jtiSeen(jti: string, now: () => number): boolean {
  const t = now();
  const hit = jtiCache.get(jti);
  if (hit !== undefined && hit > t) return true;
  if (jtiCache.size >= JTI_CACHE_MAX) {
    for (const [k, v] of jtiCache) if (v <= t) jtiCache.delete(k);
    // Hard cap: if the sweep freed nothing (sustained unique-jti load), evict
    // oldest-inserted entries (Map preserves insertion order) so the cache
    // cannot grow past JTI_CACHE_MAX. Evicted jtis are closest to iat-expiry,
    // and the iat window independently bounds any residual replay.
    while (jtiCache.size >= JTI_CACHE_MAX) {
      const oldest = jtiCache.keys().next().value;
      if (oldest === undefined) break;
      jtiCache.delete(oldest);
    }
  }
  jtiCache.set(jti, t + IAT_WINDOW_SEC * 2 * 1000);
  return false;
}

/** cnf.jkt from the access token, decoded without signature verification.
 *  See the file header for why that is sound here. */
export function tokenCnfJkt(token: string): string | undefined {
  const parts = token.split('.');
  if (parts.length !== 3) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as Record<string, unknown>;
    const cnf = payload['cnf'] as Record<string, unknown> | undefined;
    return typeof cnf?.['jkt'] === 'string' ? (cnf['jkt'] as string) : undefined;
  } catch {
    return undefined;
  }
}

/** base64url SHA-256 of the access token: the value a proof's ath must carry
 *  (RFC 9449 section 4.3.12). */
export function accessTokenHash(token: string): string {
  return createHash('sha256').update(token).digest('base64url');
}

/** Validate one inbound proof. Never throws: callers branch on the union. */
export async function verifyDpopProof(
  args: { proof: string; method: string; url: string; accessToken: string },
  deps: DpopVerifyDeps = {},
): Promise<DpopVerifyResult> {
  const now = deps.now ?? Date.now;

  // 1. Header sanity before any crypto
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(args.proof);
  } catch {
    return { ok: false, error: 'malformed_dpop_proof' };
  }
  if (header.typ !== 'dpop+jwt') return { ok: false, error: 'wrong_proof_typ' };
  if (header.alg !== 'RS256' && header.alg !== 'ES256') return { ok: false, error: 'unsupported_proof_alg' };
  if (!header.jwk) return { ok: false, error: 'missing_proof_jwk' };

  // 2. Signature against the embedded JWK
  let payload: Record<string, unknown>;
  try {
    const verified = await jwtVerify(args.proof, EmbeddedJWK, {
      typ: 'dpop+jwt',
      clockTolerance: IAT_WINDOW_SEC,
      currentDate: new Date(now()),
    });
    payload = verified.payload as Record<string, unknown>;
  } catch {
    return { ok: false, error: 'invalid_proof_signature' };
  }

  // 3. Method + URL binding (htu excludes query and fragment on both sides).
  // normalizeHtu does new URL(...), which throws on a malformed target url; the
  // validator must never throw, so a bad url returns the union, not an exception.
  if (payload['htm'] !== args.method) return { ok: false, error: 'htm_mismatch' };
  let expectedHtu: string;
  try {
    expectedHtu = normalizeHtu(args.url);
  } catch {
    return { ok: false, error: 'malformed_target_url' };
  }
  if (payload['htu'] !== expectedHtu) return { ok: false, error: 'htu_mismatch' };

  // 4. Freshness (jwtVerify covers exp/nbf; iat is checked here)
  const iat = payload['iat'];
  if (typeof iat !== 'number' || Math.abs(now() / 1000 - iat) > IAT_WINDOW_SEC) {
    return { ok: false, error: 'proof_iat_out_of_window' };
  }

  // 5. jti must be present. The replay-cache check is deferred to step 8 (after
  // ath + cnf.jkt) so only a proof bound to a real sender-constrained token can
  // consume a cache slot or trigger the replay scan. This stops an unauthenticated
  // caller from driving cache growth with self-signed proofs that fail ath/cnf.jkt.
  const jti = payload['jti'];
  if (typeof jti !== 'string' || jti.length === 0) return { ok: false, error: 'missing_proof_jti' };

  // 6. The proof is for THIS access token
  if (payload['ath'] !== accessTokenHash(args.accessToken)) return { ok: false, error: 'ath_mismatch' };

  // 7. The token was issued to THIS key
  const jkt = await calculateJwkThumbprint(header.jwk as JWK, 'sha256');
  const bound = tokenCnfJkt(args.accessToken);
  if (!bound) return { ok: false, error: 'token_not_sender_constrained' };
  if (bound !== jkt) return { ok: false, error: 'cnf_jkt_mismatch' };

  // 8. Replay: record the jti only now that the proof is fully valid and bound.
  if (jtiSeen(jti, now)) return { ok: false, error: 'proof_replayed' };

  return { ok: true, jkt };
}
