/**
 * SEP-2322 (MRTR) requestState — Phase 0, validate-if-present.
 *
 * The 2026-07-28 MCP spec's Multi-Round Tool Response pattern carries an
 * opaque `requestState` the client echoes back on a follow-up call. The spec
 * REQUIRES integrity protection whenever the value influences authorization
 * and SHOULD bind the principal, an expiry, and a digest of the originating
 * request. This gateway's HITL park/complete flow is exactly that shape — a
 * `pending` result already hands the caller a `txId` it echoes back to
 * `completePending` — so this module pre-adopts the exact requestState shape
 * now, ahead of full SEP-2322 wiring: `mintRequestState` runs at park time,
 * `verifyRequestState` runs when a completer presents one back.
 *
 * This repo stays on protocol 2025-11-25 (see mcp/header-validation.ts's own
 * doc comment for the same framing) — nothing here is REQUIRED yet. A
 * completer that sends only `txId` is unaffected: the pending store's
 * single-use semantics and completePending's own owner check already enforce
 * who may resume a transaction. A completer that DOES present a
 * requestState gets it verified, and a bad one is rejected.
 *
 * Blob format: `v1.` + base64url(JSON of RequestStateClaims) + `.` +
 * base64url(HMAC-SHA256 over the exact base64url payload string — NOT over
 * the raw JSON). Pure, synchronous, no I/O — mirrors mcp/header-validation.ts's
 * verify-fail-closed style: a typed union result, never a throw.
 *
 * Secret resolution: env `HITL_STATE_SECRET` when set and non-empty,
 * otherwise a module-level `randomBytes(32)` generated once per process.
 * Per-process is correct here, not a shortcut: hitl/pending.ts's store is
 * itself in-memory and per-process by design (see its own doc comment), so a
 * gateway restart already invalidates every outstanding txId. A requestState
 * that outlives the process it was minted in would be checking a claim
 * against a store that no longer has the entry anyway — tying the fallback
 * secret's lifetime to the same process boundary changes nothing observable.
 * The env var only matters for a MULTI-instance deployment (so instance B
 * can verify a requestState instance A minted) — this gateway's current
 * deploy is single-instance, so leaving it unset is a legitimate default,
 * not a security gap.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export interface RequestStateClaims {
  v: 1;
  txId: string;
  sub: string;
  exp: number;
  digest: string;
}

export type VerifyRequestStateResult =
  | { ok: true }
  | { ok: false; reason: 'malformed' | 'bad_signature' | 'expired' | 'mismatch' };

// Generated lazily, at most once per process — see the secret-resolution
// note in the module doc comment above. Never read at import time: doing so
// would bake in "was HITL_STATE_SECRET set at process start" instead of "is
// it set now," which is what lets a test flip the env var between two mints
// and observe both take effect (see request-state.test.ts).
let fallbackSecret: Buffer | undefined;

function secretKey(): Buffer {
  const env = process.env['HITL_STATE_SECRET'];
  if (env) return Buffer.from(env, 'utf8');
  if (!fallbackSecret) fallbackSecret = randomBytes(32);
  return fallbackSecret;
}

/**
 * Recursively sort object keys so JSON.stringify is key-order independent —
 * `requestDigest({a:1,b:2})` and `requestDigest({b:2,a:1})` must produce the
 * same hash. Arrays keep their own order (order is meaningful there); only
 * plain-object keys are sorted. Local to this module — not a general-purpose
 * canonicalizer (tool-call arguments are plain JSON-shaped values; no
 * Date/Map/BigInt handling needed).
 */
function canonicalJson(value: unknown): string {
  const sort = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(sort);
    if (v !== null && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const key of Object.keys(v as Record<string, unknown>).sort()) {
        out[key] = sort((v as Record<string, unknown>)[key]);
      }
      return out;
    }
    return v;
  };
  return JSON.stringify(sort(value));
}

/**
 * The originating-request digest SEP-2322 recommends binding requestState
 * to. Hashed over a fixed prefix + the tool name + canonical JSON of the
 * arguments, so a completer cannot replay a requestState minted for one
 * tool/args pair against a different one.
 */
export function requestDigest(toolName: string, args: Record<string, unknown>): string {
  return createHash('sha256').update(`tools/call\n${toolName}\n${canonicalJson(args)}`, 'utf8').digest('hex');
}

/** Mint a requestState blob. `claims` is everything but the version tag —
 *  callers (pipeline.ts's park sites) supply `exp` and `digest` themselves so
 *  this module carries no clock or knowledge of the pending store's shape. */
export function mintRequestState(claims: Omit<RequestStateClaims, 'v'>): string {
  const full: RequestStateClaims = { v: 1, ...claims };
  const payload = Buffer.from(JSON.stringify(full), 'utf8').toString('base64url');
  const sig = createHmac('sha256', secretKey()).update(payload, 'utf8').digest('base64url');
  return `v1.${payload}.${sig}`;
}

/**
 * Verify a requestState blob against the expectations the caller has
 * independently established (typically off the pending entry itself, never
 * off anything the completer sent) — see completePending's wiring for why
 * `expect.digest` must be recomputed from the STORED tool name/args, not
 * trusted from the request. `nowMs` defaults to `Date.now()` but is
 * injectable so tests can drive expiry deterministically without fake
 * timers, matching this codebase's existing `now()` dependency-injection
 * idiom (see pipeline.ts's RunPipelineDeps/CompletePendingDeps).
 *
 * Checks run in an order that never leaks more than the caller needs to
 * know: structural shape first (malformed), then the signature (bad_signature
 * — a tampered claims payload fails here even before it's parsed, since the
 * signature covers the raw base64url string), then expiry, then the actual
 * claim comparison (mismatch).
 *
 * `blob` is `unknown`, not `string` — this function is the boundary a
 * caller-supplied requestState of any shape ultimately reaches (a JSON body
 * places no type constraint on the field), and it must be total: a number,
 * boolean, object, or array comes back as `{ ok: false, reason: 'malformed' }`
 * exactly like a garbled string, never a thrown TypeError.
 */
export function verifyRequestState(
  blob: unknown,
  expect: { txId: string; sub: string; digest: string },
  nowMs: number = Date.now(),
): VerifyRequestStateResult {
  if (typeof blob !== 'string') return { ok: false, reason: 'malformed' };

  const parts = blob.split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') return { ok: false, reason: 'malformed' };
  const payload = parts[1];
  const sig = parts[2];
  if (!payload || !sig) return { ok: false, reason: 'malformed' };

  const expectedSigBuf = Buffer.from(createHmac('sha256', secretKey()).update(payload, 'utf8').digest('base64url'), 'utf8');
  const sigBuf = Buffer.from(sig, 'utf8');
  // Length-check BEFORE timingSafeEqual: it throws on mismatched lengths
  // instead of returning false, and the length itself is not secret.
  if (sigBuf.length !== expectedSigBuf.length || !timingSafeEqual(sigBuf, expectedSigBuf)) {
    return { ok: false, reason: 'bad_signature' };
  }

  let claims: RequestStateClaims;
  try {
    claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as RequestStateClaims;
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  if (
    typeof claims !== 'object' ||
    claims === null ||
    claims.v !== 1 ||
    typeof claims.txId !== 'string' ||
    typeof claims.sub !== 'string' ||
    typeof claims.exp !== 'number' ||
    typeof claims.digest !== 'string'
  ) {
    return { ok: false, reason: 'malformed' };
  }

  if (nowMs >= claims.exp) return { ok: false, reason: 'expired' };

  if (claims.txId !== expect.txId || claims.sub !== expect.sub || claims.digest !== expect.digest) {
    return { ok: false, reason: 'mismatch' };
  }

  return { ok: true };
}
