/**
 * Build and sign one DPoP proof JWT (RFC 9449 section 4.2). One proof per
 * outbound HTTP request. The proof binds the request to:
 *   htm  the HTTP method
 *   htu  the request URL, normalized to scheme + host + path
 *   jti  a random unique id (the receiving server caches it to catch replay)
 *   iat  issued-at, which must sit inside the receiver's clock window
 * and to the signing key via the public JWK embedded in the JWS header.
 */
import { SignJWT } from 'jose';
import { randomUUID } from 'node:crypto';
import type { DpopKey } from './dpop-key.js';

export interface DpopProofRequest {
  key: DpopKey;
  htm: string;
  htu: string;
  /** base64url SHA-256 of the access token. Required when the proof rides
   *  alongside an access token at a resource server (RFC 9449 section 4.3).
   *  Not needed on token-endpoint calls. */
  ath?: string;
}

/** RFC 9449: htu excludes query and fragment. Exported so the inbound
 *  validator (dpop-verify.ts) normalizes exactly the way proofs are built. */
export function normalizeHtu(htu: string): string {
  const u = new URL(htu);
  return `${u.protocol}//${u.host}${u.pathname}`;
}

export async function buildDpopProof(req: DpopProofRequest): Promise<string> {
  const payload: Record<string, unknown> = {
    htm: req.htm,
    htu: normalizeHtu(req.htu),
    jti: randomUUID(),
  };
  if (req.ath) payload['ath'] = req.ath;

  return await new SignJWT(payload)
    .setProtectedHeader({
      alg: 'RS256',
      typ: 'dpop+jwt',
      jwk: req.key.publicJwk,
    })
    .setIssuedAt()
    .sign(req.key.privateKey);
}
