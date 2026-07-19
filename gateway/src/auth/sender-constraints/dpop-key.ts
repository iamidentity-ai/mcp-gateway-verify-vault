/**
 * DPoP key pair for the gateway's proofs (RFC 9449).
 *
 * RSA-2048 / RS256 because IBM Verify's dpopProofSigningAlg defaults to
 * RS256. If your tenant uses ES256, change the algorithm here AND in
 * dpop-proof.ts's protected header, and keep the Verify app's
 * dpopProofSigningAlg in lockstep. A mismatch fails every token call with
 * invalid_dpop_proof (algorithm mismatch).
 *
 * The key lives in memory only. A process restart mints a new key. That is
 * fine for the gateway: OBOs are minutes-lived and re-minted per call, so
 * nothing durable is bound to the old key.
 */
import { generateKeyPair, exportJWK, calculateJwkThumbprint } from 'jose';
import type { CryptoKey, JWK } from 'jose';

export interface DpopKey {
  publicJwk: JWK;
  privateKey: CryptoKey;
  /** RFC 7638 SHA-256 JWK thumbprint. This is the value Verify echoes back
   *  in the bound token's cnf.jkt claim. */
  thumbprint(): Promise<string>;
}

export async function generateDpopKey(): Promise<DpopKey> {
  const { publicKey, privateKey } = await generateKeyPair('RS256', {
    modulusLength: 2048,
    extractable: true,
  });
  const publicJwk = await exportJWK(publicKey);
  return {
    publicJwk,
    privateKey,
    thumbprint: () => calculateJwkThumbprint(publicJwk, 'sha256'),
  };
}
