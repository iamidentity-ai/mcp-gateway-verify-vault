/**
 * TOKEN_BINDING_MODE: the single source of truth for DPoP sender-constraining.
 *
 *   none     (default) bearer only. Exactly today's behavior.
 *   outbound the gateway signs a DPoP proof on every /oauth2/token call it
 *            makes to Verify, so OBOs come back bound to the gateway's key
 *            (cnf.jkt). Invisible to callers.
 *   full     outbound, PLUS every caller-facing route requires a valid DPoP
 *            proof bound to the caller's access token. Callers must sign
 *            per-request proofs. See docs/guides/dpop-rollout.md.
 *
 * Pure resolver with an injectable env, the same pattern as
 * proxy/upstream.ts resolveUpstreamAuth, so it unit-tests without process.env.
 */
import { generateDpopKey, type DpopKey } from './sender-constraints/dpop-key.js';

export type BindingMode = 'none' | 'outbound' | 'full';

export function resolveBindingMode(env: NodeJS.ProcessEnv = process.env): BindingMode {
  const raw = (env['TOKEN_BINDING_MODE'] ?? 'none').toLowerCase();
  if (raw === 'outbound' || raw === 'full') return raw;
  if (raw !== 'none') {
    console.warn(`[binding-mode] unknown TOKEN_BINDING_MODE="${raw}"; falling back to "none"`);
  }
  return 'none';
}

let _key: Promise<DpopKey> | undefined;

/** Lazy singleton: one gateway key per process. The thumbprint is logged once
 *  on first use. It is safe to log (it is the public value Verify echoes as
 *  cnf.jkt) and it lets smoke tooling confirm the wiring. */
export async function getGatewayDpopKey(): Promise<DpopKey> {
  if (resolveBindingMode() === 'none') {
    throw new Error('getGatewayDpopKey() called but TOKEN_BINDING_MODE is "none"');
  }
  if (!_key) {
    _key = generateDpopKey().then(async (k) => {
      console.log(`[binding-mode] DPoP ${resolveBindingMode()} mode on. RSA-2048 JWK thumbprint=${await k.thumbprint()}`);
      return k;
    });
  }
  return _key;
}

export function __resetBindingForTests(): void {
  _key = undefined;
}
