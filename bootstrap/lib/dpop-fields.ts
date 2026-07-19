/**
 * The three IBM Verify additionalConfig fields that switch DPoP-bound access
 * tokens (RFC 9449) on or off for an OIDC app.
 *
 * VALUES MUST BE STRINGS. The Verify admin API silently ignores JSON
 * booleans for these fields: the payload reads as enabled, but nothing is
 * enforced. The only proof of real enforcement is a CSIAQ5168E rejection on
 * a proof-less token call (bootstrap smoke:dpop asserts exactly that).
 *
 * Disabled writes explicit string 'false' so a re-run can turn enforcement
 * back off; omitting the fields would leave a previously-enabled app stuck on.
 */
export function dpopAppFields(enabled: boolean): Record<string, string> {
  return {
    dpopBoundAccessTokens: enabled ? 'true' : 'false',
    validateDPoPProofJti: enabled ? 'true' : 'false',
    dpopProofSigningAlg: 'RS256',
  };
}
