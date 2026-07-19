import { describe, it, expect } from 'vitest';
import { dpopAppFields } from './dpop-fields.js';

describe('dpopAppFields', () => {
  it('emits STRING values, never booleans (the Verify admin API silently ignores booleans)', () => {
    for (const v of Object.values(dpopAppFields(true))) expect(typeof v).toBe('string');
    for (const v of Object.values(dpopAppFields(false))) expect(typeof v).toBe('string');
  });
  it('enabled turns on binding plus jti replay validation', () => {
    expect(dpopAppFields(true)).toEqual({
      dpopBoundAccessTokens: 'true',
      validateDPoPProofJti: 'true',
      dpopProofSigningAlg: 'RS256',
    });
  });
  it('disabled writes explicit string false so a re-run can turn enforcement OFF again', () => {
    expect(dpopAppFields(false)).toEqual({
      dpopBoundAccessTokens: 'false',
      validateDPoPProofJti: 'false',
      dpopProofSigningAlg: 'RS256',
    });
  });
});
