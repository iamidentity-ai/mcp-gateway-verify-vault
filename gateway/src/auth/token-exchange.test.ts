/**
 * Tests for token-exchange.ts.
 *
 * Coverage:
 *   (a) plain success → status 'ok' with accessToken
 *   (b) scope=mfa_challenge body → status 'mfa_challenge' with challengeToken
 *       — NOT auto-driven (no /v2.0/factors, no /verifications call)
 *   (c) stale-secret 401 → invalidate + retry once → success
 *   (d) pollOAuthMfaStatus maps USER_FRAUDULENT → denied_suspicious, and this
 *       branch is proven to run BEFORE the USER_DENIED branch
 *   (e) exchangeMfaAssertionWithRAR re-sends authorization_details on the
 *       jwt_bearer second leg
 *
 * Mocks the secrets seam (auth/secrets.js) and spiffe/svid.js at the module
 * level. token-exchange.ts resolves both client secrets ONLY through the seam
 * now (SECRETS_BACKEND-agnostic), so the seam is what these tests stub. Stubs
 * global fetch with a queue/dispatch helper that lets each test wire up
 * exactly the Verify responses it needs. No live network call is ever made.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { __resetBindingForTests } from './binding-mode.js';
import { decodeProtectedHeader } from 'jose';

// vi.mock is hoisted above imports; vi.hoisted lets us share the mock fns
// between the factory and the test bodies without TDZ errors.
const svidMocks = vi.hoisted(() => ({
  getSvid: vi.fn(async (_audience: string) => ({
    svid: 'fake-svid-jwt',
    spiffeId: 'spiffe://gateway.example.com/mcp-gateway',
    expiresAt: Date.now() + 3600_000,
  })),
}));
vi.mock('../spiffe/svid.js', () => ({
  getSvid: svidMocks.getSvid,
}));
const { getSvid } = svidMocks;

const secretsMocks = vi.hoisted(() => ({
  getExchangeClientSecret: vi.fn(),
  getAgentClientSecret: vi.fn(),
  invalidateExchangeSecret: vi.fn(),
  invalidateAgentSecret: vi.fn(),
}));
vi.mock('./secrets.js', () => ({
  getExchangeClientSecret: secretsMocks.getExchangeClientSecret,
  getAgentClientSecret: secretsMocks.getAgentClientSecret,
  invalidateExchangeSecret: secretsMocks.invalidateExchangeSecret,
  invalidateAgentSecret: secretsMocks.invalidateAgentSecret,
}));
const { getExchangeClientSecret, invalidateExchangeSecret } = secretsMocks;

import {
  parseAuthMethod,
  describeDelegationMismatch,
  safeClaimDigest,
  exchangeToken,
  triggerOAuthMfaPush,
  pollOAuthMfaStatus,
  exchangeMfaAssertionWithRAR,
  buildPushContext,
  triggerTransientEmailOtp,
  submitTransientOtp,
  maskEmail,
} from './token-exchange.js';

// ── Fetch helpers ────────────────────────────────────────────

const fetchMock = vi.fn();

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
  getExchangeClientSecret.mockReset();
  invalidateExchangeSecret.mockReset();
  getSvid.mockClear();
  // Default secret — tests can override per case
  getExchangeClientSecret.mockResolvedValue('exchange-secret-v1');
  // Speed up MFA poll loops in tests
  process.env.MFA_POLL_INTERVAL_MS = '5';
  process.env.MFA_POLL_TIMEOUT_MS = '200';
});

afterEach(() => {
  vi.unstubAllGlobals();
  __resetBindingForTests();
  vi.unstubAllEnvs();
});

// Read URL from a fetch call (handles string + URL + Request)
function urlOf(call: any[]): string {
  const arg = call[0];
  if (typeof arg === 'string') return arg;
  if (arg instanceof URL) return arg.toString();
  return arg?.url ?? String(arg);
}

// Read POST body params from a fetch call into a plain object
function paramsOf(call: any[]): Record<string, string> {
  const init = call[1];
  const body = init?.body;
  if (!body) return {};
  const sp = new URLSearchParams(body.toString());
  return Object.fromEntries(sp.entries());
}

// ── (a) Plain successful exchange ────────────────────────────

describe('exchangeToken — plain success (case a)', () => {
  it('does subject+actor+scope+RAR exchange and returns status "ok" with accessToken', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        access_token: 'obo-token-abc',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'records:read',
        authorization_details: [
          {
            type: 'urn:example:agent:records',
            operationDetails: { action: 'record_read', subaction: 'record_read', record_id: 'REC-1001' },
          },
        ],
      }),
    );

    const result = await exchangeToken({
      subjectToken: 'user-access-token',
      scope: 'records:read',
      authorizationDetails: [
        {
          type: 'urn:example:agent:records',
          operationDetails: { action: 'record_read', subaction: 'record_read', record_id: 'REC-1001' },
        },
      ],
    });

    expect(result.status).toBe('ok');
    if (result.status === 'ok') {
      expect(result.accessToken).toBe('obo-token-abc');
      expect(result.expiresIn).toBe(3600);
      expect(result.scope).toBe('records:read');
    }

    // One Verify call to /oauth2/token
    expect(fetchMock).toHaveBeenCalledTimes(1);

    // Actor token came from getSvid('tenant.verify.ibm.com'), NOT SPIRE
    expect(getSvid).toHaveBeenCalledWith('tenant.verify.ibm.com');

    const params = paramsOf(fetchMock.mock.calls[0]);
    expect(params.grant_type).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(params.subject_token).toBe('user-access-token');
    expect(params.actor_token).toBe('fake-svid-jwt');
    expect(params.actor_token_type).toBe('SPIFFE');
    expect(params.scope).toBe('records:read');
    expect(params.client_secret).toBe('exchange-secret-v1');
    expect(JSON.parse(params.authorization_details)[0].operationDetails.record_id).toBe('REC-1001');
  });
});

// ── (b) mfa_challenge surfaced, NOT auto-driven ──────────────

describe('exchangeToken — mfa_challenge is surfaced, not driven (case b)', () => {
  it('returns status "mfa_challenge" with challengeToken and makes NO further calls', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        access_token: 'challenge-token-xyz',
        scope: 'mfa_challenge',
        token_type: 'Bearer',
        expires_in: 60,
      }),
    );

    const result = await exchangeToken({
      subjectToken: 'user-access-token',
      scope: 'records:write',
      authorizationDetails: [
        {
          type: 'urn:example:agent:records',
          operationDetails: { action: 'record_write', subaction: 'record_write', record_id: 'REC-9' },
        },
      ],
    });

    expect(result.status).toBe('mfa_challenge');
    if (result.status === 'mfa_challenge') {
      expect(result.challengeToken).toBe('challenge-token-xyz');
    }

    // Exactly ONE call — /oauth2/token. If this were auto-driven, we'd
    // also see /v2.0/factors + /v1.0/authenticators/.../verifications.
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('returns status "error" when Verify sends scope=mfa_challenge with no access_token', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ scope: 'mfa_challenge' }));

    const result = await exchangeToken({ subjectToken: 'user-access-token', scope: 'records:write' });

    expect(result.status).toBe('error');
    if (result.status === 'error') expect(result.error).toBe('mfa_challenge_no_token');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

// ── (c) Stale-secret retry ───────────────────────────────────

describe('exchangeToken — CSIAQ0155E retry (case c)', () => {
  it('invalidates the role cache, refetches the secret, and retries once', async () => {
    // First /oauth2/token: 401 invalid_client / CSIAQ0155E
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'invalid_client', error_description: 'CSIAQ0155E' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    // Second /oauth2/token: success with refreshed secret
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        access_token: 'obo-after-retry',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'records:read',
      }),
    );

    // Different secret on the refresh
    getExchangeClientSecret
      .mockResolvedValueOnce('exchange-secret-stale')
      .mockResolvedValueOnce('exchange-secret-fresh');

    const result = await exchangeToken({
      subjectToken: 'user-access-token',
      scope: 'records:read',
    });

    expect(result.status).toBe('ok');
    if (result.status === 'ok') expect(result.accessToken).toBe('obo-after-retry');

    // The seam is parameterless — token-exchange no longer passes a role name.
    expect(invalidateExchangeSecret).toHaveBeenCalledTimes(1);
    expect(getExchangeClientSecret).toHaveBeenCalledTimes(2);

    // Two TE calls; second one carries the fresh secret
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(paramsOf(fetchMock.mock.calls[0]).client_secret).toBe('exchange-secret-stale');
    expect(paramsOf(fetchMock.mock.calls[1]).client_secret).toBe('exchange-secret-fresh');
  });

  it('does not retry on a non-stale error (e.g., 400 invalid_request)', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'invalid_request', error_description: 'bad scope' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    const result = await exchangeToken({
      subjectToken: 'user-access-token',
      scope: 'records:read',
    });

    expect(result.status).toBe('error');
    if (result.status === 'error') expect(result.error).toBe('invalid_request');
    expect(invalidateExchangeSecret).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

// ── (d) pollOAuthMfaStatus — suspicious precedes denied ──────

describe('pollOAuthMfaStatus — suspicious verdict precedes denied (case d)', () => {
  it('maps USER_FRAUDULENT to denied_suspicious (not denied) on the first poll', async () => {
    // Single poll response — terminal state on first call, well under 120s
    fetchMock.mockResolvedValueOnce(jsonResponse({ state: 'USER_FRAUDULENT' }));

    const startedAt = Date.now();
    const r = await pollOAuthMfaStatus('https://tenant.verify.ibm.com/tx-1', 'challenge-token', {
      intervalMs: 5,
      timeoutMs: 120_000,
    });
    const elapsedMs = Date.now() - startedAt;

    expect(r.state).toBe('denied_suspicious');
    if (r.state === 'denied_suspicious') {
      expect(r.reason).toBe('USER_FRAUDULENT');
    }
    // Must return on the first poll, well under the 120s push timeout
    expect(elapsedMs).toBeLessThan(1000);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('the denied_suspicious branch is defined before the USER_DENIED branch in source (structural guarantee — not just today\'s literal set)', () => {
    const src = readFileSync(new URL('./token-exchange.ts', import.meta.url), 'utf-8');
    const suspiciousIdx = src.indexOf("state: 'denied_suspicious'");
    const deniedIdx = src.indexOf("state === 'USER_DENIED'");
    expect(suspiciousIdx).toBeGreaterThan(-1);
    expect(deniedIdx).toBeGreaterThan(-1);
    expect(suspiciousIdx).toBeLessThan(deniedIdx);
  });

  it('maps the full fraud-family literal set + substring fallback to denied_suspicious', async () => {
    const fraudStates = [
      'USER_FRAUD',
      'FRAUD',
      'USER_REPORTED_FRAUD',
      'SUSPICIOUS',
      'USER_REPORTED_SUSPICIOUS',
      'SOMETHING_SUSPICIOUS_X', // substring fallback
    ];
    for (const state of fraudStates) {
      fetchMock.mockReset();
      fetchMock.mockResolvedValueOnce(jsonResponse({ state }));
      const r = await pollOAuthMfaStatus('https://x/tx', 'challenge-token', { intervalMs: 5, timeoutMs: 1000 });
      expect(r.state).toBe('denied_suspicious');
    }
  });

  it('still maps a plain USER_DENIED to "denied" (not suspicious)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ state: 'USER_DENIED' }));
    const r = await pollOAuthMfaStatus('https://x/tx', 'challenge-token', { intervalMs: 5, timeoutMs: 1000 });
    expect(r.state).toBe('denied');
  });

  it('returns timeout when no terminal state arrives in time', async () => {
    // Each call gets a fresh Response — Response bodies are one-shot
    fetchMock.mockImplementation(async () => jsonResponse({ state: 'PENDING' }));
    const r = await pollOAuthMfaStatus('https://tenant.verify.ibm.com/tx-1', 'challenge-token', {
      intervalMs: 5,
      timeoutMs: 30,
    });
    expect(r.state).toBe('timeout');
  });
});

// ── (e) exchangeMfaAssertionWithRAR — re-sends authorization_details ─

describe('exchangeMfaAssertionWithRAR — re-sends authorization_details (case e)', () => {
  it('includes authorization_details in the jwt_bearer body when passed', async () => {
    const rar = [
      {
        type: 'urn:example:agent:records',
        operationDetails: { action: 'record_write', subaction: 'record_write', record_id: 'REC-9' },
      },
    ];
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        access_token: 'final-obo-token',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'records:write',
      }),
    );

    const r = await exchangeMfaAssertionWithRAR('mfa-assertion-jwt', 'records:write', rar, 'secret-x');

    expect(r.status).toBe('ok');
    if (r.status === 'ok') expect(r.accessToken).toBe('final-obo-token');

    expect(urlOf(fetchMock.mock.calls[0])).toBe('https://tenant.verify.ibm.com/oauth2/token');
    const params = paramsOf(fetchMock.mock.calls[0]);
    expect(params.grant_type).toBe('urn:ietf:params:oauth:grant-type:jwt-bearer');
    expect(params.assertion).toBe('mfa-assertion-jwt');
    expect(params.scope).toBe('records:write');
    expect(JSON.parse(params.authorization_details)).toEqual(rar);
  });

  it('omits authorization_details from the body when none are passed', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ access_token: 'final', expires_in: 3600 }));
    const r = await exchangeMfaAssertionWithRAR('assertion', 'scope-x', undefined, 'secret-x');
    expect(r.status).toBe('ok');
    const params = paramsOf(fetchMock.mock.calls[0]);
    expect(params.authorization_details).toBeUndefined();
    expect(params.assertion).toBe('assertion');
  });

  it('returns status "error" on non-200 from /oauth2/token', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'expired assertion' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    const r = await exchangeMfaAssertionWithRAR('assertion', 'scope-x', undefined, 'secret-x');
    expect(r.status).toBe('error');
    if (r.status === 'error') expect(r.error).toBe('invalid_grant');
  });
});

// ── Full two-leg flow, driven manually by the "pipeline" (integration-shaped) ─

describe('manual two-leg sequencing (as the pipeline/HITL layer would drive it)', () => {
  it('challenge → triggerOAuthMfaPush → pollOAuthMfaStatus → exchangeMfaAssertionWithRAR yields a real OBO', async () => {
    const rar = [
      {
        type: 'urn:example:agent:records',
        operationDetails: { action: 'record_write', subaction: 'record_write', record_id: 'REC-9001' },
      },
    ];

    // Leg 1: /oauth2/token → 200 with scope=mfa_challenge + challenge token
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ access_token: 'challenge-token-xyz', scope: 'mfa_challenge', token_type: 'Bearer', expires_in: 60 }),
    );

    const first = await exchangeToken({ subjectToken: 'user-access-token', scope: 'records:write', authorizationDetails: rar });
    expect(first.status).toBe('mfa_challenge');
    if (first.status !== 'mfa_challenge') throw new Error('expected mfa_challenge');

    // Pipeline now drives push + poll + second leg itself
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        factors: [
          { id: 'factor-1', type: 'signature', subType: 'userPresence', references: { authenticatorId: 'authn-1' }, attributes: {} },
        ],
      }),
    );
    fetchMock.mockResolvedValueOnce(jsonResponse({ transactionUri: 'https://tenant.verify.ibm.com/v1.0/authnpolicy/transactions/tx-1' }));

    const pushContext = buildPushContext(rar);
    const transactionUri = await triggerOAuthMfaPush(first.challengeToken, pushContext);

    fetchMock.mockResolvedValueOnce(jsonResponse({ state: 'VERIFY_SUCCESS', jwt: 'mfa-assertion-jwt' }));
    const pollResult = await pollOAuthMfaStatus(transactionUri, first.challengeToken);
    expect(pollResult.state).toBe('approved');
    if (pollResult.state !== 'approved') throw new Error('expected approved');

    fetchMock.mockResolvedValueOnce(
      jsonResponse({ access_token: 'final-obo-token', token_type: 'Bearer', expires_in: 3600, scope: 'records:write' }),
    );
    const final = await exchangeMfaAssertionWithRAR(pollResult.assertion, 'records:write', rar, 'exchange-secret-v1');

    expect(final.status).toBe('ok');
    if (final.status === 'ok') expect(final.accessToken).toBe('final-obo-token');

    // 5 total network calls across the whole manually-sequenced flow
    expect(fetchMock).toHaveBeenCalledTimes(5);
  });
});

// ── Helpers exposed for direct unit testing ───────────────────

describe('triggerOAuthMfaPush', () => {
  it('throws when user has no userPresence factor', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ factors: [] }));
    await expect(triggerOAuthMfaPush('challenge-token')).rejects.toThrow(/no registered userPresence factor/);
  });

  it('prefers Verify-app (empty additionalData) factors over SDK factors', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        factors: [
          {
            id: 'sdk-1',
            type: 'signature',
            subType: 'userPresence',
            created: '2026-01-01T00:00:00Z',
            references: { authenticatorId: 'authn-sdk' },
            attributes: { additionalData: [{ name: 'sdkVersion', value: '1.0' }] },
          },
          {
            id: 'verify-app-1',
            type: 'signature',
            subType: 'userPresence',
            created: '2026-02-01T00:00:00Z',
            references: { authenticatorId: 'authn-app' },
            attributes: {},
          },
        ],
      }),
    );
    fetchMock.mockResolvedValueOnce(jsonResponse({ transactionUri: 'https://x/tx' }));

    const tx = await triggerOAuthMfaPush('challenge-token');
    expect(tx).toBe('https://x/tx');

    const verificationsCall = fetchMock.mock.calls[1];
    expect(urlOf(verificationsCall)).toContain('/v1.0/authenticators/authn-app/verifications');
    const body = JSON.parse((verificationsCall[1] as any).body);
    expect(body.authenticationMethods[0].id).toBe('verify-app-1');
  });

  it('names the record_id in both transactionData.message and pushNotification.message', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        factors: [{ id: 'f1', type: 'signature', subType: 'userPresence', references: { authenticatorId: 'a1' }, attributes: {} }],
      }),
    );
    fetchMock.mockResolvedValueOnce(jsonResponse({ transactionUri: 'https://x/tx' }));

    const rar = [
      {
        type: 'urn:example:agent:records',
        operationDetails: { action: 'record_write', subaction: 'record_write', record_id: 'REC-4242' },
      },
    ];
    const pushContext = buildPushContext(rar);
    expect(pushContext.message).toContain('REC-4242');
    expect(pushContext.message).toContain("If you didn't request this, deny.");

    await triggerOAuthMfaPush('challenge-token', pushContext);
    const verificationsCall = fetchMock.mock.calls[1];
    const body = JSON.parse((verificationsCall[1] as any).body);
    expect(body.transactionData.message).toContain('REC-4242');
    expect(body.pushNotification.message).toContain('REC-4242');
    expect(body.pushNotification.title).toBe(pushContext.title);
  });
});

describe('buildPushContext', () => {
  it('falls back to a generic message when no business RAR element is present', () => {
    const ctx = buildPushContext(undefined);
    expect(ctx.message).toContain('records action');
    expect(ctx.message).toContain("If you didn't request this, deny.");
  });
});

// ── transient email OTP (HITL_METHOD=transient_email) ────────

describe('triggerTransientEmailOtp', () => {
  it('POSTs the canonical flat body to /v2.0/factors/emailotp/transient/verifications and builds the submit URL from the response id', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        {
          id: 'verif-123',
          type: 'emailotp',
          state: 'PENDING',
          correlation: 'MCPGW',
          emailAddress: 'steve@example.com',
          attempts: 0,
          retries: 4,
        },
        201,
      ),
    );

    const { transactionUri, id } = await triggerTransientEmailOtp('challenge-token', 'steve@example.com');

    expect(id).toBe('verif-123');
    expect(transactionUri).toBe(
      'https://tenant.verify.ibm.com/v2.0/factors/emailotp/transient/verifications/verif-123',
    );

    expect(urlOf(fetchMock.mock.calls[0])).toBe(
      'https://tenant.verify.ibm.com/v2.0/factors/emailotp/transient/verifications',
    );
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    // Body must be FLAT — no nested `verification: {...}` wrapper — and the
    // default correlation must be alphanumeric only (a hyphen 400s on a real
    // tenant with CSIBN0018E).
    const body = JSON.parse(init.body as string);
    expect(body).toEqual({ emailAddress: 'steve@example.com', correlation: 'MCPGW' });
    expect(body.correlation).toMatch(/^[A-Za-z0-9]+$/);
  });

  it('throws with the response body on a non-2xx', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response('SRVE0295E: Error reported: 404', { status: 404, headers: { 'Content-Type': 'text/html' } }),
    );
    await expect(triggerTransientEmailOtp('challenge-token', 'steve@example.com')).rejects.toThrow(/404/);
  });
});

describe('submitTransientOtp', () => {
  it('returns approved with the assertion under `jwt` (the field name varies by tenant/version)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ jwt: 'mfa-assertion-from-otp' }));
    const r = await submitTransientOtp('https://tenant.verify.ibm.com/v2.0/factors/emailotp/transient/verifications/verif-123', '123456', 'challenge-token');
    expect(r).toEqual({ status: 'approved', assertion: 'mfa-assertion-from-otp' });
    expect(urlOf(fetchMock.mock.calls[0])).toContain('?returnJwt=true');
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({ otp: '123456' });
  });

  // Multi-key assertion lookup — feedback_verify_transient_otp_assertion_field_lookup:
  // the field carrying the assertion is NOT stable across endpoint versions.
  for (const [key, value] of [
    ['assertion', 'assertion-value'],
    ['accessToken', 'accessToken-value'],
    ['access_token', 'access_token-value'],
  ] as const) {
    it(`falls back to the "${key}" field when "jwt" is absent`, async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ [key]: value }));
      const r = await submitTransientOtp('https://x/tx/verif-1', '654321', 'challenge-token');
      expect(r).toEqual({ status: 'approved', assertion: value });
    });
  }

  it('204 No Content success path reads the assertion from a response header', async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204, headers: { 'x-jwt': 'header-assertion' } }));
    const r = await submitTransientOtp('https://x/tx/verif-1', '111111', 'challenge-token');
    expect(r).toEqual({ status: 'approved', assertion: 'header-assertion' });
  });

  it('204 No Content with no assertion header -> error (never silently drops the exchange)', async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));
    const r = await submitTransientOtp('https://x/tx/verif-1', '111111', 'challenge-token');
    expect(r.status).toBe('error');
  });

  it('200 with no recognized assertion key -> error that names the actual keys (so the next operator can add the 5th key in a minute)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ someOtherField: 'x', state: 'VERIFIED' }));
    const r = await submitTransientOtp('https://x/tx/verif-1', '111111', 'challenge-token');
    expect(r.status).toBe('error');
    if (r.status === 'error') {
      expect(r.error).toContain('someOtherField');
      expect(r.error).toContain('state');
    }
  });

  it('401 -> otp_invalid, with attemptsRemaining when Verify reports a retries count', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ retries: 2 }), { status: 401, headers: { 'Content-Type': 'application/json' } }));
    const r = await submitTransientOtp('https://x/tx/verif-1', '000000', 'challenge-token');
    expect(r).toEqual({ status: 'otp_invalid', attemptsRemaining: 2 });
  });

  it('401 with no parseable body -> otp_invalid with attemptsRemaining undefined (never throws)', async () => {
    fetchMock.mockResolvedValueOnce(new Response('', { status: 401 }));
    const r = await submitTransientOtp('https://x/tx/verif-1', '000000', 'challenge-token');
    expect(r).toEqual({ status: 'otp_invalid', attemptsRemaining: undefined });
  });

  it('400 -> otp_expired (already consumed or verification window closed) — distinct from otp_invalid', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ error: 'expired' }), { status: 400, headers: { 'Content-Type': 'application/json' } }));
    const r = await submitTransientOtp('https://x/tx/verif-1', '000000', 'challenge-token');
    expect(r).toEqual({ status: 'otp_expired' });
  });

  it('other non-2xx -> generic error, not swallowed as otp_invalid/otp_expired', async () => {
    fetchMock.mockResolvedValueOnce(new Response('server error', { status: 500 }));
    const r = await submitTransientOtp('https://x/tx/verif-1', '000000', 'challenge-token');
    expect(r.status).toBe('error');
  });

  it('appends returnJwt=true correctly when the transactionUri already has a query string', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ jwt: 'a' }));
    await submitTransientOtp('https://x/tx/verif-1?foo=bar', '000000', 'challenge-token');
    expect(urlOf(fetchMock.mock.calls[0])).toBe('https://x/tx/verif-1?foo=bar&returnJwt=true');
  });
});

describe('maskEmail', () => {
  it('masks the local part to a single leading character + bullet, keeps the domain', () => {
    expect(maskEmail('steve@example.com')).toBe('s•••@example.com');
  });

  it('handles a single-character local part', () => {
    expect(maskEmail('s@example.com')).toBe('s•••@example.com');
  });

  it('returns a bullet placeholder for a string with no @', () => {
    expect(maskEmail('not-an-email')).toBe('•••');
  });
});

// ── (f) TOKEN_BINDING_MODE: DPoP proofs on the token legs ────

describe('bindingFetch (TOKEN_BINDING_MODE)', () => {
  it('outbound mode attaches a fresh DPoP proof to the token-exchange leg', async () => {
    vi.stubEnv('TOKEN_BINDING_MODE', 'outbound');
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ access_token: 'obo-1', token_type: 'Bearer', expires_in: 3600, scope: 'records:read' }),
    );
    const result = await exchangeToken({ subjectToken: 'subject-tok', scope: 'records:read' });
    expect(result.status).toBe('ok');
    const init = fetchMock.mock.calls[0]![1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers['DPoP']).toMatch(/^eyJ/);
    expect(decodeProtectedHeader(headers['DPoP']!).typ).toBe('dpop+jwt');
  });

  it('none mode sends no DPoP header (byte-identical to today)', async () => {
    vi.stubEnv('TOKEN_BINDING_MODE', 'none');
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ access_token: 'obo-2', token_type: 'Bearer', expires_in: 3600, scope: 'records:read' }),
    );
    await exchangeToken({ subjectToken: 'subject-tok', scope: 'records:read' });
    const init = fetchMock.mock.calls[0]![1] as RequestInit;
    const headers = (init.headers ?? {}) as Record<string, string>;
    expect(headers['DPoP']).toBeUndefined();
  });

  it('outbound mode also proofs the jwt_bearer second leg', async () => {
    vi.stubEnv('TOKEN_BINDING_MODE', 'outbound');
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ access_token: 'obo-3', token_type: 'Bearer', expires_in: 3600, scope: 'records:write' }),
    );
    await exchangeMfaAssertionWithRAR('mfa-assertion', 'records:write', [{ type: 'records_api' }], 'exchange-secret-v1');
    const init = fetchMock.mock.calls[0]![1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers['DPoP']).toMatch(/^eyJ/);
    // The form body must be untouched by the wrapper
    expect(String(init.body)).toContain('grant_type=');
  });
});

// ── (f) REGRESSION: the actor identity the exchange presents ─────────────
//
// The bug these guard against took the whole demo down and read as an
// unexplained `invalid_request` on every call, tier 1 included.
//
// `AUTH_METHOD` arrives through a systemd `EnvironmentFile=`, and systemd
// only strips `#` comments at the START of a line. An env file line reading
// `AUTH_METHOD=spiffe   # fallback: verify` therefore sets the value to that
// whole string. The old `AUTH_METHOD === 'spiffe'` check missed, the gateway
// silently took the verify-mode fallback, and it presented a
// client_credentials actor (`sub` = the agent's client id) instead of its
// SPIFFE SVID (`sub` = spiffe://…). IBM Verify matches the actor's `sub`
// against the subject token's `may_act.sub` by exact string equality
// (RFC 8693 §4.4), so every exchange failed CSIAQ5201E.
//
// The point of these tests is to pin the SUCCESSFUL shape: in spiffe mode the
// actor token IS the SVID, presented under the configured SPIFFE token type.
describe('parseAuthMethod — an env-file typo can never silently swap the actor identity (case f)', () => {
  it('accepts the two real modes', () => {
    expect(parseAuthMethod('spiffe')).toBe('spiffe');
    expect(parseAuthMethod('verify')).toBe('verify');
  });

  it('defaults to spiffe when unset or blank', () => {
    expect(parseAuthMethod(undefined)).toBe('spiffe');
    expect(parseAuthMethod('')).toBe('spiffe');
    expect(parseAuthMethod('   ')).toBe('spiffe');
  });

  it('THE REGRESSION: a systemd inline comment still resolves to spiffe, not the verify fallback', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      // Byte-for-byte the line that was live on the demo host.
      expect(parseAuthMethod('spiffe                      # fallback per Task 7 Step 4: verify')).toBe('spiffe');
      // ...and it says so, naming the cause rather than fixing it in silence.
      const warned = warn.mock.calls.map((c) => String(c[0])).join('\n');
      expect(warned).toContain('AUTH_METHOD');
      expect(warned).toContain('EnvironmentFile');
    } finally {
      warn.mockRestore();
    }
  });

  it('trailing whitespace is normalised too', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      expect(parseAuthMethod('verify   ')).toBe('verify');
    } finally {
      warn.mockRestore();
    }
  });

  it('THROWS on a value that is neither mode — never degrades to a different actor identity', () => {
    expect(() => parseAuthMethod('spiffee')).toThrow(/AUTH_METHOD must be one of/);
    expect(() => parseAuthMethod('SPIFFE')).toThrow(/AUTH_METHOD must be one of/);
    expect(() => parseAuthMethod('none')).toThrow(/AUTH_METHOD must be one of/);
  });
});

describe('describeDelegationMismatch — names the may_act/actor drift outright (case f)', () => {
  it('flags the exact CSIAQ5201E shape: SPIFFE may_act vs a client_credentials actor', () => {
    const out = describeDelegationMismatch(
      { sub: 'user', may_act: { sub: 'spiffe://openshell-demo/parent' } },
      { sub: '323f90b0-0b5c-47f1-89fd-df45f4dceef9' },
    );
    expect(out.mayActMismatch).toBe(true);
    expect(out.hint).toContain('spiffe://openshell-demo/parent');
    expect(out.hint).toContain('323f90b0-0b5c-47f1-89fd-df45f4dceef9');
    expect(out.hint).toContain('AUTH_METHOD');
  });

  it('stays silent when the actor is exactly who may_act authorises (the WORKING shape)', () => {
    expect(
      describeDelegationMismatch(
        { sub: 'user', may_act: { sub: 'spiffe://openshell-demo/parent' } },
        { sub: 'spiffe://openshell-demo/parent' },
      ),
    ).toEqual({});
  });

  it('stays silent when either side is unreadable — never guesses a mismatch', () => {
    expect(describeDelegationMismatch({ unparseable: true }, { sub: 'a' })).toEqual({});
    expect(describeDelegationMismatch({ sub: 'u' }, { unparseable: true })).toEqual({});
    expect(describeDelegationMismatch({ sub: 'u' }, { sub: 'a' })).toEqual({});
  });
});

describe('safeClaimDigest — diagnostics never leak token material (case f)', () => {
  it('returns only the closed claim list, dropping anything else the token carries', () => {
    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const token = `${b64({ alg: 'RS256' })}.${b64({
      sub: 'user-1',
      may_act: { sub: 'spiffe://x/y' },
      iat: 1,
      exp: 2,
      // Must NOT survive into a log line:
      ssn: '000-00-0000',
      custom_tenant_claim: 'sensitive',
    })}.sig`;
    const digest = safeClaimDigest(token) as Record<string, unknown>;
    expect(digest['sub']).toBe('user-1');
    expect(digest['may_act']).toEqual({ sub: 'spiffe://x/y' });
    expect('ssn' in digest).toBe(false);
    expect('custom_tenant_claim' in digest).toBe(false);
  });

  it('marks an opaque token unparseable rather than throwing', () => {
    expect(safeClaimDigest('opaque')).toEqual({ unparseable: true });
    expect(safeClaimDigest(undefined)).toEqual({ unparseable: true });
  });
});
