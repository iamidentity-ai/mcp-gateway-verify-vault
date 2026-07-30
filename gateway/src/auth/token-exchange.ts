/**
 * Token Exchange Module (RFC 8693) with Rich Authorization Requests (RFC 9396)
 * — MCP gateway
 *
 * Every gateway-mediated MCP tool call goes through token exchange before
 * hitting the upstream MCP server. The agent's access is bound by an OBO
 * token whose RAR `authorization_details` declares exactly what operation
 * is being performed (built upstream by rar/build-rar.ts — this module
 * only forwards whatever authorization_details the caller passes in).
 *
 * Behaviors implemented here:
 *
 * 1. Plain RFC 8693 token exchange:
 *      subject_token (user's access_token) + actor_token (SPIFFE SVID or
 *      agent client_credentials JWT) + scope + authorization_details
 *      → OBO token
 *
 * 2. mfa_challenge is SURFACED, not driven, by exchangeToken():
 *      When IBM Verify's policy fires ACTION_MFA_ALWAYS, the /oauth2/token
 *      endpoint returns a 200 OK with `scope: "mfa_challenge"` and a
 *      challenge access_token (NOT a real OBO). The gateway has a caller to
 *      notify between challenge and approval, so exchangeToken() returns
 *      `{ status: 'mfa_challenge', challengeToken }` immediately — it does
 *      NOT trigger the push itself. The pipeline/HITL layer sequences:
 *        a. triggerOAuthMfaPush(challengeToken, pushContext) → transactionUri
 *        b. pollOAuthMfaStatus(transactionUri, challengeToken) → verdict
 *        c. exchangeMfaAssertionWithRAR(assertion, scope, authorizationDetails,
 *           exchangeSecret) — POSTs the assertion back as grant_type=jwt-bearer
 *           AND re-sends authorization_details (Verify does not propagate
 *           them through the second leg by default).
 *
 * 3. CSIAQ0155E single-attempt narrow-invalidation retry:
 *      The client secret comes from the secrets seam (auth/secrets.ts). In
 *      vault mode the IBM Verify Vault plugin rotates the client_secret on
 *      every read; cross-process rotations occasionally leave the cache
 *      stale. On stale-secret signals (HTTP 401, `invalid_client`,
 *      `CSIAQ0155E` in body) we invalidate via the seam, fetch fresh, retry
 *      once — no sleep, never a global flush. In env mode invalidate is a
 *      no-op (a static env secret does not rotate) so the retry is harmless.
 *
 * 4. Transient email-OTP HITL mode (HITL_METHOD=transient_email):
 *      Some populations (e.g. Entra-anchored users JIT'd into the tenant)
 *      have no enrolled Verify push factor — triggerOAuthMfaPush's
 *      `/v2.0/factors` lookup comes back empty and the push flow cannot
 *      fire. Verify offers a "transient" factor that needs no prior
 *      enrollment: a one-shot 6-digit code mailed to an address, verified
 *      with no persistent registration. `triggerTransientEmailOtp` sends
 *      it; `submitTransientOtp` verifies the code the user typed and
 *      returns the assertion JWT for the same jwt_bearer second leg the
 *      push path uses. The pipeline layer (pipeline.ts), not this module,
 *      decides which HITL method to use per HITL_METHOD — this module only
 *      exposes both primitives. See:
 *        - feedback_verify_transient_otp_canonical_endpoints (endpoint/body
 *          shape + alphanumeric `correlation` requirement)
 *        - feedback_verify_transient_otp_assertion_field_lookup (the
 *          assertion arrives under a key that varies by tenant/version —
 *          multi-key lookup, never a single hardcoded field)
 *
 * The two client secrets are resolved ONLY through auth/secrets.ts — this
 * module never reads GATEWAY_*_CLIENT_SECRET or a Vault role directly, so it
 * is identical whether SECRETS_BACKEND is env or vault.
 *
 * Environment:
 *   VERIFY_TENANT_URL          — your IBM Verify tenant base URL
 *   GATEWAY_EXCHANGE_CLIENT_ID — Token Exchange app clientId
 *   GATEWAY_AGENT_CLIENT_ID    — Agent identity clientId (for verify-mode)
 *   (the exchange/agent client SECRETS + their vault role names are owned by
 *    auth/secrets.ts — see SECRETS_BACKEND there)
 *   AUTH_METHOD                — "spiffe" (default) or "verify"
 *   GATEWAY_ACTOR_TOKEN_TYPE   — actor_token_type sent for the SPIFFE SVID;
 *                                 must match the custom token type configured
 *                                 on the Verify tenant (default "SPIFFE")
 *   HITL_METHOD                 — "push" (default) or "transient_email";
 *                                 read by pipeline.ts, documented here
 *                                 because it decides which of this module's
 *                                 HITL primitives get called
 */

import {
  getExchangeClientSecret,
  getAgentClientSecret,
  invalidateExchangeSecret,
  invalidateAgentSecret,
} from './secrets.js';
import { getSvid } from '../spiffe/svid.js';
import { rarConfig } from '../rar/rar-config.js';
import { resolveBindingMode, getGatewayDpopKey } from './binding-mode.js';
import { dpopFetch } from './sender-constraints/dpop-fetch.js';

const VERIFY_TENANT_URL = process.env.VERIFY_TENANT_URL || 'https://tenant.verify.ibm.com';
const EXCHANGE_CLIENT_ID = process.env.GATEWAY_EXCHANGE_CLIENT_ID || '';
const AGENT_CLIENT_ID = process.env.GATEWAY_AGENT_CLIENT_ID || '';
// The exchange/agent client secrets — and, in vault mode, their Vault plugin
// role names — are owned by the secrets seam (auth/secrets.ts), not here.
const AUTH_METHOD = process.env.AUTH_METHOD || 'spiffe';

// Audience the SPIFFE actor SVID is minted for — the Verify tenant itself
// (host derived from VERIFY_TENANT_URL).
const SVID_ACTOR_AUDIENCE = new URL(VERIFY_TENANT_URL).host;

// actor_token_type presented for the SVID — the name of the custom token
// type configured on the Verify tenant for SPIFFE JWT-SVIDs.
const ACTOR_TOKEN_TYPE = process.env.GATEWAY_ACTOR_TOKEN_TYPE || 'SPIFFE';

// MFA poll defaults
const MFA_POLL_INTERVAL_MS = Number(process.env.MFA_POLL_INTERVAL_MS) || 3000;
const MFA_POLL_TIMEOUT_MS = Number(process.env.MFA_POLL_TIMEOUT_MS) || 120_000;

/**
 * Wrap fetch() for the /oauth2/token legs with the configured token binding.
 * In outbound or full mode every token-endpoint call carries a fresh DPoP
 * proof, so Verify (with dpopBoundAccessTokens on the exchange app) returns
 * OBOs bound to the gateway's key via cnf.jkt. The factors, verification
 * polling, and client_credentials calls stay plain bearer on purpose: they
 * present tokens at resource endpoints and are not token issuance, and only
 * the exchange app is DPoP-bound.
 */
async function bindingFetch(url: string, init: RequestInit): Promise<Response> {
  if (resolveBindingMode() !== 'none') {
    const key = await getGatewayDpopKey();
    return dpopFetch(url, { ...init, key });
  }
  return fetch(url, init);
}

// ── Types ────────────────────────────────────────────────────

export interface AuthorizationDetail {
  type: string;
  [key: string]: any;
}

export interface TokenExchangeRequest {
  subjectToken: string;
  scope: string;
  authorizationDetails?: AuthorizationDetail[];
}

/**
 * Discriminated union — the gateway (not this module) drives HITL sequencing
 * off the 'mfa_challenge' branch.
 */
export type TokenExchangeResult =
  | {
      status: 'ok';
      accessToken: string;
      expiresIn: number;
      scope: string;
      authorizationDetails?: AuthorizationDetail[];
    }
  | { status: 'mfa_challenge'; challengeToken: string }
  | { status: 'error'; error: string; errorDescription?: string };

// ── Stale-secret detection ───────────────────────────────────

function isStaleSecretError(status: number, body: string): boolean {
  return status === 401 || body.includes('invalid_client') || body.includes('CSIAQ0155E');
}

// ── Actor token ──────────────────────────────────────────────

/**
 * Get the agent's actor token. SPIFFE mode (default) mints a Vault-native
 * JWT-SVID via getSvid and presents it under the configured custom
 * actor_token_type; verify mode does a client_credentials grant against the
 * agent OIDC app. Both paths are built so the switch is a pure env-var flip
 * — 'verify' is the fallback when the tenant has no SPIFFE custom token
 * type configured.
 */
async function getActorToken(): Promise<{ token: string; tokenType: string }> {
  if (AUTH_METHOD === 'spiffe') {
    const { svid } = await getSvid(SVID_ACTOR_AUDIENCE);
    return { token: svid, tokenType: ACTOR_TOKEN_TYPE };
  }

  // verify-mode fallback — the agent authenticates as its own OIDC client
  // instead of presenting a SPIFFE SVID.
  if (!AGENT_CLIENT_ID) {
    throw new Error('verify-mode actor token requires GATEWAY_AGENT_CLIENT_ID');
  }

  const run = async (secret: string): Promise<Response> => {
    return fetch(`${VERIFY_TENANT_URL}/v1.0/endpoint/default/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: AGENT_CLIENT_ID,
        client_secret: secret,
      }),
    });
  };

  let secret = await getAgentClientSecret();
  let response = await run(secret);
  if (!response.ok) {
    const text = await response.text();
    if (isStaleSecretError(response.status, text)) {
      invalidateAgentSecret();
      secret = await getAgentClientSecret();
      response = await run(secret);
    } else {
      throw new Error(`Agent client_credentials failed (${response.status}): ${text}`);
    }
  }
  if (!response.ok) {
    throw new Error(`Agent client_credentials failed after retry: ${await response.text()}`);
  }
  const data = await response.json();
  return { token: data.access_token, tokenType: 'urn:ietf:params:oauth:token-type:access_token' };
}

// ── Push context builder ────────────────────────────────────

const DENY_SUFFIX = "If you didn't request this, deny.";

/**
 * Display copy for the DEFAULT config/rar.json vocabulary. Purely cosmetic:
 * an action with no entry here falls back to the generic phrase below, so a
 * customer vocabulary works without touching this map — but retitling these
 * alongside config/rar.json makes the push message read naturally.
 */
const ACTION_PHRASES: Record<string, string> = {
  record_read: 'view a record',
  record_read_elevated: 'view a restricted record',
  record_write: 'update a record',
  record_delete: 'delete a record',
};

/**
 * Derive {title, message} from the business RAR element for the push
 * notification — names the domain id (config/rar.json → idField) so the
 * user's phone shows exactly which record is at stake. The business element
 * is found by config.rarType, never a hardcoded type string.
 */
export function buildPushContext(
  authorizationDetails?: AuthorizationDetail[],
): { title: string; message: string } {
  const title = 'MCP Gateway — approval';
  const business = authorizationDetails?.find((d) => d.type === rarConfig.rarType);
  const od = business?.operationDetails as Record<string, string | undefined> | undefined;
  const actionKey = od?.['subaction'] ?? od?.['action'];
  const phrase = (actionKey && ACTION_PHRASES[actionKey]) || 'a records action';
  const idValue = od?.[rarConfig.idField];
  const recordSuffix = idValue ? ` (record ${idValue})` : '';
  return { title, message: `Approve: ${phrase}${recordSuffix}. ${DENY_SUFFIX}` };
}

// ── MFA helpers (challenge → push → poll → jwt-bearer) ───────

/**
 * Trigger an IBM Verify push notification using the mfa_challenge token as
 * the bearer. Returns the transactionUri to poll.
 *
 * The challenge token is what /oauth2/token returns when the bound access
 * policy fires ACTION_MFA_ALWAYS. It carries enough authority to call the
 * factor + verifications endpoints on the user's behalf, but cannot be used
 * to call business APIs.
 */
export async function triggerOAuthMfaPush(
  challengeToken: string,
  pushContext?: { title: string; message: string },
): Promise<string> {
  // 1. Look up the user's userPresence (push) factor
  const factorsRes = await fetch(`${VERIFY_TENANT_URL}/v2.0/factors`, {
    headers: {
      Authorization: `Bearer ${challengeToken}`,
      Accept: 'application/json',
    },
  });
  if (!factorsRes.ok) {
    throw new Error(`triggerOAuthMfaPush: /v2.0/factors failed (${factorsRes.status}): ${await factorsRes.text()}`);
  }
  const factorsData = (await factorsRes.json()) as { factors?: any[] };
  const factors = factorsData?.factors ?? [];

  // Prefer non-SDK userPresence (Verify-app registrations); newest first.
  const userPresence = factors
    .filter((f) => f.type === 'signature' && f.subType === 'userPresence')
    .sort((a, b) => {
      const ta = new Date(a.created || 0).getTime();
      const tb = new Date(b.created || 0).getTime();
      return tb - ta;
    });
  const verifyAppOnly = userPresence.filter((f) => {
    const ad = f.attributes?.additionalData;
    return !ad || (Array.isArray(ad) && ad.length === 0);
  });
  const candidates = verifyAppOnly.length > 0 ? verifyAppOnly : userPresence;
  const pick = candidates[0];
  if (!pick) {
    throw new Error('triggerOAuthMfaPush: user has no registered userPresence factor');
  }
  const factorId: string | undefined = pick.id;
  const authenticatorId: string | undefined = pick.references?.authenticatorId;
  if (!factorId || !authenticatorId) {
    throw new Error('triggerOAuthMfaPush: factor record missing id or authenticatorId');
  }

  // 2. Send push notification
  const verifyRes = await fetch(
    `${VERIFY_TENANT_URL}/v1.0/authenticators/${authenticatorId}/verifications`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${challengeToken}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        transactionData: {
          message: pushContext?.message ?? 'Approve agent action',
          originIpAddress: '192.168.222.222',
          originUserAgent: 'MCP Gateway',
        },
        pushNotification: {
          send: true,
          title: pushContext?.title ?? 'MCP Gateway',
          message: pushContext?.message ?? 'Approve agent action',
        },
        authenticationMethods: [{ id: factorId, methodType: 'signature' }],
        logic: 'OR',
        expiresIn: 130,
      }),
    },
  );
  if (!verifyRes.ok) {
    throw new Error(
      `triggerOAuthMfaPush: /v1.0/authenticators/${authenticatorId}/verifications failed (${verifyRes.status}): ${await verifyRes.text()}`,
    );
  }
  const verifyData = (await verifyRes.json()) as { transactionUri?: string };
  if (!verifyData.transactionUri) {
    throw new Error(`triggerOAuthMfaPush: response missing transactionUri: ${JSON.stringify(verifyData)}`);
  }
  return verifyData.transactionUri;
}

export type MfaPollResult =
  | { state: 'approved'; assertion: string }
  | { state: 'denied'; reason: string }
  | { state: 'denied_suspicious'; reason: string }
  | { state: 'timeout' };

/**
 * Poll an IBM Verify verification transaction until success/denial/timeout.
 * Append `?returnJwt=true` so VERIFY_SUCCESS includes the assertion JWT used
 * for the second leg jwt_bearer call.
 */
export async function pollOAuthMfaStatus(
  transactionUri: string,
  challengeToken: string,
  options?: { intervalMs?: number; timeoutMs?: number },
): Promise<MfaPollResult> {
  const intervalMs = options?.intervalMs ?? MFA_POLL_INTERVAL_MS;
  const timeoutMs = options?.timeoutMs ?? MFA_POLL_TIMEOUT_MS;
  const url = transactionUri + (transactionUri.includes('?') ? '&' : '?') + 'returnJwt=true';
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${challengeToken}`, Accept: 'application/json' },
    });
    if (!res.ok) {
      // Transient? Back off and retry until outer timeout.
      await sleep(intervalMs);
      continue;
    }
    // Verify returns the assertion JWT under `assertion` (NOT `jwt`).
    // Accept both keys defensively.
    const data = (await res.json()) as { state?: string; assertion?: string; jwt?: string };
    const state = data.state;
    if (state === 'VERIFY_SUCCESS') {
      const assertion = data.assertion ?? data.jwt;
      if (!assertion) {
        throw new Error('pollOAuthMfaStatus: VERIFY_SUCCESS but no assertion JWT in response');
      }
      return { state: 'approved', assertion };
    }
    // "Mark as suspicious" / fraud-report path. MUST run BEFORE the regular
    // USER_DENIED branch because the substring fallback below (FRAUD / SUSPICIOUS)
    // would otherwise be unreachable — and because suspicious-deny triggers a
    // 1-strike immediate session-kill in the pipeline, whereas a plain
    // USER_DENIED only increments the 3-strike counter. The literal set covers
    // the Verify mobile-app poll state strings observed in the wild; the
    // substring fallback catches renamed variants.
    if (
      state === 'USER_FRAUDULENT' ||
      state === 'USER_FRAUD' ||
      state === 'FRAUD' ||
      state === 'USER_REPORTED_FRAUD' ||
      state === 'SUSPICIOUS' ||
      state === 'USER_REPORTED_SUSPICIOUS' ||
      (typeof state === 'string' && (state.includes('FRAUD') || state.includes('SUSPICIOUS')))
    ) {
      return { state: 'denied_suspicious', reason: state ?? 'suspicious' };
    }
    if (state === 'USER_DENIED' || state === 'DENY' || state === 'FAILED' || state === 'EXPIRED') {
      return { state: 'denied', reason: state };
    }
    await sleep(intervalMs);
  }
  return { state: 'timeout' };
}

/**
 * Second-leg jwt_bearer call. After MFA approval the pipeline/HITL layer
 * POSTs the assertion back to /oauth2/token with
 * grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer.
 *
 * CRITICAL — Verify does NOT propagate authorization_details through the
 * second leg by default. This function MUST re-send them or the resulting
 * OBO has no Verify-attested RAR.
 */
export async function exchangeMfaAssertionWithRAR(
  assertion: string,
  scope: string,
  authorizationDetails: AuthorizationDetail[] | undefined,
  exchangeSecret: string,
): Promise<TokenExchangeResult> {
  const params: Record<string, string> = {
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    client_id: EXCHANGE_CLIENT_ID,
    client_secret: exchangeSecret,
    assertion,
    scope,
  };
  if (authorizationDetails && authorizationDetails.length > 0) {
    params.authorization_details = JSON.stringify(authorizationDetails);
  }

  const res = await bindingFetch(`${VERIFY_TENANT_URL}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params),
  });
  const text = await res.text();
  if (!res.ok) {
    let errorData: any = {};
    try { errorData = JSON.parse(text); } catch { errorData = { error_description: text }; }
    return {
      status: 'error',
      error: errorData.error || 'jwt_bearer_failed',
      errorDescription: errorData.error_description || text,
    };
  }
  const data = JSON.parse(text);
  return {
    status: 'ok',
    accessToken: data.access_token,
    expiresIn: data.expires_in,
    scope: data.scope,
    authorizationDetails: data.authorization_details,
  };
}

// ── Transient email OTP (HITL_METHOD=transient_email) ────────
//
// Used instead of the push flow when the user has no enrolled Verify
// factor — the population this exists for is Entra-anchored users JIT'd
// into the tenant, who were never issued a Verify authenticator. Both
// functions operate on the SAME mfa_challenge token the push flow uses;
// the pipeline layer picks one or the other based on HITL_METHOD, never
// both.

/**
 * Ask Verify to mail a one-shot 6-digit code to `emailAddress`. Requires no
 * prior enrollment — that is the whole point.
 *
 * Canonical endpoint + body shape (validated against a live tenant —
 * feedback_verify_transient_otp_canonical_endpoints):
 *   POST /v2.0/factors/emailotp/transient/verifications
 *   body: { emailAddress, correlation }        (FLAT — no nested wrapper)
 *
 * Bugs this deliberately avoids (all empirically hit before):
 *   - factor type name is `emailotp`, NOT `transientotpemail` (wrong name
 *     404s with WebSphere SRVE0295E, not a normal 4xx)
 *   - URL ends `/transient/verifications`, NOT `/transient`
 *   - `correlation` MUST be alphanumeric only — a hyphen 400s with
 *     CSIBN0018E ("correlation is either invalid or missing")
 */
export async function triggerTransientEmailOtp(
  challengeToken: string,
  emailAddress: string,
  correlation = 'MCPGW',
): Promise<{ transactionUri: string; id: string }> {
  const url = `${VERIFY_TENANT_URL}/v2.0/factors/emailotp/transient/verifications`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${challengeToken}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({ emailAddress, correlation }),
  });
  if (!res.ok) {
    throw new Error(`triggerTransientEmailOtp: ${res.status} ${await res.text()}`);
  }
  const body = (await res.json()) as Record<string, unknown>;
  const id = body['id'] as string | undefined;
  if (!id) {
    throw new Error(`triggerTransientEmailOtp: response missing id: ${JSON.stringify(body)}`);
  }
  // Verify's CREATE response does not always include a fully-qualified
  // self-link — build the submit URL from the id, same as the push flow
  // builds its poll URL from transactionUri.
  return { transactionUri: `${url}/${id}`, id };
}

/**
 * Discriminated verdict for submitTransientOtp. A discriminated result
 * (rather than throwing) lets pipeline.ts map each case to a distinct HTTP
 * envelope (otp_invalid / otp_expired / generic error) instead of parsing a
 * thrown Error's message.
 */
export type SubmitOtpResult =
  | { status: 'approved'; assertion: string }
  | { status: 'otp_invalid'; attemptsRemaining?: number }
  | { status: 'otp_expired' }
  | { status: 'error'; error: string };

/**
 * Submit the code the user typed back. Distinguishes:
 *   - 401 → wrong code (otp_invalid). If Verify's error body reports a
 *     `retries` or `attemptsRemaining` count, it's surfaced so the caller
 *     can tell the user how many tries are left.
 *   - 400 → the code was already consumed or the verification expired
 *     (otp_expired) — distinct from "wrong code" so the caller knows to
 *     request a NEW code rather than let the user retype the same one.
 *
 * On success the assertion JWT's field name varies by tenant/factor-type
 * version (feedback_verify_transient_otp_assertion_field_lookup) — try
 * `jwt`, `assertion`, `accessToken`, `access_token` in that order, plus the
 * 204-with-header path, and log the actual response keys on a miss so the
 * next operator can add a 5th key in a minute instead of debugging for an
 * hour.
 */
export async function submitTransientOtp(
  transactionUri: string,
  otp: string,
  challengeToken: string,
): Promise<SubmitOtpResult> {
  const url = transactionUri.includes('?')
    ? `${transactionUri}&returnJwt=true`
    : `${transactionUri}?returnJwt=true`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${challengeToken}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({ otp }),
  });

  if (res.status === 401) {
    let attemptsRemaining: number | undefined;
    try {
      const body = JSON.parse(await res.text()) as Record<string, unknown>;
      const retries = body['retries'] ?? body['attemptsRemaining'];
      if (typeof retries === 'number') attemptsRemaining = retries;
    } catch {
      // Body wasn't JSON or had neither field — leave attemptsRemaining
      // undefined; the caller still gets a clear otp_invalid.
    }
    return { status: 'otp_invalid', attemptsRemaining };
  }
  if (res.status === 400) {
    return { status: 'otp_expired' };
  }
  if (!res.ok) {
    return { status: 'error', error: `submitTransientOtp: ${res.status} ${await res.text()}` };
  }

  const text = await res.text();
  if (!text) {
    // 204 No Content — the assertion (if any) is in a response header.
    const hdr = res.headers.get('x-jwt') || res.headers.get('jwt') || res.headers.get('assertion');
    if (hdr) return { status: 'approved', assertion: hdr };
    return { status: 'error', error: 'submitTransientOtp: 204 No Content with no assertion header' };
  }
  const body = JSON.parse(text) as Record<string, unknown>;
  const assertion = (body['jwt'] ?? body['assertion'] ?? body['accessToken'] ?? body['access_token']) as
    | string
    | undefined;
  if (!assertion) {
    console.warn('[token-exchange] submitTransientOtp: no assertion in response, keys=', Object.keys(body));
    return {
      status: 'error',
      error: `submitTransientOtp: Verify response missing assertion; keys=${Object.keys(body).join(',')}`,
    };
  }
  return { status: 'approved', assertion };
}

/**
 * Mask an email for safe display in a pending-HITL envelope, e.g.
 * "steve@example.com" -> "s•••@example.com". Never sent anywhere as a
 * credential — purely a UI hint so the user knows which inbox to check.
 */
export function maskEmail(email: string): string {
  const at = email.indexOf('@');
  if (at <= 0) return '•••';
  return `${email[0]}•••@${email.slice(at + 1)}`;
}

// ── Top-level exchange ───────────────────────────────────────

/**
 * Perform RFC 8693 token exchange with optional RFC 9396 RAR.
 *
 * Note this does NOT auto-drive the mfa_challenge
 * follow-on — it returns `{ status: 'mfa_challenge', challengeToken }`
 * immediately so the gateway can notify its UI, then separately call
 * triggerOAuthMfaPush / pollOAuthMfaStatus / exchangeMfaAssertionWithRAR.
 *
 * Still handles internally:
 *   - stale-secret signal → narrow invalidate + retry once
 */
export async function exchangeToken(request: TokenExchangeRequest): Promise<TokenExchangeResult> {
  const { subjectToken, scope, authorizationDetails } = request;

  const actor = await getActorToken();

  let exchangeSecret = await getExchangeClientSecret();

  const callTokenEndpoint = async (secret: string): Promise<{ res: Response; body: string }> => {
    const params: Record<string, string> = {
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      client_id: EXCHANGE_CLIENT_ID,
      client_secret: secret,
      subject_token: subjectToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      actor_token: actor.token,
      actor_token_type: actor.tokenType,
      requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      scope,
    };
    if (authorizationDetails && authorizationDetails.length > 0) {
      params.authorization_details = JSON.stringify(authorizationDetails);
    }
    const res = await bindingFetch(`${VERIFY_TENANT_URL}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(params),
    });
    const body = await res.text();
    return { res, body };
  };

  // First attempt
  let { res, body } = await callTokenEndpoint(exchangeSecret);

  // Single-attempt narrow-invalidation retry on stale-secret signal
  if (!res.ok && isStaleSecretError(res.status, body)) {
    invalidateExchangeSecret();
    exchangeSecret = await getExchangeClientSecret();
    ({ res, body } = await callTokenEndpoint(exchangeSecret));
  }

  if (!res.ok) {
    let errorData: any = {};
    try { errorData = JSON.parse(body); } catch { errorData = { error_description: body }; }
    return {
      status: 'error',
      error: errorData.error || 'token_exchange_failed',
      errorDescription: errorData.error_description || body,
    };
  }

  // Parse success body. Verify returns 200 even when MFA is required —
  // detect via tokenData.scope === "mfa_challenge".
  const tokenData = JSON.parse(body);

  if (tokenData.scope === 'mfa_challenge') {
    const challengeToken: string = tokenData.access_token;
    if (!challengeToken) {
      return {
        status: 'error',
        error: 'mfa_challenge_no_token',
        errorDescription: 'Verify returned mfa_challenge with no access_token',
      };
    }

    // Surface the challenge to the caller — do NOT trigger push here. The
    // gateway sequences triggerOAuthMfaPush / pollOAuthMfaStatus /
    // exchangeMfaAssertionWithRAR itself so it can notify its UI between
    // challenge and approval.
    return { status: 'mfa_challenge', challengeToken };
  }

  return {
    status: 'ok',
    accessToken: tokenData.access_token,
    expiresIn: tokenData.expires_in,
    scope: tokenData.scope,
    authorizationDetails: tokenData.authorization_details,
  };
}

// ── Internals ────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
