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
 * Environment:
 *   VERIFY_TENANT_URL — your IBM Verify tenant base URL
 */

const VERIFY_TENANT_URL = process.env.VERIFY_TENANT_URL || 'https://tenant.verify.ibm.com';

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
}

/**
 * GET /oauth2/userinfo with the caller's bearer.
 *   200 -> { active: true, verifyUserId: <sub>, email: <email> }
 *   anything else (401, network error, ...) -> { active: false }
 *
 * Never throws — a network failure or non-200 is treated the same as an
 * inactive session so callers can fail closed without a try/catch of their
 * own.
 */
export async function introspectUser(token: string, deps: IntrospectDeps = {}): Promise<IntrospectResult> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const tenantUrl = deps.tenantUrl ?? VERIFY_TENANT_URL;

  try {
    const res = await fetchImpl(`${tenantUrl}/oauth2/userinfo`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (res.status !== 200) {
      return { active: false };
    }

    const data = (await res.json()) as Record<string, unknown>;
    return {
      active: true,
      verifyUserId: typeof data['sub'] === 'string' ? (data['sub'] as string) : undefined,
      email: typeof data['email'] === 'string' ? (data['email'] as string) : undefined,
    };
  } catch {
    // Network / TLS error reaching Verify — fail closed, same as a 401.
    return { active: false };
  }
}
