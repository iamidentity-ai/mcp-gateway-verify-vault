/**
 * Tests for vault/mint.ts — the OBO-as-X-Vault-Token Vault-POST half.
 *
 * The caller (a later pipeline task) already holds the OBO — this module
 * does NOT do token exchange. It only POSTs the OBO as X-Vault-Token to
 * verify-rar/creds/<role> and parses the minted credential.
 *
 * Coverage:
 *   - mintCred POSTs to /v1/<credsPath>, X-Vault-Token == the OBO, body
 *     carries claims.jti (from the OBO's own jti, or a synthesized one for
 *     an opaque token) + claims.authorization_details
 *   - mintCred returns { username, password, leaseId }
 *   - mintCred throws on non-ok Vault response
 *   - mintCred throws when the Vault response is missing
 *     username/password/lease_id
 *   - revokeLease PUTs to /v1/sys/leases/revoke with the leaseId + token
 *   - revokeLease swallows a failing fetch (best-effort, never throws)
 *   - revokeLease swallows a non-OK Vault response (best-effort)
 */
import { describe, it, expect, vi } from 'vitest';
import { SignJWT } from 'jose';
import { mintCred, revokeLease } from './mint.js';
import type { AuthorizationDetail } from '../rar/build-rar.js';

const AUTHZ_DETAILS: AuthorizationDetail[] = [
  {
    type: 'urn:example:agent:records',
    operationDetails: { action: 'record_read', subaction: 'record_read' },
  },
  {
    type: 'vault:path_access',
    path_constraint: 'verify-rar/creds/records',
    action: 'update',
    path: 'verify-rar/creds/records',
    capabilities: ['update'],
  },
  {
    type: 'vault:path_access',
    path_constraint: 'sys/leases/revoke',
    action: 'update',
    path: 'sys/leases/revoke',
    capabilities: ['update'],
  },
];

async function realJwtObo(jti: string): Promise<string> {
  const secret = new TextEncoder().encode('test-signing-secret-does-not-matter');
  return new SignJWT({})
    .setProtectedHeader({ alg: 'HS256' })
    .setJti(jti)
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(secret);
}

function vaultMintResponse(): Response {
  return new Response(
    JSON.stringify({
      lease_id: 'verify-rar/creds/records/abc123',
      lease_duration: 300,
      renewable: true,
      data: {
        username: 'v-records-abcdef',
        password: 'p4ssw0rd-r0tat3d',
      },
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
}

describe('mintCred', () => {
  it('POSTs the OBO as X-Vault-Token to /v1/<credsPath> with claims.jti + claims.authorization_details, returns username/password/leaseId', async () => {
    const obo = await realJwtObo('jti-real-123');
    const fetchMock = vi.fn<typeof fetch>(async () => vaultMintResponse());

    const cred = await mintCred(
      { obo, authorizationDetails: AUTHZ_DETAILS, credsPath: 'verify-rar/creds/records' },
      { fetchImpl: fetchMock, vaultAddr: 'https://vault.test' },
    );

    expect(cred.username).toBe('v-records-abcdef');
    expect(cred.password).toBe('p4ssw0rd-r0tat3d');
    expect(cred.leaseId).toBe('verify-rar/creds/records/abc123');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://vault.test/v1/verify-rar/creds/records');
    expect(init.method).toBe('POST');

    const headers = init.headers as Record<string, string>;
    expect(headers['X-Vault-Token']).toBe(obo);
    expect(headers['Content-Type']).toBe('application/json');

    const body = JSON.parse(init.body as string);
    expect(body.claims.jti).toBe('jti-real-123');
    expect(body.claims.authorization_details).toEqual(AUTHZ_DETAILS);
  });

  it('synthesizes a jti when the OBO is opaque (not a real JWT)', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => vaultMintResponse());

    await mintCred(
      { obo: 'opaque-not-a-jwt', authorizationDetails: AUTHZ_DETAILS, credsPath: 'verify-rar/creds/records' },
      { fetchImpl: fetchMock, vaultAddr: 'https://vault.test' },
    );

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string);
    // Synthesized (randomUUID) jti — just assert it's a non-empty UUID shape,
    // not the literal opaque token.
    expect(typeof body.claims.jti).toBe('string');
    expect(body.claims.jti.length).toBeGreaterThan(0);
    expect(body.claims.jti).toMatch(/^[0-9a-f-]{36}$/i);
  });

  it('uses the credsPath the caller passed in (elevated / write role routing lives in build-rar, not here)', async () => {
    const obo = await realJwtObo('jti-elevated');
    const fetchMock = vi.fn<typeof fetch>(async () => vaultMintResponse());

    await mintCred(
      { obo, authorizationDetails: AUTHZ_DETAILS, credsPath: 'verify-rar/creds/records-elevated' },
      { fetchImpl: fetchMock, vaultAddr: 'https://vault.test' },
    );

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://vault.test/v1/verify-rar/creds/records-elevated');
  });

  it('throws when Vault returns non-ok, including status + body excerpt', async () => {
    const obo = await realJwtObo('jti-err');
    const fetchMock = vi.fn<typeof fetch>(
      async () =>
        new Response(
          JSON.stringify({ errors: ['1 error occurred:\n\t* RAR action mismatch\n\n'] }),
          { status: 403, headers: { 'Content-Type': 'application/json' } },
        ),
    );

    await expect(
      mintCred(
        { obo, authorizationDetails: AUTHZ_DETAILS, credsPath: 'verify-rar/creds/records' },
        { fetchImpl: fetchMock, vaultAddr: 'https://vault.test' },
      ),
    ).rejects.toThrow(/verify-rar mint failed \(403\).*RAR action mismatch/);
  });

  it('throws when the Vault response is missing username/password/lease_id', async () => {
    const obo = await realJwtObo('jti-missing');
    const fetchMock = vi.fn<typeof fetch>(
      async () =>
        new Response(JSON.stringify({ data: {} }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
    );

    await expect(
      mintCred(
        { obo, authorizationDetails: AUTHZ_DETAILS, credsPath: 'verify-rar/creds/records' },
        { fetchImpl: fetchMock, vaultAddr: 'https://vault.test' },
      ),
    ).rejects.toThrow(/verify-rar mint response missing/);
  });

  it('SECURITY: a partial mint response (password present, lease_id absent) must NOT leak the password into the thrown error', async () => {
    const obo = await realJwtObo('jti-partial');
    const secretPassword = 'p4ssw0rd-must-not-leak';
    const fetchMock = vi.fn<typeof fetch>(
      async () =>
        // Abnormal Vault response: a live username+password but no lease_id.
        new Response(JSON.stringify({ data: { username: 'v-records-x', password: secretPassword } }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
    );

    const err = await mintCred(
      { obo, authorizationDetails: AUTHZ_DETAILS, credsPath: 'verify-rar/creds/records' },
      { fetchImpl: fetchMock, vaultAddr: 'https://vault.test' },
    ).catch((e: Error) => e);

    expect(err).toBeInstanceOf(Error);
    // It still names WHAT is missing (booleans), so operators can diagnose...
    expect((err as Error).message).toMatch(/verify-rar mint response missing/);
    expect((err as Error).message).toContain('lease_id:false');
    // ...but the live credential value must never appear in the message.
    expect((err as Error).message).not.toContain(secretPassword);
  });

  it('defaults vaultAddr to VAULT_ADDR / the local-dev default when no override is passed', async () => {
    const obo = await realJwtObo('jti-default-addr');
    const fetchMock = vi.fn<typeof fetch>(async () => vaultMintResponse());

    await mintCred(
      { obo, authorizationDetails: AUTHZ_DETAILS, credsPath: 'verify-rar/creds/records' },
      { fetchImpl: fetchMock },
    );

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url.startsWith('http://127.0.0.1:8200/v1/')).toBe(true);
  });
});

describe('revokeLease', () => {
  it('PUTs to /v1/sys/leases/revoke with the leaseId and vault token', async () => {
    const fetchImpl = vi.fn<typeof fetch>(
      async () => new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
    );

    await revokeLease('verify-rar/creds/records/abc123', 'vault-client-token', {
      fetchImpl,
      vaultAddr: 'https://vault.test',
    });

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://vault.test/v1/sys/leases/revoke');
    expect(init.method).toBe('PUT');
    const headers = init.headers as Record<string, string>;
    expect(headers['X-Vault-Token']).toBe('vault-client-token');
    expect(JSON.parse(init.body as string)).toEqual({
      lease_id: 'verify-rar/creds/records/abc123',
    });
  });

  it('does NOT throw when fetch rejects (best-effort) and REPORTS false', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error('network down');
    });
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => { });

    // Swallow-don't-throw is the load-bearing contract (pipeline.ts calls this
    // from a `finally`). Reporting the outcome is what lets `_diagnostic
    // .credRevoked` be honest instead of decorative — a failed revoke must
    // surface as false, never as a missing signal a UI can render as "revoked".
    await expect(
      revokeLease('lease-abc', 'tok', { fetchImpl, vaultAddr: 'https://v' }),
    ).resolves.toBe(false);

    expect(warnSpy).toHaveBeenCalled();
    warnSpy.mockRestore();
  });

  it('does NOT throw on a non-OK Vault response (best-effort) and REPORTS false', async () => {
    const fetchImpl = vi.fn(
      async () =>
        new Response(JSON.stringify({ errors: ['bad lease id'] }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        }),
    );
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => { });

    await expect(
      revokeLease('lease-bad', 'tok', { fetchImpl, vaultAddr: 'https://v' }),
    ).resolves.toBe(false);

    expect(warnSpy).toHaveBeenCalled();
    warnSpy.mockRestore();
  });

  it('treats 200 OK as success without warning and REPORTS true', async () => {
    const fetchImpl = vi.fn(
      async () => new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
    );
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => { });

    await expect(
      revokeLease('lease-ok', 'tok', { fetchImpl, vaultAddr: 'https://v' }),
    ).resolves.toBe(true);

    expect(warnSpy).not.toHaveBeenCalled();
    warnSpy.mockRestore();
  });
});
