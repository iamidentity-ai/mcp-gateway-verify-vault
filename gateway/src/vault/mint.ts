/**
 * verify-rar Vault mint + revoke — MCP gateway
 *
 * This is the Vault-POST HALF of the flow only. Token Exchange (RFC 8693)
 * happens elsewhere (`../auth/token-exchange.ts`) — by the time this module
 * is called, the caller already holds a scoped OBO carrying the RAR
 * (`authorization_details`) that Verify minted. This module presents that
 * OBO to Vault as `X-Vault-Token`:
 *
 *   POST ${VAULT_ADDR}/v1/<credsPath>
 *     X-Vault-Token: <obo>
 *     { claims: { jti, authorization_details } }
 *
 * Vault's OAuth-RS profile validates the OBO against the tenant JWKS,
 * resolves the agent entity, and the verify-rar plugin matches the
 * `authorization_details` in the body against the role's `rar_mappings`
 * before minting an ephemeral Postgres credential.
 *
 * There is deliberately NO token-exchange leg here — the gateway's caller
 * already did that step and passes the OBO straight in.
 */

import { decodeJwt } from 'jose';
import { randomUUID } from 'node:crypto';
import type { AuthorizationDetail } from '../rar/build-rar.js';

const VAULT_ADDR =
  process.env.VAULT_ADDR ?? process.env.VAULT_BASE_URI ?? 'http://127.0.0.1:8200';

// ── mintCred ──────────────────────────────────────────────────

export interface MintCredArgs {
  /** The scoped OBO from Token Exchange — presented to Vault as X-Vault-Token. */
  obo: string;
  /** RFC 9396 authorization_details already minted into (and re-sent alongside) the OBO. */
  authorizationDetails: AuthorizationDetail[];
  /** verify-rar creds path, e.g. "verify-rar/creds/records" — from build-rar's vaultCredsPath(). */
  credsPath: string;
}

export interface VaultFetchDeps {
  /** Override fetch impl (tests). */
  fetchImpl?: typeof fetch;
  /** Override Vault address (tests). */
  vaultAddr?: string;
}

export interface MintedCred {
  username: string;
  password: string;
  leaseId: string;
}

/**
 * POST the OBO as X-Vault-Token to verify-rar/creds/<role>, parse the
 * minted Postgres credential. Throws on a non-ok Vault response or on a
 * response missing data.username / data.password / lease_id.
 */
export async function mintCred(args: MintCredArgs, deps: VaultFetchDeps = {}): Promise<MintedCred> {
  const f = deps.fetchImpl ?? fetch;
  const addr = deps.vaultAddr ?? VAULT_ADDR;

  // The verify-rar plugin expects the claims in the body even though the
  // OBO is also presented as X-Vault-Token. Extract jti from the OBO when
  // it's a real JWT; synthesize a UUID otherwise (opaque token).
  let jti = '';
  try {
    const decoded = decodeJwt(args.obo);
    if (typeof decoded.jti === 'string' && decoded.jti) jti = decoded.jti;
  } catch {
    // OBO was opaque — synthesize. The plugin only requires jti to be
    // present and non-empty; uniqueness is the guarantee that matters.
  }
  if (!jti) jti = randomUUID();

  const vaultUrl = `${addr}/v1/${args.credsPath}`;
  // POST not GET — Vault's HTTP layer doesn't deserialize JSON bodies on
  // GET, and the plugin registers pathCredsRead for both Read AND Update.
  // Workload calls go through Update (ie POST).
  const res = await f(vaultUrl, {
    method: 'POST',
    headers: {
      'X-Vault-Token': args.obo,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      claims: {
        jti,
        authorization_details: args.authorizationDetails,
      },
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(
      `verify-rar mint failed (${res.status}) at ${args.credsPath}: ${text.slice(0, 300)}`,
    );
  }

  const body = (await res.json()) as {
    lease_id?: string;
    lease_duration?: number;
    data?: { username?: string; password?: string };
  };

  const username = body?.data?.username;
  const password = body?.data?.password;
  const leaseId = body?.lease_id;
  if (!username || !password || !leaseId) {
    // Report WHICH fields are missing as booleans — NEVER serialize the Vault
    // response body into the error, because on a partial response it can carry
    // the live ephemeral Postgres password (which would then reach logs and,
    // via the route error handlers, the client).
    throw new Error(
      `verify-rar mint response missing required fields (username:${!!username} password:${!!password} lease_id:${!!leaseId})`,
    );
  }

  return { username, password, leaseId };
}

// ── revokeLease ───────────────────────────────────────────────

/**
 * Best-effort early revocation of a verify-rar lease. PUTs to
 * /v1/sys/leases/revoke with the leaseId. Vault fires the plugin's
 * secretCredsRevoke callback which drops the Postgres role.
 *
 * Swallows fetch errors and non-OK responses — the lease will still expire
 * on TTL anyway; manual revoke is a cleanup nicety, not a security boundary.
 * That swallow-don't-throw contract is LOAD-BEARING: pipeline.ts calls this
 * from a `finally`, so a throw here would mask the real upstream error.
 *
 * REPORTS its outcome instead of discarding it: `true` when Vault accepted the
 * revoke, `false` when it did not (non-OK response or a transport failure).
 * The pipeline surfaces that as `_diagnostic.credRevoked` so a UI can show
 * that the ephemeral credential really is gone — and, just as importantly,
 * show `false` when it is NOT. A caller that ignores the return value gets
 * exactly the previous behaviour.
 */
export async function revokeLease(
  leaseId: string,
  vaultToken: string,
  deps: VaultFetchDeps = {},
): Promise<boolean> {
  const f = deps.fetchImpl ?? fetch;
  const addr = deps.vaultAddr ?? VAULT_ADDR;
  try {
    const res = await f(`${addr}/v1/sys/leases/revoke`, {
      method: 'PUT',
      headers: {
        'X-Vault-Token': vaultToken,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ lease_id: leaseId }),
    });
    if (!res.ok && res.status !== 204) {
      const text = await res.text().catch(() => '');
      console.warn(
        `[vault/mint] revokeLease non-OK (${res.status}) for ${leaseId}: ${text.slice(0, 200)}`,
      );
      return false;
    }
    return true;
  } catch (err) {
    console.warn('[vault/mint] revokeLease best-effort failed:', (err as Error).message);
    return false;
  }
}
