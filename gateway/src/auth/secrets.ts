/**
 * Verify client-secret seam — MCP gateway
 *
 * The gateway authenticates to IBM Verify's /oauth2/token endpoint with two
 * OAuth client secrets: the Token-Exchange app's secret (every exchange) and,
 * only under AUTH_METHOD=verify, the agent identity app's secret (the actor
 * client_credentials grant). This module is the ONE place the rest of the
 * code asks for those secrets — it dispatches on SECRETS_BACKEND so how they
 * are stored is a config choice, not a code change.
 *
 *   SECRETS_BACKEND=env  (DEFAULT — the drop-in / local-evaluation posture)
 *     Reads GATEWAY_EXCHANGE_CLIENT_SECRET / GATEWAY_AGENT_CLIENT_SECRET from
 *     the process environment. A missing var throws a named MissingSecretError
 *     naming the exact variable. invalidate*() is a no-op — an env value never
 *     rotates mid-process, so a stale-secret retry just re-reads the same
 *     value (harmless: the retry ladder in token-exchange.ts / pipeline.ts
 *     still runs, it simply won't help, which is correct for a static secret).
 *
 *   SECRETS_BACKEND=vault  (RECOMMENDED for production — see
 *     docs/guides/secrets.md)
 *     Delegates UNCHANGED to auth/vault-secret.ts: reads the secret from the
 *     IBM Verify Vault plugin role (ibm-verify/creds/<role>), which rotates
 *     the client_secret on every read. invalidate*() drops that one role's
 *     cache so the next read fetches a fresh secret (the CSIAQ0155E
 *     single-retry pattern).
 *
 * SECRETS_BACKEND scopes ONLY these two Verify client secrets. Vault is still
 * used regardless for the verify-rar ephemeral Postgres credential (OBO as
 * X-Vault-Token) and, under AUTH_METHOD=spiffe, for the actor JWT-SVID — so
 * "env mode" does not mean "no Vault".
 *
 * Environment:
 *   SECRETS_BACKEND               — "env" (default) or "vault"
 *   GATEWAY_EXCHANGE_CLIENT_SECRET — exchange app secret (env mode only)
 *   GATEWAY_AGENT_CLIENT_SECRET    — agent app secret (env mode, AUTH_METHOD=verify)
 *   GATEWAY_EXCHANGE_ROLE          — Vault plugin role for the exchange secret
 *                                     (vault mode; default "gateway-exchange")
 *   GATEWAY_AGENT_ROLE             — Vault plugin role for the agent secret
 *                                     (vault mode; default "gateway-agent")
 */

import { getPluginSecret, invalidatePluginSecret } from './vault-secret.js';

export type SecretsBackend = 'env' | 'vault';

const EXCHANGE_ENV_VAR = 'GATEWAY_EXCHANGE_CLIENT_SECRET';
const AGENT_ENV_VAR = 'GATEWAY_AGENT_CLIENT_SECRET';

/** Thrown when a required secret is absent in the active backend. Named so a
 *  startup/first-request failure is grep-ably "MissingSecretError: ...". */
export class MissingSecretError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MissingSecretError';
  }
}

/** Thrown when SECRETS_BACKEND is set to something other than env|vault. */
export class SecretsConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SecretsConfigError';
  }
}

/**
 * Resolve the active backend. Read at call time (not module load) so the
 * mode is honoured after dotenv config and so tests can flip it per case.
 * Defaults to 'env' — the drop-in posture.
 */
export function secretsBackend(): SecretsBackend {
  const raw = (process.env.SECRETS_BACKEND ?? 'env').toLowerCase();
  if (raw !== 'env' && raw !== 'vault') {
    throw new SecretsConfigError(
      `SECRETS_BACKEND must be "env" or "vault" (got "${process.env.SECRETS_BACKEND}")`,
    );
  }
  return raw;
}

// Vault plugin role names (vault mode only). Defaults match token-exchange.ts's
// historical GATEWAY_EXCHANGE_ROLE / GATEWAY_AGENT_ROLE constants.
function exchangeRole(): string {
  return process.env.GATEWAY_EXCHANGE_ROLE || 'gateway-exchange';
}
function agentRole(): string {
  return process.env.GATEWAY_AGENT_ROLE || 'gateway-agent';
}

function readEnvSecret(varName: string): string {
  const value = process.env[varName];
  if (!value) {
    throw new MissingSecretError(
      `${varName} is not set. In SECRETS_BACKEND=env mode the gateway reads this Verify ` +
        `client secret from the environment — set ${varName}, or switch to SECRETS_BACKEND=vault ` +
        `(see docs/guides/secrets.md).`,
    );
  }
  return value;
}

// ── Exchange app secret ──────────────────────────────────────

export async function getExchangeClientSecret(): Promise<string> {
  if (secretsBackend() === 'vault') return getPluginSecret(exchangeRole());
  return readEnvSecret(EXCHANGE_ENV_VAR);
}

export function invalidateExchangeSecret(): void {
  // env mode: a static env value never rotates — invalidation is a no-op.
  if (secretsBackend() === 'vault') invalidatePluginSecret(exchangeRole());
}

// ── Agent app secret (AUTH_METHOD=verify only) ───────────────

export async function getAgentClientSecret(): Promise<string> {
  if (secretsBackend() === 'vault') return getPluginSecret(agentRole());
  return readEnvSecret(AGENT_ENV_VAR);
}

export function invalidateAgentSecret(): void {
  if (secretsBackend() === 'vault') invalidatePluginSecret(agentRole());
}
