/**
 * SPIFFE SVID module (Vault-native — no SPIRE) — MCP gateway
 *
 * This workload never talks to a SPIRE agent socket. Instead it bootstraps
 * its own identity straight from HashiCorp Vault:
 *
 *   1. AppRole login (GATEWAY_APPROLE_ROLE_ID / GATEWAY_APPROLE_SECRET_ID)
 *      → POST /v1/auth/approle/login → auth.client_token
 *   2. Mint a JWT-SVID with that token
 *      → POST /v1/spiffe/role/<GATEWAY_SPIFFE_MINT_ROLE>/mintjwt {audience}
 *      → data.token (the raw SVID string)
 *
 * The SVID is cached per-audience in-process and refreshed ~1 minute before
 * it expires. Everything Vault-facing goes through an injectable `deps`
 * object so tests never make a live network call.
 *
 * Environment:
 *   VAULT_ADDR                  — defaults to http://127.0.0.1:8200
 *   GATEWAY_APPROLE_ROLE_ID     — required at runtime; no default (role_id is
 *                                  not secret, but it is deployment-specific)
 *   GATEWAY_APPROLE_SECRET_ID   — required at runtime; no default (secret)
 *   GATEWAY_SPIFFE_MINT_ROLE    — defaults to "mcp-gateway"
 */

const DEFAULT_VAULT_ADDR = 'http://127.0.0.1:8200';
const DEFAULT_MINT_ROLE = 'mcp-gateway';

const REFRESH_BUFFER_MS = 60_000;

export interface SvidDeps {
  /** Injectable fetch — tests pass a mock so no live Vault call is ever made. */
  fetchImpl?: typeof fetch;
  addr?: string;
  roleId?: string;
  secretId?: string;
}

export interface Svid {
  /** The raw JWT-SVID string, as minted by Vault. */
  svid: string;
  /** The `sub` claim decoded from the SVID, e.g. spiffe://gateway.example.com/mcp-gateway */
  spiffeId: string;
  /** The `exp` claim decoded from the SVID, converted to epoch milliseconds. */
  expiresAt: number;
}

// Per-audience SVID cache. Module-level by design — one gateway process,
// one identity per audience it talks to.
const svidCache = new Map<string, Svid>();

/**
 * Reset the module-level SVID cache. For tests only.
 */
export function __resetSvidCacheForTests(): void {
  svidCache.clear();
}

function decodeSvidPayload(svid: string): { sub: string; exp: number } {
  const parts = svid.split('.');
  if (parts.length < 2) {
    throw new Error('Malformed SVID: expected a JWT with at least 2 dot-separated segments');
  }
  const payloadJson = Buffer.from(parts[1], 'base64url').toString('utf8');
  const payload = JSON.parse(payloadJson) as { sub?: unknown; exp?: unknown };
  if (typeof payload.sub !== 'string' || !payload.sub) {
    throw new Error('SVID payload missing "sub" claim');
  }
  if (typeof payload.exp !== 'number') {
    throw new Error('SVID payload missing "exp" claim');
  }
  return { sub: payload.sub, exp: payload.exp };
}

async function loginWithAppRole(
  addr: string,
  roleId: string,
  secretId: string,
  fetchImpl: typeof fetch,
): Promise<string> {
  const res = await fetchImpl(`${addr}/v1/auth/approle/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role_id: roleId, secret_id: secretId }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Vault AppRole login failed (${res.status}): ${body}`);
  }
  const data = (await res.json()) as { auth?: { client_token?: string } };
  const clientToken = data?.auth?.client_token;
  if (!clientToken) {
    throw new Error('No auth.client_token in Vault AppRole login response');
  }
  return clientToken;
}

async function mintSvid(
  addr: string,
  mintRole: string,
  clientToken: string,
  audience: string,
  fetchImpl: typeof fetch,
): Promise<string> {
  const res = await fetchImpl(`${addr}/v1/spiffe/role/${mintRole}/mintjwt`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Vault-Token': clientToken },
    body: JSON.stringify({ audience }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Vault SPIFFE mintjwt failed (${res.status}): ${body}`);
  }
  const data = (await res.json()) as { data?: { token?: string } };
  const svid = data?.data?.token;
  if (!svid) {
    throw new Error('No data.token in Vault mintjwt response');
  }
  return svid;
}

/**
 * Resolve a JWT-SVID for the given audience. Cached per-audience until
 * ~1 minute before expiry, then transparently re-minted.
 *
 * `deps` is injectable (fetchImpl/addr/roleId/secretId) so tests never hit
 * a live Vault. In production, all four default from the environment.
 */
export async function getSvid(audience: string, deps: SvidDeps = {}): Promise<Svid> {
  const cached = svidCache.get(audience);
  if (cached && Date.now() <= cached.expiresAt - REFRESH_BUFFER_MS) {
    return cached;
  }

  const fetchImpl = deps.fetchImpl ?? fetch;
  const addr = deps.addr ?? process.env.VAULT_ADDR ?? DEFAULT_VAULT_ADDR;
  const roleId = deps.roleId ?? process.env.GATEWAY_APPROLE_ROLE_ID;
  const secretId = deps.secretId ?? process.env.GATEWAY_APPROLE_SECRET_ID;
  const mintRole = process.env.GATEWAY_SPIFFE_MINT_ROLE ?? DEFAULT_MINT_ROLE;

  if (!roleId || !secretId) {
    throw new Error(
      'GATEWAY_APPROLE_ROLE_ID and GATEWAY_APPROLE_SECRET_ID are required (set the env vars, or pass deps.roleId/deps.secretId in tests)',
    );
  }

  const clientToken = await loginWithAppRole(addr, roleId, secretId, fetchImpl);
  const svid = await mintSvid(addr, mintRole, clientToken, audience, fetchImpl);
  const { sub, exp } = decodeSvidPayload(svid);

  const result: Svid = {
    svid,
    spiffeId: sub,
    expiresAt: exp * 1000,
  };
  svidCache.set(audience, result);
  return result;
}
