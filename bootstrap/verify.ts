/**
 * bootstrap/verify.ts — IBM Verify tenant bootstrap for the MCP gateway.
 *
 *   npm run bootstrap:verify        (create / update, idempotent)
 *   npm run bootstrap:verify -- --rollback   (delete everything by name)
 *
 * Stands up, on a Verify tenant, everything the gateway's Token-Exchange +
 * RAR + policy-driven HITL chain needs — all GENERATED from the gateway's own
 * config/{tools,rar}.json (via lib/generate.ts) so it can never drift from
 * what the gateway actually sends:
 *
 *   1. Token Exchange app  — RFC 8693 + RFC 9396. tokenExchange + jwtBearer
 *      grants, the SPIFFE actor token type, sendAllKnownUserAttributes, the
 *      authorizeRequestMap/tokenRequestMap/tokenResponseMap that surface
 *      authorization_details as the CELX `authz` context value, a static
 *      agent_id claim, and the registered scopes from tools.json.
 *   2. Agent Identity app  — client_credentials, the actor principal used in
 *      AUTH_METHOD=verify (the SPIFFE-actor fallback).
 *   3. UI app              — OIDC PKCE user sign-in; issues the subject_token,
 *      constrains delegation via a may_act claim.
 *   4. CELX custom attributes — DENY / elevated-read / sensitive-write /
 *      standard-write, POSTed with explicit id == name.
 *   5. Access policy       — DENY -> MFA_ALWAYS -> MFA_ALWAYS -> MFA_PER_SESSION
 *      -> ALLOW, enforcementType under meta, IN opCode — bound to the TE app
 *      via the app-level authPolicy field.
 *
 * WRITE-ONLY SAFETY: authored against a well-documented gotcha list, NOT run
 * live from this repo. Every object is looked up by name/value before write;
 * apps are PUT with the FULL canonical body (never a partial patch) so a
 * re-run cannot leave one half-configured. This script never reads or writes a
 * clientSecret — see the printed summary for where the gateway gets them.
 *
 * Gotchas embodied (all from hard-won production experience):
 *   - list apps under _embedded.applications (wrong key -> silent [])
 *   - sendAllKnownUserAttributes UNDER providers.oidc.properties;
 *     restrictEntitlements a SIBLING of properties
 *   - custom attrs POST with explicit id, and id == name
 *   - access policy enforcementType UNDER meta (top-level silently stripped)
 *   - conditions use IN, never EQ
 *   - bind the policy via the app-level app.authPolicy field, then PUT the
 *     whole app — NOT PUT /v1.0/applications/{id}/authPolicy (empty-body 400s)
 *   - register both record scopes on the TE app (restrictScopes + an
 *     unregistered scope makes policy conditions silently never match)
 */

import {
  loadTools,
  loadRarConfig,
  type ToolsConfig,
  type RarConfig,
} from './lib/config.js';
import {
  generateCelxAttributes,
  generateAccessPolicy,
  toolScopes,
  domainPrefix,
  validateToolRarActions,
  type AttributeDef,
  type AccessPolicy,
} from './lib/generate.js';

// ── Config (env, with generic non-leaky defaults) ─────────────────────────

function reqEnv(name: string): string {
  const v = process.env[name];
  if (!v) {
    console.error(`Error: ${name} is required.`);
    process.exit(1);
  }
  return v;
}

const BASE = (process.env['VERIFY_TENANT_URL'] || '').replace(/\/+$/, '');
if (!BASE) {
  console.error('Error: VERIFY_TENANT_URL is required (e.g. https://your-tenant.verify.ibm.com).');
  process.exit(1);
}
const ADMIN_CLIENT_ID = reqEnv('VERIFY_ADMIN_CLIENT_ID');
const ADMIN_SECRET = reqEnv('VERIFY_ADMIN_SECRET');

// App naming + wiring knobs — all overridable, all generic by default.
const APP_PREFIX = process.env['GATEWAY_APP_PREFIX'] || 'MCP Gateway';
const UI_ORIGIN = (process.env['GATEWAY_UI_ORIGIN'] || 'http://localhost:5173').replace(/\/+$/, '');
const ACTOR_TOKEN_TYPE = process.env['GATEWAY_ACTOR_TOKEN_TYPE'] || 'SPIFFE';
const AGENT_ID_CLAIM = process.env['GATEWAY_AGENT_ID_CLAIM'] || 'mcp-gateway-agent';
const ACTOR_SPIFFE_SUB = process.env['GATEWAY_ACTOR_SPIFFE_SUB'] || 'spiffe://example.org/mcp-gateway';
const COMPANY_NAME = process.env['GATEWAY_COMPANY_NAME'] || 'Example';
// Tenant-specific — leaking a real one would be an internal detail, so these
// are opt-in. Without an identity source the UI login loops at Verify.
const IDENTITY_SOURCE_ID = process.env['VERIFY_IDENTITY_SOURCE_ID'] || '';
const LOGIN_THEME_ID = process.env['VERIFY_LOGIN_THEME_ID'] || '';

const ROLLBACK = process.argv.includes('--rollback');

const APP_NAMES = {
  ui: `${APP_PREFIX} UI`,
  exchange: `${APP_PREFIX} Token Exchange`,
  agent: `${APP_PREFIX} Agent Identity`,
};

const tools: ToolsConfig = loadTools();
const rar: RarConfig = loadRarConfig();
validateToolRarActions(tools, rar); // #2: reject a tools.json ↔ rar.json mismatch before generating anything
const SCOPES = toolScopes(tools); // e.g. ['records:read', 'records:write']
const POLICY_NAME = `${domainPrefix(rar)}-RAR-HITL`;

// ── HTTP helpers ──────────────────────────────────────────────────────────

async function getAdminToken(): Promise<string> {
  const res = await fetch(`${BASE}/v1.0/endpoint/default/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: ADMIN_CLIENT_ID,
      client_secret: ADMIN_SECRET,
    }),
  });
  if (!res.ok) {
    console.error(`admin token failed (${res.status}): ${await res.text()}`);
    process.exit(1);
  }
  return ((await res.json()) as { access_token: string }).access_token;
}

async function api(method: string, path: string, token: string, body?: unknown): Promise<any> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}: ${text.slice(0, 500)}`);
  return text ? JSON.parse(text) : {};
}

// ── Entitlement preflight (Task 6a seed) ──────────────────────────────────
//
// Before mutating anything, probe each admin API family the script writes to.
// On a 403 we FAIL naming the missing entitlement, so a half-provisioned
// tenant is impossible: the admin client either has every grant or the run
// stops before the first write. A 401 anywhere means the admin credentials
// themselves are wrong (fatal, distinct from a missing grant).

interface Preflight {
  family: string;
  method: string;
  path: string;
  entitlement: string;
  required: boolean;
}

const PREFLIGHTS: Preflight[] = [
  { family: 'Applications', method: 'GET', path: '/v1.0/applications?limit=1', entitlement: 'Manage application lifecycle (manageApplications)', required: true },
  { family: 'Attributes', method: 'GET', path: '/v1.0/attributes', entitlement: 'Manage attributes (manageAttributes)', required: true },
  { family: 'Access policies', method: 'GET', path: '/v5.0/policyvault/accesspolicy', entitlement: 'Manage access policies (managePolicies)', required: true },
  { family: 'Groups', method: 'GET', path: '/v2.0/Groups?count=1', entitlement: 'Manage user groups (manageUserGroups) — only needed for the optional group-entitlement fixup', required: false },
];

async function preflightEntitlements(token: string): Promise<void> {
  console.log('[verify] entitlement preflight…');
  const missing: string[] = [];
  const warn: string[] = [];
  for (const p of PREFLIGHTS) {
    const res = await fetch(`${BASE}${p.path}`, {
      method: p.method,
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    });
    if (res.status === 401) {
      console.error('[verify] preflight got 401 — the admin client credentials are invalid (not an entitlement problem).');
      process.exit(1);
    }
    if (res.status === 403) {
      (p.required ? missing : warn).push(`  - ${p.family}: needs "${p.entitlement}"`);
      console.log(`  [DENY] ${p.family} (${res.status})`);
    } else {
      console.log(`  [ok]   ${p.family} (${res.status})`);
    }
  }
  if (warn.length) {
    console.warn('[verify] optional entitlement(s) missing (non-fatal):\n' + warn.join('\n'));
  }
  if (missing.length) {
    console.error(
      '\n[verify] FAILED preflight — the admin client is missing required entitlement(s):\n' +
        missing.join('\n') +
        `\n\nGrant them to admin client ${ADMIN_CLIENT_ID} on the tenant, then re-run. Nothing was created.`,
    );
    process.exit(1);
  }
  console.log('[verify] preflight ok — admin client has every required entitlement.');
}

// ── CELX snippets (app-body plumbing) ─────────────────────────────────────

/** may_act: which actor(s) may act on the signed-in user's behalf — the
 *  SPIFFE actor sub (spiffe mode) AND the Agent Identity clientId (verify
 *  mode). Constrains RFC 8693 delegation. */
function mayActCelx(subs: string[]): string {
  const list = subs.map((s) => `"${s}"`).join(', ');
  return 'statements:\n- return: >-\n   {\n     "sub": [' + list + ']\n   }';
}

/** Static agent_id claim stamped on every OBO. YAML-single-quoted wrapping a
 *  CEL-double-quoted string literal — without this nested escape Verify's CEL
 *  parser reads `mcp-gateway-agent` as subtraction of undeclared identifiers
 *  and the PUT 400s (CSIAQ0344). */
function agentIdCelx(claim: string): string {
  return `statements:\n- return: '"${claim}"'`;
}

// ── App bodies ────────────────────────────────────────────────────────────

function withCustomization(body: Record<string, unknown>): Record<string, unknown> {
  // Theme is an app-level field (sibling of providers), NOT under providers.oidc.
  if (LOGIN_THEME_ID) body['customization'] = { themeId: LOGIN_THEME_ID };
  return body;
}

function buildUiBody(agentClientId: string): Record<string, unknown> {
  return withCustomization({
    name: APP_NAMES.ui,
    templateId: '998',
    providers: {
      saml: { properties: { companyName: COMPANY_NAME } },
      sso: { userOptions: 'oidc' },
      oidc: {
        applicationUrl: UI_ORIGIN,
        properties: {
          grantTypes: {
            authorizationCode: 'true',
            implicit: 'false',
            deviceFlow: 'false',
            ropc: 'false',
            jwtBearer: 'true',
            policyAuth: 'false',
            clientCredentials: 'false',
            tokenExchange: 'false',
          },
          redirectUris: [`${UI_ORIGIN}/api/oidc-callback`, `${UI_ORIGIN}/signin`],
          idTokenSigningAlg: 'RS256',
          accessTokenExpiry: 3600,
          refreshTokenExpiry: 86400,
          doNotGenerateClientSecret: 'false',
          generateRefreshToken: 'false',
          sendAllKnownUserAttributes: 'true',
          consentType: 'dpcm',
          renewRefreshToken: 'true',
          additionalConfig: {
            responseTypes: ['none', 'code'],
            logoutOption: 'none',
            exchangeForSSOSessionOption: 'default',
            clientAuthMethod: 'default',
            actorTokenRequired: false,
            responseModes: ['query', 'fragment', 'form_post'],
            requestObjectParametersOnly: false,
            useUserDefaultEntitlements: true,
            dpopBoundAccessTokens: false,
            oidcv3: true,
            requirePushAuthorize: false,
            validateDPoPProofJti: false,
            certificateBoundAccessTokens: false,
            requestObjectSigningAlg: 'RS256',
            authorizeRspSigningAlg: 'RS256',
            authorizeRspEncryptionEnc: 'none',
            authorizeRspEncryptionAlg: 'none',
            dpopProofSigningAlg: 'RS256',
            requestObjectMaxExpFromNbf: 1800,
            requestObjectRequireExp: true,
            suppressDefaultClaims: false,
          },
          idTokenEncryptAlg: 'none',
          idTokenEncryptEnc: 'none',
        },
        // The two record scopes are registered so the login can request them
        // and they exchange cleanly; restrictScopes is off to avoid the
        // silent-drop trap on any additional scope the customer's UI requests.
        restrictScopes: 'false',
        scopes: SCOPES.map((s) => ({ name: s, description: `Allow the gateway agent to perform ${s} on your behalf` })),
        entitlements: [],
        restrictEntitlements: true,
        grantProperties: { generateDeviceFlowQRCode: 'false' },
        token: {
          accessTokenType: 'jwt',
          attributeMappings: [{ targetName: 'may_act', function: { custom: mayActCelx([ACTOR_SPIFFE_SUB, agentClientId]) } }],
        },
        consentAction: 'always_prompt',
        requirePkceVerification: 'true',
        ...(IDENTITY_SOURCE_ID ? { jwtBearerProperties: { userIdentifier: 'uid', identitySource: IDENTITY_SOURCE_ID } } : {}),
      },
    },
    applicationState: true,
    approvalRequired: false,
    signonState: true,
    identitySources: IDENTITY_SOURCE_ID ? [IDENTITY_SOURCE_ID] : [],
    visibleOnLaunchpad: true,
  });
}

function buildAgentBody(): Record<string, unknown> {
  // The actor principal for AUTH_METHOD=verify: client_credentials only.
  return withCustomization({
    name: APP_NAMES.agent,
    templateId: '998',
    providers: {
      saml: { properties: { companyName: COMPANY_NAME } },
      sso: { userOptions: 'oidc' },
      oidc: {
        properties: {
          grantTypes: {
            authorizationCode: 'false',
            implicit: 'false',
            deviceFlow: 'false',
            ropc: 'false',
            jwtBearer: 'false',
            policyAuth: 'false',
            clientCredentials: 'true',
            tokenExchange: 'false',
          },
          redirectUris: [],
          accessTokenExpiry: 3600,
          doNotGenerateClientSecret: 'false',
          sendAllKnownUserAttributes: 'false',
          consentType: 'never_prompt',
          additionalConfig: {
            clientAuthMethod: 'default',
            oidcv3: true,
            responseTypes: [],
            responseModes: [],
            logoutOption: 'none',
            suppressDefaultClaims: false,
          },
        },
        scopes: [],
        entitlements: [],
        restrictEntitlements: true,
        grantProperties: { generateDeviceFlowQRCode: 'false' },
        token: { accessTokenType: 'jwt' },
        consentAction: 'never_prompt',
        requirePkceVerification: 'false',
      },
    },
    applicationState: true,
    approvalRequired: false,
    signonState: true,
    identitySources: [],
    visibleOnLaunchpad: false,
  });
}

function buildTeBody(uiClientId: string, agentClientId: string, authPolicy?: Record<string, unknown>): Record<string, unknown> {
  const body: Record<string, unknown> = withCustomization({
    name: APP_NAMES.exchange,
    templateId: '998',
    providers: {
      saml: { properties: { companyName: COMPANY_NAME } },
      sso: { userOptions: 'oidc' },
      oidc: {
        properties: {
          grantTypes: {
            authorizationCode: 'false',
            implicit: 'false',
            deviceFlow: 'false',
            ropc: 'false',
            // jwtBearer TRUE: the HITL second leg posts the MFA assertion back
            // with grant_type=jwt-bearer (re-sending authorization_details).
            jwtBearer: 'true',
            policyAuth: 'false',
            clientCredentials: 'false',
            tokenExchange: 'true',
          },
          redirectUris: [],
          idTokenSigningAlg: 'RS256',
          accessTokenExpiry: 3600,
          refreshTokenExpiry: 86400,
          doNotGenerateClientSecret: 'false',
          generateRefreshToken: 'false',
          sendAllKnownUserAttributes: 'true',
          consentType: 'dpcm',
          renewRefreshToken: 'true',
          additionalConfig: {
            requestObjectMaxExpFromNbf: 1800,
            authorizeRspSigningAlg: 'RS256',
            allowedClientAssertionVerificationKeys: [],
            requireConsentAttributeMapClaimNames: [],
            // RAR plumbing — surfaces authorization_details as the CELX `authz`
            // context value the generated attributes read. Load-bearing: do not
            // reshape without matching lib/generate.ts's CELX preamble.
            authorizeRequestMap: [{ name: 'context', custom: 'statements:\n- return: requestContext.authorization_details' }],
            tokenRequestMap: [
              {
                name: 'context',
                custom: '{ "authz": has(requestContext.authorization_details) ? jsonToString(requestContext.authorization_details) : "" }',
              },
            ],
            tokenResponseMap: [
              { name: 'authorization_details', type: 'parameter', custom: 'statements:\n- return: requestContext.authorization_details' },
            ],
            clientAuthMethod: 'default',
            validateDPoPProofJti: false,
            subjectTokenTypes: ['urn:ietf:params:oauth:token-type:access_token'],
            certificateBoundAccessTokens: false,
            requestObjectSigningAlg: 'RS256',
            requestedTokenTypes: ['urn:ietf:params:oauth:token-type:access_token'],
            actorTokenRequired: true,
            responseModes: [],
            requestObjectParametersOnly: false,
            responseTypes: [],
            logoutOption: 'none',
            exchangeForSSOSessionOption: 'default',
            refreshAttributeMapClaimNames: [],
            refreshIntrospectMapClaimNames: [],
            suppressDefaultClaims: false,
            useUserDefaultEntitlements: true,
            dpopBoundAccessTokens: false,
            oidcv3: true,
            requestObjectRequireExp: true,
            authorizeRspEncryptionEnc: 'none',
            dpopProofSigningAlg: 'RS256',
            authorizeRspEncryptionAlg: 'none',
            requirePushAuthorize: false,
            // Both actor types: the SPIFFE JWT-SVID custom type (spiffe mode)
            // and access_token (the Agent Identity client_credentials JWT in
            // verify mode).
            actorTokenTypes: ['urn:ietf:params:oauth:token-type:access_token', ACTOR_TOKEN_TYPE],
            // Clients permitted to perform the exchange: the UI (subject issuer)
            // and the Agent Identity app (verify-mode actor issuer).
            clientGroups: { tokenExchange: [uiClientId, agentClientId] },
          },
          idTokenEncryptAlg: 'none',
          idTokenEncryptEnc: 'none',
        },
        // Exactly the scopes config/tools.json requests — registering both is
        // required or restrictScopes-driven policy conditions silently miss.
        scopes: SCOPES.map((s) => ({ name: s, description: `Gateway scope ${s}` })),
        entitlements: [],
        // restrictEntitlements FALSE is a sibling of `properties` (NOT inside it).
        restrictEntitlements: false,
        grantProperties: { generateDeviceFlowQRCode: 'false' },
        token: {
          accessTokenType: 'jwt',
          audiences: [ACTOR_TOKEN_TYPE, UI_ORIGIN],
          attributeMappings: [{ targetName: 'agent_id', function: { custom: agentIdCelx(AGENT_ID_CLAIM) } }],
        },
        consentAction: 'always_prompt',
        requirePkceVerification: 'true',
      },
    },
    applicationState: true,
    approvalRequired: false,
    signonState: true,
    identitySources: [],
    visibleOnLaunchpad: false,
  });
  // Bind the access policy via the app-level authPolicy field (NOT the
  // PUT /authPolicy sub-resource, which empty-body-400s), then PUT the app.
  if (authPolicy) body['authPolicy'] = authPolicy;
  return body;
}

// ── App upsert ────────────────────────────────────────────────────────────

interface AppResult {
  id: string;
  clientId: string;
}

function extractAppId(app: any): string {
  const href = app?._links?.self?.href || '';
  const m = href.match(/\/applications\/(\d+)/);
  return m ? m[1] : app?.id || '';
}

function extractClientId(app: any): string {
  return app?.providers?.oidc?.clientId || app?.providers?.oidc?.properties?.clientId || '';
}

async function findAppByName(token: string, name: string): Promise<{ id: string; raw: any } | null> {
  const data = await api('GET', '/v1.0/applications?limit=200', token);
  // The list lives under _embedded.applications — the wrong key silently
  // yields [] and reads as "app not found".
  const apps = data._embedded?.applications || (Array.isArray(data) ? data : []);
  const hit = apps.find((a: any) => a.name === name);
  if (!hit) return null;
  const id = extractAppId(hit);
  if (!id) return null;
  return { id, raw: await api('GET', `/v1.0/applications/${id}`, token) };
}

async function upsertApp(token: string, name: string, build: () => Record<string, unknown>): Promise<AppResult> {
  const existing = await findAppByName(token, name);
  const body = build();
  if (existing) {
    await api('PUT', `/v1.0/applications/${existing.id}`, token, body);
    const full = await api('GET', `/v1.0/applications/${existing.id}`, token);
    const clientId = extractClientId(full);
    console.log(`[verify] app "${name}" updated (id ${existing.id}, clientId ${clientId})`);
    return { id: existing.id, clientId };
  }
  const created = await api('POST', '/v1.0/applications', token, body);
  const appId = extractAppId(created);
  if (!appId) throw new Error(`Could not determine app id for "${name}" from POST response`);
  const full = await api('GET', `/v1.0/applications/${appId}`, token);
  const clientId = extractClientId(full);
  console.log(`[verify] app "${name}" created (id ${appId}, clientId ${clientId})`);
  return { id: appId, clientId };
}

async function deleteAppByName(token: string, name: string): Promise<void> {
  const existing = await findAppByName(token, name);
  if (!existing) return;
  await api('DELETE', `/v1.0/applications/${existing.id}`, token);
  console.log(`[verify] app "${name}" deleted (id ${existing.id})`);
}

// ── Custom attributes ─────────────────────────────────────────────────────

async function findAttrByName(token: string, name: string): Promise<{ id: string } | undefined> {
  const resp = await api('GET', '/v1.0/attributes', token).catch(() => null);
  const all = Array.isArray(resp) ? resp : resp?.attributes ?? resp?.response?.attributes ?? [];
  return all.find((a: any) => a.name === name);
}

async function upsertAttribute(token: string, def: AttributeDef): Promise<void> {
  const existing = await findAttrByName(token, def.name);
  if (existing?.id) {
    await api('PUT', `/v1.0/attributes/${existing.id}`, token, def);
    console.log(`[verify] attribute ${def.name} updated (id ${existing.id})`);
  } else {
    // POST with explicit id (== name) so policy conditions never point at a
    // dead auto-generated UUID after a rename.
    const created = await api('POST', '/v1.0/attributes', token, def);
    console.log(`[verify] attribute ${def.name} created (id ${created.id ?? def.id})`);
  }
}

// ── Access policy ─────────────────────────────────────────────────────────

async function upsertAccessPolicy(token: string, body: AccessPolicy): Promise<string> {
  const existing = await api('GET', `/v5.0/policyvault/accesspolicy?search=name="${POLICY_NAME}"`, token).catch(() => null);
  const list = (existing as { policies?: Array<{ id: string }> })?.policies || [];
  let policyId: string;
  if (list[0]?.id) {
    await api('PUT', `/v5.0/policyvault/accesspolicy/${list[0].id}`, token, body);
    policyId = list[0].id;
    console.log(`[verify] policy ${POLICY_NAME} updated (id ${policyId})`);
  } else {
    const created = await api('POST', '/v5.0/policyvault/accesspolicy', token, body);
    policyId = created.id;
    console.log(`[verify] policy ${POLICY_NAME} created (id ${policyId})`);
  }
  // Read back: a silently-stripped top-level enforcementType is the #1 way this
  // kind of policy lands ACTIVE but never evaluates.
  const live = await api('GET', `/v5.0/policyvault/accesspolicy/${policyId}`, token);
  if (live?.meta?.state === 'ACTIVE' && live?.meta?.enforcementType === 'fedSSO') {
    console.log(`[verify] policy ${POLICY_NAME} confirmed ACTIVE / fedSSO`);
  } else {
    console.warn(
      `[verify] WARNING: policy ${POLICY_NAME} landed state=${live?.meta?.state} enforcementType=${live?.meta?.enforcementType} ` +
        '(expected ACTIVE/fedSSO). Open it in the Admin UI and Save+Publish once before trusting it live.',
    );
  }
  return policyId;
}

// ── main ──────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log('══════════════════════════════════════════════════');
  console.log('  MCP Gateway — Verify Tenant Bootstrap');
  console.log(`  Tenant: ${BASE}`);
  console.log(`  Mode:   ${ROLLBACK ? 'ROLLBACK' : 'CREATE/UPDATE (idempotent)'}`);
  console.log('══════════════════════════════════════════════════');

  const token = await getAdminToken();
  console.log('[verify] admin token acquired');

  const attributes = generateCelxAttributes(tools, rar);
  const policy = generateAccessPolicy(tools, rar);

  if (ROLLBACK) {
    await deleteAppByName(token, APP_NAMES.exchange);
    await deleteAppByName(token, APP_NAMES.agent);
    await deleteAppByName(token, APP_NAMES.ui);
    const existingPolicy = await api('GET', `/v5.0/policyvault/accesspolicy?search=name="${POLICY_NAME}"`, token).catch(() => null);
    for (const p of existingPolicy?.policies || []) {
      await api('DELETE', `/v5.0/policyvault/accesspolicy/${p.id}`, token);
      console.log(`[verify] policy ${POLICY_NAME} deleted (id ${p.id})`);
    }
    for (const def of attributes) {
      const existing = await findAttrByName(token, def.name);
      if (existing?.id) {
        await api('DELETE', `/v1.0/attributes/${existing.id}`, token);
        console.log(`[verify] attribute ${def.name} deleted (id ${existing.id})`);
      }
    }
    console.log('\n[verify] rollback complete.');
    return;
  }

  await preflightEntitlements(token);

  // 1. Agent Identity (its clientId feeds may_act + clientGroups).
  const agentApp = await upsertApp(token, APP_NAMES.agent, buildAgentBody);
  // 2. UI (may_act constrains delegation to the SPIFFE sub + agent clientId).
  const uiApp = await upsertApp(token, APP_NAMES.ui, () => buildUiBody(agentApp.clientId));
  // 3. Token Exchange (clientGroups needs both peer clientIds).
  const teApp = await upsertApp(token, APP_NAMES.exchange, () => buildTeBody(uiApp.clientId, agentApp.clientId));

  // 4. Custom attributes.
  for (const def of attributes) await upsertAttribute(token, def);

  // 5. Access policy + bind to the TE app via the app-level authPolicy field.
  const policyId = await upsertAccessPolicy(token, policy);
  await upsertApp(token, APP_NAMES.exchange, () =>
    buildTeBody(uiApp.clientId, agentApp.clientId, {
      id: policyId,
      name: POLICY_NAME,
      grantTypes: [{ tokenExchange: true }],
    }),
  );
  const boundApp = await api('GET', `/v1.0/applications/${teApp.id}`, token);
  if (boundApp?.authPolicy?.id === policyId) {
    console.log(`[verify] ${APP_NAMES.exchange} — authPolicy bound to ${POLICY_NAME} (${policyId})`);
  } else {
    console.warn(
      `[verify] WARNING: could not confirm authPolicy bind (app.authPolicy.id=${boundApp?.authPolicy?.id ?? '(none)'}, expected ${policyId}). ` +
        'Bind manually: Admin UI -> Applications -> Token Exchange -> Sign-on -> Authentication policy.',
    );
  }

  // ── Summary ──────────────────────────────────────────────────────────────
  console.log('\n══════════════════════════════════════════════════');
  console.log('  BOOTSTRAP COMPLETE — set these in the gateway .env');
  console.log('══════════════════════════════════════════════════');
  console.log(`VERIFY_TENANT_URL=${BASE}`);
  console.log(`GATEWAY_EXCHANGE_CLIENT_ID=${teApp.clientId}`);
  console.log(`GATEWAY_AGENT_CLIENT_ID=${agentApp.clientId}`);
  console.log(`GATEWAY_ACTOR_TOKEN_TYPE=${ACTOR_TOKEN_TYPE}`);
  console.log('# UI login client (for your own sign-in UI):');
  console.log(`#   ${APP_NAMES.ui} clientId=${uiApp.clientId}`);
  console.log('\n# Client SECRETS are NOT printed (GET rarely returns them, and a PUT can');
  console.log('# regenerate them). Get GATEWAY_EXCHANGE_CLIENT_SECRET + GATEWAY_AGENT_CLIENT_SECRET');
  console.log('# from the Admin console (App -> Sign-on -> Client secret), OR read them live via');
  console.log('# the Vault ibm-verify plugin (SECRETS_BACKEND=vault) so nothing sits on disk.');

  console.log('\n── IDs created ────────────────────────────────────');
  console.log(`UI app:             id=${uiApp.id}  clientId=${uiApp.clientId}`);
  console.log(`Token Exchange app: id=${teApp.id}  clientId=${teApp.clientId}`);
  console.log(`Agent Identity app: id=${agentApp.id}  clientId=${agentApp.clientId}`);
  console.log(`Access policy:      ${POLICY_NAME} (id ${policyId})`);
  console.log(`CELX attributes:    ${attributes.map((a) => a.name).join(', ')}`);
  console.log(`Registered scopes:  ${SCOPES.join(', ')}`);

  console.log('\n── Feeds bootstrap:vault ──────────────────────────');
  console.log(`GATEWAY_AGENT_ID_CLAIM=${AGENT_ID_CLAIM}   # oauth-rs SUBJECT entity external_id`);
  console.log(`GATEWAY_ACTOR_SPIFFE_SUB=${ACTOR_SPIFFE_SUB}   # oauth-rs ACTOR entity external_id (spiffe mode)`);

  console.log('\n── Still open (NOT done by this script) ───────────');
  if (!IDENTITY_SOURCE_ID) {
    console.log('1. VERIFY_IDENTITY_SOURCE_ID was not set — the UI app has NO identity source, so');
    console.log('   sign-in will loop at Verify. Set it and re-run, or enable a source on the UI');
    console.log("   app's Sign-on tab in the Admin console.");
  }
  console.log('2. SPIFFE actor-token trust: a Vault-native JWT-SVID is not internet-reachable, so');
  console.log(`   Verify must validate the "${ACTOR_TOKEN_TYPE}" actor token by a STATICALLY configured`);
  console.log('   JWKS (the Vault trust_bundle) + issuer — configure that on the tenant, then prove');
  console.log('   one exchange. (Or run AUTH_METHOD=verify, which uses the Agent Identity app instead.)');
  console.log('══════════════════════════════════════════════════');
}

main().catch((err) => {
  console.error('\nFATAL:', (err as Error).message);
  process.exit(1);
});
