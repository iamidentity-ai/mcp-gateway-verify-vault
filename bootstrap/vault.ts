/**
 * bootstrap/vault.ts — HashiCorp Vault bootstrap for the MCP gateway.
 *
 *   npm run bootstrap:vault
 *
 * Idempotent against a Vault with the verify-rar plugin + OAuth-Resource-Server
 * profile ("Path Y"). Creates, all GENERATED from config/rar.json:
 *
 *   1. verify-rar roles — one per non-blocked creds path. rar_mappings keyed
 *      "<rarType>|<action>" -> GRANT the pre-baked Postgres role (records_read
 *      / records_write from examples/db/vault-roles.sql). 5-minute lease.
 *   2. A runtime ACL policy granting read+update on every verify-rar/creds/*
 *      path + update on sys/leases/revoke.
 *   3. The TWO OAuth-RS entities the OBO resolves against:
 *        SUBJECT — external_id = the agent_id claim the TE app stamps on every
 *                  OBO (user_claim=agent_id: ONE entity covers ALL users).
 *        ACTOR  — external_id = the OBO's act.sub (the SPIFFE SVID sub in
 *                  spiffe mode, or the Agent Identity clientId in verify mode).
 *      Both attached to the runtime policy + registered in agent-registry.
 *   4. (optional, --with-ibm-verify) ibm-verify plugin roles that rotate the
 *      TE/agent client secrets for SECRETS_BACKEND=vault.
 *
 * IMMUTABILITY: an entity-alias's external_id AND issuer are immutable after
 * creation — they must be right in the POST body; a later change needs
 * delete+recreate. This script therefore skips an alias that already exists on
 * the mount rather than trying to patch it.
 *
 * WRITE-ONLY SAFETY: authored against the documented Path Y recipe, not run
 * live from this repo. A real run (Task 7) confirms the mount accessor + issuer.
 *
 * SPIFFE note: this configures the OAuth-RS "OBO-as-X-Vault-Token" path. The
 * separate Vault-native SPIFFE issuer+validator loop (spiffe secrets + auth
 * engines) that mints the gateway's ACTOR SVID in AUTH_METHOD=spiffe is a
 * distinct, licensed feature — see docs/guides + the .env SPIFFE section; it is
 * intentionally NOT provisioned here.
 */

import { loadRarConfig, loadTools, type RarConfig } from './lib/config.js';
import { generateVaultRoles, generateRuntimePolicyHcl, domainSlug } from './lib/generate.js';

// ── Config ────────────────────────────────────────────────────────────────

const VAULT_ADDR = (process.env['VAULT_ADDR'] || 'http://127.0.0.1:8200').replace(/\/+$/, '');
const VAULT_TOKEN = process.env['VAULT_TOKEN'];
if (!VAULT_TOKEN) {
  console.error('Error: VAULT_TOKEN is required (a token allowed to write verify-rar roles, ACL policies, and identity entities).');
  process.exit(1);
}

const rar: RarConfig = loadRarConfig();
const SLUG = domainSlug(rar);

const DB_NAME = process.env['VAULT_RAR_DB_NAME'] || SLUG; // db_name on the verify-rar roles
const RUNTIME_POLICY = process.env['VAULT_RUNTIME_POLICY'] || `${SLUG}-gateway`;
const SUBJECT_ENTITY = process.env['VAULT_SUBJECT_ENTITY'] || `${SLUG}-gateway-agent`;
const ACTOR_ENTITY = process.env['VAULT_ACTOR_ENTITY'] || `${SLUG}-gateway-actor`;

// external_ids the OBO resolves against.
const AGENT_ID_CLAIM = process.env['GATEWAY_AGENT_ID_CLAIM'] || 'mcp-gateway-agent';
const ACTOR_SUB =
  process.env['GATEWAY_ACTOR_SUB'] ||
  process.env['GATEWAY_ACTOR_SPIFFE_SUB'] ||
  process.env['GATEWAY_AGENT_CLIENT_ID'] ||
  'spiffe://example.org/mcp-gateway';

// The alias issuer tracks the JWT's `iss` (the OBO), NOT the natural issuer of
// the claim value — so even the SPIFFE actor alias uses the Verify /oauth2 iss.
const ISSUER =
  process.env['VERIFY_ISSUER'] ||
  (process.env['VERIFY_TENANT_URL']
    ? `${process.env['VERIFY_TENANT_URL'].replace(/\/+$/, '')}/oauth2`
    : 'https://your-tenant.verify.ibm.com/oauth2');

let MOUNT_ACCESSOR = process.env['VAULT_OAUTH_RS_MOUNT_ACCESSOR'] || '';

// optional ibm-verify plugin roles (SECRETS_BACKEND=vault)
const WITH_IBM_VERIFY = process.argv.includes('--with-ibm-verify');
const EXCHANGE_ROLE = process.env['GATEWAY_EXCHANGE_ROLE'] || 'gateway-exchange';
const AGENT_ROLE = process.env['GATEWAY_AGENT_ROLE'] || 'gateway-agent';

// ── Vault HTTP helpers ────────────────────────────────────────────────────

async function vaultReq(method: string, path: string, body?: unknown): Promise<any> {
  const res = await fetch(`${VAULT_ADDR}/v1/${path}`, {
    method,
    headers: { 'X-Vault-Token': VAULT_TOKEN!, 'Content-Type': 'application/json' },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  if (!res.ok && res.status !== 204) throw new Error(`${method} ${path} -> ${res.status}: ${text.slice(0, 400)}`);
  return text ? JSON.parse(text) : {};
}

async function vaultGet(path: string): Promise<any | null> {
  const res = await fetch(`${VAULT_ADDR}/v1/${path}`, { headers: { 'X-Vault-Token': VAULT_TOKEN! } });
  if (res.status === 404) return null;
  const text = await res.text();
  if (!res.ok) throw new Error(`GET ${path} -> ${res.status}: ${text.slice(0, 400)}`);
  return text ? JSON.parse(text) : {};
}

// ── verify-rar roles ──────────────────────────────────────────────────────

async function applyRarRoles(): Promise<string[]> {
  const roles = generateVaultRoles(rar, DB_NAME, loadTools());
  const applied: string[] = [];
  for (const r of roles) {
    await vaultReq('POST', `verify-rar/roles/${r.roleName}`, r.body);
    const back = await vaultGet(`verify-rar/roles/${r.roleName}`);
    const keys = Object.keys(back?.data?.rar_mappings ?? {});
    console.log(`[vault] verify-rar role "${r.roleName}" (${r.action} -> ${r.pgRole}) rar_mappings=[${keys.join(', ')}]`);
    applied.push(r.roleName);
  }
  return applied;
}

// ── runtime ACL policy ────────────────────────────────────────────────────

async function applyRuntimePolicy(): Promise<void> {
  const extraReadPaths = WITH_IBM_VERIFY ? [`ibm-verify/creds/${EXCHANGE_ROLE}`, `ibm-verify/creds/${AGENT_ROLE}`] : [];
  const hcl = generateRuntimePolicyHcl(rar, extraReadPaths);
  await vaultReq('PUT', `sys/policies/acl/${RUNTIME_POLICY}`, { policy: hcl });
  console.log(`[vault] runtime ACL policy "${RUNTIME_POLICY}" written`);
}

// ── OAuth-RS entities (subject + actor) ───────────────────────────────────

async function resolveMountAccessor(): Promise<string> {
  if (MOUNT_ACCESSOR) return MOUNT_ACCESSOR;
  const auth = await vaultGet('sys/auth');
  // sys/auth is keyed by mount path; find the oauth-resource-server mount.
  const src = auth?.data ?? auth ?? {};
  for (const [mount, cfg] of Object.entries<any>(src)) {
    if (cfg?.type === 'oauth-resource-server' && cfg?.accessor) {
      console.log(`[vault] resolved oauth-rs mount accessor from ${mount} -> ${cfg.accessor}`);
      return cfg.accessor as string;
    }
  }
  return '';
}

async function ensureEntity(name: string, policies: string[]): Promise<string> {
  const existing = await vaultGet(`identity/entity/name/${encodeURIComponent(name)}`);
  if (existing?.data?.id) {
    // Keep policies in sync (POST-by-name is an upsert on the existing entity).
    await vaultReq('POST', `identity/entity/name/${encodeURIComponent(name)}`, { policies });
    console.log(`[vault] entity "${name}" exists (id ${existing.data.id}) — policies ensured [${policies.join(', ')}]`);
    return existing.data.id as string;
  }
  await vaultReq('POST', 'identity/entity', { name, policies });
  const created = await vaultGet(`identity/entity/name/${encodeURIComponent(name)}`);
  const id = created?.data?.id as string;
  console.log(`[vault] entity "${name}" created (id ${id})`);
  return id;
}

async function ensureAlias(entityId: string, entityName: string, externalId: string): Promise<void> {
  // An alias is unique per (entity, mount_accessor); external_id + issuer are
  // IMMUTABLE. If an alias already exists on this mount, leave it — recreating
  // is the only way to change external_id, which is a destructive op we don't
  // do automatically.
  const entity = await vaultGet(`identity/entity/id/${entityId}`);
  const aliases: any[] = entity?.data?.aliases ?? [];
  const existing = aliases.find((a) => a.mount_accessor === MOUNT_ACCESSOR);
  if (existing) {
    if (existing.name !== externalId) {
      console.warn(
        `[vault] WARNING: "${entityName}" already has an alias (external_id="${existing.name}") on this mount, but config wants "${externalId}". ` +
          'external_id is immutable — delete the alias + re-run to change it.',
      );
    } else {
      console.log(`[vault] alias for "${entityName}" already present (external_id="${externalId}")`);
    }
    return;
  }
  await vaultReq('POST', 'identity/entity-alias', {
    name: externalId,
    canonical_id: entityId,
    mount_accessor: MOUNT_ACCESSOR,
    external_id: externalId,
    issuer: ISSUER,
  });
  console.log(`[vault] alias created for "${entityName}" (external_id="${externalId}", issuer="${ISSUER}")`);
}

async function registerAgent(displayName: string, entityId: string): Promise<void> {
  // Vault 2.0 gates RFC 8693 delegated auth on the entity being present in
  // agent-registry. ceiling_policy_identifiers = the MAX policy scope (a
  // ceiling, not an added grant). Re-runs may create duplicate registrations
  // (Vault doesn't dedupe) — harmless, but noted.
  try {
    await vaultReq('POST', 'agent-registry/register', {
      display_name: displayName,
      entity_id: entityId,
      ceiling_policy_identifiers: RUNTIME_POLICY,
    });
    console.log(`[vault] agent-registry registered "${displayName}" (ceiling ${RUNTIME_POLICY})`);
  } catch (err) {
    console.warn(`[vault] agent-registry register for "${displayName}" returned: ${(err as Error).message}`);
  }
}

async function applyEntities(): Promise<boolean> {
  MOUNT_ACCESSOR = await resolveMountAccessor();
  if (!MOUNT_ACCESSOR) {
    console.warn(
      '[vault] SKIPPING oauth-rs entities — no oauth-resource-server mount accessor found and VAULT_OAUTH_RS_MOUNT_ACCESSOR is unset. ' +
        'Enable the OAuth-RS auth profile (or set the env var), then re-run. verify-rar roles + policy are still applied.',
    );
    return false;
  }

  const subjectId = await ensureEntity(SUBJECT_ENTITY, [RUNTIME_POLICY]);
  await ensureAlias(subjectId, SUBJECT_ENTITY, AGENT_ID_CLAIM);
  await registerAgent(SUBJECT_ENTITY, subjectId);

  const actorId = await ensureEntity(ACTOR_ENTITY, [RUNTIME_POLICY]);
  await ensureAlias(actorId, ACTOR_ENTITY, ACTOR_SUB);
  await registerAgent(ACTOR_ENTITY, actorId);
  return true;
}

// ── optional ibm-verify plugin roles ──────────────────────────────────────

async function applyIbmVerifyRoles(): Promise<void> {
  const exId = process.env['GATEWAY_EXCHANGE_APP_ID'];
  const exClient = process.env['GATEWAY_EXCHANGE_CLIENT_ID'];
  const agId = process.env['GATEWAY_AGENT_APP_ID'];
  const agClient = process.env['GATEWAY_AGENT_CLIENT_ID'];
  if (!exId || !exClient) {
    console.warn('[vault] --with-ibm-verify: set GATEWAY_EXCHANGE_APP_ID + GATEWAY_EXCHANGE_CLIENT_ID to create the exchange role — skipping.');
  } else {
    await vaultReq('POST', `ibm-verify/roles/${EXCHANGE_ROLE}`, { application_id: exId, api_client_id: exClient });
    console.log(`[vault] ibm-verify role "${EXCHANGE_ROLE}" written (rotates the TE client secret on read)`);
  }
  if (!agId || !agClient) {
    console.warn('[vault] --with-ibm-verify: set GATEWAY_AGENT_APP_ID + GATEWAY_AGENT_CLIENT_ID to create the agent role — skipping.');
  } else {
    await vaultReq('POST', `ibm-verify/roles/${AGENT_ROLE}`, { application_id: agId, api_client_id: agClient });
    console.log(`[vault] ibm-verify role "${AGENT_ROLE}" written (rotates the agent client secret on read)`);
  }
}

// ── main ──────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log('══════════════════════════════════════════════════');
  console.log('  MCP Gateway — Vault Bootstrap');
  console.log(`  Vault:  ${VAULT_ADDR}`);
  console.log(`  Domain: ${SLUG}  (db_name=${DB_NAME})`);
  console.log('══════════════════════════════════════════════════');
  console.log('NOTE: the pre-baked Postgres roles (examples/db/vault-roles.sql) must exist,');
  console.log('and the verify-rar plugin connection user must hold them WITH ADMIN OPTION,');
  console.log('BEFORE these roles can mint. Apply that SQL first.\n');

  const roles = await applyRarRoles();
  await applyRuntimePolicy();
  const entitiesDone = await applyEntities();
  if (WITH_IBM_VERIFY) await applyIbmVerifyRoles();

  console.log('\n══════════════════════════════════════════════════');
  console.log('  VAULT BOOTSTRAP COMPLETE');
  console.log('══════════════════════════════════════════════════');
  console.log(`verify-rar roles:   ${roles.join(', ')}`);
  console.log(`runtime policy:     ${RUNTIME_POLICY}`);
  console.log(`oauth-rs entities:  ${entitiesDone ? `${SUBJECT_ENTITY} (external_id=${AGENT_ID_CLAIM}), ${ACTOR_ENTITY} (external_id=${ACTOR_SUB})` : '(skipped — see warning)'}`);

  console.log('\n── gateway .env (Vault side) ──────────────────────');
  console.log(`VAULT_ADDR=${VAULT_ADDR}`);
  console.log('# Give the gateway a token/AppRole whose policy is (at least) the runtime policy above.');
  console.log('# The gateway presents each user OBO as X-Vault-Token to verify-rar/creds/* directly,');
  console.log('# so its own token only needs to reach those paths + sys/leases/revoke.');
  if (WITH_IBM_VERIFY) {
    console.log('SECRETS_BACKEND=vault');
    console.log(`GATEWAY_EXCHANGE_ROLE=${EXCHANGE_ROLE}`);
    console.log(`GATEWAY_AGENT_ROLE=${AGENT_ROLE}`);
  }

  console.log('\n── Confirm on a live run (Task 7) ─────────────────');
  console.log('- The oauth-rs mount accessor + issuer above match the tenant that issues the OBO.');
  console.log(`- The TE app's agent_id claim value ("${AGENT_ID_CLAIM}") matches the SUBJECT external_id.`);
  console.log(`- The OBO's act.sub ("${ACTOR_SUB}") matches the ACTOR external_id.`);
  console.log('══════════════════════════════════════════════════');
}

main().catch((err) => {
  console.error('\nFATAL:', (err as Error).message);
  process.exit(1);
});
