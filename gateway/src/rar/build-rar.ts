/**
 * RFC 9396 RAR builder — MCP gateway
 *
 * Feeds the OBO-as-X-Vault-Token flow: Token Exchange with
 * authorization_details → OBO POSTed as X-Vault-Token to verify-rar. This
 * module only builds the authorization_details array — token exchange + Vault
 * POST live in separate modules (auth/token-exchange.ts, vault/mint.ts).
 *
 * The RAR VOCABULARY (business RAR type, id field, action collapse rules,
 * creds paths) is NOT hardcoded here — it all comes from config/rar.json via
 * rar/rar-config.ts, so a customer retargets the gateway at their own domain
 * by editing config, not code. Under the shipped default config the
 * vocabulary is the "records" example domain.
 *
 * authorization_details (3 elements when DB-backed; just element 1 in a NO-DB
 * deployment, UPSTREAM_DB_BACKED=false, where there is no Vault cred leg):
 *   1. business RAR        type = config.rarType, nested under
 *      operationDetails — the CELx nav invariant every access policy on the
 *      Verify tenant depends on (CELx rules navigate
 *      requestContext.authorizationDetails[...].operationDetails.<field>).
 *      The domain id rides under config.idField.
 *   2. vault:path_access   the collapsed action's config.actions[*].credsPath
 *   3. vault:path_access   sys/leases/revoke
 *
 * RAR-action collapse (config-driven):
 *   The Vault verify-rar role only registers a rar_mappings key per action
 *   that has its own non-blocked entry in config.actions. An action WITH its
 *   own entry passes through unchanged; anything else (per-tool subactions,
 *   unknown values, blocked entries) collapses onto the single action marked
 *   `default: true`. The original action is preserved verbatim in the
 *   business RAR's `subaction` for audit.
 *
 *   Step-up: when the gateway passes `elevated: true` and the collapsed action
 *   has an elevation target (some action declaring `elevatedFrom` it), the
 *   collapse elevates to that target (and its creds path). Actions with no
 *   elevation target — writes, under the default config — ignore `elevated`.
 *
 * Callers that need BOTH the authorization_details AND the Vault creds path
 * for the same call (i.e. pipeline.ts) MUST use `resolveRar()` below rather
 * than calling `buildRAR` and `vaultCredsPath(vaultRarAction(...))`
 * separately — the latter re-derives the elevation collapse independently
 * and can drift out of sync with what `buildRAR` actually sent (see
 * resolveRar's own doc comment for the incident this guards against).
 * `buildRAR`/`vaultRarAction`/`vaultCredsPath` remain exported for
 * back-compat and for callers that genuinely only need one or the other.
 *
 * Every export takes an optional trailing `config` (defaulting to the
 * config/rar.json singleton) so tests can drive a custom-domain vocabulary
 * without touching the shipped file.
 */

import { rarConfig, type RarConfig } from './rar-config.js';

// ── Types ─────────────────────────────────────────────────────

/**
 * The business element's `type` is config.rarType (a string, not a literal —
 * the vocabulary is customer-editable), and the domain id key inside
 * operationDetails is config.idField.
 */
export type AuthorizationDetail =
  | {
    type: string;
    operationDetails: { [key: string]: string | undefined; action: string; subaction: string };
  }
  | {
    type: 'vault:path_access';
    path_constraint: string;
    action: string;
  };

// ── RAR action / path resolution ────────────────────────────────

/**
 * Collapse an action down to one of the configured Vault rar_mappings keys.
 * An action with its own non-blocked config.actions entry passes through
 * unchanged; everything else — per-tool subactions, unknown values, and
 * blocked entries (already denied at the tier gate; they can never be minted
 * from) — collapses to the `default: true` action.
 */
export function vaultRarAction(rarAction: string, config: RarConfig = rarConfig): string {
  const entry = config.actions[rarAction];
  if (entry && entry.blocked !== true) return rarAction;
  return config.defaultAction;
}

export function vaultCredsPath(collapsedAction: string, config: RarConfig = rarConfig): string | undefined {
  const entry = config.actions[collapsedAction];
  // A DB-backed collapsed action always has a non-blocked entry with a credsPath
  // (the parse-time validation guarantees the default action does); the fallback
  // covers callers passing a raw, un-collapsed action. In a NO-DB deployment
  // (UPSTREAM_DB_BACKED=false) actions carry NO credsPath — this returns
  // undefined (it must NOT invent the default action's path, which is also
  // absent), and buildRAR/resolveRar then omit the vault:path_access elements.
  return entry?.credsPath ?? config.actions[config.defaultAction]?.credsPath;
}

/**
 * Elevation + Vault role-mapping collapse in one place. `buildRAR`
 * and `resolveRar` both call THIS (never re-derive the elevation logic
 * independently) so the business RAR's `operationDetails.action` and the
 * Vault creds path it feeds can never drift apart — see resolveRar's header
 * comment for the bug class this guards against.
 *
 * Step-up only applies where the config declares an elevation: the
 * collapsed action is elevated iff some action lists it as `elevatedFrom`.
 * Under the default config that is record_read → record_read_elevated only —
 * record_write has no elevation target, so writes ignore the elevated flag.
 */
function collapseAction(args: { rarAction: string; elevated?: boolean }, config: RarConfig): string {
  const collapsed = vaultRarAction(args.rarAction, config);
  if (args.elevated === true) {
    const elevated = config.elevationByBase[collapsed];
    if (elevated) return elevated;
  }
  return collapsed;
}

/**
 * Build the authorization_details array sent to Verify. The business element
 * preserves the FULL (original) action as `subaction`; `action` carries the
 * Vault-role-mapping-collapsed value the plugin's rar_mapping lookup keys on.
 *
 * DB-backed (default): 3 elements — the business element plus two
 * vault:path_access elements granting explicit Vault path-level authority for
 * the OAuth-RS profile. NO-DB (UPSTREAM_DB_BACKED=false, the collapsed action
 * has no credsPath): 1 element — the business element ONLY. There is no Vault
 * ephemeral-cred leg, so a vault:path_access grant would be meaningless.
 *
 * `recordId` is the domain id value (pipeline.ts reads it off
 * args[config.argIdKey]); it is nested under config.idField in the business
 * element. The parameter keeps its original name for caller back-compat.
 */
export function buildRAR(
  args: {
    rarAction: string;
    recordId?: string;
    elevated?: boolean;
  },
  config: RarConfig = rarConfig,
): AuthorizationDetail[] {
  const collapsedAction = collapseAction(args, config);
  const credsPath = vaultCredsPath(collapsedAction, config);

  const business: AuthorizationDetail = {
    type: config.rarType,
    operationDetails: {
      action: collapsedAction,
      subaction: args.rarAction,
      ...(args.recordId ? { [config.idField]: args.recordId } : {}),
    },
  };

  // NO-DB upstream: no creds path → emit ONLY the business element.
  if (!credsPath) return [business];

  return [
    business,
    {
      type: 'vault:path_access',
      path_constraint: credsPath,
      action: 'update',
    },
    {
      type: 'vault:path_access',
      path_constraint: 'sys/leases/revoke',
      action: 'update',
    },
  ];
}

/**
 * Single source of truth for callers that need BOTH the authorization_details
 * sent to Verify AND the Vault creds path used to mint the ephemeral
 * credential for the same call.
 *
 * Bug this fixes (found in security review): callers used to compute
 * `vaultCredsPath(vaultRarAction(rarAction))` on the RAW rarAction
 * independently of `buildRAR`, which internally elevates an
 * `elevated: true` read to the configured step-up action. For an elevated read
 * that meant the RAR sent to Verify claimed the elevated action while the creds
 * path resolved to the non-elevated default — minting from the wrong Vault
 * role and breaking the step-up flow.
 *
 * `resolveRar` runs the elevation + collapse logic (via the shared
 * `collapseAction` helper) exactly once and derives both outputs from that
 * single collapsed action, so they can never disagree.
 */
export function resolveRar(
  args: {
    rarAction: string;
    recordId?: string;
    elevated?: boolean;
  },
  config: RarConfig = rarConfig,
): { authorizationDetails: AuthorizationDetail[]; credsPath: string | undefined; collapsedAction: string } {
  const collapsedAction = collapseAction(args, config);
  // undefined in a NO-DB deployment (UPSTREAM_DB_BACKED=false) — the caller
  // (pipeline.ts) skips the mint/revoke leg entirely in that case.
  const credsPath = vaultCredsPath(collapsedAction, config);
  const authorizationDetails = buildRAR(args, config);

  return { authorizationDetails, credsPath, collapsedAction };
}
