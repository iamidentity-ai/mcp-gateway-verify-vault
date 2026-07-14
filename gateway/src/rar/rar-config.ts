/**
 * RAR vocabulary config — MCP gateway
 *
 * Everything domain-specific about the gateway's RFC 9396 handling lives in
 * config/rar.json, NOT in code. To put the gateway in front of a different
 * domain (tickets, orders, shipments, ...) a customer edits that file —
 * rar/build-rar.ts and pipeline.ts read the vocabulary from here and never
 * hardcode it.
 *
 * Schema (config/rar.json):
 *   rarType      — `type` of the business authorization_details element
 *                  (the CELx nav invariant Verify access policies key on)
 *   idField      — key the domain id is nested under inside operationDetails
 *                  (e.g. "record_id")
 *   argIdKey     — tool-call argument the id is read FROM (e.g. "recordId");
 *                  pipeline.ts maps args[argIdKey] → operationDetails[idField]
 *   actions      — the Vault rar_mappings vocabulary. Per action:
 *       credsPath    — verify-rar creds path this action mints from
 *                      (required unless the action is blocked)
 *       default      — exactly ONE action must set true; any action without
 *                      its own (non-blocked) entry collapses onto it
 *       elevatedFrom — marks this action as the step-up of the named base
 *                      action: `vip: true` on the base elevates to this one
 *       blocked      — never reaches token exchange. Tier 4 is already gated
 *                      in policy/tiers.ts before RAR is built; the entry here
 *                      is documentation + validation. For collapse purposes a
 *                      blocked action behaves like an unmapped one (falls to
 *                      the default action) — it can never be minted from.
 *   vipElevation — the gateway-derived VIP step-up (pipeline.ts step 2.5):
 *       discoveryTools — tool names whose reads run the cheap discovery probe
 *       vipField       — field on the discovery-read result that marks the
 *                        row as VIP (elevation-worthy)
 *
 * The file is read via fs at module load (same readFileSync-at-import
 * pattern as policy/tiers.ts — no ESM import-attribute requirement under
 * module: Node16), and validated immediately: a bad config throws a NAMED
 * RarConfigError at startup, not at the first request.
 */
import { readFileSync } from 'node:fs';

/** Named so a startup crash is grep-ably "RarConfigError: config/rar.json ...". */
export class RarConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RarConfigError';
  }
}

export interface RarActionConfig {
  credsPath?: string;
  default?: boolean;
  elevatedFrom?: string;
  blocked?: boolean;
}

export interface RarVipElevationConfig {
  discoveryTools: string[];
  vipField: string;
  /**
   * Tool the discovery probe CALLS to learn vipField. Defaults to the requested
   * tool. Set it so record-scoped reads whose OWN result does not carry vipField
   * (detail/history rows) can probe the PARENT record's VIP status via a single
   * flag-carrying read (e.g. get_record). Must be one of discoveryTools.
   */
  probeTool?: string;
}

export interface RarConfig {
  rarType: string;
  idField: string;
  argIdKey: string;
  actions: Record<string, RarActionConfig>;
  vipElevation: RarVipElevationConfig;
  /** Derived at parse: the single actions entry with `default: true`. */
  defaultAction: string;
  /** Derived at parse: base action → the action that `elevatedFrom`s it. */
  elevationByBase: Record<string, string>;
}

function requireNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new RarConfigError(`config/rar.json: "${field}" must be a non-empty string`);
  }
  return value;
}

/**
 * Validate + derive. Pure (no I/O) so tests can drive it with custom-domain
 * fixtures — proving a different vocabulary works with zero code change.
 *
 * Rules enforced:
 *   - rarType / idField / argIdKey non-empty strings
 *   - actions is a non-empty object
 *   - exactly one action sets `default: true`, and it is not blocked
 *   - every non-blocked action has a credsPath
 *   - every `elevatedFrom` references an existing action, and no two actions
 *     elevate from the same base (elevation must be unambiguous)
 *   - vipElevation, when present, has a string[] discoveryTools and a
 *     non-empty vipField; when absent, VIP discovery is simply disabled
 */
export function parseRarConfig(raw: unknown): RarConfig {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new RarConfigError('config/rar.json: top level must be an object');
  }
  const cfg = raw as Record<string, unknown>;

  const rarType = requireNonEmptyString(cfg['rarType'], 'rarType');
  const idField = requireNonEmptyString(cfg['idField'], 'idField');
  const argIdKey = requireNonEmptyString(cfg['argIdKey'], 'argIdKey');

  const actionsRaw = cfg['actions'];
  if (
    typeof actionsRaw !== 'object' ||
    actionsRaw === null ||
    Array.isArray(actionsRaw) ||
    Object.keys(actionsRaw).length === 0
  ) {
    throw new RarConfigError('config/rar.json: "actions" must be a non-empty object');
  }
  const actions = actionsRaw as Record<string, RarActionConfig>;

  const defaults = Object.entries(actions).filter(([, entry]) => entry.default === true);
  if (defaults.length !== 1) {
    throw new RarConfigError(
      `config/rar.json: exactly one action must set "default": true (found ${defaults.length})`,
    );
  }
  const [defaultAction, defaultEntry] = defaults[0]!;
  if (defaultEntry.blocked === true) {
    throw new RarConfigError(
      `config/rar.json: the default action ("${defaultAction}") must not be blocked — unmapped actions collapse onto it`,
    );
  }

  const elevationByBase: Record<string, string> = {};
  for (const [name, entry] of Object.entries(actions)) {
    if (entry.blocked !== true) {
      requireNonEmptyString(entry.credsPath, `actions.${name}.credsPath`);
    }
    if (entry.elevatedFrom !== undefined) {
      const base = requireNonEmptyString(entry.elevatedFrom, `actions.${name}.elevatedFrom`);
      if (!(base in actions)) {
        throw new RarConfigError(
          `config/rar.json: actions.${name}.elevatedFrom references unknown action "${base}"`,
        );
      }
      const existing = elevationByBase[base];
      if (existing) {
        throw new RarConfigError(
          `config/rar.json: both "${existing}" and "${name}" set elevatedFrom "${base}" — elevation must be unambiguous`,
        );
      }
      elevationByBase[base] = name;
    }
  }

  let vipElevation: RarVipElevationConfig = { discoveryTools: [], vipField: '' };
  if (cfg['vipElevation'] !== undefined) {
    const ve = cfg['vipElevation'];
    if (typeof ve !== 'object' || ve === null || Array.isArray(ve)) {
      throw new RarConfigError('config/rar.json: "vipElevation" must be an object');
    }
    const veObj = ve as Record<string, unknown>;
    const discoveryTools = veObj['discoveryTools'] ?? [];
    if (!Array.isArray(discoveryTools) || discoveryTools.some((t) => typeof t !== 'string' || t === '')) {
      throw new RarConfigError(
        'config/rar.json: vipElevation.discoveryTools must be an array of tool-name strings',
      );
    }
    let probeTool: string | undefined;
    if (veObj['probeTool'] !== undefined) {
      probeTool = requireNonEmptyString(veObj['probeTool'], 'vipElevation.probeTool');
      if (!(discoveryTools as string[]).includes(probeTool)) {
        throw new RarConfigError(
          `config/rar.json: vipElevation.probeTool "${probeTool}" must be listed in discoveryTools`,
        );
      }
    }
    vipElevation = {
      discoveryTools: discoveryTools as string[],
      vipField: requireNonEmptyString(veObj['vipField'], 'vipElevation.vipField'),
      probeTool,
    };
  }

  return { rarType, idField, argIdKey, actions, vipElevation, defaultAction, elevationByBase };
}

/**
 * True when `credsPath` belongs to an ELEVATED action (one declaring
 * `elevatedFrom`). Replaces the old hardcoded `credsPath.includes('-vip')`
 * display heuristic in pipeline.ts — the config, not a path-suffix naming
 * convention, is what defines "elevated".
 */
export function isElevatedCredsPath(credsPath: string, config: RarConfig = rarConfig): boolean {
  return Object.values(config.elevationByBase).some(
    (elevated) => config.actions[elevated]?.credsPath === credsPath,
  );
}

// ── The singleton every runtime module uses ─────────────────────────────
// Loaded + validated once at import — a bad config/rar.json kills the
// gateway at startup with a RarConfigError, never at first request.
const rarConfigPath = new URL('../../config/rar.json', import.meta.url);
export const rarConfig: RarConfig = parseRarConfig(JSON.parse(readFileSync(rarConfigPath, 'utf-8')));
