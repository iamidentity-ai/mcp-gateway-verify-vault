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
 *                      action: an `elevated: true` read on the base elevates
 *                      to this one
 *       blocked      — never reaches token exchange. Tier 4 is already gated
 *                      in policy/tiers.ts before RAR is built; the entry here
 *                      is documentation + validation. For collapse purposes a
 *                      blocked action behaves like an unmapped one (falls to
 *                      the default action) — it can never be minted from.
 *   stepUp — the gateway-derived step-up (pipeline.ts step 2.5):
 *       discoveryTools — tool names whose reads run the cheap discovery probe
 *       elevateWhen    — declarative match rule evaluated against the
 *                        discovery-read result; a match forces the step-up.
 *                        Exactly ONE matcher is set:
 *                          equals — value === equals
 *                          in     — in.includes(value)      (allow-list)
 *                          notIn  — !notIn.includes(value)  (fail-closed
 *                                   safe-list: elevate for anything NOT
 *                                   explicitly safe, incl. unknown levels)
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

/**
 * Declarative match rule for stepUp.elevateWhen. Exactly ONE of
 * equals/in/notIn is set (validated at parse). Evaluated against the value at
 * `field` on the unwrapped discovery-read record.
 */
export interface ElevateWhenRule {
  field: string;
  equals?: unknown;
  in?: unknown[];
  notIn?: unknown[];
}

export interface RarStepUpConfig {
  discoveryTools: string[];
  elevateWhen: ElevateWhenRule;
  /**
   * Tool the discovery probe CALLS to learn the classification. Defaults to the
   * requested tool. Set it so record-scoped reads whose OWN result does not
   * carry the classification field (detail/history rows) can probe the PARENT
   * record's classification via a single flag-carrying read (e.g. get_record).
   * Must be one of discoveryTools.
   */
  probeTool?: string;
}

export interface RarConfig {
  rarType: string;
  idField: string;
  argIdKey: string;
  actions: Record<string, RarActionConfig>;
  stepUp: RarStepUpConfig;
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
 *   - every non-blocked action has a credsPath (ONLY when opts.requireCredsPath
 *     is true — the default. A NO-DB deployment fronting a non-database upstream
 *     (UPSTREAM_DB_BACKED=false) has no Vault ephemeral-cred leg, so its actions
 *     carry no credsPath; the singleton below relaxes the requirement in that mode)
 *   - every `elevatedFrom` references an existing action, and no two actions
 *     elevate from the same base (elevation must be unambiguous)
 *   - stepUp, when present, has a string[] discoveryTools and an elevateWhen
 *     rule with a non-empty field and EXACTLY ONE of equals/in/notIn; when
 *     absent, step-up discovery is simply disabled
 */
export function parseRarConfig(raw: unknown, opts: { requireCredsPath?: boolean } = {}): RarConfig {
  const requireCredsPath = opts.requireCredsPath ?? true;
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
    if (entry.blocked !== true && requireCredsPath) {
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

  let stepUp: RarStepUpConfig = { discoveryTools: [], elevateWhen: { field: '' } };
  if (cfg['stepUp'] !== undefined) {
    const su = cfg['stepUp'];
    if (typeof su !== 'object' || su === null || Array.isArray(su)) {
      throw new RarConfigError('config/rar.json: "stepUp" must be an object');
    }
    const suObj = su as Record<string, unknown>;
    const discoveryTools = suObj['discoveryTools'] ?? [];
    if (!Array.isArray(discoveryTools) || discoveryTools.some((t) => typeof t !== 'string' || t === '')) {
      throw new RarConfigError(
        'config/rar.json: stepUp.discoveryTools must be an array of tool-name strings',
      );
    }
    let probeTool: string | undefined;
    if (suObj['probeTool'] !== undefined) {
      probeTool = requireNonEmptyString(suObj['probeTool'], 'stepUp.probeTool');
      if (!(discoveryTools as string[]).includes(probeTool)) {
        throw new RarConfigError(
          `config/rar.json: stepUp.probeTool "${probeTool}" must be listed in discoveryTools`,
        );
      }
    }
    stepUp = {
      discoveryTools: discoveryTools as string[],
      elevateWhen: parseElevateWhen(suObj['elevateWhen']),
      probeTool,
    };
  }

  return { rarType, idField, argIdKey, actions, stepUp, defaultAction, elevationByBase };
}

/**
 * Validate + return the declarative elevateWhen match rule. `field` must be a
 * non-empty string, and EXACTLY ONE of equals/in/notIn must be set (a
 * RarConfigError naming the rule otherwise). `in`/`notIn`, when set, must be
 * arrays. `notIn` is the fail-closed safe-list: the gateway elevates for any
 * value NOT explicitly listed (including unknown/new levels).
 */
export function parseElevateWhen(raw: unknown): ElevateWhenRule {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new RarConfigError('config/rar.json: stepUp.elevateWhen must be an object');
  }
  const r = raw as Record<string, unknown>;
  const field = requireNonEmptyString(r['field'], 'stepUp.elevateWhen.field');

  const setMatchers = (['equals', 'in', 'notIn'] as const).filter((k) => r[k] !== undefined);
  if (setMatchers.length !== 1) {
    throw new RarConfigError(
      `config/rar.json: stepUp.elevateWhen (field "${field}") must set EXACTLY ONE of equals/in/notIn (found ${setMatchers.length})`,
    );
  }
  for (const key of ['in', 'notIn'] as const) {
    if (r[key] !== undefined && !Array.isArray(r[key])) {
      throw new RarConfigError(
        `config/rar.json: stepUp.elevateWhen.${key} (field "${field}") must be an array`,
      );
    }
  }
  return {
    field,
    ...(r['equals'] !== undefined ? { equals: r['equals'] } : {}),
    ...(r['in'] !== undefined ? { in: r['in'] as unknown[] } : {}),
    ...(r['notIn'] !== undefined ? { notIn: r['notIn'] as unknown[] } : {}),
  };
}

/**
 * True when `credsPath` belongs to an ELEVATED action (one declaring
 * `elevatedFrom`). Replaces the old hardcoded `credsPath.includes('-elevated')`
 * display heuristic in pipeline.ts — the config, not a path-suffix naming
 * convention, is what defines "elevated".
 *
 * An action with NO credsPath (a NO-DB deployment) simply isn't an elevated
 * creds path — the `p !== undefined` guard stops an undefined elevated-action
 * credsPath from matching an undefined argument.
 */
export function isElevatedCredsPath(credsPath: string, config: RarConfig = rarConfig): boolean {
  return Object.values(config.elevationByBase).some((elevated) => {
    const p = config.actions[elevated]?.credsPath;
    return p !== undefined && p === credsPath;
  });
}

// ── The singleton every runtime module uses ─────────────────────────────
// Loaded + validated once at import — a bad config/rar.json kills the
// gateway at startup with a RarConfigError, never at first request.
const rarConfigPath = new URL('../../config/rar.json', import.meta.url);
export const rarConfig: RarConfig = parseRarConfig(JSON.parse(readFileSync(rarConfigPath, 'utf-8')), {
  // A credsPath is required on every non-blocked action UNLESS this is a NO-DB
  // deployment (UPSTREAM_DB_BACKED=false) fronting a non-database upstream —
  // there is no Vault ephemeral-cred leg to point a creds path at.
  requireCredsPath: process.env['UPSTREAM_DB_BACKED'] !== 'false',
});
