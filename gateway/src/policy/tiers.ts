/**
 * Tool tier map + tier gate — MCP gateway
 *
 * Loads config/tools.json (tool name → { tier, rarAction, scope }) and
 * exposes gateTool(), the single choke point every MCP tool call passes
 * through before Token Exchange + RAR are attempted upstream.
 *
 * Tiers:
 *   1 read        — Token Exchange only
 *   2 write       — Token Exchange + RAR, one Verify-policy push
 *   3 sensitive   — push every call
 *   4 blocked     — policy deny, gated here (never reaches Verify)
 *
 * config/tools.json is read via fs (not a JSON import) so this module has
 * no ESM import-attribute requirement to satisfy under module: Node16.
 *
 * GATEWAY_CONFIG_DIR, when set, points the loader at a DIFFERENT upstream's
 * config directory (tools.json + rar.json) instead of the shipped
 * gateway/config/ so the gateway can front a different MCP without clobbering
 * the shipped "records" config, and two instances can run side by side. The
 * bootstrap (bootstrap/lib/config.ts) and rar/rar-config.ts read the SAME env,
 * so runtime and bootstrap can never diverge onto different configs.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { rarConfig } from '../rar/rar-config.js';

export type Tier = 1 | 2 | 3 | 4;

/** Primitive types buildToolSpecs (index.ts) knows how to turn into a real
 *  zod field for a config-driven /mcp tool's inputSchema. */
export type ToolArgType = 'string' | 'number' | 'boolean';

export interface ToolPolicy {
  tier: Tier;
  rarAction: string;
  scope: string;
  /**
   * Optional per-field argument schema (field name -> primitive type),
   * matching the upstream MCP tool's real parameters — e.g.
   * `{"table":"string","note":"string"}` for a two-field write. When
   * present, index.ts's buildToolSpecs uses it to advertise a REAL
   * `tools/list` inputSchema for this tool instead of the generic
   * `z.record` passthrough (which advertises an empty `properties: {}` —
   * a real MCP client sees no arguments and calls with `{}`). Optional
   * because the gateway doesn't always know an upstream's exact argument
   * names; when absent, the passthrough fallback still forwards whatever
   * arguments a caller sends, just without an advertised schema.
   */
  args?: Record<string, ToolArgType>;
}

export interface GateResult {
  /** 0 for unknown tools — no policy entry exists to report a real tier. */
  tier: Tier | 0;
  rarAction: string;
  scope: string;
  allowed: boolean;
  reason?: string;
}

const configDir = process.env['GATEWAY_CONFIG_DIR'];
const toolsPath = configDir ? join(configDir, 'tools.json') : new URL('../../config/tools.json', import.meta.url);
/**
 * Exported (not just module-private) so index.ts's /mcp tool surface can be
 * built from the SAME parsed map the tier gate itself uses, instead of
 * re-reading tools.json a second time under a second GATEWAY_CONFIG_DIR
 * resolution — one parse, one source of truth, no way for the two
 * transports to see a different tool list for the same process.
 */
export const tools = JSON.parse(readFileSync(toolsPath, 'utf-8')) as Record<string, ToolPolicy>;

/**
 * Cross-validate config/tools.json against config/rar.json. Every tool's
 * rarAction MUST be a defined action, and only a tier-4 (blocked) tool may map
 * to a blocked action.
 *
 * WHY this matters: at exchange time `vaultRarAction` silently collapses any
 * rarAction that is NOT a defined, non-blocked rar.json action down to the
 * DEFAULT (read) action. So a typo'd or newly-added tier-2/3 `rarAction` that
 * isn't wired into rar.json would run with no step-up and read-only creds — a
 * silent under-protection with false tier confidence. This turns that latent
 * mistake into a NAMED crash at startup instead. Pure + exported so it is unit
 * tested; called once at module load below against the shipped config.
 */
export function assertToolActionsValid(
  toolPolicies: Record<string, ToolPolicy>,
  rarActions: Record<string, { blocked?: boolean }>,
): void {
  for (const [name, policy] of Object.entries(toolPolicies)) {
    const action = rarActions[policy.rarAction];
    if (!action) {
      throw new Error(
        `config/tools.json: tool "${name}" uses rarAction "${policy.rarAction}" which is not a defined action in config/rar.json — it would silently collapse to the default action and skip its tier's step-up`,
      );
    }
    if (policy.tier !== 4 && action.blocked === true) {
      throw new Error(
        `config/tools.json: tier-${policy.tier} tool "${name}" maps to the BLOCKED rarAction "${policy.rarAction}" — only tier-4 tools may use a blocked action`,
      );
    }
  }
}

const VALID_ARG_TYPES: ToolArgType[] = ['string', 'number', 'boolean'];

/**
 * Validate every tool's optional `args` map has recognized primitive types
 * — a typo (e.g. "sting") would otherwise silently fall through
 * buildToolSpecs' type lookup to a default rather than failing loudly.
 * Pure + exported for the same fail-fast-at-startup reason as
 * assertToolActionsValid above.
 */
export function assertToolArgsValid(toolPolicies: Record<string, ToolPolicy>): void {
  for (const [name, policy] of Object.entries(toolPolicies)) {
    if (!policy.args) continue;
    for (const [field, type] of Object.entries(policy.args)) {
      if (!VALID_ARG_TYPES.includes(type)) {
        throw new Error(
          `config/tools.json: tool "${name}" arg "${field}" has unrecognized type "${type}" (want one of ${VALID_ARG_TYPES.join(', ')})`,
        );
      }
    }
  }
}

// Fail fast at startup on any tools.json ↔ rar.json mismatch, or an
// unrecognized args field type.
assertToolActionsValid(tools, rarConfig.actions);
assertToolArgsValid(tools);

/**
 * Gate a tool call by its tier-4 policy alone (no RAR/Verify call here).
 *   - Unknown tool name → denied, reason 'unknown_tool'.
 *   - Tier 4 (blocked)  → denied, reason 'policy_deny'.
 *   - Tier 1-3          → allowed; caller still owes Token Exchange (+ RAR
 *     for tier 2/3) before the upstream tool actually runs.
 */
export function gateTool(name: string): GateResult {
  const policy = tools[name];
  if (!policy) {
    return { tier: 0, rarAction: '', scope: '', allowed: false, reason: 'unknown_tool' };
  }
  if (policy.tier === 4) {
    return { ...policy, allowed: false, reason: 'policy_deny' };
  }
  return { ...policy, allowed: true };
}
