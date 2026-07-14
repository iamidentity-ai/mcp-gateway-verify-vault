/**
 * Gateway config loader — bootstrap
 *
 * The bootstrap scripts derive EVERYTHING they create on the Verify tenant
 * and in Vault from the gateway's OWN config files:
 *   ../../gateway/config/tools.json  (tool -> { tier, rarAction, scope })
 *   ../../gateway/config/rar.json    (RAR vocabulary — actions, creds paths)
 *
 * That is the whole point: the CELX attributes, access-policy rule order, and
 * Vault verify-rar rar_mappings can never drift from what the gateway's
 * pipeline actually sends, because they are generated from the same two files
 * the gateway reads at runtime (gateway/src/policy/tiers.ts +
 * gateway/src/rar/rar-config.ts).
 *
 * These loaders read the raw JSON with a light, standalone type shape (they do
 * NOT import gateway source — bootstrap has zero runtime deps on the gateway
 * package). The PURE generators in generate.ts take the parsed config as an
 * argument, so they unit-test against custom-domain fixtures with no I/O.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export type Tier = 1 | 2 | 3 | 4;

export interface ToolPolicy {
  tier: Tier;
  rarAction: string;
  scope: string;
}

export type ToolsConfig = Record<string, ToolPolicy>;

export interface RarActionConfig {
  credsPath?: string;
  default?: boolean;
  elevatedFrom?: string;
  blocked?: boolean;
}

export interface ElevateWhenRule {
  field: string;
  equals?: unknown;
  in?: unknown[];
  notIn?: unknown[];
}

export interface RarStepUpConfig {
  discoveryTools: string[];
  elevateWhen: ElevateWhenRule;
  probeTool?: string;
}

export interface RarConfig {
  rarType: string;
  idField: string;
  argIdKey: string;
  actions: Record<string, RarActionConfig>;
  stepUp?: RarStepUpConfig;
}

// The gateway's shipped config directory, relative to THIS file (bootstrap/lib/).
// Used unless GATEWAY_CONFIG_DIR overrides it (see configPath).
const DEFAULT_GATEWAY_CONFIG_DIR = new URL('../../gateway/config/', import.meta.url);

/**
 * Resolve a config file (tools.json / rar.json), honoring GATEWAY_CONFIG_DIR.
 *
 * The runtime (gateway/src/policy/tiers.ts + rar/rar-config.ts) reads the SAME
 * env, so a bootstrap generated here can never target a different config than
 * the gateway actually runs; a bootstrap-vs-runtime config divergence is a
 * silent trap the shared env closes.
 */
function configPath(file: string): string {
  const dir = process.env['GATEWAY_CONFIG_DIR'];
  return dir ? join(dir, file) : fileURLToPath(new URL(file, DEFAULT_GATEWAY_CONFIG_DIR));
}

export function loadTools(): ToolsConfig {
  return JSON.parse(readFileSync(configPath('tools.json'), 'utf-8')) as ToolsConfig;
}

export function loadRarConfig(): RarConfig {
  return JSON.parse(readFileSync(configPath('rar.json'), 'utf-8')) as RarConfig;
}
