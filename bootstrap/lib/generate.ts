/**
 * Config -> Verify/Vault artifact generators — bootstrap (PURE, no I/O)
 *
 * Every object the bootstrap scripts create is DERIVED here from the parsed
 * gateway config (tools.json + rar.json), so retargeting the gateway at a new
 * domain (edit the two config files) automatically retargets the whole trust
 * setup — zero bootstrap edits. These functions take the config as arguments
 * and never touch the network or filesystem, so lib/generate.test.ts drives
 * them with custom-domain fixtures.
 *
 * What is generated (each shape is faithful to a battle-tested production
 * deployment of this same Verify + Vault chain):
 *   - CELX custom attributes  (Verify)
 *   - access policy           (Verify)
 *   - verify-rar roles        (Vault)
 *   - runtime ACL policy      (Vault)
 *
 * Rule order (first match wins), mirroring the reference access policy:
 *   blocked action  -> ACTION_DENY            (defense-in-depth; tier 4 is
 *                                              already gated pre-exchange)
 *   VIP read        -> ACTION_MFA_ALWAYS      (step-up every call)
 *   sensitive write -> ACTION_MFA_ALWAYS      (tier 3, push every call)
 *   standard write  -> ACTION_MFA_PER_SESSION (tier 2, push once per session)
 *   default         -> ACTION_ALLOW
 */
import type { RarConfig, ToolsConfig } from './config.js';

// ── Verify object shapes ─────────────────────────────────────────

export interface AttributeDef {
  id: string;
  name: string;
  description: string;
  sourceType: 'static';
  datatype: 'string';
  tags: string[];
  multiValued: boolean;
  function: { custom: string };
}

export interface PolicyCondition {
  type: 'customAttributes';
  customAttributes: { name: string; opCode: 'IN'; values: string[] }[];
}

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  alwaysRun: boolean;
  firstFactor: boolean;
  conditions: PolicyCondition[];
  result: { action: string; serverSideActions: unknown[]; authnMethods: string[] };
}

export interface AccessPolicy {
  name: string;
  description: string;
  containsFirstFactor: boolean;
  rules: PolicyRule[];
  meta: { state: string; schema: string; label: string; scope: string[]; enforcementType: string };
}

// ── Vault object shapes ──────────────────────────────────────────

export interface VaultRarRole {
  /** Vault role name = last path segment of credsPath (e.g. "records-vip"). */
  roleName: string;
  /** verify-rar/creds/<role> — the path the gateway POSTs the OBO to. */
  credsPath: string;
  /** The RAR operationDetails.action this role's rar_mapping is keyed on. */
  action: string;
  /** The pre-baked NOLOGIN Postgres role granted to each ephemeral user. */
  pgRole: string;
  body: {
    db_name: string;
    creation_statements: string[];
    default_ttl: string;
    max_ttl: string;
    rar_mappings: Record<string, { grants: string[]; ttl: string }>;
  };
}

// ── Constants (mirrors the reference policy) ─────────────────────

/** IBM Verify mobile push / OTP method — used on every MFA + default rule. */
const MACOTP = 'urn:ibm:security:authentication:asf:macotp';
const CREDS_TTL = '5m';

// ── Naming helpers ───────────────────────────────────────────────

function pascalCase(s: string): string {
  return s
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join('');
}

/** Last `:`/`_`-delimited token, e.g. "record_delete" -> "delete". */
function lastToken(action: string): string {
  const parts = action.split(/[_:]/).filter(Boolean);
  return parts[parts.length - 1] ?? action;
}

/** PascalCase last colon-segment of the RAR type — the naming prefix. */
export function domainPrefix(rar: RarConfig): string {
  const seg = rar.rarType.split(':').filter(Boolean).pop() ?? rar.rarType;
  return pascalCase(seg);
}

/** Lowercase last colon-segment of the RAR type — the Postgres-role slug. */
export function domainSlug(rar: RarConfig): string {
  const seg = rar.rarType.split(':').filter(Boolean).pop() ?? rar.rarType;
  return seg.toLowerCase();
}

// ── Action classification (the single source of truth) ───────────

export interface ActionRoles {
  defaultAction: string;
  /** blocked: true actions -> the DENY rule. */
  denyActions: string[];
  /** the action some other action `elevatedFrom`s -> the VIP-read rule. */
  vipAction?: string;
  /** the rarAction shared by tier 2/3 write tools -> the write rules. */
  writeAction?: string;
  /** tier 2 tool name -> the standard-write disambiguator. */
  standardTool?: string;
  /** tier 3 tool name -> the sensitive-write disambiguator. */
  sensitiveTool?: string;
}

/**
 * Derive, from tools.json + rar.json, which action fills each policy role.
 * This is the ONE place the mapping is computed; the CELX + policy + Vault
 * generators all consume it, so they can never disagree about which action is
 * "the write action" or "the VIP action".
 */
export function classifyActions(tools: ToolsConfig, rar: RarConfig): ActionRoles {
  const defaultAction =
    Object.entries(rar.actions).find(([, a]) => a.default === true)?.[0] ?? '';

  const denyActions = Object.entries(rar.actions)
    .filter(([, a]) => a.blocked === true)
    .map(([name]) => name);

  // The elevated action is the one another action points at via elevatedFrom.
  const vipAction = Object.entries(rar.actions).find(([, a]) => a.elevatedFrom !== undefined)?.[0];

  // Write tools = tier 2 (standard) and tier 3 (sensitive). They share one
  // rarAction under the reference vocabularies (record_write / policy:update).
  const tier2Tools = Object.entries(tools).filter(([, t]) => t.tier === 2);
  const tier3Tools = Object.entries(tools).filter(([, t]) => t.tier === 3);
  const writeAction =
    tier2Tools[0]?.[1].rarAction ?? tier3Tools[0]?.[1].rarAction ?? undefined;

  // Forward-compat tool disambiguators. Both references have a tier-2 AND a
  // tier-3 write tool; where a domain has only one, both fall back to it (the
  // rule order still makes the stricter ACTION_MFA_ALWAYS win).
  const standardTool = tier2Tools[0]?.[0] ?? tier3Tools[0]?.[0];
  const sensitiveTool = tier3Tools[0]?.[0] ?? tier2Tools[0]?.[0];

  return { defaultAction, denyActions, vipAction, writeAction, standardTool, sensitiveTool };
}

/**
 * #2 (security review): fail fast if config/tools.json and config/rar.json
 * disagree. Every tool's rarAction must be a defined action, and only a tier-4
 * tool may map to a blocked action. Mirrors the runtime guard in the gateway
 * (policy/tiers.ts::assertToolActionsValid) so a bad config is rejected at
 * BOOTSTRAP time too — before wrong CELX/policies/roles are generated from it.
 */
export function validateToolRarActions(tools: ToolsConfig, rar: RarConfig): void {
  for (const [name, policy] of Object.entries(tools)) {
    const action = rar.actions[policy.rarAction];
    if (!action) {
      throw new Error(
        `config/tools.json: tool "${name}" uses rarAction "${policy.rarAction}" not defined in config/rar.json actions — it would silently collapse to the default action and skip its tier's step-up`,
      );
    }
    if (policy.tier !== 4 && action.blocked === true) {
      throw new Error(
        `config/tools.json: tier-${policy.tier} tool "${name}" maps to the blocked rarAction "${policy.rarAction}" — only tier-4 tools may use a blocked action`,
      );
    }
  }
}

// ── CELX builders (byte-faithful to the reference attributes) ────

/**
 * "authz preamble + exists(action)" CELX — used for the DENY and VIP-read
 * attributes. Matches the battle-tested reference cancel-deny / VIP-read
 * attribute shape exactly (indentation is load-bearing: CELX is
 * whitespace-sensitive YAML).
 */
function actionMatchCelx(varName: string, rarType: string, actions: string[]): string {
  const clause =
    actions.length === 1
      ? `ad.operationDetails.action == "${actions[0]}"`
      : `(${actions.map((a) => `ad.operationDetails.action == "${a}"`).join('\n           || ')})`;
  return `statements:
    - context: >
        authz := requestContext.getValue("authz") != ""
                    ? stringToJson(requestContext.getValue("authz"))
                    : []
    - context: >
        ${varName} := context.authz.exists(ad,
          ad.type == "${rarType}" &&
          ${clause})
    - return: context.${varName}
`;
}

/**
 * Sensitive-write CELX (tier 3). Matches the reference sensitive-write shape:
 * KNOWN LIMITATION — tier 2 and tier 3 both send action == writeAction today,
 * so until a future task adds operationDetails.tool to the RAR, has(...) is
 * false and the ternary falls through to `true`, matching EVERY write (the
 * safe, stricter-than-spec default: tier 2 also gets a push every call). Once
 * the tool field lands, this narrows to the tier-3 tool only.
 */
function sensitiveWriteCelx(rarType: string, writeAction: string, sensitiveTool: string): string {
  return `statements:
    - context: >
        authz := requestContext.getValue("authz") != ""
                    ? stringToJson(requestContext.getValue("authz"))
                    : []
    - context: >
        writeEntry := context.authz.exists(ad,
                        ad.type == "${rarType}" &&
                        ad.operationDetails.action == "${writeAction}")
                      ? context.authz.filter(ad,
                          ad.type == "${rarType}" &&
                          ad.operationDetails.action == "${writeAction}")[0]
                      : null
    - context: >
        hasTool := context.writeEntry != null && has(context.writeEntry.operationDetails.tool)
    - context: >
        isSensitive := context.writeEntry != null &&
                        (context.hasTool
                          ? context.writeEntry.operationDetails.tool == "${sensitiveTool}"
                          : true)
    - return: context.isSensitive
`;
}

/**
 * Standard-write CELX (tier 2). Matches the reference standard-write shape:
 * matches writeAction ONLY when a forward-compat operationDetails.tool is present
 * AND equals the tier-2 tool. Because the gateway never sets a tool field
 * today, has(...) is false and this NEVER matches under current ground truth —
 * all writes fall through to the sensitive (MFA_ALWAYS) rule (safe/stricter).
 * Exists so tier 2 auto-gets the lighter MFA_PER_SESSION the day a tool
 * disambiguator lands in the RAR, with zero Verify-side change.
 */
function standardWriteCelx(rarType: string, writeAction: string, standardTool: string): string {
  return `statements:
    - context: >
        authz := requestContext.getValue("authz") != ""
                    ? stringToJson(requestContext.getValue("authz"))
                    : []
    - context: >
        writeEntry := context.authz.exists(ad,
                        ad.type == "${rarType}" &&
                        ad.operationDetails.action == "${writeAction}")
                      ? context.authz.filter(ad,
                          ad.type == "${rarType}" &&
                          ad.operationDetails.action == "${writeAction}")[0]
                      : null
    - context: >
        isStandardWrite := context.writeEntry != null &&
                            has(context.writeEntry.operationDetails.tool) &&
                            context.writeEntry.operationDetails.tool == "${standardTool}"
    - return: context.isStandardWrite
`;
}

// ── Attribute names (deterministic, derived from config) ─────────

export interface AttributeNames {
  deny?: string;
  vip?: string;
  sensitive?: string;
  standard?: string;
}

export function attributeNames(tools: ToolsConfig, rar: RarConfig): AttributeNames {
  const prefix = domainPrefix(rar);
  const roles = classifyActions(tools, rar);
  const names: AttributeNames = {};
  if (roles.denyActions.length > 0) {
    const verb = roles.denyActions.length === 1 ? pascalCase(lastToken(roles.denyActions[0]!)) : 'Blocked';
    names.deny = `${prefix}${verb}Deny`;
  }
  if (roles.vipAction) names.vip = `${prefix}VipRead`;
  if (roles.writeAction) {
    names.sensitive = `${prefix}SensitiveWrite`;
    names.standard = `${prefix}StandardWrite`;
  }
  return names;
}

// ── Public generators ────────────────────────────────────────────

function attr(name: string, description: string, custom: string): AttributeDef {
  // id == name — a MUST per verify-admin-api.md: an auto-generated UUID id
  // leaves policy conditions pointing at a dead id after any rename.
  return {
    id: name,
    name,
    description,
    sourceType: 'static',
    datatype: 'string',
    tags: ['sso'],
    multiValued: false,
    function: { custom },
  };
}

/**
 * The (up to) 4 CELX custom attributes: DENY / VIP-read / sensitive-write /
 * standard-write. All POSTed with explicit id == name.
 */
export function generateCelxAttributes(tools: ToolsConfig, rar: RarConfig): AttributeDef[] {
  const roles = classifyActions(tools, rar);
  const names = attributeNames(tools, rar);
  const out: AttributeDef[] = [];

  if (names.deny && roles.denyActions.length > 0) {
    out.push(
      attr(
        names.deny,
        `Returns "true" when the request's authorization_details carries a ${rar.rarType} entry whose operationDetails.action is a blocked (tier 4) action [${roles.denyActions.join(', ')}]. Bound to ACTION_DENY as a defense-in-depth backstop — the gateway's tier gate already blocks tier-4 tools before Token Exchange, so this only fires if that gate is bypassed or removed.`,
        actionMatchCelx('isBlocked', rar.rarType, roles.denyActions),
      ),
    );
  }

  if (names.vip && roles.vipAction) {
    out.push(
      attr(
        names.vip,
        `Returns "true" when authorization_details carries a ${rar.rarType} entry with operationDetails.action == "${roles.vipAction}" — the gateway-derived VIP step-up action. Bound to ACTION_MFA_ALWAYS (step-up every call). The caller never sets this; the gateway elevates a VIP record's read to this action.`,
        actionMatchCelx('isVipRead', rar.rarType, [roles.vipAction]),
      ),
    );
  }

  if (names.sensitive && names.standard && roles.writeAction) {
    const sensitiveTool = roles.sensitiveTool ?? roles.standardTool ?? roles.writeAction;
    const standardTool = roles.standardTool ?? roles.sensitiveTool ?? roles.writeAction;
    out.push(
      attr(
        names.sensitive,
        `KNOWN LIMITATION: tier 2 and tier 3 writes both send operationDetails.action == "${roles.writeAction}" today, with no field distinguishing which tool ran. Forward-compatible: if a future task adds operationDetails.tool, this narrows to "${sensitiveTool}" (tier 3) only; until then has(...) is false and this matches EVERY write — the safe default (tier 3's "push every call" is never violated). Bound to ACTION_MFA_ALWAYS.`,
        sensitiveWriteCelx(rar.rarType, roles.writeAction, sensitiveTool),
      ),
    );
    out.push(
      attr(
        names.standard,
        `Companion to ${names.sensitive} (same known limitation). Matches operationDetails.action == "${roles.writeAction}" ONLY when a forward-compat operationDetails.tool field is present AND equals "${standardTool}" (tier 2). The gateway sets no tool field today, so this NEVER matches — all writes fall through to the sensitive ACTION_MFA_ALWAYS rule (safe/stricter). Exists so tier 2 auto-gets ACTION_MFA_PER_SESSION the day a tool disambiguator lands. Bound to ACTION_MFA_PER_SESSION.`,
        standardWriteCelx(rar.rarType, roles.writeAction, standardTool),
      ),
    );
  }

  return out;
}

function rule(
  id: string,
  name: string,
  description: string,
  attributeName: string,
  action: string,
): PolicyRule {
  return {
    id,
    name,
    description,
    alwaysRun: false,
    firstFactor: false,
    conditions: [
      {
        type: 'customAttributes',
        // IN, never EQ — EQ + a value list silently never matches
        // (verify-admin-api.md).
        customAttributes: [{ name: attributeName, opCode: 'IN', values: ['true'] }],
      },
    ],
    result: {
      action,
      serverSideActions: [],
      authnMethods: action === 'ACTION_DENY' ? [] : [MACOTP],
    },
  };
}

/**
 * The RAR-keyed HITL access policy, bound (by verify.ts) to the Token Exchange
 * app. Rule order (first match wins) is DENY -> VIP -> sensitive -> standard ->
 * default ALLOW. enforcementType lives under `meta` (top-level is silently
 * stripped -> policy ACTIVE but never evaluates).
 */
export function generateAccessPolicy(tools: ToolsConfig, rar: RarConfig): AccessPolicy {
  const prefix = domainPrefix(rar);
  const names = attributeNames(tools, rar);
  const rules: PolicyRule[] = [];

  if (names.deny) {
    rules.push(
      rule(
        '0',
        `${prefix} blocked-action hard deny`,
        'Defense-in-depth backstop for tier-4 (blocked) tools. The gateway blocks these before Token Exchange; this only fires if that gate is bypassed or removed.',
        names.deny,
        'ACTION_DENY',
      ),
    );
  }
  if (names.vip) {
    rules.push(
      rule(
        '1',
        `${prefix} VIP read step-up`,
        'Step-up MFA (every call) when the RAR carries the gateway-derived VIP-read action — protects VIP records from session-hijack reads.',
        names.vip,
        'ACTION_MFA_ALWAYS',
      ),
    );
  }
  if (names.sensitive) {
    rules.push(
      rule(
        '2',
        `${prefix} sensitive write (tier 3, push every call)`,
        'Tier-3 write. KNOWN LIMITATION: today this also matches tier-2 writes because both send identical RAR content — see the attribute description before changing rule order.',
        names.sensitive,
        'ACTION_MFA_ALWAYS',
      ),
    );
  }
  if (names.standard) {
    rules.push(
      rule(
        '3',
        `${prefix} standard write (tier 2, push once)`,
        'Tier-2 write. Currently unreachable (see the attribute description). Kept so tier 2 auto-gets the lighter once-per-session treatment the day a tool disambiguator lands in the RAR.',
        names.standard,
        'ACTION_MFA_PER_SESSION',
      ),
    );
  }

  rules.push({
    id: '100',
    name: 'Default rule',
    description: 'Standard (non-VIP) reads and anything unmatched above — token exchange succeeds immediately, no push.',
    alwaysRun: false,
    firstFactor: false,
    conditions: [],
    result: { action: 'ACTION_ALLOW', serverSideActions: [], authnMethods: [MACOTP] },
  });

  return {
    name: `${prefix}-RAR-HITL`,
    description: `${prefix} — RAR-keyed HITL. Bound to the Token Exchange app. Rule order (first match wins): blocked-action DENY -> VIP read (MFA every call) -> sensitive write (MFA every call) -> standard write (MFA once) -> default allow.`,
    containsFirstFactor: false,
    rules,
    meta: {
      state: 'ACTIVE',
      schema: 'urn:access:policy:5.0:schema',
      label: 'initial revision',
      scope: ['administrators'],
      enforcementType: 'fedSSO',
    },
  };
}

/** Unique registered scopes across all tools (records:read, records:write). */
export function toolScopes(tools: ToolsConfig): string[] {
  return [...new Set(Object.values(tools).map((t) => t.scope))].sort();
}

// ── Vault generators ─────────────────────────────────────────────

function lastPathSegment(p: string): string {
  const parts = p.split('/').filter(Boolean);
  return parts[parts.length - 1] ?? p;
}

/**
 * One verify-rar role per non-blocked action's creds path. rar_mappings is
 * keyed "<rarType>|<action>" and its VALUE MUST be an { grants:[...], ttl }
 * object — a plain string 400s (a hard-won reference gotcha). The Postgres role
 * granted is derived from the SAME tier-driven classification the CELX/policy
 * generation uses (classifyActions), NOT a positional scan over rar.json:
 *   - the write action (from tier-2/3 tools)      -> <slug>_write
 *   - the elevated/VIP action (elevatedFrom)       -> <slug>_read_vip (a role
 *     that CAN read VIP rows; the base <slug>_read is restricted to non-VIP)
 *   - every other read action                      -> <slug>_read
 * so a DB grant can never disagree with the policy, and an extra read action
 * that happens to carry its own creds path is never mistaken for "the write
 * action" (matches examples/db/vault-roles.sql).
 */
export function generateVaultRoles(rar: RarConfig, dbName: string, tools: ToolsConfig): VaultRarRole[] {
  const slug = domainSlug(rar);
  const { writeAction, vipAction } = classifyActions(tools, rar);
  const out: VaultRarRole[] = [];

  for (const [action, cfg] of Object.entries(rar.actions)) {
    if (cfg.blocked === true || !cfg.credsPath) continue;
    const pgRole =
      action === writeAction
        ? `${slug}_write`
        : action === vipAction
          ? `${slug}_read_vip`
          : `${slug}_read`;
    const roleName = lastPathSegment(cfg.credsPath);
    out.push({
      roleName,
      credsPath: cfg.credsPath,
      action,
      pgRole,
      body: {
        db_name: dbName,
        creation_statements: [
          `CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`,
          `GRANT ${pgRole} TO "{{name}}";`,
        ],
        default_ttl: CREDS_TTL,
        max_ttl: '1h',
        rar_mappings: {
          [`${rar.rarType}|${action}`]: {
            grants: [`GRANT ${pgRole} TO "{{name}}"`],
            ttl: CREDS_TTL,
          },
        },
      },
    });
  }
  return out;
}

/**
 * The runtime ACL policy attached to BOTH oauth-rs entities (subject + actor).
 * Grants read+update on every verify-rar/creds/* the gateway mints from, plus
 * update on sys/leases/revoke (early lease revoke). Optional extra paths cover
 * the ibm-verify plugin creds path in vault-mode secrets.
 */
export function generateRuntimePolicyHcl(rar: RarConfig, extraReadPaths: string[] = []): string {
  const credsPaths = Object.values(rar.actions)
    .filter((a) => a.blocked !== true && a.credsPath)
    .map((a) => a.credsPath!);
  const blocks: string[] = [
    '# Runtime policy for the gateway agent — attached to the OAuth-RS-resolved',
    '# subject + actor entities. Read+update on each verify-rar creds path the',
    '# gateway mints ephemeral Postgres credentials from.',
  ];
  for (const p of credsPaths) {
    blocks.push(`path "${p}" {\n  capabilities = ["read", "update"]\n}`);
  }
  for (const p of extraReadPaths) {
    blocks.push(`path "${p}" {\n  capabilities = ["read"]\n}`);
  }
  blocks.push('# Early-revoke ephemeral leases.');
  blocks.push('path "sys/leases/revoke" {\n  capabilities = ["update"]\n}');
  return blocks.join('\n\n') + '\n';
}
