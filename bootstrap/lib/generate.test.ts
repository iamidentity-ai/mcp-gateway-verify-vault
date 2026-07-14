/**
 * Tests for lib/generate.ts — the PURE config -> Verify/Vault artifact
 * generators. Driven with BOTH the shipped "records" config (loaded from the
 * gateway's own config files) and a custom "tickets" fixture, proving the
 * generators retarget with zero code change.
 */
import { describe, it, expect } from 'vitest';
import { loadTools, loadRarConfig, type ToolsConfig, type RarConfig } from './config.js';
import {
  domainPrefix,
  domainSlug,
  classifyActions,
  validateToolRarActions,
  attributeNames,
  generateCelxAttributes,
  generateAccessPolicy,
  generateVaultRoles,
  generateRuntimePolicyHcl,
  toolScopes,
} from './generate.js';

// ── Custom-domain fixture (nothing "records" about it) ───────────
function ticketsRar(): RarConfig {
  return {
    rarType: 'urn:example:agent:tickets',
    idField: 'ticket_id',
    argIdKey: 'ticketId',
    actions: {
      ticket_read: { credsPath: 'verify-rar/creds/tickets', default: true },
      ticket_read_priority: { credsPath: 'verify-rar/creds/tickets-priority', elevatedFrom: 'ticket_read' },
      ticket_write: { credsPath: 'verify-rar/creds/tickets-write' },
      ticket_purge: { blocked: true },
    },
    vipElevation: { discoveryTools: ['get_ticket'], vipField: 'priority_flag' },
  };
}
function ticketsTools(): ToolsConfig {
  return {
    get_ticket: { tier: 1, rarAction: 'ticket_read', scope: 'tickets:read' },
    update_ticket: { tier: 2, rarAction: 'ticket_write', scope: 'tickets:write' },
    escalate_ticket: { tier: 3, rarAction: 'ticket_write', scope: 'tickets:write' },
    purge_ticket: { tier: 4, rarAction: 'ticket_purge', scope: 'tickets:write' },
  };
}

describe('naming helpers', () => {
  it('derives the prefix + slug from the RAR type last segment', () => {
    expect(domainPrefix(loadRarConfig())).toBe('Records');
    expect(domainSlug(loadRarConfig())).toBe('records');
    expect(domainPrefix(ticketsRar())).toBe('Tickets');
    expect(domainSlug(ticketsRar())).toBe('tickets');
  });
});

describe('validateToolRarActions (#2 config cross-validation)', () => {
  it('passes the shipped records config', () => {
    expect(() => validateToolRarActions(loadTools(), loadRarConfig())).not.toThrow();
  });
  it('throws when a tool uses a rarAction absent from rar.json', () => {
    expect(() =>
      validateToolRarActions({ x: { tier: 3, rarAction: 'record_escalate', scope: 's' } }, loadRarConfig()),
    ).toThrow(/not defined in config\/rar\.json/);
  });
  it('throws when a non-tier-4 tool maps to a blocked action', () => {
    expect(() =>
      validateToolRarActions({ x: { tier: 2, rarAction: 'record_delete', scope: 's' } }, loadRarConfig()),
    ).toThrow(/blocked rarAction/);
  });
});

describe('classifyActions', () => {
  it('maps the shipped records config to policy roles', () => {
    const roles = classifyActions(loadTools(), loadRarConfig());
    expect(roles.defaultAction).toBe('record_read');
    expect(roles.denyActions).toEqual(['record_delete']);
    expect(roles.vipAction).toBe('record_read_vip');
    expect(roles.writeAction).toBe('record_write');
    expect(roles.standardTool).toBe('update_record'); // tier 2
    expect(roles.sensitiveTool).toBe('update_contact'); // tier 3
  });

  it('maps the custom tickets config the same way', () => {
    const roles = classifyActions(ticketsTools(), ticketsRar());
    expect(roles.denyActions).toEqual(['ticket_purge']);
    expect(roles.vipAction).toBe('ticket_read_priority');
    expect(roles.writeAction).toBe('ticket_write');
    expect(roles.standardTool).toBe('update_ticket');
    expect(roles.sensitiveTool).toBe('escalate_ticket');
  });
});

describe('generateCelxAttributes (records)', () => {
  const attrs = generateCelxAttributes(loadTools(), loadRarConfig());
  const byName = Object.fromEntries(attrs.map((a) => [a.name, a]));

  it('produces exactly the 4 attributes with id == name', () => {
    expect(attrs).toHaveLength(4);
    for (const a of attrs) {
      expect(a.id).toBe(a.name);
      expect(a.sourceType).toBe('static');
      expect(a.datatype).toBe('string');
      expect(a.tags).toEqual(['sso']);
    }
    expect(Object.keys(byName).sort()).toEqual([
      'RecordsDeleteDeny',
      'RecordsSensitiveWrite',
      'RecordsStandardWrite',
      'RecordsVipRead',
    ]);
  });

  it('keys the deny CELX on the blocked action', () => {
    expect(byName['RecordsDeleteDeny']!.function.custom).toContain('ad.operationDetails.action == "record_delete"');
    expect(byName['RecordsDeleteDeny']!.function.custom).toContain('ad.type == "urn:example:agent:records"');
  });

  it('keys the VIP CELX on the elevated read action', () => {
    expect(byName['RecordsVipRead']!.function.custom).toContain('ad.operationDetails.action == "record_read_vip"');
  });

  it('keys both write CELX on record_write and disambiguates by tool', () => {
    expect(byName['RecordsSensitiveWrite']!.function.custom).toContain('ad.operationDetails.action == "record_write"');
    expect(byName['RecordsSensitiveWrite']!.function.custom).toContain('operationDetails.tool == "update_contact"');
    expect(byName['RecordsStandardWrite']!.function.custom).toContain('operationDetails.tool == "update_record"');
  });
});

describe('generateCelxAttributes (tickets — genericity)', () => {
  it('produces tickets-prefixed attributes keyed on the tickets RAR type', () => {
    const attrs = generateCelxAttributes(ticketsTools(), ticketsRar());
    const names = attrs.map((a) => a.name).sort();
    expect(names).toEqual([
      'TicketsPurgeDeny',
      'TicketsSensitiveWrite',
      'TicketsStandardWrite',
      'TicketsVipRead',
    ]);
    const deny = attrs.find((a) => a.name === 'TicketsPurgeDeny')!;
    expect(deny.function.custom).toContain('ad.operationDetails.action == "ticket_purge"');
    expect(deny.function.custom).toContain('urn:example:agent:tickets');
  });
});

describe('generateAccessPolicy (records)', () => {
  const policy = generateAccessPolicy(loadTools(), loadRarConfig());

  it('orders rules DENY -> MFA_ALWAYS(vip) -> MFA_ALWAYS(sensitive) -> MFA_PER_SESSION -> ALLOW', () => {
    expect(policy.rules.map((r) => r.result.action)).toEqual([
      'ACTION_DENY',
      'ACTION_MFA_ALWAYS',
      'ACTION_MFA_ALWAYS',
      'ACTION_MFA_PER_SESSION',
      'ACTION_ALLOW',
    ]);
  });

  it('names the policy from the domain prefix and puts enforcementType under meta', () => {
    expect(policy.name).toBe('Records-RAR-HITL');
    expect(policy.meta.enforcementType).toBe('fedSSO');
    expect(policy.meta.state).toBe('ACTIVE');
    // enforcementType must NOT leak to the top level (silent strip trap).
    expect((policy as unknown as Record<string, unknown>)['enforcementType']).toBeUndefined();
  });

  it('uses IN opCode against the generated attribute names', () => {
    const names = attributeNames(loadTools(), loadRarConfig());
    const conds = policy.rules.flatMap((r) => r.conditions.flatMap((c) => c.customAttributes));
    for (const c of conds) expect(c.opCode).toBe('IN');
    const referenced = conds.map((c) => c.name);
    expect(referenced).toContain(names.deny);
    expect(referenced).toContain(names.vip);
    expect(referenced).toContain(names.sensitive);
    expect(referenced).toContain(names.standard);
  });

  it('the deny rule carries no authnMethods; MFA rules carry macotp', () => {
    const deny = policy.rules.find((r) => r.result.action === 'ACTION_DENY')!;
    expect(deny.result.authnMethods).toEqual([]);
    const mfa = policy.rules.find((r) => r.result.action === 'ACTION_MFA_ALWAYS')!;
    expect(mfa.result.authnMethods).toEqual(['urn:ibm:security:authentication:asf:macotp']);
  });
});

describe('toolScopes', () => {
  it('returns the unique registered scopes', () => {
    expect(toolScopes(loadTools())).toEqual(['records:read', 'records:write']);
    expect(toolScopes(ticketsTools())).toEqual(['tickets:read', 'tickets:write']);
  });
});

describe('generateVaultRoles (records)', () => {
  const roles = generateVaultRoles(loadRarConfig(), 'records', loadTools());

  it('creates one role per non-blocked creds path, skipping the blocked action', () => {
    expect(roles.map((r) => r.roleName).sort()).toEqual(['records', 'records-vip', 'records-write']);
  });

  it('keys rar_mappings on <rarType>|<action> with an object value (not a string)', () => {
    const read = roles.find((r) => r.roleName === 'records')!;
    const mapping = read.body.rar_mappings['urn:example:agent:records|record_read'];
    expect(mapping).toBeDefined();
    expect(mapping!.grants).toEqual(['GRANT records_read TO "{{name}}"']);
    expect(mapping!.ttl).toBe('5m');
    expect(typeof mapping).toBe('object');
  });

  it('grants a DISTINCT read_vip PG role to the VIP role (base records_read is RLS-restricted to non-VIP rows)', () => {
    const vip = roles.find((r) => r.roleName === 'records-vip')!;
    expect(vip.pgRole).toBe('records_read_vip');
    expect(vip.body.rar_mappings['urn:example:agent:records|record_read_vip']!.grants).toEqual([
      'GRANT records_read_vip TO "{{name}}"',
    ]);
  });

  it('grants the write PG role to the write role, 5m default TTL', () => {
    const write = roles.find((r) => r.roleName === 'records-write')!;
    expect(write.pgRole).toBe('records_write');
    expect(write.body.default_ttl).toBe('5m');
    expect(write.body.db_name).toBe('records');
  });
});

describe('generateVaultRoles (tickets — genericity)', () => {
  it('produces tickets-prefixed PG roles + creds paths with zero code change', () => {
    const roles = generateVaultRoles(ticketsRar(), 'tickets_db', ticketsTools());
    expect(roles.map((r) => r.roleName).sort()).toEqual(['tickets', 'tickets-priority', 'tickets-write']);
    const write = roles.find((r) => r.roleName === 'tickets-write')!;
    expect(write.pgRole).toBe('tickets_write');
    expect(write.body.db_name).toBe('tickets_db');
    expect(write.body.rar_mappings['urn:example:agent:tickets|ticket_write']).toBeDefined();
    // The priority (elevated) action gets the distinct read_vip role.
    expect(roles.find((r) => r.roleName === 'tickets-priority')!.pgRole).toBe('tickets_read_vip');
  });

  // ── #7 regression: grant derived from TIER, not rar.json position ─────────
  it('#7: an extra read action carrying its own creds path is NOT mis-granted the write role', () => {
    const rar: RarConfig = {
      rarType: 'urn:example:agent:tickets',
      idField: 'ticket_id',
      argIdKey: 'ticketId',
      actions: {
        ticket_read: { credsPath: 'verify-rar/creds/tickets', default: true },
        // an EXTRA read path, positioned BEFORE the write action — the old
        // positional heuristic (first non-default/non-elevated w/ credsPath)
        // would have picked THIS as "the write action".
        ticket_read_pii: { credsPath: 'verify-rar/creds/tickets-pii' },
        ticket_write: { credsPath: 'verify-rar/creds/tickets-write' },
      },
      vipElevation: { discoveryTools: [], vipField: '' },
    } as RarConfig;
    const tools: ToolsConfig = {
      get_ticket: { tier: 1, rarAction: 'ticket_read', scope: 'tickets:read' },
      get_ticket_pii: { tier: 1, rarAction: 'ticket_read_pii', scope: 'tickets:read' },
      update_ticket: { tier: 2, rarAction: 'ticket_write', scope: 'tickets:write' },
    };
    const roles = generateVaultRoles(rar, 'tickets_db', tools);
    // The extra read gets a READ grant; only the tier-2-backed action is write.
    expect(roles.find((r) => r.roleName === 'tickets-pii')!.pgRole).toBe('tickets_read');
    expect(roles.find((r) => r.roleName === 'tickets-write')!.pgRole).toBe('tickets_write');
  });
});

describe('generateRuntimePolicyHcl', () => {
  it('grants read+update on every creds path plus sys/leases/revoke', () => {
    const hcl = generateRuntimePolicyHcl(loadRarConfig());
    expect(hcl).toContain('path "verify-rar/creds/records" {');
    expect(hcl).toContain('path "verify-rar/creds/records-vip" {');
    expect(hcl).toContain('path "verify-rar/creds/records-write" {');
    expect(hcl).toContain('path "sys/leases/revoke" {');
    expect(hcl).toContain('capabilities = ["read", "update"]');
    // the blocked action has no creds path -> no policy stanza for it
    expect(hcl).not.toContain('record_delete');
  });

  it('appends optional read-only extra paths (ibm-verify plugin creds)', () => {
    const hcl = generateRuntimePolicyHcl(loadRarConfig(), ['ibm-verify/creds/gateway-exchange']);
    expect(hcl).toContain('path "ibm-verify/creds/gateway-exchange" {');
    expect(hcl).toContain('capabilities = ["read"]');
  });
});
