/**
 * Tests for rar/rar-config.ts — the config/rar.json loader + validator.
 *
 * Coverage:
 *   - a good config parses, with defaultAction + elevationByBase derived
 *   - the SHIPPED config/rar.json singleton loads and matches the default
 *     "records" vocabulary
 *   - validation failures each throw a NAMED RarConfigError (startup, not
 *     first-request): missing/duplicate default, dangling elevatedFrom,
 *     ambiguous elevation, blocked default, empty rarType/idField/argIdKey,
 *     missing credsPath on a non-blocked action, malformed vipElevation
 *   - vipElevation is optional — absence just disables VIP discovery
 *   - isElevatedCredsPath keys off elevatedFrom entries, not a path-suffix
 *     naming convention
 */
import { describe, it, expect } from 'vitest';
import { parseRarConfig, isElevatedCredsPath, rarConfig, RarConfigError } from './rar-config.js';

/** A valid custom-domain fixture (nothing "records" about it). */
function ticketsConfig(): Record<string, unknown> {
  return {
    rarType: 'urn:example:agent:tickets',
    idField: 'ticket_id',
    argIdKey: 'ticketId',
    actions: {
      ticket_read: { credsPath: 'verify-rar/creds/tickets', default: true },
      ticket_read_priority: {
        credsPath: 'verify-rar/creds/tickets-priority',
        elevatedFrom: 'ticket_read',
      },
      ticket_write: { credsPath: 'verify-rar/creds/tickets-write' },
      ticket_purge: { blocked: true },
    },
    vipElevation: { discoveryTools: ['get_ticket'], vipField: 'priority_flag' },
  };
}

describe('parseRarConfig — good config', () => {
  it('parses a valid custom-domain config and derives defaultAction + elevationByBase', () => {
    const cfg = parseRarConfig(ticketsConfig());
    expect(cfg.rarType).toBe('urn:example:agent:tickets');
    expect(cfg.idField).toBe('ticket_id');
    expect(cfg.argIdKey).toBe('ticketId');
    expect(cfg.defaultAction).toBe('ticket_read');
    expect(cfg.elevationByBase).toEqual({ ticket_read: 'ticket_read_priority' });
    expect(cfg.vipElevation).toEqual({ discoveryTools: ['get_ticket'], vipField: 'priority_flag' });
  });

  it('treats vipElevation as optional — absence disables VIP discovery, no error', () => {
    const raw = ticketsConfig();
    delete raw['vipElevation'];
    const cfg = parseRarConfig(raw);
    expect(cfg.vipElevation.discoveryTools).toEqual([]);
  });
});

describe('the shipped config/rar.json singleton', () => {
  it('loads at import with the default "records" vocabulary', () => {
    expect(rarConfig.rarType).toBe('urn:example:agent:records');
    expect(rarConfig.idField).toBe('record_id');
    expect(rarConfig.argIdKey).toBe('recordId');
    expect(rarConfig.defaultAction).toBe('record_read');
    expect(rarConfig.elevationByBase).toEqual({ record_read: 'record_read_vip' });
    expect(rarConfig.vipElevation).toEqual({
      discoveryTools: ['get_record', 'get_record_detail', 'get_record_history'],
      probeTool: 'get_record',
      vipField: 'vip_flag',
    });
    // The blocked entry is kept for documentation/validation (tier 4 gates
    // in tiers.ts) — it never carries a credsPath.
    expect(rarConfig.actions['record_delete']).toEqual({ blocked: true });
  });
});

describe('parseRarConfig — validation failures (named error at startup)', () => {
  function expectRarConfigError(raw: unknown, pattern: RegExp): void {
    let thrown: unknown;
    try {
      parseRarConfig(raw);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(RarConfigError);
    expect((thrown as Error).name).toBe('RarConfigError');
    expect((thrown as Error).message).toMatch(pattern);
  }

  it('rejects a config with NO default:true action', () => {
    const raw = ticketsConfig();
    delete ((raw['actions'] as Record<string, Record<string, unknown>>)['ticket_read'] as Record<string, unknown>)[
      'default'
    ];
    expectRarConfigError(raw, /exactly one action must set "default": true \(found 0\)/);
  });

  it('rejects a config with TWO default:true actions', () => {
    const raw = ticketsConfig();
    (raw['actions'] as Record<string, Record<string, unknown>>)['ticket_write']!['default'] = true;
    expectRarConfigError(raw, /exactly one action must set "default": true \(found 2\)/);
  });

  it('rejects a dangling elevatedFrom (references a nonexistent action)', () => {
    const raw = ticketsConfig();
    (raw['actions'] as Record<string, Record<string, unknown>>)['ticket_read_priority']!['elevatedFrom'] =
      'no_such_action';
    expectRarConfigError(raw, /elevatedFrom references unknown action "no_such_action"/);
  });

  it('rejects two actions elevating from the same base (ambiguous elevation)', () => {
    const raw = ticketsConfig();
    (raw['actions'] as Record<string, Record<string, unknown>>)['ticket_write']!['elevatedFrom'] = 'ticket_read';
    expectRarConfigError(raw, /elevation must be unambiguous/);
  });

  it('rejects a blocked default action', () => {
    const raw = ticketsConfig();
    (raw['actions'] as Record<string, Record<string, unknown>>)['ticket_read']!['blocked'] = true;
    expectRarConfigError(raw, /default action .* must not be blocked/);
  });

  it.each(['rarType', 'idField', 'argIdKey'] as const)('rejects an empty %s', (field) => {
    const raw = ticketsConfig();
    raw[field] = '';
    expectRarConfigError(raw, new RegExp(`"${field}" must be a non-empty string`));
  });

  it('rejects a non-blocked action with no credsPath', () => {
    const raw = ticketsConfig();
    delete (raw['actions'] as Record<string, Record<string, unknown>>)['ticket_write']!['credsPath'];
    expectRarConfigError(raw, /actions\.ticket_write\.credsPath/);
  });

  it('rejects an empty actions object', () => {
    const raw = ticketsConfig();
    raw['actions'] = {};
    expectRarConfigError(raw, /"actions" must be a non-empty object/);
  });

  it('rejects a vipElevation with an empty vipField', () => {
    const raw = ticketsConfig();
    raw['vipElevation'] = { discoveryTools: ['get_ticket'], vipField: '' };
    expectRarConfigError(raw, /vipElevation\.vipField/);
  });

  it('rejects a vipElevation whose discoveryTools is not a string array', () => {
    const raw = ticketsConfig();
    raw['vipElevation'] = { discoveryTools: [42], vipField: 'priority_flag' };
    expectRarConfigError(raw, /vipElevation\.discoveryTools must be an array of tool-name strings/);
  });

  it('accepts a probeTool that is listed in discoveryTools', () => {
    const raw = ticketsConfig();
    raw['vipElevation'] = { discoveryTools: ['get_ticket', 'get_ticket_line'], probeTool: 'get_ticket', vipField: 'priority_flag' };
    expect(parseRarConfig(raw).vipElevation.probeTool).toBe('get_ticket');
  });

  it('rejects a probeTool that is NOT listed in discoveryTools', () => {
    const raw = ticketsConfig();
    raw['vipElevation'] = { discoveryTools: ['get_ticket'], probeTool: 'not_a_discovery_tool', vipField: 'priority_flag' };
    expectRarConfigError(raw, /probeTool.*must be listed in discoveryTools/);
  });
});

describe('isElevatedCredsPath', () => {
  it('recognizes an elevated creds path via elevatedFrom (custom config)', () => {
    const cfg = parseRarConfig(ticketsConfig());
    expect(isElevatedCredsPath('verify-rar/creds/tickets-priority', cfg)).toBe(true);
    expect(isElevatedCredsPath('verify-rar/creds/tickets', cfg)).toBe(false);
    expect(isElevatedCredsPath('verify-rar/creds/tickets-write', cfg)).toBe(false);
  });

  it('matches the default config the same way the old "-vip" suffix heuristic did', () => {
    expect(isElevatedCredsPath('verify-rar/creds/records-vip')).toBe(true);
    expect(isElevatedCredsPath('verify-rar/creds/records')).toBe(false);
    expect(isElevatedCredsPath('verify-rar/creds/records-write')).toBe(false);
  });
});
