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
 *     missing credsPath on a non-blocked action, malformed stepUp
 *   - stepUp is optional — absence just disables step-up discovery
 *   - isElevatedCredsPath keys off elevatedFrom entries, not a path-suffix
 *     naming convention
 */
import { describe, it, expect } from 'vitest';
import { parseRarConfig, isElevatedCredsPath, rarConfig, RarConfigError } from './rar-config.js';

/** A valid custom-domain fixture (nothing "records" about it). Note the
 *  DIFFERENT matcher (`in`) — proving elevateWhen is generic, not a boolean. */
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
    stepUp: { discoveryTools: ['get_ticket'], elevateWhen: { field: 'priority', in: ['high', 'urgent'] } },
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
    expect(cfg.stepUp).toEqual({ discoveryTools: ['get_ticket'], elevateWhen: { field: 'priority', in: ['high', 'urgent'] } });
  });

  it('treats stepUp as optional — absence disables step-up discovery, no error', () => {
    const raw = ticketsConfig();
    delete raw['stepUp'];
    const cfg = parseRarConfig(raw);
    expect(cfg.stepUp.discoveryTools).toEqual([]);
  });
});

describe('the shipped config/rar.json singleton', () => {
  it('loads at import with the default "records" vocabulary', () => {
    expect(rarConfig.rarType).toBe('urn:example:agent:records');
    expect(rarConfig.idField).toBe('record_id');
    expect(rarConfig.argIdKey).toBe('recordId');
    expect(rarConfig.defaultAction).toBe('record_read');
    expect(rarConfig.elevationByBase).toEqual({ record_read: 'record_read_elevated' });
    expect(rarConfig.stepUp).toEqual({
      discoveryTools: ['get_record', 'get_record_detail', 'get_record_history'],
      probeTool: 'get_record',
      elevateWhen: { field: 'classification', notIn: ['public', 'internal'] },
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

  it('rejects a stepUp with an empty elevateWhen.field', () => {
    const raw = ticketsConfig();
    raw['stepUp'] = { discoveryTools: ['get_ticket'], elevateWhen: { field: '', in: ['high'] } };
    expectRarConfigError(raw, /stepUp\.elevateWhen\.field/);
  });

  it('rejects a stepUp whose elevateWhen sets NO matcher', () => {
    const raw = ticketsConfig();
    raw['stepUp'] = { discoveryTools: ['get_ticket'], elevateWhen: { field: 'priority' } };
    expectRarConfigError(raw, /must set EXACTLY ONE of equals\/in\/notIn \(found 0\)/);
  });

  it('rejects a stepUp whose elevateWhen sets MORE THAN ONE matcher', () => {
    const raw = ticketsConfig();
    raw['stepUp'] = { discoveryTools: ['get_ticket'], elevateWhen: { field: 'priority', in: ['high'], notIn: ['low'] } };
    expectRarConfigError(raw, /must set EXACTLY ONE of equals\/in\/notIn \(found 2\)/);
  });

  it('rejects a stepUp whose elevateWhen.in is not an array', () => {
    const raw = ticketsConfig();
    raw['stepUp'] = { discoveryTools: ['get_ticket'], elevateWhen: { field: 'priority', in: 'high' } };
    expectRarConfigError(raw, /stepUp\.elevateWhen\.in .* must be an array/);
  });

  it('accepts the notIn fail-closed safe-list matcher', () => {
    const raw = ticketsConfig();
    raw['stepUp'] = { discoveryTools: ['get_ticket'], elevateWhen: { field: 'classification', notIn: ['public', 'internal'] } };
    expect(parseRarConfig(raw).stepUp.elevateWhen).toEqual({ field: 'classification', notIn: ['public', 'internal'] });
  });

  it('rejects a stepUp whose discoveryTools is not a string array', () => {
    const raw = ticketsConfig();
    raw['stepUp'] = { discoveryTools: [42], elevateWhen: { field: 'priority', in: ['high'] } };
    expectRarConfigError(raw, /stepUp\.discoveryTools must be an array of tool-name strings/);
  });

  it('accepts a probeTool that is listed in discoveryTools', () => {
    const raw = ticketsConfig();
    raw['stepUp'] = { discoveryTools: ['get_ticket', 'get_ticket_line'], probeTool: 'get_ticket', elevateWhen: { field: 'priority', in: ['high'] } };
    expect(parseRarConfig(raw).stepUp.probeTool).toBe('get_ticket');
  });

  it('rejects a probeTool that is NOT listed in discoveryTools', () => {
    const raw = ticketsConfig();
    raw['stepUp'] = { discoveryTools: ['get_ticket'], probeTool: 'not_a_discovery_tool', elevateWhen: { field: 'priority', in: ['high'] } };
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

  it('matches the default config the same way the old "-elevated" suffix heuristic did', () => {
    expect(isElevatedCredsPath('verify-rar/creds/records-elevated')).toBe(true);
    expect(isElevatedCredsPath('verify-rar/creds/records')).toBe(false);
    expect(isElevatedCredsPath('verify-rar/creds/records-write')).toBe(false);
  });
});
