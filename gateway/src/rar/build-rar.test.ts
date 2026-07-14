/**
 * Tests for rar/build-rar.ts
 *
 * Coverage:
 *   - buildRAR shape (3 elements: business + 2× vault:path_access)
 *   - business RAR type + operationDetails.action + subaction nesting
 *   - record_id present only when passed
 *   - VIP read collapses to record_read_vip + records-vip path
 *   - record_write routes to records-write path (vip ignored on writes)
 *   - vaultRarAction / vaultCredsPath collapse rules directly
 *   - resolveRar: single source of truth for authorizationDetails + credsPath
 *     — the two must always AGREE on the collapsed action
 */
import { describe, it, expect } from 'vitest';
import { buildRAR, vaultRarAction, vaultCredsPath, resolveRar } from './build-rar.js';
import { parseRarConfig } from './rar-config.js';

describe('buildRAR', () => {
  it('produces a 3-element array (business + 2× vault:path_access)', () => {
    const rar = buildRAR({ rarAction: 'record_read' });
    expect(rar).toHaveLength(3);
  });

  it('business element carries type + operationDetails.action + subaction', () => {
    const rar = buildRAR({ rarAction: 'record_read' });
    const [business] = rar;
    expect(business.type).toBe('urn:example:agent:records');
    expect((business as any).operationDetails.action).toBe('record_read');
    expect((business as any).operationDetails.subaction).toBe('record_read');
  });

  it('includes record_id in operationDetails when passed', () => {
    const rar = buildRAR({ rarAction: 'record_read', recordId: 'REC-1001' });
    expect((rar[0] as any).operationDetails.record_id).toBe('REC-1001');
  });

  it('omits record_id from operationDetails when not passed', () => {
    const rar = buildRAR({ rarAction: 'record_read' });
    expect((rar[0] as any).operationDetails.record_id).toBeUndefined();
  });

  it('both vault:path_access elements are present (creds path + sys/leases/revoke)', () => {
    const rar = buildRAR({ rarAction: 'record_read' });
    const [, credsPath, leasesPath] = rar;

    expect(credsPath.type).toBe('vault:path_access');
    expect((credsPath as any).path_constraint).toBe('verify-rar/creds/records');
    expect((credsPath as any).action).toBe('update');

    expect(leasesPath.type).toBe('vault:path_access');
    expect((leasesPath as any).path_constraint).toBe('sys/leases/revoke');
    expect((leasesPath as any).action).toBe('update');
  });

  it('a VIP read collapses to record_read_vip and the -vip creds path', () => {
    const rar = buildRAR({ rarAction: 'record_read', vip: true });
    expect((rar[0] as any).operationDetails.action).toBe('record_read_vip');
    // subaction preserves the ORIGINAL rarAction, not the collapsed value
    expect((rar[0] as any).operationDetails.subaction).toBe('record_read');
    expect((rar[1] as any).path_constraint).toBe('verify-rar/creds/records-vip');
  });

  it('record_write routes to records-write regardless of vip', () => {
    const rar = buildRAR({ rarAction: 'record_write', vip: true });
    expect((rar[0] as any).operationDetails.action).toBe('record_write');
    expect((rar[1] as any).path_constraint).toBe('verify-rar/creds/records-write');
  });
});

describe('vaultRarAction (Vault role-mapping collapse)', () => {
  it('preserves record_read_vip', () => {
    expect(vaultRarAction('record_read_vip')).toBe('record_read_vip');
  });

  it('preserves record_write', () => {
    expect(vaultRarAction('record_write')).toBe('record_write');
  });

  it('collapses everything else onto record_read', () => {
    expect(vaultRarAction('record_read')).toBe('record_read');
    expect(vaultRarAction('record_delete')).toBe('record_read');
    expect(vaultRarAction('something_new')).toBe('record_read');
  });
});

describe('vaultCredsPath', () => {
  it('maps collapsed actions to their Vault creds paths', () => {
    expect(vaultCredsPath('record_read_vip')).toBe('verify-rar/creds/records-vip');
    expect(vaultCredsPath('record_write')).toBe('verify-rar/creds/records-write');
    expect(vaultCredsPath('record_read')).toBe('verify-rar/creds/records');
  });
});

describe('resolveRar (single source of truth for authorizationDetails + credsPath)', () => {
  it('VIP read: credsPath is the -vip path AND authorizationDetails agree on record_read_vip', () => {
    const { authorizationDetails, credsPath, collapsedAction } = resolveRar({
      rarAction: 'record_read',
      vip: true,
    });

    expect(credsPath).toBe('verify-rar/creds/records-vip');
    expect(collapsedAction).toBe('record_read_vip');
    expect((authorizationDetails[0] as any).operationDetails.action).toBe('record_read_vip');
    // subaction preserves the ORIGINAL rarAction, not the collapsed value
    expect((authorizationDetails[0] as any).operationDetails.subaction).toBe('record_read');
    // the vault:path_access element's path_constraint must match credsPath too
    expect((authorizationDetails[1] as any).path_constraint).toBe(credsPath);
  });

  it('non-VIP read: credsPath is the standard path AND authorizationDetails agree on record_read', () => {
    const { authorizationDetails, credsPath, collapsedAction } = resolveRar({
      rarAction: 'record_read',
    });

    expect(credsPath).toBe('verify-rar/creds/records');
    expect(collapsedAction).toBe('record_read');
    expect((authorizationDetails[0] as any).operationDetails.action).toBe('record_read');
  });

  it('record_write: credsPath is the write path AND authorizationDetails agree on record_write (vip ignored)', () => {
    const { authorizationDetails, credsPath, collapsedAction } = resolveRar({
      rarAction: 'record_write',
      vip: true,
    });

    expect(credsPath).toBe('verify-rar/creds/records-write');
    expect(collapsedAction).toBe('record_write');
    expect((authorizationDetails[0] as any).operationDetails.action).toBe('record_write');
  });

  it('a per-tool action other than record_read (e.g. get_record_history) still collapses correctly', () => {
    const { authorizationDetails, credsPath, collapsedAction } = resolveRar({
      rarAction: 'get_record_history',
      vip: true,
    });

    expect(collapsedAction).toBe('record_read_vip');
    expect(credsPath).toBe('verify-rar/creds/records-vip');
    expect((authorizationDetails[0] as any).operationDetails.subaction).toBe('get_record_history');
  });
});

// ── Config-driven: a DIFFERENT domain works with zero code change ─────────
//
// The collapse/elevation rules and the business RAR vocabulary all come from
// config/rar.json. These drive resolveRar/buildRAR with a "tickets" config
// (nothing "records" about it) and assert the SAME semantics hold — proving a
// customer retargets the gateway by editing config, not code.
describe('config-driven vocabulary (custom "tickets" domain, zero code change)', () => {
  const ticketsConfig = parseRarConfig({
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
  });

  it('business element uses the custom rarType + idField', () => {
    const rar = buildRAR({ rarAction: 'ticket_read', recordId: 'TKT-77' }, ticketsConfig);
    expect(rar[0].type).toBe('urn:example:agent:tickets');
    expect((rar[0] as any).operationDetails.ticket_id).toBe('TKT-77');
    // the id is under the configured idField, NOT the default record_id
    expect((rar[0] as any).operationDetails.record_id).toBeUndefined();
  });

  it('vip read elevates to the config-declared step-up action + its creds path', () => {
    const { authorizationDetails, credsPath, collapsedAction } = resolveRar(
      { rarAction: 'ticket_read', vip: true },
      ticketsConfig,
    );
    expect(collapsedAction).toBe('ticket_read_priority');
    expect(credsPath).toBe('verify-rar/creds/tickets-priority');
    expect((authorizationDetails[0] as any).operationDetails.action).toBe('ticket_read_priority');
    expect((authorizationDetails[0] as any).operationDetails.subaction).toBe('ticket_read');
    expect((authorizationDetails[1] as any).path_constraint).toBe(credsPath);
  });

  it('write ignores vip (no elevation target) and unknown/blocked actions collapse to the default', () => {
    expect(resolveRar({ rarAction: 'ticket_write', vip: true }, ticketsConfig).credsPath).toBe(
      'verify-rar/creds/tickets-write',
    );
    // per-tool subaction with no own entry -> default
    expect(vaultRarAction('get_ticket_history', ticketsConfig)).toBe('ticket_read');
    // blocked action collapses to default too (it can never be minted from)
    expect(vaultRarAction('ticket_purge', ticketsConfig)).toBe('ticket_read');
    expect(vaultCredsPath('ticket_purge', ticketsConfig)).toBe('verify-rar/creds/tickets');
  });
});
