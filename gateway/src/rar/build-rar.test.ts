/**
 * Tests for rar/build-rar.ts
 *
 * Coverage:
 *   - buildRAR shape (3 elements: business + 2× vault:path_access)
 *   - business RAR type + operationDetails.action + subaction nesting
 *   - record_id present only when passed
 *   - elevated read collapses to record_read_elevated + records-elevated path
 *   - record_write routes to records-write path (elevated ignored on writes)
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

  it('an elevated read collapses to record_read_elevated and the -elevated creds path', () => {
    const rar = buildRAR({ rarAction: 'record_read', elevated: true });
    expect((rar[0] as any).operationDetails.action).toBe('record_read_elevated');
    // subaction preserves the ORIGINAL rarAction, not the collapsed value
    expect((rar[0] as any).operationDetails.subaction).toBe('record_read');
    expect((rar[1] as any).path_constraint).toBe('verify-rar/creds/records-elevated');
  });

  it('record_write routes to records-write regardless of elevated', () => {
    const rar = buildRAR({ rarAction: 'record_write', elevated: true });
    expect((rar[0] as any).operationDetails.action).toBe('record_write');
    expect((rar[1] as any).path_constraint).toBe('verify-rar/creds/records-write');
  });
});

describe('vaultRarAction (Vault role-mapping collapse)', () => {
  it('preserves record_read_elevated', () => {
    expect(vaultRarAction('record_read_elevated')).toBe('record_read_elevated');
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
    expect(vaultCredsPath('record_read_elevated')).toBe('verify-rar/creds/records-elevated');
    expect(vaultCredsPath('record_write')).toBe('verify-rar/creds/records-write');
    expect(vaultCredsPath('record_read')).toBe('verify-rar/creds/records');
  });
});

describe('resolveRar (single source of truth for authorizationDetails + credsPath)', () => {
  it('elevated read: credsPath is the -elevated path AND authorizationDetails agree on record_read_elevated', () => {
    const { authorizationDetails, credsPath, collapsedAction } = resolveRar({
      rarAction: 'record_read',
      elevated: true,
    });

    expect(credsPath).toBe('verify-rar/creds/records-elevated');
    expect(collapsedAction).toBe('record_read_elevated');
    expect((authorizationDetails[0] as any).operationDetails.action).toBe('record_read_elevated');
    // subaction preserves the ORIGINAL rarAction, not the collapsed value
    expect((authorizationDetails[0] as any).operationDetails.subaction).toBe('record_read');
    // the vault:path_access element's path_constraint must match credsPath too
    expect((authorizationDetails[1] as any).path_constraint).toBe(credsPath);
  });

  it('non-elevated read: credsPath is the standard path AND authorizationDetails agree on record_read', () => {
    const { authorizationDetails, credsPath, collapsedAction } = resolveRar({
      rarAction: 'record_read',
    });

    expect(credsPath).toBe('verify-rar/creds/records');
    expect(collapsedAction).toBe('record_read');
    expect((authorizationDetails[0] as any).operationDetails.action).toBe('record_read');
  });

  it('record_write: credsPath is the write path AND authorizationDetails agree on record_write (elevated ignored)', () => {
    const { authorizationDetails, credsPath, collapsedAction } = resolveRar({
      rarAction: 'record_write',
      elevated: true,
    });

    expect(credsPath).toBe('verify-rar/creds/records-write');
    expect(collapsedAction).toBe('record_write');
    expect((authorizationDetails[0] as any).operationDetails.action).toBe('record_write');
  });

  it('a per-tool action other than record_read (e.g. get_record_history) still collapses correctly', () => {
    const { authorizationDetails, credsPath, collapsedAction } = resolveRar({
      rarAction: 'get_record_history',
      elevated: true,
    });

    expect(collapsedAction).toBe('record_read_elevated');
    expect(credsPath).toBe('verify-rar/creds/records-elevated');
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
    stepUp: { discoveryTools: ['get_ticket'], elevateWhen: { field: 'priority', in: ['high', 'urgent'] } },
  });

  it('business element uses the custom rarType + idField', () => {
    const rar = buildRAR({ rarAction: 'ticket_read', recordId: 'TKT-77' }, ticketsConfig);
    expect(rar[0].type).toBe('urn:example:agent:tickets');
    expect((rar[0] as any).operationDetails.ticket_id).toBe('TKT-77');
    // the id is under the configured idField, NOT the default record_id
    expect((rar[0] as any).operationDetails.record_id).toBeUndefined();
  });

  it('elevated read elevates to the config-declared step-up action + its creds path', () => {
    const { authorizationDetails, credsPath, collapsedAction } = resolveRar(
      { rarAction: 'ticket_read', elevated: true },
      ticketsConfig,
    );
    expect(collapsedAction).toBe('ticket_read_priority');
    expect(credsPath).toBe('verify-rar/creds/tickets-priority');
    expect((authorizationDetails[0] as any).operationDetails.action).toBe('ticket_read_priority');
    expect((authorizationDetails[0] as any).operationDetails.subaction).toBe('ticket_read');
    expect((authorizationDetails[1] as any).path_constraint).toBe(credsPath);
  });

  it('write ignores elevated (no elevation target) and unknown/blocked actions collapse to the default', () => {
    expect(resolveRar({ rarAction: 'ticket_write', elevated: true }, ticketsConfig).credsPath).toBe(
      'verify-rar/creds/tickets-write',
    );
    // per-tool subaction with no own entry -> default
    expect(vaultRarAction('get_ticket_history', ticketsConfig)).toBe('ticket_read');
    // blocked action collapses to default too (it can never be minted from)
    expect(vaultRarAction('ticket_purge', ticketsConfig)).toBe('ticket_read');
    expect(vaultCredsPath('ticket_purge', ticketsConfig)).toBe('verify-rar/creds/tickets');
  });
});

// ── NO-DB upstream (UPSTREAM_DB_BACKED=false): actions carry NO credsPath ─────
//
// Fronting a non-database MCP (e.g. GitHub's) there is no Vault ephemeral-cred
// leg, so the config's actions have no credsPath and the two vault:path_access
// elements are meaningless. buildRAR/resolveRar must emit ONLY the business
// operationDetails element. The DB-backed default (a credsPath present) is
// UNCHANGED — still all 3 elements.
describe('no-DB config (credsPath-less actions): business-only authorization_details', () => {
  const noDbConfig = parseRarConfig(
    {
      rarType: 'urn:example:agent:issues',
      idField: 'issue_id',
      argIdKey: 'issueId',
      actions: {
        issue_read: { default: true },
        issue_write: {},
      },
      stepUp: { discoveryTools: ['get_issue'], elevateWhen: { field: 'sensitivity', in: ['high'] } },
    },
    { requireCredsPath: false },
  );

  it('buildRAR emits a 1-element array (business only, no vault:path_access) when the action has no credsPath', () => {
    const rar = buildRAR({ rarAction: 'issue_read', recordId: 'ISS-1' }, noDbConfig);
    expect(rar).toHaveLength(1);
    expect(rar[0].type).toBe('urn:example:agent:issues');
    expect((rar[0] as any).operationDetails.action).toBe('issue_read');
    expect((rar[0] as any).operationDetails.issue_id).toBe('ISS-1');
    // No vault:path_access elements at all.
    expect(rar.some((e) => e.type === 'vault:path_access')).toBe(false);
  });

  it('resolveRar returns credsPath undefined AND a 1-element authorization_details in the no-DB case', () => {
    const { authorizationDetails, credsPath, collapsedAction } = resolveRar({ rarAction: 'issue_write' }, noDbConfig);
    expect(credsPath).toBeUndefined();
    expect(collapsedAction).toBe('issue_write');
    expect(authorizationDetails).toHaveLength(1);
  });

  it('CONTRAST: the DB-backed default config still yields all 3 elements + a real credsPath', () => {
    const rar = buildRAR({ rarAction: 'record_read' });
    expect(rar).toHaveLength(3);
    expect(resolveRar({ rarAction: 'record_read' }).credsPath).toBe('verify-rar/creds/records');
  });
});
