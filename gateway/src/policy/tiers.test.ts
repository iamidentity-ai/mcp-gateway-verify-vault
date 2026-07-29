/**
 * Tests for tiers.ts.
 *
 * Coverage:
 *   - tier 4 (delete_record) is denied with reason policy_deny
 *   - tier 1 reads are allowed
 *   - tier 2/3 writes are allowed (RAR-gated upstream, not here)
 *   - unknown tools are denied with reason unknown_tool
 */
import { describe, it, expect } from 'vitest';
import { gateTool, assertToolActionsValid, assertToolArgsValid } from './tiers.js';

describe('gateTool', () => {
  it('gates tier 4 delete_record as denied', () => {
    const g = gateTool('delete_record');
    expect(g.tier).toBe(4);
    expect(g.allowed).toBe(false);
    expect(g.reason).toBe('policy_deny');
  });

  it('allows tier 1 reads', () => {
    expect(gateTool('get_record').allowed).toBe(true);
  });

  it('allows tier 2 writes', () => {
    const g = gateTool('update_record');
    expect(g.tier).toBe(2);
    expect(g.allowed).toBe(true);
    expect(g.rarAction).toBe('record_write');
    expect(g.scope).toBe('records:write');
  });

  it('allows tier 3 writes', () => {
    const g = gateTool('update_contact');
    expect(g.tier).toBe(3);
    expect(g.allowed).toBe(true);
    expect(g.rarAction).toBe('record_write');
    expect(g.scope).toBe('records:write');
  });

  it('denies unknown tools', () => {
    expect(gateTool('drop_table').reason).toBe('unknown_tool');
  });
});

// ── #2 (security review): tools.json ↔ rar.json cross-validation ──────────
describe('assertToolActionsValid', () => {
  const rarActions = {
    record_read: {},
    record_write: {},
    record_delete: { blocked: true },
  };

  it('passes a consistent config', () => {
    expect(() =>
      assertToolActionsValid(
        {
          get_record: { tier: 1, rarAction: 'record_read', scope: 'records:read' },
          delete_record: { tier: 4, rarAction: 'record_delete', scope: 'records:write' },
        },
        rarActions,
      ),
    ).not.toThrow();
  });

  it('THROWS when a tool uses a rarAction absent from rar.json (the silent-collapse trap)', () => {
    expect(() =>
      assertToolActionsValid(
        { escalate_record: { tier: 3, rarAction: 'record_escalate', scope: 'records:write' } },
        rarActions,
      ),
    ).toThrow(/record_escalate.*not a defined action|collapse to the default/);
  });

  it('THROWS when a non-tier-4 tool maps to a blocked action', () => {
    expect(() =>
      assertToolActionsValid(
        { sneaky_delete: { tier: 2, rarAction: 'record_delete', scope: 'records:write' } },
        rarActions,
      ),
    ).toThrow(/BLOCKED rarAction/);
  });

  it('ALLOWS a tier-4 tool to map to a blocked action', () => {
    expect(() =>
      assertToolActionsValid(
        { delete_record: { tier: 4, rarAction: 'record_delete', scope: 'records:write' } },
        rarActions,
      ),
    ).not.toThrow();
  });
});

// ── assertToolArgsValid — a config-driven /mcp tool's optional per-field
// schema (index.ts's buildToolSpecs reads this to advertise real tools/list
// properties instead of an empty-object passthrough) ───────────────────────
describe('assertToolArgsValid', () => {
  it('passes a tool with no args at all (the passthrough case)', () => {
    expect(() =>
      assertToolArgsValid({ get_record: { tier: 1, rarAction: 'record_read', scope: 'records:read' } }),
    ).not.toThrow();
  });

  it('passes a tool with a valid multi-field args map', () => {
    expect(() =>
      assertToolArgsValid({
        databricks_write: {
          tier: 3,
          rarAction: 'databricks_write',
          scope: 'databricks:write',
          args: { table: 'string', note: 'string' },
        },
      }),
    ).not.toThrow();
  });

  it('THROWS on an unrecognized arg type (the typo trap)', () => {
    expect(() =>
      assertToolArgsValid({
        databricks_write: {
          tier: 3,
          rarAction: 'databricks_write',
          scope: 'databricks:write',
          // @ts-expect-error deliberately invalid for the test
          args: { table: 'sting' },
        },
      }),
    ).toThrow(/databricks_write.*table.*unrecognized type "sting"/);
  });
});
