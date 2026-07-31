/**
 * Tests for index.ts's resolveTestVerdictOverride and
 * pipelineResultToEnvelope — the /hitl/complete dev/test verdict-override
 * gate and the /tool + /mcp response-envelope mapper.
 *
 * index.ts binds a real Express listener at module load (`app.listen(...)`
 * runs top-level). We pin PORT to an unlikely-to-clash value before
 * importing so this test file never contends with a live gateway process
 * on the real :3014.
 *
 * resolveTestVerdictOverride and pipelineResultToEnvelope are both pure
 * functions (no I/O) exported specifically so they're unit-testable without
 * booting a real HTTP round-trip. resolveTestVerdictOverride isolates the
 * security-relevant decision that a client-supplied `verdict` in the
 * /hitl/complete request body must be IGNORED unless
 * GATEWAY_ALLOW_TEST_VERDICT === '1'. pipelineResultToEnvelope isolates
 * the mapping from PipelineResult (pipeline.ts's `{status:'ok'|'pending'|
 * 'denied'|'session_killed_suspicious'|'error', ...}` shape) to the
 * `{ok, data, _diagnostic}` / `{ok:false, ...}` envelope downstream UI/agent
 * clients actually read — including the MCP CallToolResult content-unwrap
 * for the `ok` case (see pipelineResultToEnvelope's own doc comment in
 * index.ts for why that unwrap, not just the top-level status/ok naming, is
 * the real "happy path breaks" bug). See pipeline.test.ts for
 * completePending's own (deps-injected) coverage of the identity-binding
 * fix and the leg-2 retry.
 */
import { describe, it, expect } from 'vitest';

process.env['PORT'] = process.env['PORT'] ?? '39714';

const { resolveTestVerdictOverride, pipelineResultToEnvelope, statusCodeFor, mcpToolNames, buildToolSpecs } =
  await import('./index.js');
// Import the SAME config/tools.json (or GATEWAY_CONFIG_DIR override) the
// production /mcp surface is now built from (see index.ts's buildToolSpecs),
// instead of a hardcoded path to the shipped default — this repo's own
// local .env can point GATEWAY_CONFIG_DIR at a different upstream's config
// (e.g. examples/upstreams/github) for local dev, and mcpToolNames() must
// track THAT, not the shipped reference tools.json, once GATEWAY_CONFIG_DIR
// is honored.
const { tools: configuredTools } = await import('./policy/tiers.js');

describe('mcpToolNames — /mcp surface stays in sync with tools.json (or GATEWAY_CONFIG_DIR)', () => {
  it('registers exactly the configured tools, plus the always-on complete_hitl tool (no drift between the two transports)', () => {
    expect(mcpToolNames().slice().sort()).toEqual([...Object.keys(configuredTools), 'complete_hitl'].sort());
  });
});

describe('buildToolSpecs — per-tool schema choice + complete_hitl dedupe', () => {
  it('gives a config-driven tool with an "args" map a REAL per-field inputSchema, not an empty passthrough', () => {
    const specs = buildToolSpecs({
      databricks_write: {
        tier: 3,
        rarAction: 'databricks_write',
        scope: 'databricks:write',
        args: { table: 'string', note: 'string' },
      },
    });
    const spec = specs.find((s) => s.name === 'databricks_write')!;
    // A raw shape is a plain object of zod types (table/note keys present),
    // NOT a single ZodType instance (which is what the old z.record(...)
    // catch-all was, and what the SDK can't turn into non-empty JSON Schema
    // for tools/list — see buildToolSpecs' own doc comment in index.ts).
    expect(Object.keys(spec.config.inputSchema as object).sort()).toEqual(['note', 'table']);
  });

  it('falls back to the z.record passthrough for a tool with no "args" map', () => {
    const specs = buildToolSpecs({
      mystery_tool: { tier: 1, rarAction: 'record_read', scope: 'records:read' },
    });
    const spec = specs.find((s) => s.name === 'mystery_tool')!;
    // A bare ZodType (the record) has a `_def`/parse method, unlike a raw
    // shape's plain field-map object.
    expect(typeof (spec.config.inputSchema as { parse?: unknown }).parse).toBe('function');
  });

  it('does NOT double-register complete_hitl when a tools.json defines a tool literally named that', () => {
    const specs = buildToolSpecs({
      complete_hitl: { tier: 1, rarAction: 'record_read', scope: 'records:read' },
    });
    expect(specs.filter((s) => s.name === 'complete_hitl')).toHaveLength(1);
  });

  it('appends complete_hitl exactly once for a normal config with no name collision', () => {
    const specs = buildToolSpecs({
      get_record: { tier: 1, rarAction: 'record_read', scope: 'records:read' },
    });
    expect(specs.filter((s) => s.name === 'complete_hitl')).toHaveLength(1);
  });
});

describe('resolveTestVerdictOverride', () => {
  it('ignores a body verdict when GATEWAY_ALLOW_TEST_VERDICT is unset', () => {
    const result = resolveTestVerdictOverride({ txId: 'tx-1', verdict: 'denied_suspicious' }, {});
    expect(result).toBeUndefined();
  });

  it('ignores a body verdict when GATEWAY_ALLOW_TEST_VERDICT is "0" (or anything other than "1")', () => {
    const result = resolveTestVerdictOverride(
      { txId: 'tx-1', verdict: 'denied_suspicious' },
      { GATEWAY_ALLOW_TEST_VERDICT: '0' },
    );
    expect(result).toBeUndefined();
  });

  it('honors a body verdict ONLY when GATEWAY_ALLOW_TEST_VERDICT === "1"', () => {
    const result = resolveTestVerdictOverride(
      { txId: 'tx-1', verdict: 'approved' },
      { GATEWAY_ALLOW_TEST_VERDICT: '1' },
    );
    expect(result).toBe('approved');
  });

  it('returns undefined when the flag is set but the body carries no verdict', () => {
    const result = resolveTestVerdictOverride({ txId: 'tx-1' }, { GATEWAY_ALLOW_TEST_VERDICT: '1' });
    expect(result).toBeUndefined();
  });
});

describe('pipelineResultToEnvelope', () => {
  it('ok — unwraps an upstream MCP CallToolResult (content[0].text JSON) into data, and sets ok:true + empty _diagnostic', () => {
    // Exactly what proxy/upstream.ts's callUpstreamTool returns in
    // production — client.callTool() handed back verbatim, and a naive
    // upstream's handlers all do `return { content: [{ type: 'text', text:
    // JSON.stringify(result) }] }` (no structuredContent).
    const record = { record_id: 'REC-1006', display_name: 'Marisol Okafor', classification: 'public' };
    const envelope = pipelineResultToEnvelope({
      status: 'ok',
      data: { content: [{ type: 'text', text: JSON.stringify(record) }] },
    });
    expect(envelope).toEqual({ ok: true, data: record, _diagnostic: {} });
  });

  it('ok — falls back to the raw data verbatim when it does not look like an MCP text-content result (e.g. pipeline.test.ts-style plain-object mocks)', () => {
    const plain = { ok: true, record: { recordId: 'REC-1' } };
    const envelope = pipelineResultToEnvelope({ status: 'ok', data: plain });
    expect(envelope).toEqual({ ok: true, data: plain, _diagnostic: {} });
  });

  it('ok — falls back to the raw MCP envelope verbatim (does not throw) when content[0].text is not valid JSON', () => {
    const mcpEnvelope = { content: [{ type: 'text', text: 'not json' }] };
    const envelope = pipelineResultToEnvelope({ status: 'ok', data: mcpEnvelope });
    expect(envelope).toEqual({ ok: true, data: mcpEnvelope, _diagnostic: {} });
  });

  it('pending — maps txId + pushInfo, ok:false, pending:true', () => {
    const pushInfo = { title: 'Approve update', message: 'Confirm on your phone', transactionUri: 'urn:tx:1' };
    const envelope = pipelineResultToEnvelope({ status: 'pending', txId: 'tx-123', pushInfo });
    expect(envelope).toEqual({ ok: false, pending: true, txId: 'tx-123', pushInfo });
  });

  it('denied — maps reason, ok:false, denied:true', () => {
    const envelope = pipelineResultToEnvelope({ status: 'denied', reason: 'policy_deny' });
    expect(envelope).toEqual({ ok: false, denied: true, reason: 'policy_deny' });
  });

  it('denied WITH killed — the deny that crossed the 3-strike threshold carries killed:true so a client can tell it apart from an ordinary policy deny', () => {
    const envelope = pipelineResultToEnvelope({
      status: 'denied',
      reason: 'otp_deny_threshold_reached',
      killed: true,
    });
    expect(envelope).toEqual({
      ok: false,
      denied: true,
      reason: 'otp_deny_threshold_reached',
      killed: true,
    });
  });

  it('denied WITH denyCount/denyThreshold — a blocked-action strike tells the client how close the kill is', () => {
    const envelope = pipelineResultToEnvelope({
      status: 'denied',
      reason: 'policy_deny',
      denyCount: 2,
      denyThreshold: 3,
    });
    expect(envelope).toEqual({ ok: false, denied: true, reason: 'policy_deny', denyCount: 2, denyThreshold: 3 });
  });

  it('denied — the blocked-action third strike carries killed:true AND the counts', () => {
    const envelope = pipelineResultToEnvelope({
      status: 'denied',
      reason: 'blocked_action_threshold_reached',
      killed: true,
      denyCount: 3,
      denyThreshold: 3,
    });
    expect(envelope).toEqual({
      ok: false,
      denied: true,
      reason: 'blocked_action_threshold_reached',
      killed: true,
      denyCount: 3,
      denyThreshold: 3,
    });
  });

  it('session_killed_suspicious — maps to ok:false, killed:true, reason: "suspicious"', () => {
    const envelope = pipelineResultToEnvelope({ status: 'session_killed_suspicious' });
    expect(envelope).toEqual({ ok: false, killed: true, reason: 'suspicious' });
  });

  it('error — maps error, ok:false, no fabricated message field (PipelineResult error variant carries no message)', () => {
    const envelope = pipelineResultToEnvelope({ status: 'error', error: 'inactive_session' });
    expect(envelope).toEqual({ ok: false, error: 'inactive_session' });
  });

  it('error: forbidden — stays the plain error shape (no denied:true) — only access_denied gets that treatment', () => {
    const envelope = pipelineResultToEnvelope({ status: 'error', error: 'forbidden' });
    expect(envelope).toEqual({ ok: false, error: 'forbidden' });
  });

  it('error: access_denied — a real Verify Token-Exchange deny (CSIAQ0278E hard-cap or CSIAQ0279E entitlement gap) gets the SAME denied:true shape as a tier-4 local "denied" result', () => {
    const envelope = pipelineResultToEnvelope({ status: 'error', error: 'access_denied' });
    expect(envelope).toEqual({ ok: false, denied: true, error: 'access_denied' });
  });

  // ── HITL_METHOD=transient_email error envelopes ────────────────────────
  it('error: otp_invalid with attemptsRemaining — carries attemptsRemaining through to the client envelope', () => {
    const envelope = pipelineResultToEnvelope({ status: 'error', error: 'otp_invalid', attemptsRemaining: 2 });
    expect(envelope).toEqual({ ok: false, error: 'otp_invalid', attemptsRemaining: 2 });
  });

  it('error: otp_invalid also carries denyCount/denyThreshold — this gateway\'s own kill budget, distinct from Verify\'s per-code retry budget', () => {
    const envelope = pipelineResultToEnvelope({
      status: 'error',
      error: 'otp_invalid',
      attemptsRemaining: 2,
      denyCount: 2,
      denyThreshold: 3,
    });
    expect(envelope).toEqual({
      ok: false,
      error: 'otp_invalid',
      attemptsRemaining: 2,
      denyCount: 2,
      denyThreshold: 3,
    });
  });

  it('error: otp_invalid with NO attemptsRemaining reported — the key is absent, not null/undefined-valued (mapper never fabricates values it doesn\'t have)', () => {
    const envelope = pipelineResultToEnvelope({ status: 'error', error: 'otp_invalid' });
    expect(envelope).toEqual({ ok: false, error: 'otp_invalid' });
    expect(envelope).not.toHaveProperty('attemptsRemaining');
  });

  it('error: otp_expired — plain error shape, same as any other non-access_denied error', () => {
    const envelope = pipelineResultToEnvelope({ status: 'error', error: 'otp_expired' });
    expect(envelope).toEqual({ ok: false, error: 'otp_expired' });
  });

  it('pending — email_otp pushInfo shape (method + maskedDestination, no title/message/transactionUri)', () => {
    const envelope = pipelineResultToEnvelope({
      status: 'pending',
      txId: 'tx-456',
      pushInfo: { method: 'email_otp', maskedDestination: 's•••@example.com' },
    });
    expect(envelope).toEqual({
      ok: false,
      pending: true,
      txId: 'tx-456',
      pushInfo: { method: 'email_otp', maskedDestination: 's•••@example.com' },
    });
  });
});

describe('statusCodeFor', () => {
  it.each([
    ['ok', { status: 'ok', data: {} }, 200],
    ['pending', { status: 'pending', txId: 'tx-1' }, 202],
    ['denied (tier-4 local gate)', { status: 'denied', reason: 'policy_deny' }, 403],
    ['session_killed_suspicious', { status: 'session_killed_suspicious' }, 401],
    ['error: inactive_session', { status: 'error', error: 'inactive_session' }, 401],
    ['error: session_killed', { status: 'error', error: 'session_killed' }, 401],
    ['error: forbidden', { status: 'error', error: 'forbidden' }, 403],
    // NEW: a Verify Token-Exchange access_denied (real policy deny) now maps
    // to 403 like the tier-4 'denied' status, not the generic 500 every
    // other exchange error still gets below.
    ['error: access_denied', { status: 'error', error: 'access_denied' }, 403],
    // Unchanged — any OTHER exchange-error string (bad scope, stale
    // config, a network blip surfaced as token_exchange_failed, ...) still
    // falls through to 500. access_denied must not have widened this.
    ['error: invalid_scope (unrelated exchange error)', { status: 'error', error: 'invalid_scope' }, 500],
    ['error: token_exchange_failed', { status: 'error', error: 'token_exchange_failed' }, 500],
    // HITL_METHOD=transient_email error codes — caller-correctable input
    // errors get 400, not the generic 500 an unrelated exchange error gets.
    ['error: otp_required', { status: 'error', error: 'otp_required' }, 400],
    ['error: otp_invalid', { status: 'error', error: 'otp_invalid' }, 400],
    ['error: otp_expired', { status: 'error', error: 'otp_expired' }, 400],
    ['error: mfa_no_email', { status: 'error', error: 'mfa_no_email' }, 400],
    // The trigger (push or OTP) never fired at park time — nothing to
    // complete. Distinct from both a 400 (not the caller's fault) and the
    // generic 500 (not an unexpected exception either).
    ['error: no_poll_url', { status: 'error', error: 'no_poll_url' }, 409],
    ['error: otp_init_failed', { status: 'error', error: 'otp_init_failed' }, 409],
  ] as const)('%s -> %d', (_label, result, expected) => {
    expect(statusCodeFor(result as Parameters<typeof statusCodeFor>[0])).toBe(expected);
  });
});
