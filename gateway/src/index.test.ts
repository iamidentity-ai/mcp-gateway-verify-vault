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
import { readFileSync } from 'node:fs';

process.env['PORT'] = process.env['PORT'] ?? '39714';

const { resolveTestVerdictOverride, pipelineResultToEnvelope, mcpToolNames } = await import('./index.js');

describe('mcpToolNames — /mcp surface stays in sync with config/tools.json', () => {
  it('registers exactly the configured tools (no drift between the two transports)', () => {
    const tools = JSON.parse(
      readFileSync(new URL('../config/tools.json', import.meta.url), 'utf-8'),
    ) as Record<string, unknown>;
    expect(mcpToolNames().slice().sort()).toEqual(Object.keys(tools).sort());
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

  it('session_killed_suspicious — maps to ok:false, killed:true, reason: "suspicious"', () => {
    const envelope = pipelineResultToEnvelope({ status: 'session_killed_suspicious' });
    expect(envelope).toEqual({ ok: false, killed: true, reason: 'suspicious' });
  });

  it('error — maps error, ok:false, no fabricated message field (PipelineResult error variant carries no message)', () => {
    const envelope = pipelineResultToEnvelope({ status: 'error', error: 'inactive_session' });
    expect(envelope).toEqual({ ok: false, error: 'inactive_session' });
  });
});
