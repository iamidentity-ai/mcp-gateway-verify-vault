/**
 * Tests for opa.ts: the OPA guardrails query + env config.
 *
 * queryOpa is dependency-injected via `fetchImpl` (same seam as antenna.ts's
 * emitSessionRevoked), so no real OPA process is ever contacted here. The
 * response shape asserted below (decision_id / provenance.bundles.*.revision
 * / result.allow / result.reasons) was confirmed against a real `opa run -s`
 * on loopback, per the plan's Task 3 report, not re-derived here.
 */
import { describe, it, expect, vi } from 'vitest';
import { queryOpa, loadOpaConfig, egressHostFromUrl } from './opa.js';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('queryOpa', () => {
  it('POSTs {input} to <url>/v1/data/agent/guardrails/decision?provenance=true', async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(
      jsonResponse({ decision_id: 'd1', provenance: { bundles: { guardrails: { revision: 'sha1' } } }, result: { allow: true, reasons: [] } }),
    );

    await queryOpa({ agent_id: 'agent-1', tool_id: 'records/get_record' }, { url: 'http://127.0.0.1:8181', timeoutMs: 300, fetchImpl });

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://127.0.0.1:8181/v1/data/agent/guardrails/decision?provenance=true');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ input: { agent_id: 'agent-1', tool_id: 'records/get_record' } });
  });

  it('returns {ok:true, allow, reasons, decisionId, revision} on a well-formed 200', async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(
      jsonResponse({
        decision_id: 'd-123',
        provenance: { bundles: { guardrails: { revision: 'abc123' } } },
        result: { allow: false, reasons: ['egress-host-not-granted'] },
      }),
    );

    const result = await queryOpa({ agent_id: 'agent-1', tool_id: 'webfetch/web_fetch', egress_host: 'github.com' }, { url: 'http://x', timeoutMs: 300, fetchImpl });

    expect(result).toEqual({ ok: true, allow: false, reasons: ['egress-host-not-granted'], decisionId: 'd-123', revision: 'abc123' });
  });

  it('decisionId is undefined when OPA console decision logging is off (no decision_id in the body)', async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(
      jsonResponse({ provenance: { bundles: { guardrails: { revision: 'abc123' } } }, result: { allow: true, reasons: [] } }),
    );

    const result = await queryOpa({ agent_id: 'a', tool_id: 't' }, { url: 'http://x', timeoutMs: 300, fetchImpl });

    expect(result.ok).toBe(true);
    expect((result as { decisionId?: string }).decisionId).toBeUndefined();
  });

  it('returns {ok:false, error} on a non-2xx response', async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(jsonResponse({ error: 'boom' }, 500));

    const result = await queryOpa({ agent_id: 'a', tool_id: 't' }, { url: 'http://x', timeoutMs: 300, fetchImpl });

    expect(result.ok).toBe(false);
  });

  it('returns {ok:false, error} when fetch throws', async () => {
    const fetchImpl = vi.fn().mockRejectedValueOnce(new Error('network down'));

    const result = await queryOpa({ agent_id: 'a', tool_id: 't' }, { url: 'http://x', timeoutMs: 300, fetchImpl });

    expect(result).toEqual({ ok: false, error: expect.stringContaining('network down') });
  });

  it('returns {ok:false, error: "timeout"} when the request outlives timeoutMs', async () => {
    // A fetch stub that respects the abort signal it's given, like a real
    // fetch would, but never resolves on its own: this proves queryOpa's
    // OWN timeoutMs (not a hung test) is what ends it.
    const fetchImpl = vi.fn(
      (_url: string, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            const reason = (init.signal as AbortSignal).reason;
            reject(reason instanceof Error ? reason : new Error('aborted'));
          });
        }),
    );

    const result = await queryOpa({ agent_id: 'a', tool_id: 't' }, { url: 'http://x', timeoutMs: 20, fetchImpl: fetchImpl as unknown as typeof fetch });

    expect(result).toEqual({ ok: false, error: 'timeout' });
  });

  it('a MISSING result is NOT an allow: {ok:false} when the body has no "result" key', async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(
      jsonResponse({ decision_id: 'd1', provenance: { bundles: {} } }), // no `result`, the real OPA shape for an undefined decision rule
    );

    const result = await queryOpa({ agent_id: 'a', tool_id: 't' }, { url: 'http://x', timeoutMs: 300, fetchImpl });

    expect(result.ok).toBe(false);
  });

  it('a MALFORMED result (allow not boolean) is NOT an allow', async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(jsonResponse({ result: { allow: 'yes' } }));

    const result = await queryOpa({ agent_id: 'a', tool_id: 't' }, { url: 'http://x', timeoutMs: 300, fetchImpl });

    expect(result.ok).toBe(false);
  });

  it('a result with reasons missing or not all strings is NOT an allow', async () => {
    for (const result of [{ allow: true }, { allow: true, reasons: 'none' }, { allow: false, reasons: [1] }]) {
      const fetchImpl = vi.fn().mockResolvedValueOnce(jsonResponse({ result }));
      expect((await queryOpa({ agent_id: 'a', tool_id: 't' }, { url: 'http://x', timeoutMs: 300, fetchImpl })).ok).toBe(false);
    }
  });

  it('a 200 whose body is not JSON is NOT an allow', async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(new Response('<html>proxy</html>', { status: 200 }));

    const result = await queryOpa({ agent_id: 'a', tool_id: 't' }, { url: 'http://x', timeoutMs: 300, fetchImpl });

    expect(result.ok).toBe(false);
  });
});

describe('loadOpaConfig', () => {
  it('defaults: mode off, url loopback:8181, timeoutMs 300, ttl 300', () => {
    const cfg = loadOpaConfig({});
    expect(cfg.mode).toBe('off');
    expect(cfg.url).toBe('http://127.0.0.1:8181');
    expect(cfg.timeoutMs).toBe(300);
    expect(cfg.suspendTtlSeconds).toBe(300);
  });

  it('parses shadow and enforce; empty is off', () => {
    const agent = { GATEWAY_OPA_AGENT_ID: 'spiffe://example/agent' };
    expect(loadOpaConfig({ ...agent, GATEWAY_OPA_MODE: 'shadow' }).mode).toBe('shadow');
    expect(loadOpaConfig({ ...agent, GATEWAY_OPA_MODE: 'enforce' }).mode).toBe('enforce');
    expect(loadOpaConfig({ GATEWAY_OPA_MODE: '' }).mode).toBe('off');
  });

  it('an unrecognized mode value refuses to start: a typo must never run as off', () => {
    const agent = { GATEWAY_OPA_AGENT_ID: 'spiffe://example/agent' };
    expect(() => loadOpaConfig({ ...agent, GATEWAY_OPA_MODE: 'enforec' })).toThrow(/enforec/);
    expect(() => loadOpaConfig({ ...agent, GATEWAY_OPA_MODE: 'Enforce' })).toThrow(/off\|shadow\|enforce/);
  });

  it('shadow or enforce without GATEWAY_OPA_AGENT_ID refuses to start', () => {
    expect(() => loadOpaConfig({ GATEWAY_OPA_MODE: 'shadow' })).toThrow(/GATEWAY_OPA_AGENT_ID/);
    expect(() => loadOpaConfig({ GATEWAY_OPA_MODE: 'enforce', GATEWAY_OPA_AGENT_ID: '' })).toThrow(/GATEWAY_OPA_AGENT_ID/);
  });

  it('reads the rest of the env block straight through', () => {
    const cfg = loadOpaConfig({
      GATEWAY_OPA_MODE: 'enforce',
      GATEWAY_OPA_URL: 'http://127.0.0.1:9999',
      GATEWAY_OPA_TIMEOUT_MS: '750',
      GATEWAY_OPA_AGENT_ID: 'spiffe://example/agent',
      GATEWAY_VERIFY_AGENT_ID: 'verify-agent-1',
      GATEWAY_AGENT_RISK_URL: 'https://localhost:9042/sources/agent_risk/events',
      GATEWAY_AGENT_SUSPEND_TTL_SECONDS: '600',
    });
    expect(cfg).toEqual({
      mode: 'enforce',
      url: 'http://127.0.0.1:9999',
      timeoutMs: 750,
      agentId: 'spiffe://example/agent',
      verifyAgentId: 'verify-agent-1',
      agentRiskUrl: 'https://localhost:9042/sources/agent_risk/events',
      suspendTtlSeconds: 600,
    });
  });

  it('caps GATEWAY_AGENT_SUSPEND_TTL_SECONDS at 900', () => {
    expect(loadOpaConfig({ GATEWAY_AGENT_SUSPEND_TTL_SECONDS: '3600' }).suspendTtlSeconds).toBe(900);
  });
});

describe('egressHostFromUrl', () => {
  it('lowercases the hostname of a parseable URL', () => {
    expect(egressHostFromUrl('https://GitHub.com/some/path')).toBe('github.com');
  });

  it('returns undefined for a non-string value', () => {
    expect(egressHostFromUrl(undefined)).toBeUndefined();
    expect(egressHostFromUrl(42)).toBeUndefined();
  });

  it('returns undefined for an unparseable URL', () => {
    expect(egressHostFromUrl('not a url')).toBeUndefined();
  });

  it('drops userinfo, port and one trailing dot; keeps IPv6 brackets; no host is undefined', () => {
    expect(egressHostFromUrl('https://user:pw@GitLab.com.:8443/p?q=secret')).toBe('gitlab.com');
    expect(egressHostFromUrl('foo://GitHub.com/x')).toBe('github.com');
    expect(egressHostFromUrl('http://[2001:DB8::1]:8080/')).toBe('[2001:db8::1]');
    expect(egressHostFromUrl('file:///etc/passwd')).toBeUndefined();
  });
});
