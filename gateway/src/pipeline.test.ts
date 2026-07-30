/**
 * Tests for pipeline.ts — the six-step orchestrator.
 *
 * Every external module is injected via the `deps` param on runPipeline /
 * completePending — no live Verify/Vault/naive-mcp network call is ever
 * made here (end-to-end integration lives outside this unit suite).
 *
 * Coverage:
 *   - killed-session short-circuit (isSessionKilled true) BEFORE gate/exchange
 *   - tier 4 -> denied('policy_deny'), no exchange call, CAEP-deny audit
 *   - unknown tool -> denied('unknown_tool')
 *   - tier 1 ok -> introspect -> gate -> exchange(ok) -> mint -> upstream ->
 *     revoke -> appendAudit, returns ok; clearDeny NOT called (not MFA-gated)
 *   - tier 2 mfa_challenge -> pending + txId, putPending called with the
 *     right ctx, push triggered
 *   - inactive session -> error('inactive_session'), no gate/exchange
 *   - completePending: approved -> exchangeMfaAssertionWithRAR -> mint ->
 *     upstream -> revoke -> clearDeny -> ok
 *   - completePending: denied (not yet at threshold) -> recordDeny only
 *   - completePending: denied, 3rd strike -> emitSessionRevoked + markKilled
 *     + {status:'denied', killed:true}
 *   - completePending: denied_suspicious -> emitSessionRevoked(reason
 *     'suspicious') + markKilled + session_killed_suspicious
 *   - completePending: timeout -> error('mfa_timeout')
 *   - completePending: unknown/expired txId -> error, no further calls
 *
 * Additional coverage (security review — CRITICAL + IMPORTANT fixes):
 *   - completePending: callerVerifyUserId MISMATCHES the pending ctx's owner
 *     -> {status:'error', error:'forbidden'}; emitSessionRevoked/markKilled/
 *     recordDeny/pollOAuthMfaStatus are NEVER called (identity check runs
 *     before anything else, off a non-destructive peek).
 *   - completePending: matching caller + denied_suspicious -> unchanged
 *     happy path (still kills) — regression guard that the identity-binding
 *     fix didn't break the legitimate flow.
 *   - completePending: leg-2 (exchangeMfaAssertionWithRAR) stale-secret
 *     result -> invalidateExchangeSecret + refetch + retry once -> success.
 *   - args now round-trip via PendingCtx itself (no pipeline-local
 *     `pendingArgs` side-channel map — review FIX 3).
 *
 * Call-order assertions use a `calls: string[]` array populated by a
 * generic wrap-every-function-in-the-deps-object helper, so overriding any
 * single dep in an individual test still gets tracked automatically (no
 * risk of a test's override silently falling out of the order trace).
 */
import { describe, it, expect, vi } from 'vitest';
import { runPipeline, completePending } from './pipeline.js';
import {
  putPending as realPutPending,
  peekPending as realPeekPending,
  takePending as realTakePending,
  __resetForTests as resetPendingStore,
  type PendingCtx,
} from './hitl/pending.js';

function makeGateResult(
  overrides: Partial<{
    tier: 0 | 1 | 2 | 3 | 4;
    rarAction: string;
    scope: string;
    allowed: boolean;
    reason?: string;
  }> = {},
) {
  return {
    tier: 1 as const,
    rarAction: 'record_read',
    scope: 'records:read',
    allowed: true,
    ...overrides,
  };
}

/**
 * Wraps every function-valued property of `obj` in a vi.fn() that records
 * its key into `calls` before delegating to the original implementation.
 * Works transparently for both sync and async underlying functions — it
 * never awaits, it just returns whatever the delegate returns (a Promise
 * or a plain value), so callers that `await` still get the right behavior.
 */
function wrapWithCallTracking<T extends Record<string, unknown>>(obj: T, calls: string[]): T {
  const wrapped = {} as T;
  for (const [key, val] of Object.entries(obj)) {
    if (typeof val === 'function') {
      (wrapped as Record<string, unknown>)[key] = vi.fn((...args: unknown[]) => {
        calls.push(key);
        return (val as (...a: unknown[]) => unknown)(...args);
      });
    } else {
      (wrapped as Record<string, unknown>)[key] = val;
    }
  }
  return wrapped;
}

function makeRunDeps(overrides: Record<string, unknown> = {}) {
  const calls: string[] = [];

  const base = {
    introspectUser: async () => ({
      active: true,
      verifyUserId: 'user-1',
      email: 'agent@example.com',
    }),
    isSessionKilled: (_id: string) => false,
    gateTool: (_name: string) => makeGateResult(),
    // Self-contained fake mirroring build-rar.ts's real collapse rules (NOT
    // the real module — pipeline tests stay isolated from rar/ internals).
    // Deliberately reimplements the same elevation-then-collapse
    // sequence in ONE function so overriding it in a single test can't
    // reintroduce the "two separate derivations" bug class this task fixes.
    resolveRar: (args: { rarAction: string; recordId?: string; elevated?: boolean }) => {
      const isRead = args.rarAction !== 'record_write';
      const collapsedAction =
        args.elevated === true && isRead
          ? 'record_read_elevated'
          : args.rarAction === 'record_write'
            ? 'record_write'
            : 'record_read';
      const credsPath =
        collapsedAction === 'record_read_elevated'
          ? 'verify-rar/creds/records-elevated'
          : collapsedAction === 'record_write'
            ? 'verify-rar/creds/records-write'
            : 'verify-rar/creds/records';
      return {
        authorizationDetails: [
          {
            type: 'urn:example:agent:records',
            operationDetails: {
              action: collapsedAction,
              subaction: args.rarAction,
              ...(args.recordId ? { record_id: args.recordId } : {}),
            },
          },
        ],
        credsPath,
        collapsedAction,
      };
    },
    exchangeToken: async () => ({
      status: 'ok' as const,
      accessToken: 'obo-token-1',
      expiresIn: 3600,
      scope: 'records:read',
    }),
    triggerOAuthMfaPush: async () => 'https://verify.test/tx/abc',
    buildPushContext: () => ({
      title: 'MCP Gateway — approval',
      message: 'Approve: view a record.',
    }),
    // transient_email HITL mode only — unused unless a test overrides
    // hitlMethod:'transient_email' (default 'push' below never calls this).
    triggerTransientEmailOtp: async () => ({
      transactionUri: 'https://verify.test/v2.0/factors/emailotp/transient/verifications/verif-default',
      id: 'verif-default',
    }),
    mintCred: async () => ({ username: 'v-records-1', password: 'p4ss', leaseId: 'lease-1' }),
    // Public by default (explicit classification:'public' — shouldStepUp now
    // FAILS CLOSED, so a discovery probe with no classification is treated as
    // restricted).
    callUpstreamTool: async () => ({ ok: true, classification: 'public', record: { recordId: 'REC-1' } }),
    revokeLease: async () => undefined,
    appendAudit: (_rec: unknown) => undefined,
    clearDeny: (_id: string) => undefined,
    putPending: (_txId: string, _ctx: PendingCtx) => undefined,
    genTxId: () => 'tx-fixed-1',
    now: () => 1_000,
  };

  const deps = wrapWithCallTracking({ ...base, ...overrides }, calls);
  return { deps, calls };
}

/** Asserts each step name in `order` appears in `calls`, strictly increasing. */
function expectOrder(calls: string[], order: string[]): void {
  let lastIdx = -1;
  for (const step of order) {
    const idx = calls.indexOf(step);
    expect(idx, `expected "${step}" to have been called`).toBeGreaterThan(-1);
    expect(idx, `expected "${step}" to come after the previous step in ${JSON.stringify(order)} (got ${JSON.stringify(calls)})`).toBeGreaterThan(lastIdx);
    lastIdx = idx;
  }
}

describe('runPipeline', () => {
  // ── Gateway-derived step-up (discovery read → elevate) ──────────────────
  it('restricted record: gateway discovery read detects classification and forces a step-up (2 exchanges, mfa_challenge → pending)', async () => {
    const { deps, calls } = makeRunDeps({
      // Upstream returns the PRODUCTION MCP CallToolResult envelope (record +
      // its classification live inside content[0].text) — this is what would
      // have caught the "always public" unwrap bug.
      callUpstreamTool: async () => ({
        content: [{ type: 'text', text: JSON.stringify({ record_id: 'REC-9001', display_name: 'Jordan Reyes', classification: 'restricted' }) }],
      }),
      // Standard RAR (discovery) exchanges OK; the elevated record_read_elevated
      // RAR is what Verify challenges — keyed off the collapsed action so the
      // test mirrors the real elevated-read policy rule.
      exchangeToken: async (args: any) => {
        const action = args?.authorizationDetails?.[0]?.operationDetails?.action;
        if (action === 'record_read_elevated') {
          return { status: 'mfa_challenge', challengeToken: 'challenge-1' };
        }
        return { status: 'ok', accessToken: 'obo-token-1', expiresIn: 3600, scope: 'records:read' };
      },
    });

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'get_record', args: { recordId: 'REC-9001' } },
      deps as any,
    );

    expect(result.status).toBe('pending');
    // Two exchanges: the standard discovery read, then the elevated read.
    expect(calls.filter((c) => c === 'exchangeToken').length).toBe(2);
    expect(calls).toContain('triggerOAuthMfaPush');
    expect(calls).toContain('putPending');
    // The parked pending must mint from the elevated creds path, not the base one.
    const putPending = deps.putPending as unknown as { mock: { calls: unknown[][] } };
    const pendingCtx = putPending.mock.calls[0][1] as { credsPath: string };
    expect(pendingCtx.credsPath).toBe('verify-rar/creds/records-elevated');
  });

  it('public record: discovery read is the delivered read — no step-up (1 exchange, ok)', async () => {
    const { deps, calls } = makeRunDeps({
      // Production MCP envelope, public record.
      callUpstreamTool: async () => ({
        content: [{ type: 'text', text: JSON.stringify({ record_id: 'REC-1006', display_name: 'Marisol Okafor', classification: 'public' }) }],
      }),
    });

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'get_record', args: { recordId: 'REC-1006' } },
      deps as any,
    );

    expect(result.status).toBe('ok');
    // data is the raw MCP envelope at this layer (index.ts unwraps it for HTTP).
    // Only the discovery read ran — no elevation, no push.
    expect(calls.filter((c) => c === 'exchangeToken').length).toBe(1);
    expect(calls).not.toContain('triggerOAuthMfaPush');
  });

  // ── SECURITY (review #1): step-up covers detail/history via probeTool ─────
  it('restricted record via get_record_detail: probe(get_record) detects restricted -> step-up on the DETAIL read (2 exchanges, pending, elevated creds)', async () => {
    const { deps, calls } = makeRunDeps({
      // The probe (get_record) returns a restricted record; the elevated detail
      // read short-circuits at mfa_challenge before calling upstream.
      callUpstreamTool: async () => ({
        content: [{ type: 'text', text: JSON.stringify({ record_id: 'REC-9002', classification: 'restricted' }) }],
      }),
      exchangeToken: async (args: any) => {
        const action = args?.authorizationDetails?.[0]?.operationDetails?.action;
        if (action === 'record_read_elevated') return { status: 'mfa_challenge', challengeToken: 'challenge-1' };
        return { status: 'ok', accessToken: 'obo-token-1', expiresIn: 3600, scope: 'records:read' };
      },
    });

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'get_record_detail', args: { recordId: 'REC-9002' } },
      deps as any,
    );

    expect(result.status).toBe('pending');
    expect(calls.filter((c) => c === 'exchangeToken').length).toBe(2); // probe + elevated
    expect(calls).toContain('putPending');
    // The parked step-up is for the DETAIL tool, minting from the elevated creds path.
    const putPending = deps.putPending as unknown as { mock: { calls: unknown[][] } };
    const pendingCtx = putPending.mock.calls[0][1] as { credsPath: string; toolName: string };
    expect(pendingCtx.toolName).toBe('get_record_detail');
    expect(pendingCtx.credsPath).toBe('verify-rar/creds/records-elevated');
  });

  it('public record via get_record_detail: probe(get_record) public -> delivers the detail read (2 exchanges, ok, no push)', async () => {
    const { deps, calls } = makeRunDeps({
      callUpstreamTool: async () => ({
        content: [{ type: 'text', text: JSON.stringify({ record_id: 'REC-1006', classification: 'public' }) }],
      }),
    });

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'get_record_detail', args: { recordId: 'REC-1006' } },
      deps as any,
    );

    expect(result.status).toBe('ok');
    // Probe (get_record) + delivered (get_record_detail) — two exchanges, no step-up.
    expect(calls.filter((c) => c === 'exchangeToken').length).toBe(2);
    expect(calls).not.toContain('triggerOAuthMfaPush');
  });

  it('fail-closed: an unparseable probe result forces a step-up (shouldStepUp defaults to elevate, never leaks)', async () => {
    const { deps, calls } = makeRunDeps({
      callUpstreamTool: async () => ({ content: [{ type: 'text', text: '{ not valid json' }] }),
      exchangeToken: async (args: any) => {
        const action = args?.authorizationDetails?.[0]?.operationDetails?.action;
        if (action === 'record_read_elevated') return { status: 'mfa_challenge', challengeToken: 'challenge-1' };
        return { status: 'ok', accessToken: 'obo-token-1', expiresIn: 3600, scope: 'records:read' };
      },
    });

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'get_record', args: { recordId: 'REC-1' } },
      deps as any,
    );

    expect(result.status).toBe('pending'); // could-not-parse → step-up, not silent deliver
    expect(calls.filter((c) => c === 'exchangeToken').length).toBe(2);
  });

  // ── fail-closed on the notIn safe-list: an UNKNOWN classification elevates ──
  it('fail-closed safe-list: an unknown classification (not in notIn) forces a step-up', async () => {
    const { deps, calls } = makeRunDeps({
      // "confidential" is not in the shipped notIn safe-list ["public","internal"].
      callUpstreamTool: async () => ({
        content: [{ type: 'text', text: JSON.stringify({ record_id: 'REC-42', classification: 'confidential' }) }],
      }),
      exchangeToken: async (args: any) => {
        const action = args?.authorizationDetails?.[0]?.operationDetails?.action;
        if (action === 'record_read_elevated') return { status: 'mfa_challenge', challengeToken: 'challenge-1' };
        return { status: 'ok', accessToken: 'obo-token-1', expiresIn: 3600, scope: 'records:read' };
      },
    });

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'get_record', args: { recordId: 'REC-42' } },
      deps as any,
    );

    expect(result.status).toBe('pending');
    expect(calls.filter((c) => c === 'exchangeToken').length).toBe(2);
  });

  it('killed session short-circuits BEFORE gateTool/exchangeToken are called', async () => {
    const { deps, calls } = makeRunDeps({ isSessionKilled: () => true });

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'get_record', args: {} },
      deps as any,
    );

    expect(result).toEqual({ status: 'error', error: 'session_killed' });
    expect(deps.introspectUser).toHaveBeenCalledTimes(1);
    expect(deps.gateTool).not.toHaveBeenCalled();
    expect(deps.exchangeToken).not.toHaveBeenCalled();
    expect(deps.mintCred).not.toHaveBeenCalled();
    expectOrder(calls, ['introspectUser', 'isSessionKilled']);
  });

  it('inactive session -> error(inactive_session), no gate/killed-check/exchange', async () => {
    const { deps } = makeRunDeps({
      introspectUser: async () => ({ active: false }),
    });

    const result = await runPipeline(
      { userToken: 'dead-token', toolName: 'get_record', args: {} },
      deps as any,
    );

    expect(result).toEqual({ status: 'error', error: 'inactive_session' });
    expect(deps.isSessionKilled).not.toHaveBeenCalled();
    expect(deps.gateTool).not.toHaveBeenCalled();
    expect(deps.exchangeToken).not.toHaveBeenCalled();
  });

  it('tier 4 (policy_deny) -> denied, no exchange call, CAEP-deny audit recorded', async () => {
    const { deps } = makeRunDeps({
      gateTool: () => ({ tier: 4, rarAction: 'record_delete', scope: 'records:write', allowed: false, reason: 'policy_deny' }),
    });

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'delete_record', args: { recordId: 'REC-1' } },
      deps as any,
    );

    expect(result).toEqual({ status: 'denied', reason: 'policy_deny' });
    expect(deps.exchangeToken).not.toHaveBeenCalled();
    expect(deps.mintCred).not.toHaveBeenCalled();
    expect(deps.appendAudit).toHaveBeenCalledTimes(1);
    const rec = (deps.appendAudit as any).mock.calls[0][0];
    expect(rec.decision).toBe('tier4_deny');
    expect(rec.tool).toBe('delete_record');
  });

  it('unknown tool -> denied(unknown_tool), no exchange call', async () => {
    const { deps } = makeRunDeps({
      gateTool: () => ({ tier: 0, rarAction: '', scope: '', allowed: false, reason: 'unknown_tool' }),
    });

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'drop_table', args: {} },
      deps as any,
    );

    expect(result).toEqual({ status: 'denied', reason: 'unknown_tool' });
    expect(deps.exchangeToken).not.toHaveBeenCalled();
  });

  it('tier 1 ok: introspect -> gate -> exchange(ok) -> mint -> upstream -> revoke -> appendAudit, returns ok; clearDeny NOT called (lookup, not MFA-gated)', async () => {
    const { deps, calls } = makeRunDeps();

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'get_record', args: { recordId: 'REC-1' } },
      deps as any,
    );

    expect(result).toMatchObject({ status: 'ok', data: { ok: true, record: { recordId: 'REC-1' } } });
    // Every ok result carries the OBO observability payload (`_diagnostic`
    // on the /tool envelope) — the non-secret jti/ttl/scope from the exchange,
    // the minted cred + lease, and the resolved creds path.
    const okDiag = (result as { status: 'ok'; diag?: Record<string, unknown> }).diag;
    expect(okDiag).toMatchObject({
      oboTtl: 3600,
      oboScope: 'records:read',
      cred: { username: 'v-records-1', leaseId: 'lease-1', path: 'verify-rar/creds/records' },
      elevated: false,
    });
    // Security control: the raw OBO bearer token must NEVER leak into the
    // client-visible diagnostics — it is a replayable credential.
    expect(okDiag).not.toHaveProperty('obo');
    // Baseline (no senderConstrained on ctx): tokenBinding must be absent.
    // none/outbound mode must be byte-identical for callers.
    expect((result as { diag?: { tokenBinding?: string } }).diag?.tokenBinding).toBeUndefined();

    expectOrder(calls, [
      'introspectUser',
      'isSessionKilled',
      'gateTool',
      'exchangeToken',
      'mintCred',
      'callUpstreamTool',
      'revokeLease',
      'appendAudit',
    ]);

    expect(deps.mintCred).toHaveBeenCalledWith({
      obo: 'obo-token-1',
      authorizationDetails: expect.any(Array),
      credsPath: 'verify-rar/creds/records',
    });
    expect(deps.callUpstreamTool).toHaveBeenCalledWith({
      name: 'get_record',
      arguments: { recordId: 'REC-1' },
      obo: 'obo-token-1',
      dbUser: 'v-records-1',
      dbPass: 'p4ss',
    });
    expect(deps.revokeLease).toHaveBeenCalledWith('lease-1', 'obo-token-1');

    const rec = (deps.appendAudit as any).mock.calls[0][0];
    expect(rec.decision).toBe('ok');
    expect(rec.leaseId).toBe('lease-1');
    expect(rec.userId).toBe('user-1');

    // Regression guard for the "lookups clear the deny counter" bug class —
    // tier 1 is a pure read, never MFA-gated, so a successful call must NOT
    // reset another tool's in-flight deny count.
    expect(deps.clearDeny).not.toHaveBeenCalled();
  });

  it('marks diag.tokenBinding = "dpop" when the ctx is sender-constrained', async () => {
    const { deps } = makeRunDeps();

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'get_record', args: { recordId: 'REC-1' }, senderConstrained: true },
      deps as any,
    );

    expect(result.status).toBe('ok');
    expect((result as { diag?: { tokenBinding?: string } }).diag?.tokenBinding).toBe('dpop');
  });

  it('elevated read (gateway-derived) mints from the elevated creds path AND the RAR agrees on the ' +
    'collapsed action — regression guard for the RAR-action/creds-path mismatch fixed by resolveRar', async () => {
      const { deps } = makeRunDeps({
        // Restricted record → the gateway derives the elevation (the caller can
        // no longer request it). The default exchange mock returns OK for BOTH
        // the discovery and the elevated read (no challenge), so the elevated
        // read is delivered ok.
        callUpstreamTool: async () => ({
          content: [{ type: 'text', text: JSON.stringify({ record_id: 'REC-1', classification: 'restricted' }) }],
        }),
      });

      const result = await runPipeline(
        { userToken: 'user-token', toolName: 'get_record', args: { recordId: 'REC-1' } },
        deps as any,
      );

      expect(result.status).toBe('ok');

      // The Vault creds path the mint dep receives for the elevated read MUST be
      // the -elevated path — the pre-fix bug derived credsPath from the raw
      // (non-elevated) rarAction separately from authorizationDetails, so it
      // stayed on the base path even when the RAR claimed record_read_elevated.
      expect(deps.mintCred).toHaveBeenCalledWith({
        obo: 'obo-token-1',
        authorizationDetails: expect.any(Array),
        credsPath: 'verify-rar/creds/records-elevated',
      });

      // The RAR sent to Verify and the minted creds path must AGREE on the
      // collapsed action — the elevated exchange (the last one) claims
      // record_read_elevated.
      const exchangeCalls = (deps.exchangeToken as any).mock.calls;
      const elevatedArgs = exchangeCalls[exchangeCalls.length - 1][0];
      expect(elevatedArgs.authorizationDetails[0].operationDetails.action).toBe('record_read_elevated');
    });

  it('tier 2/3 direct ok (no challenge fired) DOES clearDeny — it is an MFA-gated tool by tier', async () => {
    const { deps } = makeRunDeps({
      gateTool: () => ({ tier: 2, rarAction: 'record_write', scope: 'records:write', allowed: true }),
    });

    await runPipeline(
      { userToken: 'user-token', toolName: 'update_record', args: { recordId: 'REC-1' } },
      deps as any,
    );

    expect(deps.clearDeny).toHaveBeenCalledWith('user-1');
  });

  it('tier 2 mfa_challenge -> pending + txId, putPending called with the right ctx, push triggered', async () => {
    const { deps, calls } = makeRunDeps({
      gateTool: () => ({ tier: 2, rarAction: 'record_write', scope: 'records:write', allowed: true }),
      exchangeToken: async () => ({ status: 'mfa_challenge' as const, challengeToken: 'challenge-xyz' }),
    });

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'update_record', args: { recordId: 'REC-1', field: 'status', value: 'active' } },
      deps as any,
    );

    expect(result.status).toBe('pending');
    if (result.status !== 'pending') throw new Error('expected pending');
    expect(result.txId).toBe('tx-fixed-1');

    expect(deps.triggerOAuthMfaPush).toHaveBeenCalledWith('challenge-xyz', expect.any(Object));
    expect(deps.mintCred).not.toHaveBeenCalled();
    expect(deps.callUpstreamTool).not.toHaveBeenCalled();

    expect(deps.putPending).toHaveBeenCalledTimes(1);
    const [txId, ctx] = (deps.putPending as any).mock.calls[0];
    expect(txId).toBe('tx-fixed-1');
    expect(ctx.verifyUserId).toBe('user-1');
    expect(ctx.challengeToken).toBe('challenge-xyz');
    expect(ctx.transactionUri).toBe('https://verify.test/tx/abc');
    expect(ctx.scope).toBe('records:write');
    expect(ctx.toolName).toBe('update_record');
    expect(ctx.credsPath).toBe('verify-rar/creds/records-write');
    // FIX 3 (security review): args now ride directly on PendingCtx — no
    // separate pipeline-local pendingArgs side-channel map to leak.
    expect(ctx.args).toEqual({ recordId: 'REC-1', field: 'status', value: 'active' });

    expectOrder(calls, ['gateTool', 'exchangeToken', 'triggerOAuthMfaPush', 'putPending']);
  });

  it('exchangeToken error -> {status:"error"}, no mint/upstream, audited as "exchange_error"', async () => {
    // list_records is NOT a discovery tool (see the DB-backed tests below) —
    // it takes the normal single-exchange, suppressAudit:false path, unlike
    // get_record which would route through the gateway-derived step-up
    // probe first.
    const { deps } = makeRunDeps({
      exchangeToken: async () => ({ status: 'error' as const, error: 'invalid_scope' }),
    });

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'list_records', args: {} },
      deps as any,
    );

    expect(result).toEqual({ status: 'error', error: 'invalid_scope' });
    expect(deps.mintCred).not.toHaveBeenCalled();
    // AUDIT PARITY: a Token-Exchange-level failure is audited exactly like
    // the tier-4 local-gate 'denied' path is — no more silent gap between
    // the two deny mechanisms.
    expect(deps.appendAudit).toHaveBeenCalledTimes(1);
    expect((deps.appendAudit as any).mock.calls[0][0]).toMatchObject({ decision: 'exchange_error' });
  });

  it('exchangeToken access_denied (real Verify policy deny — CSIAQ0278E/CSIAQ0279E) -> {status:"error", error:"access_denied"}, audited as "exchange_denied", no mint/upstream', async () => {
    const { deps } = makeRunDeps({
      exchangeToken: async () => ({ status: 'error' as const, error: 'access_denied', errorDescription: 'CSIAQ0278E' }),
    });

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'list_records', args: {} },
      deps as any,
    );

    expect(result).toEqual({ status: 'error', error: 'access_denied' });
    expect(deps.mintCred).not.toHaveBeenCalled();
    expect(deps.callUpstreamTool).not.toHaveBeenCalled();
    expect(deps.appendAudit).toHaveBeenCalledTimes(1);
    expect((deps.appendAudit as any).mock.calls[0][0]).toMatchObject({ decision: 'exchange_denied' });
  });

  it('exchangeToken access_denied on the gateway-derived DISCOVERY PROBE (get_record) does NOT double-audit — probe failures stay suppressAudit:true and bubble the error straight up', async () => {
    const { deps, calls } = makeRunDeps({
      exchangeToken: async () => ({ status: 'error' as const, error: 'access_denied' }),
    });

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'get_record', args: { recordId: 'REC-1' } },
      deps as any,
    );

    expect(result).toEqual({ status: 'error', error: 'access_denied' });
    // Only ONE exchange attempt (the probe) — it failed, so the "actual"
    // elevated/standard call after it never runs.
    expect(calls.filter((c) => c === 'exchangeToken').length).toBe(1);
    // The probe path passes suppressAudit:true — this must still hold for an
    // error result, not just the 'ok' path, or a failed discovery probe would
    // leave a spurious audit row for a call the caller never actually made.
    expect(deps.appendAudit).not.toHaveBeenCalled();
  });

  // ── UPSTREAM_DB_BACKED: the DEFAULT is DB-backed (security-safe) ───────────
  //
  // list_records is NOT a discovery tool, so it takes the normal single-exchange
  // path — the cleanest lens on the mint-vs-skip decision.
  it('REGRESSION: the DEFAULT is DB-backed — with NO dbBacked override a tier-1 read STILL mints + revokes and the diag carries cred', async () => {
    const { deps } = makeRunDeps({
      callUpstreamTool: async () => ({ ok: true, record: { recordId: 'REC-1' } }),
    });

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'list_records', args: {} },
      deps as any,
    );

    expect(result.status).toBe('ok');
    // Unset UPSTREAM_DB_BACKED === DB-backed: the Vault ephemeral-cred leg runs,
    // exactly as before this feature existed.
    expect(deps.mintCred).toHaveBeenCalledTimes(1);
    expect(deps.revokeLease).toHaveBeenCalledTimes(1);
    const okDiag = (result as { status: 'ok'; diag?: Record<string, unknown> }).diag;
    expect(okDiag).toMatchObject({
      cred: { username: 'v-records-1', leaseId: 'lease-1', path: 'verify-rar/creds/records' },
    });
  });

  it('explicit dbBacked:true behaves identically to the default (mints + revokes + cred in diag)', async () => {
    const { deps } = makeRunDeps({
      dbBacked: true,
      callUpstreamTool: async () => ({ ok: true, record: { recordId: 'REC-1' } }),
    });

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'list_records', args: {} },
      deps as any,
    );

    expect(result.status).toBe('ok');
    expect(deps.mintCred).toHaveBeenCalledTimes(1);
    expect(deps.revokeLease).toHaveBeenCalledTimes(1);
    expect((result as { status: 'ok'; diag?: Record<string, unknown> }).diag).toHaveProperty('cred');
  });

  it('NO-DB upstream (dbBacked:false): tier-1 read SKIPS mint/revoke, calls upstream WITHOUT dbUser/dbPass, ok diag has NO cred (but oboJti/oboScope), audit still written', async () => {
    // A real 3-segment JWT so decodeJwtJti resolves the correlation id.
    const oboJwt = ['eyJhbGciOiJub25lIn0', Buffer.from(JSON.stringify({ jti: 'jti-nodb' })).toString('base64url'), 'sig'].join('.');
    const { deps, calls } = makeRunDeps({
      dbBacked: false,
      exchangeToken: async () => ({ status: 'ok' as const, accessToken: oboJwt, expiresIn: 3600, scope: 'records:read' }),
      callUpstreamTool: async () => ({ ok: true, record: { recordId: 'REC-1' } }),
    });

    const result = await runPipeline(
      { userToken: 'user-token', toolName: 'list_records', args: { limit: 10 } },
      deps as any,
    );

    expect(result.status).toBe('ok');
    // The Vault leg is skipped ENTIRELY.
    expect(deps.mintCred).not.toHaveBeenCalled();
    expect(deps.revokeLease).not.toHaveBeenCalled();
    // Upstream is called on the OBO alone — no ephemeral DB creds in the args.
    expect(deps.callUpstreamTool).toHaveBeenCalledWith({
      name: 'list_records',
      arguments: { limit: 10 },
      obo: oboJwt,
    });
    // diag proves the exchange happened but carries NO cred (there is none),
    // while still carrying the non-secret oboJti/oboScope correlation fields.
    const okDiag = (result as { status: 'ok'; diag?: Record<string, unknown> }).diag;
    expect(okDiag).not.toHaveProperty('cred');
    expect(okDiag).toMatchObject({ oboJti: 'jti-nodb', oboScope: 'records:read', elevated: false });
    // Audit is still written — with no lease id (there was no lease).
    expect(deps.appendAudit).toHaveBeenCalledTimes(1);
    const rec = (deps.appendAudit as any).mock.calls[0][0];
    expect(rec.decision).toBe('ok');
    expect(rec.leaseId).toBeUndefined();
    // Exchange -> upstream, with NO mint/revoke between them.
    expectOrder(calls, ['introspectUser', 'gateTool', 'exchangeToken', 'callUpstreamTool', 'appendAudit']);
  });

  // ── HITL_METHOD=transient_email mode selection ─────────────────────────
  //
  // Entra-anchored / federated users JIT'd into the tenant typically have no
  // enrolled Verify push factor — triggerOAuthMfaPush's /v2.0/factors lookup
  // comes back empty and the push flow cannot fire. hitlMethod:'transient_email'
  // (default 'push' — see defaultRunPipelineDeps) switches the mfa_challenge
  // branch to mail a one-shot code instead.
  describe('HITL_METHOD=transient_email mode selection', () => {
    it('mode selection default (hitlMethod unset in deps): a tier-2 mfa_challenge still triggers the PUSH path, never triggerTransientEmailOtp — zero behavior change for existing deployments', async () => {
      const { deps, calls } = makeRunDeps({
        gateTool: () => ({ tier: 2, rarAction: 'record_write', scope: 'records:write', allowed: true }),
        exchangeToken: async () => ({ status: 'mfa_challenge' as const, challengeToken: 'challenge-xyz' }),
      });

      const result = await runPipeline(
        { userToken: 'user-token', toolName: 'update_record', args: { recordId: 'REC-1' } },
        deps as any,
      );

      expect(result.status).toBe('pending');
      expect(calls).toContain('triggerOAuthMfaPush');
      expect(calls).not.toContain('triggerTransientEmailOtp');

      const [, ctx] = (deps.putPending as any).mock.calls[0];
      expect(ctx.hitlMethod).toBe('push');
    });

    it('push-path pending envelope carries pushInfo.method:"push" alongside the existing title/message/transactionUri shape (regression guard: adding the discriminator did not drop the original fields)', async () => {
      const { deps } = makeRunDeps({
        gateTool: () => ({ tier: 2, rarAction: 'record_write', scope: 'records:write', allowed: true }),
        exchangeToken: async () => ({ status: 'mfa_challenge' as const, challengeToken: 'challenge-xyz' }),
      });

      const result = await runPipeline(
        { userToken: 'user-token', toolName: 'update_record', args: { recordId: 'REC-1' } },
        deps as any,
      );

      if (result.status !== 'pending') throw new Error('expected pending');
      expect(result.pushInfo).toMatchObject({
        method: 'push',
        title: 'MCP Gateway — approval',
        transactionUri: 'https://verify.test/tx/abc',
      });
    });

    it('hitlMethod:"transient_email": mfa_challenge triggers triggerTransientEmailOtp (with the challenge token + the INTROSPECTED email), never triggerOAuthMfaPush', async () => {
      const { deps, calls } = makeRunDeps({
        gateTool: () => ({ tier: 2, rarAction: 'record_write', scope: 'records:write', allowed: true }),
        exchangeToken: async () => ({ status: 'mfa_challenge' as const, challengeToken: 'challenge-xyz' }),
        hitlMethod: 'transient_email' as const,
        triggerTransientEmailOtp: async () => ({
          transactionUri: 'https://verify.test/v2.0/factors/emailotp/transient/verifications/verif-1',
          id: 'verif-1',
        }),
      });

      const result = await runPipeline(
        { userToken: 'user-token', toolName: 'update_record', args: { recordId: 'REC-1' } },
        deps as any,
      );

      expect(result.status).toBe('pending');
      expect(deps.triggerTransientEmailOtp).toHaveBeenCalledWith('challenge-xyz', 'agent@example.com');
      expect(calls).not.toContain('triggerOAuthMfaPush');

      // Pending envelope shape: method:'email_otp' + masked destination, NOT
      // a push-shaped title/message/transactionUri.
      if (result.status !== 'pending') throw new Error('expected pending');
      expect(result.pushInfo).toEqual({ method: 'email_otp', maskedDestination: 'a•••@example.com' });

      // PendingCtx carries hitlMethod + the transient-verification submit URL
      // in transactionUri (same field the push path uses for its poll URL).
      const [, ctx] = (deps.putPending as any).mock.calls[0];
      expect(ctx.hitlMethod).toBe('email_otp');
      expect(ctx.transactionUri).toBe('https://verify.test/v2.0/factors/emailotp/transient/verifications/verif-1');
    });

    it('hitlMethod:"transient_email" with no email on the introspected identity -> error("mfa_no_email"), triggerTransientEmailOtp never called, no pending parked', async () => {
      const { deps, calls } = makeRunDeps({
        introspectUser: async () => ({ active: true, verifyUserId: 'user-1' }), // no email field
        gateTool: () => ({ tier: 2, rarAction: 'record_write', scope: 'records:write', allowed: true }),
        exchangeToken: async () => ({ status: 'mfa_challenge' as const, challengeToken: 'challenge-xyz' }),
        hitlMethod: 'transient_email' as const,
      });

      const result = await runPipeline(
        { userToken: 'user-token', toolName: 'update_record', args: { recordId: 'REC-1' } },
        deps as any,
      );

      expect(result).toEqual({ status: 'error', error: 'mfa_no_email' });
      expect(calls).not.toContain('triggerTransientEmailOtp');
      expect(deps.putPending).not.toHaveBeenCalled();
    });

    // ── Live finding (2026-07-30): some STS custom token types (Okta, and
    // Entra with certain claim mappings) emit NO `email` claim at all —
    // /oauth2/userinfo then has nothing under `email` even though the token
    // DOES carry `preferred_username`. userEmail's resolution in
    // runPipeline falls back to preferred_username, but only when it's
    // email-shaped (contains '@') — proven pattern from
    // mcp-refund-okta-verify-vault's selectTransientOtpChannel.
    describe('userEmail resolution: email claim vs. preferred_username fallback', () => {
      it('email claim present -> wins outright, preferred_username is never consulted even if also present', async () => {
        const { deps } = makeRunDeps({
          introspectUser: async () => ({
            active: true,
            verifyUserId: 'user-1',
            email: 'real-email@example.com',
            preferredUsername: 'different-value-not-an-email',
          }),
          gateTool: () => ({ tier: 2, rarAction: 'record_write', scope: 'records:write', allowed: true }),
          exchangeToken: async () => ({ status: 'mfa_challenge' as const, challengeToken: 'challenge-xyz' }),
          hitlMethod: 'transient_email' as const,
          triggerTransientEmailOtp: async () => ({
            transactionUri: 'https://verify.test/v2.0/factors/emailotp/transient/verifications/verif-1',
            id: 'verif-1',
          }),
        });

        const result = await runPipeline(
          { userToken: 'user-token', toolName: 'update_record', args: { recordId: 'REC-1' } },
          deps as any,
        );

        expect(result.status).toBe('pending');
        expect(deps.triggerTransientEmailOtp).toHaveBeenCalledWith('challenge-xyz', 'real-email@example.com');
      });

      it('no email claim, preferred_username IS email-shaped -> falls back to preferred_username (the live-found gap this fixes)', async () => {
        const { deps } = makeRunDeps({
          introspectUser: async () => ({
            active: true,
            verifyUserId: '6430083FU5',
            // no `email` field at all — the STS custom token type case
            preferredUsername: 'operator@example.com',
          }),
          gateTool: () => ({ tier: 2, rarAction: 'record_write', scope: 'records:write', allowed: true }),
          exchangeToken: async () => ({ status: 'mfa_challenge' as const, challengeToken: 'challenge-xyz' }),
          hitlMethod: 'transient_email' as const,
          triggerTransientEmailOtp: async () => ({
            transactionUri: 'https://verify.test/v2.0/factors/emailotp/transient/verifications/verif-1',
            id: 'verif-1',
          }),
        });

        const result = await runPipeline(
          { userToken: 'user-token', toolName: 'update_record', args: { recordId: 'REC-1' } },
          deps as any,
        );

        expect(result.status).toBe('pending');
        expect(deps.triggerTransientEmailOtp).toHaveBeenCalledWith(
          'challenge-xyz',
          'operator@example.com',
        );
        if (result.status !== 'pending') throw new Error('expected pending');
        expect(result.pushInfo).toEqual({ method: 'email_otp', maskedDestination: 'o•••@example.com' });
      });

      it('no email claim, preferred_username is NOT email-shaped (no "@") -> still mfa_no_email, never sent as a destination', async () => {
        const { deps, calls } = makeRunDeps({
          introspectUser: async () => ({
            active: true,
            verifyUserId: 'user-1',
            preferredUsername: 'not-an-email-just-a-upn',
          }),
          gateTool: () => ({ tier: 2, rarAction: 'record_write', scope: 'records:write', allowed: true }),
          exchangeToken: async () => ({ status: 'mfa_challenge' as const, challengeToken: 'challenge-xyz' }),
          hitlMethod: 'transient_email' as const,
        });

        const result = await runPipeline(
          { userToken: 'user-token', toolName: 'update_record', args: { recordId: 'REC-1' } },
          deps as any,
        );

        expect(result).toEqual({ status: 'error', error: 'mfa_no_email' });
        expect(calls).not.toContain('triggerTransientEmailOtp');
      });
    });

    it('hitlMethod:"transient_email": triggerTransientEmailOtp failure still PARKS the pending tx (best-effort, mirrors the push trigger-failure behavior) with transactionUri left undefined', async () => {
      const { deps } = makeRunDeps({
        gateTool: () => ({ tier: 2, rarAction: 'record_write', scope: 'records:write', allowed: true }),
        exchangeToken: async () => ({ status: 'mfa_challenge' as const, challengeToken: 'challenge-xyz' }),
        hitlMethod: 'transient_email' as const,
        triggerTransientEmailOtp: async () => {
          throw new Error('Verify unreachable');
        },
      });

      const result = await runPipeline(
        { userToken: 'user-token', toolName: 'update_record', args: { recordId: 'REC-1' } },
        deps as any,
      );

      expect(result.status).toBe('pending');
      const [, ctx] = (deps.putPending as any).mock.calls[0];
      expect(ctx.hitlMethod).toBe('email_otp');
      expect(ctx.transactionUri).toBeUndefined();
    });
  });
});

describe('completePending', () => {
  function makeCtx(overrides: Partial<PendingCtx> = {}): PendingCtx {
    return {
      verifyUserId: 'user-1',
      challengeToken: 'challenge-xyz',
      transactionUri: 'https://verify.test/tx/abc',
      scope: 'records:write',
      authorizationDetails: [
        { type: 'urn:example:agent:records', operationDetails: { action: 'record_write', subaction: 'record_write', record_id: 'REC-1' } },
      ],
      toolName: 'update_record',
      credsPath: 'verify-rar/creds/records-write',
      startedAt: 500,
      args: {},
      ...overrides,
    };
  }

  function makeCompleteDeps(overrides: Record<string, unknown> = {}) {
    const calls: string[] = [];

    const base = {
      peekPending: (_txId: string) => makeCtx(),
      takePending: (_txId: string) => makeCtx(),
      gateTool: () => makeGateResult({ tier: 2, rarAction: 'record_write', scope: 'records:write' }),
      pollOAuthMfaStatus: async () => ({ state: 'approved' as const, assertion: 'mfa-assertion-jwt' }),
      // transient_email HITL mode only — unused unless a test's makeCtx has
      // hitlMethod:'email_otp' (default makeCtx() is 'push', never calls this).
      submitTransientOtp: async () => ({ status: 'approved' as const, assertion: 'otp-assertion-jwt-default' }),
      getExchangeClientSecret: async () => 'exchange-secret-1',
      invalidateExchangeSecret: () => undefined,
      exchangeMfaAssertionWithRAR: async () => ({
        status: 'ok' as const,
        accessToken: 'final-obo',
        expiresIn: 3600,
        scope: 'records:write',
      }),
      mintCred: async () => ({ username: 'v-write-1', password: 'p4ss', leaseId: 'lease-2' }),
      callUpstreamTool: async () => ({ ok: true }),
      revokeLease: async () => undefined,
      appendAudit: (_rec: unknown) => undefined,
      clearDeny: (_id: string) => undefined,
      recordDeny: (_id: string) => ({ count: 1, thresholdReached: false, windowMs: 300_000, threshold: 3 }),
      emitSessionRevoked: async () => ({ ok: true, status: 200 }),
      markKilled: (_id: string) => undefined,
      isSessionKilled: (_id: string) => false,
      now: () => 2_000,
    };

    const deps = wrapWithCallTracking({ ...base, ...overrides }, calls);
    return { deps, calls };
  }

  it('unknown/expired txId -> error, no further calls', async () => {
    const { deps } = makeCompleteDeps({ peekPending: () => undefined, takePending: () => undefined });

    const result = await completePending('tx-gone', 'user-1', deps as any);

    expect(result).toEqual({ status: 'error', error: 'unknown_or_expired_tx' });
    expect(deps.pollOAuthMfaStatus).not.toHaveBeenCalled();
  });

  // ── SECURITY (review #5): kill-gate on the parked-step-up resume path ──
  it('OWNER session killed while a step-up is parked -> session_killed BEFORE takePending/poll/mint (no resume in the propagation window)', async () => {
    const { deps } = makeCompleteDeps({ isSessionKilled: (_id: string) => true });

    // Matching caller (owns the tx) so it clears the identity binding; the
    // kill-gate is what must stop it.
    const result = await completePending('tx-1', 'user-1', deps as any);

    expect(result).toEqual({ status: 'error', error: 'session_killed' });
    // Nothing past the gate ran: the tx is NOT consumed, no poll, no mint/upstream.
    expect(deps.takePending).not.toHaveBeenCalled();
    expect(deps.pollOAuthMfaStatus).not.toHaveBeenCalled();
    expect(deps.mintCred).not.toHaveBeenCalled();
    expect(deps.callUpstreamTool).not.toHaveBeenCalled();
  });

  // ── FIX 1 (CRITICAL, security review): identity binding ───────────────
  it('callerVerifyUserId MISMATCHES the pending ctx owner -> forbidden, NOTHING acted on (no poll/deny/kill)', async () => {
    const { deps } = makeCompleteDeps(); // pending ctx belongs to 'user-1'

    const result = await completePending('tx-1', 'attacker-999', deps as any);

    expect(result).toEqual({ status: 'error', error: 'forbidden' });

    // The whole point of the fix: an identity mismatch must NEVER reach any
    // side-effecting step, especially not the session-kill path.
    expect(deps.pollOAuthMfaStatus).not.toHaveBeenCalled();
    expect(deps.recordDeny).not.toHaveBeenCalled();
    expect(deps.emitSessionRevoked).not.toHaveBeenCalled();
    expect(deps.markKilled).not.toHaveBeenCalled();
    expect(deps.exchangeMfaAssertionWithRAR).not.toHaveBeenCalled();
    expect(deps.mintCred).not.toHaveBeenCalled();
    expect(deps.callUpstreamTool).not.toHaveBeenCalled();

    // The entry is peeked, never destructively taken — the legitimate owner
    // must still be able to complete it.
    expect(deps.peekPending).toHaveBeenCalledWith('tx-1');
    expect(deps.takePending).not.toHaveBeenCalled();
  });

  it('missing/undefined callerVerifyUserId (caller session inactive) -> forbidden, same as a mismatch', async () => {
    const { deps } = makeCompleteDeps();

    const result = await completePending('tx-1', undefined, deps as any);

    expect(result).toEqual({ status: 'error', error: 'forbidden' });
    expect(deps.pollOAuthMfaStatus).not.toHaveBeenCalled();
    expect(deps.emitSessionRevoked).not.toHaveBeenCalled();
    expect(deps.markKilled).not.toHaveBeenCalled();
  });

  it('approved -> exchangeMfaAssertionWithRAR -> mint -> upstream -> revoke -> clearDeny -> ok (matching caller — unchanged happy path)', async () => {
    const { deps, calls } = makeCompleteDeps();

    const result = await completePending('tx-1', 'user-1', deps as any);

    expect(result).toMatchObject({ status: 'ok', data: { ok: true } });

    expect(deps.exchangeMfaAssertionWithRAR).toHaveBeenCalledWith(
      'mfa-assertion-jwt',
      'records:write',
      expect.any(Array),
      'exchange-secret-1',
    );
    expect(deps.mintCred).toHaveBeenCalledWith({
      obo: 'final-obo',
      authorizationDetails: expect.any(Array),
      credsPath: 'verify-rar/creds/records-write',
    });
    expect(deps.callUpstreamTool).toHaveBeenCalledWith({
      name: 'update_record',
      arguments: {},
      obo: 'final-obo',
      dbUser: 'v-write-1',
      dbPass: 'p4ss',
    });
    expect(deps.revokeLease).toHaveBeenCalledWith('lease-2', 'final-obo');
    expect(deps.clearDeny).toHaveBeenCalledWith('user-1');
    expect(deps.invalidateExchangeSecret).not.toHaveBeenCalled();

    expectOrder(calls, [
      'peekPending',
      'takePending',
      'pollOAuthMfaStatus',
      'getExchangeClientSecret',
      'exchangeMfaAssertionWithRAR',
      'mintCred',
      'callUpstreamTool',
      'revokeLease',
      'clearDeny',
    ]);
  });

  // ── UPSTREAM_DB_BACKED=false on the post-approval (leg-2) path ─────────────
  it('NO-DB upstream (dbBacked:false): approved step-up returns data WITHOUT minting/revoking, calls upstream on the OBO alone, diag has no cred', async () => {
    const { deps } = makeCompleteDeps({ dbBacked: false });

    const result = await completePending('tx-1', 'user-1', deps as any);

    expect(result).toMatchObject({ status: 'ok', data: { ok: true } });
    // Vault leg skipped even on the stepped-up (post-approval) path.
    expect(deps.mintCred).not.toHaveBeenCalled();
    expect(deps.revokeLease).not.toHaveBeenCalled();
    expect(deps.callUpstreamTool).toHaveBeenCalledWith({
      name: 'update_record',
      arguments: {},
      obo: 'final-obo',
    });
    const okDiag = (result as { status: 'ok'; diag?: Record<string, unknown> }).diag;
    expect(okDiag).not.toHaveProperty('cred');
    expect(okDiag).toMatchObject({ oboScope: 'records:write', elevated: false });
    // Approval bookkeeping (clearDeny + audit) is unchanged.
    expect(deps.clearDeny).toHaveBeenCalledWith('user-1');
    expect(deps.appendAudit).toHaveBeenCalledTimes(1);
    const rec = (deps.appendAudit as any).mock.calls[0][0];
    expect(rec.decision).toBe('ok');
    expect(rec.leaseId).toBeUndefined();
  });

  // ── FIX 2 (IMPORTANT, security review): leg-2 CSIAQ0155E retry ─────────
  it('leg-2 stale-secret (CSIAQ0155E/invalid_client) -> invalidateExchangeSecret + refetch + retry once -> success', async () => {
    let call = 0;
    const { deps, calls } = makeCompleteDeps({
      getExchangeClientSecret: async () => (call === 0 ? 'stale-secret' : 'fresh-secret'),
      exchangeMfaAssertionWithRAR: async (_assertion: string, _scope: string, _ad: unknown, secret: string) => {
        call += 1;
        if (secret === 'stale-secret') {
          return { status: 'error' as const, error: 'invalid_client', errorDescription: 'CSIAQ0155E client secret mismatch' };
        }
        return { status: 'ok' as const, accessToken: 'final-obo', expiresIn: 3600, scope: 'records:write' };
      },
    });

    const result = await completePending('tx-1', 'user-1', deps as any);

    expect(result).toMatchObject({ status: 'ok', data: { ok: true } });
    expect(deps.getExchangeClientSecret).toHaveBeenCalledTimes(2);
    expect(deps.exchangeMfaAssertionWithRAR).toHaveBeenCalledTimes(2);
    expect(deps.invalidateExchangeSecret).toHaveBeenCalledTimes(1);

    // expectOrder() assumes each step name is unique in `calls` (indexOf
    // finds only the FIRST occurrence) — getExchangeClientSecret/
    // exchangeMfaAssertionWithRAR each fire twice here (retry), so assert
    // the exact call sequence directly instead.
    const firstGetSecret = calls.indexOf('getExchangeClientSecret');
    const firstExchange = calls.indexOf('exchangeMfaAssertionWithRAR');
    const invalidateIdx = calls.indexOf('invalidateExchangeSecret');
    const secondGetSecret = calls.indexOf('getExchangeClientSecret', invalidateIdx + 1);
    const secondExchange = calls.indexOf('exchangeMfaAssertionWithRAR', secondGetSecret + 1);
    const mintIdx = calls.indexOf('mintCred');

    expect(firstGetSecret).toBeGreaterThan(-1);
    expect(firstExchange).toBeGreaterThan(firstGetSecret);
    expect(invalidateIdx).toBeGreaterThan(firstExchange);
    expect(secondGetSecret).toBeGreaterThan(invalidateIdx);
    expect(secondExchange).toBeGreaterThan(secondGetSecret);
    expect(mintIdx).toBeGreaterThan(secondExchange);
  });

  it('leg-2 stale-secret persists on the retry too -> single attempt only, returns the second error', async () => {
    const { deps } = makeCompleteDeps({
      exchangeMfaAssertionWithRAR: async () => ({
        status: 'error' as const,
        error: 'invalid_client',
        errorDescription: 'CSIAQ0155E client secret mismatch',
      }),
    });

    const result = await completePending('tx-1', 'user-1', deps as any);

    expect(result).toEqual({ status: 'error', error: 'invalid_client' });
    // Exactly one retry — not a loop.
    expect(deps.exchangeMfaAssertionWithRAR).toHaveBeenCalledTimes(2);
    expect(deps.invalidateExchangeSecret).toHaveBeenCalledTimes(1);
    expect(deps.mintCred).not.toHaveBeenCalled();
  });

  it('leg-2 non-stale error -> no retry, error surfaced immediately', async () => {
    const { deps } = makeCompleteDeps({
      exchangeMfaAssertionWithRAR: async () => ({
        status: 'error' as const,
        error: 'invalid_scope',
        errorDescription: 'requested scope not granted',
      }),
    });

    const result = await completePending('tx-1', 'user-1', deps as any);

    expect(result).toEqual({ status: 'error', error: 'invalid_scope' });
    expect(deps.exchangeMfaAssertionWithRAR).toHaveBeenCalledTimes(1);
    expect(deps.invalidateExchangeSecret).not.toHaveBeenCalled();
  });

  it('denied (not at threshold) -> recordDeny only, no session kill', async () => {
    const { deps } = makeCompleteDeps({
      pollOAuthMfaStatus: async () => ({ state: 'denied' as const, reason: 'USER_DENIED' }),
      recordDeny: () => ({ count: 1, thresholdReached: false, windowMs: 300_000, threshold: 3 }),
    });

    const result = await completePending('tx-1', 'user-1', deps as any);

    expect(result).toEqual({ status: 'denied', reason: 'USER_DENIED' });
    expect(deps.recordDeny).toHaveBeenCalledWith('user-1');
    expect(deps.emitSessionRevoked).not.toHaveBeenCalled();
    expect(deps.markKilled).not.toHaveBeenCalled();
    expect(deps.exchangeMfaAssertionWithRAR).not.toHaveBeenCalled();
  });

  it('denied, 3rd strike (thresholdReached) -> emitSessionRevoked + markKilled + {status:denied, killed:true}', async () => {
    const { deps, calls } = makeCompleteDeps({
      pollOAuthMfaStatus: async () => ({ state: 'denied' as const, reason: 'USER_DENIED' }),
      recordDeny: () => ({ count: 3, thresholdReached: true, windowMs: 300_000, threshold: 3 }),
    });

    const result = await completePending('tx-1', 'user-1', deps as any);

    expect(result).toEqual({ status: 'denied', reason: 'USER_DENIED', killed: true });
    expect(deps.emitSessionRevoked).toHaveBeenCalledTimes(1);
    expect(deps.markKilled).toHaveBeenCalledWith('user-1');

    expectOrder(calls, ['recordDeny', 'emitSessionRevoked', 'markKilled']);
  });

  it('denied_suspicious -> emitSessionRevoked(reason:"suspicious") + markKilled + session_killed_suspicious (matching caller)', async () => {
    const { deps, calls } = makeCompleteDeps({
      pollOAuthMfaStatus: async () => ({ state: 'denied_suspicious' as const, reason: 'USER_FRAUDULENT' }),
    });

    const result = await completePending('tx-1', 'user-1', deps as any);

    expect(result).toEqual({ status: 'session_killed_suspicious' });
    expect(deps.emitSessionRevoked).toHaveBeenCalledTimes(1);
    const emitArg = (deps.emitSessionRevoked as any).mock.calls[0][0];
    expect(emitArg.reason).toBe('suspicious');
    expect(emitArg.verifyUserId).toBe('user-1');
    expect(deps.markKilled).toHaveBeenCalledWith('user-1');
    expect(deps.recordDeny).not.toHaveBeenCalled();

    expectOrder(calls, ['emitSessionRevoked', 'markKilled']);
  });

  it('timeout -> error(mfa_timeout), no mint/upstream/deny bookkeeping', async () => {
    const { deps } = makeCompleteDeps({
      pollOAuthMfaStatus: async () => ({ state: 'timeout' as const }),
    });

    const result = await completePending('tx-1', 'user-1', deps as any);

    expect(result).toEqual({ status: 'error', error: 'mfa_timeout' });
    expect(deps.mintCred).not.toHaveBeenCalled();
    expect(deps.recordDeny).not.toHaveBeenCalled();
    expect(deps.markKilled).not.toHaveBeenCalled();
  });

  it('preserves the original tool call args across the txId round-trip via the REAL PendingCtx store (review FIX 3: no pipeline-local pendingArgs side-channel)', async () => {
    resetPendingStore();

    // Use the real putPending/peekPending/takePending (not mocked) so this
    // test actually exercises the round-trip through hitl/pending.ts's own
    // store — args now live directly on PendingCtx, so there is no
    // separate side-channel map to drift out of sync or leak.
    const { deps: runDeps } = makeRunDeps({
      gateTool: () => ({ tier: 2, rarAction: 'record_write', scope: 'records:write', allowed: true }),
      exchangeToken: async () => ({ status: 'mfa_challenge' as const, challengeToken: 'challenge-xyz' }),
      genTxId: () => 'tx-args-roundtrip',
      putPending: realPutPending,
    });

    await runPipeline(
      { userToken: 'user-token', toolName: 'update_record', args: { recordId: 'REC-1', field: 'status', value: 'active' } },
      runDeps as any,
    );

    const { deps } = makeCompleteDeps({
      peekPending: realPeekPending,
      takePending: realTakePending,
    });

    const result = await completePending('tx-args-roundtrip', 'user-1', deps as any);

    expect(result.status).toBe('ok');
    expect(deps.callUpstreamTool).toHaveBeenCalledWith({
      name: 'update_record',
      arguments: { recordId: 'REC-1', field: 'status', value: 'active' },
      obo: 'final-obo',
      dbUser: 'v-write-1',
      dbPass: 'p4ss',
    });

    resetPendingStore();
  });

  // ── Hardening fix: no-poll-URL guard (both HITL methods) ────────────────
  //
  // A pending tx whose push/OTP trigger never actually fired (best-effort
  // trigger failed at park time — see runPipeline's transient_email/push
  // tests above) has transactionUri === undefined. Before this fix,
  // completePending fell straight into pollOAuthMfaStatus('', ...), which
  // threw a raw "Failed to parse URL from ?returnJwt=true" instead of a
  // clean error envelope.
  describe('no-poll-URL guard (hardening fix)', () => {
    it('push ctx with no transactionUri -> error("no_poll_url"), pollOAuthMfaStatus is NEVER called (does not crash)', async () => {
      const { deps } = makeCompleteDeps({
        peekPending: () => makeCtx({ hitlMethod: 'push', transactionUri: undefined }),
        takePending: () => makeCtx({ hitlMethod: 'push', transactionUri: undefined }),
      });

      const result = await completePending('tx-1', 'user-1', deps as any);

      expect(result).toEqual({ status: 'error', error: 'no_poll_url' });
      expect(deps.pollOAuthMfaStatus).not.toHaveBeenCalled();
      expect(deps.exchangeMfaAssertionWithRAR).not.toHaveBeenCalled();
    });

    it('email_otp ctx with no transactionUri (trigger never fired) -> error("otp_init_failed"), submitTransientOtp is NEVER called', async () => {
      const { deps } = makeCompleteDeps({
        peekPending: () => makeCtx({ hitlMethod: 'email_otp', transactionUri: undefined }),
        takePending: () => makeCtx({ hitlMethod: 'email_otp', transactionUri: undefined }),
        submitTransientOtp: async () => ({ status: 'approved' as const, assertion: 'should-not-be-called' }),
      });

      const result = await completePending('tx-1', 'user-1', deps as any, '123456');

      expect(result).toEqual({ status: 'error', error: 'otp_init_failed' });
      expect(deps.submitTransientOtp).not.toHaveBeenCalled();
    });
  });

  // ── HITL_METHOD=transient_email resume path ──────────────────────────────
  describe('transient_email (email_otp) resume path', () => {
    function makeOtpCtx(overrides: Partial<PendingCtx> = {}): PendingCtx {
      return makeCtx({
        hitlMethod: 'email_otp',
        transactionUri: 'https://verify.test/v2.0/factors/emailotp/transient/verifications/verif-1',
        ...overrides,
      });
    }

    function makeOtpDeps(overrides: Record<string, unknown> = {}) {
      return makeCompleteDeps({
        peekPending: () => makeOtpCtx(),
        takePending: () => makeOtpCtx(),
        submitTransientOtp: async () => ({ status: 'approved' as const, assertion: 'otp-assertion-jwt' }),
        ...overrides,
      });
    }

    it('otp missing -> error("otp_required"), validated off the non-destructive PEEK — takePending/submitTransientOtp/pollOAuthMfaStatus are NEVER called (the one-shot tx is not burned by a forgotten field)', async () => {
      const { deps } = makeOtpDeps();

      const result = await completePending('tx-1', 'user-1', deps as any); // no otp arg

      expect(result).toEqual({ status: 'error', error: 'otp_required' });
      expect(deps.takePending).not.toHaveBeenCalled();
      expect(deps.submitTransientOtp).not.toHaveBeenCalled();
      expect(deps.pollOAuthMfaStatus).not.toHaveBeenCalled();
    });

    it('otp missing but push-parked (hitlMethod:"push") -> otp is simply ignored, normal poll-based flow proceeds', async () => {
      const { deps } = makeCompleteDeps(); // default makeCtx() has no hitlMethod -> 'push'

      const result = await completePending('tx-1', 'user-1', deps as any); // no otp

      expect(result).toMatchObject({ status: 'ok' });
      expect(deps.pollOAuthMfaStatus).toHaveBeenCalled();
      expect(deps.submitTransientOtp).not.toHaveBeenCalled();
    });

    it('correct otp -> submitTransientOtp -> exchangeMfaAssertionWithRAR -> mint -> upstream -> revoke -> clearDeny -> ok (mirrors the push happy path)', async () => {
      const { deps, calls } = makeOtpDeps();

      const result = await completePending('tx-1', 'user-1', deps as any, '123456');

      expect(result).toMatchObject({ status: 'ok', data: { ok: true } });
      expect(deps.submitTransientOtp).toHaveBeenCalledWith(
        'https://verify.test/v2.0/factors/emailotp/transient/verifications/verif-1',
        '123456',
        'challenge-xyz',
      );
      expect(deps.exchangeMfaAssertionWithRAR).toHaveBeenCalledWith(
        'otp-assertion-jwt',
        'records:write',
        expect.any(Array),
        'exchange-secret-1',
      );
      expect(deps.pollOAuthMfaStatus).not.toHaveBeenCalled();
      expect(deps.clearDeny).toHaveBeenCalledWith('user-1');

      expectOrder(calls, [
        'peekPending',
        'takePending',
        'submitTransientOtp',
        'getExchangeClientSecret',
        'exchangeMfaAssertionWithRAR',
        'mintCred',
        'callUpstreamTool',
        'revokeLease',
        'clearDeny',
      ]);
    });

    it('wrong otp -> error("otp_invalid") with attemptsRemaining passed through, exchangeMfaAssertionWithRAR/mint/upstream never run', async () => {
      const { deps } = makeOtpDeps({
        submitTransientOtp: async () => ({ status: 'otp_invalid' as const, attemptsRemaining: 2 }),
      });

      const result = await completePending('tx-1', 'user-1', deps as any, '000000');

      expect(result).toEqual({ status: 'error', error: 'otp_invalid', attemptsRemaining: 2 });
      expect(deps.exchangeMfaAssertionWithRAR).not.toHaveBeenCalled();
      expect(deps.mintCred).not.toHaveBeenCalled();
      expect(deps.appendAudit).toHaveBeenCalledTimes(1);
      expect((deps.appendAudit as any).mock.calls[0][0]).toMatchObject({ decision: 'otp_invalid' });
    });

    it('wrong otp with no attemptsRemaining reported -> error("otp_invalid") with no attemptsRemaining key', async () => {
      const { deps } = makeOtpDeps({
        submitTransientOtp: async () => ({ status: 'otp_invalid' as const }),
      });

      const result = await completePending('tx-1', 'user-1', deps as any, '000000');

      expect(result).toEqual({ status: 'error', error: 'otp_invalid' });
      expect(result).not.toHaveProperty('attemptsRemaining');
    });

    it('expired/already-consumed otp -> error("otp_expired"), distinct from otp_invalid', async () => {
      const { deps } = makeOtpDeps({
        submitTransientOtp: async () => ({ status: 'otp_expired' as const }),
      });

      const result = await completePending('tx-1', 'user-1', deps as any, '123456');

      expect(result).toEqual({ status: 'error', error: 'otp_expired' });
      expect(deps.exchangeMfaAssertionWithRAR).not.toHaveBeenCalled();
      expect((deps.appendAudit as any).mock.calls[0][0]).toMatchObject({ decision: 'otp_expired' });
    });

    it('submitTransientOtp transport/parse error -> surfaced verbatim as {status:"error"}', async () => {
      const { deps } = makeOtpDeps({
        submitTransientOtp: async () => ({ status: 'error' as const, error: 'submitTransientOtp: 500 upstream down' }),
      });

      const result = await completePending('tx-1', 'user-1', deps as any, '123456');

      expect(result).toEqual({ status: 'error', error: 'submitTransientOtp: 500 upstream down' });
      expect(deps.exchangeMfaAssertionWithRAR).not.toHaveBeenCalled();
    });

    it('identity binding still applies BEFORE the otp check — a mismatched caller gets forbidden without submitTransientOtp ever running (even with a correct otp supplied)', async () => {
      const { deps } = makeOtpDeps();

      const result = await completePending('tx-1', 'attacker-999', deps as any, '123456');

      expect(result).toEqual({ status: 'error', error: 'forbidden' });
      expect(deps.submitTransientOtp).not.toHaveBeenCalled();
      expect(deps.takePending).not.toHaveBeenCalled();
    });
  });
});
