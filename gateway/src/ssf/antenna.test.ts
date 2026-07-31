/**
 * Tests for antenna.ts.
 *
 * Uses the injected `deps.fetchImpl` for testability; the last test proves
 * the global-fetch fallback still works when no deps are passed.
 *
 * Asserts the canonical CAEP payload shape: top-level sub_id,
 * events[uri].event_timestamp as epoch SECONDS (not ms),
 * reasonAdmin/reasonUser set.
 */
import { describe, it, expect, vi } from 'vitest';
import { emitSessionRevoked } from './antenna.js';

const SESSION_REVOKED_URI =
  'https://schemas.openid.net/secevent/caep/event-type/session-revoked';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('emitSessionRevoked', () => {
  it('POSTs a well-formed CAEP payload with email sub_id when email is provided', async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(jsonResponse({ ok: true }, 201));

    const result = await emitSessionRevoked(
      { verifyUserId: 'U1', email: 'a@b.com', reason: 'test' },
      { fetchImpl },
    );

    expect(result.ok).toBe(true);
    expect(result.status).toBe(201);

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://localhost:9042/sources/agentic/events');
    expect(init.method).toBe('POST');

    const body = JSON.parse(init.body as string);

    // sub_id is TOP-LEVEL (not nested under events) — canonical CAEP shape
    expect(body.sub_id).toEqual({
      format: 'email',
      verifyUserId: 'U1',
      email: 'a@b.com',
    });

    // events keyed by the CAEP session-revoked URI
    expect(body.events).toHaveProperty(SESSION_REVOKED_URI);
    const event = body.events[SESSION_REVOKED_URI];
    expect(event.initiatingEntity).toBe('policy');
    expect(event.reasonAdmin).toEqual({ en: 'test' });
    expect(event.reasonUser).toEqual({ en: 'test' });

    // event_timestamp must be epoch SECONDS (integer), not milliseconds
    expect(typeof event.event_timestamp).toBe('number');
    expect(Number.isInteger(event.event_timestamp)).toBe(true);
    // Epoch seconds in 2026 should be ~1.78e9
    expect(event.event_timestamp).toBeGreaterThan(1_700_000_000);
    expect(event.event_timestamp).toBeLessThan(10_000_000_000); // not ms
  });

  it('uses opaque format and omits email key when no email is provided', async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(jsonResponse({ ok: true }, 201));

    await emitSessionRevoked({ verifyUserId: 'U2', reason: 'no-email-test' }, { fetchImpl });

    const [, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string);

    expect(body.sub_id.format).toBe('opaque');
    expect(body.sub_id.verifyUserId).toBe('U2');
    expect('email' in body.sub_id).toBe(false);
  });

  it('carries the Entra object id as sub_id.entraUserId when one is supplied', async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(jsonResponse({ ok: true }, 201));

    await emitSessionRevoked(
      { verifyUserId: 'U6', email: 'a@b.com', reason: 'dual-kill', entraOid: '11111111-2222-3333-4444-555555555555' },
      { fetchImpl },
    );

    const [, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string);

    // The key name is the handler's, not ours: `entraUserId`, alongside
    // verifyUserId, both TOP-LEVEL under sub_id.
    expect(body.sub_id).toEqual({
      format: 'email',
      verifyUserId: 'U6',
      email: 'a@b.com',
      entraUserId: '11111111-2222-3333-4444-555555555555',
    });
  });

  it('omits sub_id.entraUserId entirely when no oid is supplied (never an empty string)', async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(jsonResponse({ ok: true }, 201));

    await emitSessionRevoked({ verifyUserId: 'U7', email: 'a@b.com', reason: 'single-kill' }, { fetchImpl });

    const [, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string);
    // An empty entraUserId would make the handler attempt Graph with a blank
    // key; absence makes it skip the leg, which is the correct behaviour.
    expect('entraUserId' in body.sub_id).toBe(false);
  });

  it('warns loudly when emitting with no email, because the handler aborts on it while the ingester 201s', async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(jsonResponse({ ok: true }, 201));
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      await emitSessionRevoked({ verifyUserId: 'U8', reason: 'no-email' }, { fetchImpl });
      const warned = warn.mock.calls.map((c) => String(c[0])).join('\n');
      expect(warned).toContain('NO email');
      expect(warned).toContain('U8');
    } finally {
      warn.mockRestore();
    }
  });

  it('returns { ok: false, status, body } on a non-2xx fetch response', async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'bad request' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    const result = await emitSessionRevoked({ verifyUserId: 'U3', reason: 'fail-test' }, { fetchImpl });

    expect(result.ok).toBe(false);
    expect(result.status).toBe(400);
    expect(typeof result.body).toBe('string');
  });

  it('returns { ok: false, status: 0, body: <message> } when fetch throws (does not rethrow)', async () => {
    const fetchImpl = vi.fn().mockRejectedValueOnce(new Error('network failure'));

    const result = await emitSessionRevoked({ verifyUserId: 'U4', reason: 'network-fail' }, { fetchImpl });

    expect(result.ok).toBe(false);
    expect(result.status).toBe(0);
    expect(result.body).toBe('network failure');
  });

  it('falls back to the global fetch when no deps.fetchImpl is injected', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse({ ok: true }, 201));
    vi.stubGlobal('fetch', fetchMock);
    try {
      const result = await emitSessionRevoked({ verifyUserId: 'U5', reason: 'default-fetch' });
      expect(result.ok).toBe(true);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
