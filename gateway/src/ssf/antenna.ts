// ssf/antenna.ts — CAEP session-revoked emitter.
//
// Emits CAEP session-revoked events to an SSF transmitter ("Antenna")
// container. The session_revoked action handler on the transmitter calls
// Verify's DELETE /v1.0/auth/sessions/{verifyUserId} to terminate the
// user's sessions across every app federated to the tenant.
//
// The transmitter's expected payload shape (must match exactly, otherwise
// the transmitter persists "unsigned" events and the receiver never fires):
//
//   {
//     sub_id: {
//       format: 'email' | 'opaque',
//       email?: '<user-email>',
//       verifyUserId: '<internal Verify uid>',  // required
//       entraUserId?: '<Entra object id (oid)>' // optional dual-kill key
//     },
//     events: {
//       'https://schemas.openid.net/secevent/caep/event-type/session-revoked': {
//         event_timestamp: <epoch_sec>,
//         initiatingEntity: 'policy',
//         reasonAdmin: { en: '<reason>' },
//         reasonUser: { en: '<reason>' }
//       }
//     }
//   }
//
// Notes:
//   - sub_id is TOP-LEVEL (not nested under events); event_timestamp is
//     epoch SECONDS (not ms). Getting either wrong makes the ingester 201
//     and silently drop the event.
//   - The action handler reads sub_id.verifyUserId (older handlers fall
//     back to SCIM-by-email, which is why email rides along when known)
//     and calls DELETE /v1.0/auth/sessions/{id}.
//   - `email` is treated as REQUIRED by the reference `session_revoked`
//     action handler: its very first check is `sub_id.email` and it returns
//     without doing anything when that is absent. The ingester still 201s.
//     So an emit with no email is a kill that silently does not happen —
//     this module cannot fix that from here, but it does say so loudly in
//     the log rather than let it pass unremarked.
//   - `entraUserId` drives the handler's SECOND leg, Microsoft Graph's
//     POST /users/{oid}/revokeSignInSessions, for deployments where the
//     human's primary session lives in Entra and Verify holds only the
//     delegated (STS-minted) identity. It MUST be the Entra object id: Graph
//     resolves /users/{key} as an oid or a userPrincipalName and never as
//     the `mail` attribute, so an email here 404s on a guest (`#EXT#`)
//     account. Omit it and the handler simply skips that leg.
//     A Verify subject token carries no `oid`, so a gateway fronting an
//     Entra-federated UI generally cannot fill this in itself — the oid has
//     to be threaded from the sign-in that saw the Entra id_token. Callers
//     that have it pass it; callers that do not leave it out and let the
//     event be enriched downstream.
//   - The `source_id` path segment of ANTENNA_SOURCE_URL must match a
//     source configured on the transmitter's ingester (conventionally
//     `agentic`); any other value is a 404 at the ingester, not a drop.
//   - NODE_TLS_REJECT_UNAUTHORIZED=0 may be needed in the gateway's service
//     env to allow connections to a transmitter serving self-signed HTTPS
//     on localhost.
//
// fetch is dependency-injectable via an optional `deps.fetchImpl` param;
// default behavior is the bare global `fetch`.

/** Service name — the `source` on central-dashboard events + log prefixes. */
const SERVICE_NAME = process.env.GATEWAY_SERVICE_NAME || 'mcp-gateway';

const SESSION_REVOKED_URI =
  'https://schemas.openid.net/secevent/caep/event-type/session-revoked';

// Default: the transmitter source endpoint the session_revoked handler is
// bound to. The source_id segment must match a source configured on the
// transmitter — any other source_id returns 404 at the ingester.
const SOURCE_URL =
  process.env.ANTENNA_SOURCE_URL ??
  'https://localhost:9042/sources/agentic/events';

export interface EmitInput {
  verifyUserId: string;
  email?: string;
  reason: string;
  /** Entra object id (`oid`) — NOT an email, NOT a UPN. See the header. */
  entraOid?: string;
}

export interface EmitResult {
  ok: boolean;
  status: number;
  body?: string;
}

export interface EmitDeps {
  /** Injectable for tests; defaults to the global fetch. */
  fetchImpl?: typeof fetch;
}

// ── Central events dashboard (optional) ──────────────────────────────────
// The CAEP emit below is the SECURITY channel (transmitter → Verify session
// DELETE). The dashboard is a SEPARATE observability channel: a webhook
// server that shows a "Session Revoked" badge for events pushed to
// /api/events with type agent:session_revoked. The gateway is the single
// kill choke point, so it pushes here — otherwise a real tenant-wide kill
// is invisible on the dashboard (the transmitter 201s, the Verify session
// dies, and nothing shows).
const WEBHOOK_URL = process.env.WEBHOOK_URL ?? 'http://127.0.0.1:3003';
const WEBHOOK_API_KEY = process.env.WEBHOOK_API_KEY ?? '';

/** Fire-and-forget push of the kill to the central events dashboard.
 *  Silently skipped when WEBHOOK_API_KEY is unset (local dev / tests). */
function pushKillToCentralDashboard(input: EmitInput, doFetch: typeof fetch): void {
  if (!WEBHOOK_API_KEY) return;
  doFetch(`${WEBHOOK_URL.replace(/\/$/, '')}/api/events`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Webhook-Key': WEBHOOK_API_KEY,
    },
    body: JSON.stringify({
      source: SERVICE_NAME,
      type: 'agent:session_revoked',
      userId: input.verifyUserId,
      ...(input.email ? { userEmail: input.email } : {}),
      reason: input.reason,
      timestamp: new Date().toISOString(),
    }),
    signal: AbortSignal.timeout(3_000),
  }).then(
    (res) => {
      if (!res.ok) console.warn(`[${SERVICE_NAME}-ssf] central dashboard push -> ${res.status}`);
    },
    (e: unknown) => {
      console.warn(`[${SERVICE_NAME}-ssf] central dashboard push failed: ${e instanceof Error ? e.message : e}`);
    },
  );
}

export async function emitSessionRevoked(
  input: EmitInput,
  deps: EmitDeps = {},
): Promise<EmitResult> {
  const doFetch = deps.fetchImpl ?? fetch;

  // Observability channel first (fire-and-forget) — a dashboard hiccup must
  // never delay or fail the actual CAEP kill below.
  pushKillToCentralDashboard(input, doFetch);

  // A missing email is not an error here — the emit still goes out, and a
  // downstream validator/enricher may supply it. But the reference action
  // handler aborts on it while the ingester returns 201, so the ONE thing
  // that must not happen is this passing silently.
  if (!input.email) {
    console.warn(
      `[${SERVICE_NAME}-ssf] emitting session-revoked for user=${input.verifyUserId} with NO email — ` +
        `the reference session_revoked handler returns early without sub_id.email, so the ingester will 201 ` +
        `and the kill will not happen unless something downstream supplies it`,
    );
  }

  const payload = {
    sub_id: {
      format: input.email ? 'email' : 'opaque',
      verifyUserId: input.verifyUserId,
      ...(input.email ? { email: input.email } : {}),
      ...(input.entraOid ? { entraUserId: input.entraOid } : {}),
    },
    events: {
      [SESSION_REVOKED_URI]: {
        event_timestamp: Math.floor(Date.now() / 1000),
        initiatingEntity: 'policy' as const,
        reasonAdmin: { en: input.reason },
        reasonUser: { en: input.reason },
      },
    },
  };

  try {
    const res = await doFetch(SOURCE_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5_000),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      console.warn(`[${SERVICE_NAME}-ssf] non-2xx from the transmitter: ${res.status} ${text.slice(0, 200)}`);
      return { ok: false, status: res.status, body: text };
    }
    console.log(`[${SERVICE_NAME}-ssf] session-revoked emitted for user=${input.verifyUserId} status=${res.status}`);
    return { ok: true, status: res.status };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.warn(`[${SERVICE_NAME}-ssf] fetch failed: ${msg}`);
    return { ok: false, status: 0, body: msg };
  }
}
