/**
 * policy/opa.ts: OPA guardrails query + env config (GATEWAY_OPA_MODE).
 *
 * Queries the OPA process running the agent-policy-lifecycle `guardrails`
 * bundle: POST /v1/data/agent/guardrails/decision?provenance=true, one call
 * per inbound gateway request (pipeline.ts wires this in after the tier
 * gate, see that module's Step 2.4). The real response shape below was
 * confirmed against a live `opa run -s` on loopback, not assumed:
 *
 *   { "decision_id": "<uuid>",              // only when decision_logs.console=true
 *     "provenance": { "bundles": { "<bundle-key>": { "revision": "<sha>" } } },
 *     "result": { "allow": bool, "reasons": [...], "effective_grants": {...} } }
 *
 * A bundle whose decision rule is undefined for the given input, or a path
 * that doesn't resolve, comes back 200 with NO "result" key at all. That is
 * NOT an allow, and queryOpa treats it as a query failure (`ok:false`) so a
 * caller can never mistake "OPA had nothing to say" for "OPA said yes".
 */

export type OpaMode = 'off' | 'shadow' | 'enforce';

export interface OpaConfig {
  mode: OpaMode;
  url: string;
  timeoutMs: number;
  /** GATEWAY_OPA_AGENT_ID, this gateway process's own agent identity (one
   *  agent per process; see pipeline.ts's opa input builder). */
  agentId: string;
  /** GATEWAY_VERIFY_AGENT_ID, the Verify Agent Registry id used as
   *  sub_id.id on an emitAgentRisk POST. */
  verifyAgentId: string;
  /** GATEWAY_AGENT_RISK_URL, Antenna's agent_risk source. Empty means the
   *  agent-risk emit is skipped (a warning is logged at the call site). */
  agentRiskUrl: string;
  suspendTtlSeconds: number;
}

const DEFAULT_URL = 'http://127.0.0.1:8181';
const DEFAULT_TIMEOUT_MS = 300;
const DEFAULT_SUSPEND_TTL_SECONDS = 300;
const MAX_SUSPEND_TTL_SECONDS = 900;

function parseMode(raw: string | undefined): OpaMode {
  if (!raw || raw === 'off') return 'off';
  if (raw === 'shadow' || raw === 'enforce') return raw;
  // Unknown value: refuse to start. This is a security control, and a typo
  // like "enforec" must never quietly run as off. Unset or empty stays off,
  // so a deployment that never set the var sees no change.
  throw new Error(`GATEWAY_OPA_MODE=${JSON.stringify(raw)} is not one of off|shadow|enforce`);
}

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  const n = Number(raw);
  return raw !== undefined && Number.isFinite(n) && n > 0 ? n : fallback;
}

/** Read the GATEWAY_OPA_* / GATEWAY_AGENT_* env block into one config
 *  object. `env` is injectable (tests pass a plain object), the same way
 *  every other env-driven default in this gateway is: see pipeline.ts's
 *  defaultRunPipelineDeps. */
export function loadOpaConfig(env: NodeJS.ProcessEnv = process.env): OpaConfig {
  const mode = parseMode(env['GATEWAY_OPA_MODE']);
  // Without it every call would be agent-unknown, and in enforce the third
  // one would request a suspension of GATEWAY_VERIFY_AGENT_ID.
  if (mode !== 'off' && !env['GATEWAY_OPA_AGENT_ID']) {
    throw new Error(`GATEWAY_OPA_MODE=${mode} requires GATEWAY_OPA_AGENT_ID`);
  }
  return {
    mode,
    url: env['GATEWAY_OPA_URL'] || DEFAULT_URL,
    timeoutMs: parsePositiveInt(env['GATEWAY_OPA_TIMEOUT_MS'], DEFAULT_TIMEOUT_MS),
    agentId: env['GATEWAY_OPA_AGENT_ID'] ?? '',
    verifyAgentId: env['GATEWAY_VERIFY_AGENT_ID'] ?? '',
    agentRiskUrl: env['GATEWAY_AGENT_RISK_URL'] ?? '',
    suspendTtlSeconds: Math.min(parsePositiveInt(env['GATEWAY_AGENT_SUSPEND_TTL_SECONDS'], DEFAULT_SUSPEND_TTL_SECONDS), MAX_SUSPEND_TTL_SECONDS),
  };
}

export interface OpaInput {
  agent_id: string;
  tool_id: string;
  /** Only sent when args.url is a string that parses (see egressHostFromUrl). */
  egress_host?: string;
}

export interface OpaQueryOk {
  ok: true;
  allow: boolean;
  reasons: string[];
  /** Present only when OPA's console decision log is on. */
  decisionId?: string;
  /** The bundle revision from provenance.bundles.*.revision, when present. */
  revision?: string;
}

export interface OpaQueryErr {
  ok: false;
  error: string;
}

export type OpaQueryResult = OpaQueryOk | OpaQueryErr;

interface OpaHttpBody {
  decision_id?: string;
  provenance?: { bundles?: Record<string, { revision?: string }> };
  result?: { allow?: unknown; reasons?: unknown };
}

/**
 * POST {input} to <url>/v1/data/agent/guardrails/decision?provenance=true.
 * Never throws: a timeout (AbortSignal.timeout(timeoutMs)), a non-2xx, or a
 * missing/malformed `result` all come back as {ok:false, error}, never as an
 * allow. `fetchImpl` is injectable for tests, same seam as ssf/antenna.ts.
 */
export async function queryOpa(
  input: OpaInput,
  opts: { url: string; timeoutMs: number; fetchImpl?: typeof fetch },
): Promise<OpaQueryResult> {
  const doFetch = opts.fetchImpl ?? fetch;
  try {
    const res = await doFetch(`${opts.url.replace(/\/+$/, '')}/v1/data/agent/guardrails/decision?provenance=true`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input }),
      signal: AbortSignal.timeout(opts.timeoutMs),
    });
    if (!res.ok) {
      return { ok: false, error: `http_${res.status}` };
    }
    const body = (await res.json()) as OpaHttpBody;
    const reasons = body.result?.reasons;
    if (
      typeof body.result?.allow !== 'boolean' ||
      !Array.isArray(reasons) ||
      !reasons.every((r) => typeof r === 'string')
    ) {
      return { ok: false, error: 'missing_result' };
    }
    const bundles = body.provenance?.bundles ?? {};
    return {
      ok: true,
      allow: body.result.allow,
      reasons: reasons as string[],
      decisionId: body.decision_id,
      revision: Object.values(bundles)[0]?.revision,
    };
  } catch (err) {
    const e = err as Error;
    return { ok: false, error: e.name === 'TimeoutError' ? 'timeout' : `fetch_failed:${e.message}` };
  }
}

/** `new URL(value).hostname`, lowercased, one trailing dot stripped.
 *  Userinfo and port are never part of it; an IPv6 literal keeps its
 *  brackets. Undefined for anything that isn't a parseable-URL string with
 *  a host: a missing or unparseable args.url on an egress
 *  tool must deny in enforce mode, never allow (see pipeline.ts). */
export function egressHostFromUrl(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  try {
    // One trailing dot stripped ("gitlab.com." is gitlab.com to DNS); an
    // empty host (file:, mailto:) is no host at all.
    return new URL(value).hostname.toLowerCase().replace(/\.$/, '') || undefined;
  } catch {
    return undefined;
  }
}
