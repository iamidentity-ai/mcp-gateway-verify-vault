/**
 * Upstream MCP proxy — MCP gateway → the upstream ("naive") MCP server
 *
 * The gateway holds the OBO (from Token Exchange) and the ephemeral
 * verify-rar Postgres credential (from `../vault/mint.ts`). This module
 * hands both to the upstream MCP over the real MCP protocol
 * (`@modelcontextprotocol/sdk`'s `Client` + `StreamableHTTPClientTransport`),
 * injecting them as per-call HTTP headers. In the default `obo` auth mode:
 *
 *   Authorization: Bearer <obo>
 *   X-DB-Username: <dbUser>
 *   X-DB-Password: <dbPass>
 *
 * A THIRD-PARTY upstream (e.g. github/github-mcp-server) consumes Authorization
 * as ITS OWN API credential, so `upstream_token` mode relocates the OBO to a
 * custom header (X-Verify-OBO) and puts the upstream's token in Authorization —
 * see resolveUpstreamAuth. This keeps IBM Verify's OBO from both 401-ing the
 * upstream AND leaking to a SaaS API that must never receive it.
 *
 * The upstream (see examples/naive-mcp) reads exactly these
 * `x-db-username` / `x-db-password` headers off the MCP request and
 * connects to Postgres as the ephemeral role for that one tool call — this
 * is the load-bearing seam that makes the short-lived credential actually
 * reach the database. The SDK propagates per-request headers through to
 * `/mcp` tool callbacks via `requestInit.headers` on the client transport,
 * so the MCP-client path is used here — no REST fallback is needed.
 *
 * Per-call Client construction (not a shared/reused client) is deliberate —
 * the upstream `/mcp` transport is stateless (`sessionIdGenerator:
 * undefined`), and reusing a client across calls is a known MCP transport
 * desync failure mode.
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const DEFAULT_MCP_URL = 'http://127.0.0.1:3015/mcp';

// ── Types ─────────────────────────────────────────────────────

export interface CallUpstreamToolArgs {
  /** MCP tool name registered on the upstream MCP (e.g. get_record). */
  name: string;
  /** Tool arguments, forwarded verbatim to tools/call. */
  arguments: Record<string, unknown>;
  /** The scoped OBO — sent as Authorization: Bearer <obo>. */
  obo: string;
  /** Ephemeral verify-rar Postgres username — sent as X-DB-Username. */
  dbUser: string;
  /** Ephemeral verify-rar Postgres password — sent as X-DB-Password. */
  dbPass: string;
}

/** Minimal surface the proxy needs from an MCP client — real SDK Client
 *  satisfies this; the injected test double only needs to match it. */
interface UpstreamClient {
  connect(transport: unknown): Promise<void>;
  callTool(args: { name: string; arguments: Record<string, unknown> }): Promise<unknown>;
  close(): Promise<void>;
}

interface UpstreamClientBundle {
  client: UpstreamClient;
  transport: unknown;
}

export interface CallUpstreamToolDeps {
  /** Override the upstream MCP URL (tests / non-default infra). */
  url?: string;
  /**
   * Override client + transport construction. Injected so tests can mock
   * the MCP client/transport WITHOUT a live upstream server — called with
   * (url, headers) and must return { client, transport }.
   */
  clientFactory?: (url: string, headers: Record<string, string>) => UpstreamClientBundle;
  /** Override the resolved upstream auth config (tests / per-upstream tuning). */
  authConfig?: UpstreamAuthConfig;
}

// ── Upstream auth mode (Finding 3: Authorization-header collision) ─────────

export type UpstreamAuthMode = 'obo' | 'upstream_token';

export interface UpstreamAuthConfig {
  mode: UpstreamAuthMode;
  /** Header the OBO is placed in when mode === 'upstream_token' (default X-Verify-OBO). */
  oboHeader: string;
  /** Token placed in Authorization when mode === 'upstream_token' (e.g. a GitHub PAT). */
  upstreamToken?: string;
}

/**
 * Resolve the upstream auth config from env. Pure (env injectable) so it unit
 * tests without process.env. Defaults to `obo` mode — the shipped example
 * naive-mcp, and any gateway-aware upstream, read the OBO from Authorization.
 */
export function resolveUpstreamAuth(env: NodeJS.ProcessEnv = process.env): UpstreamAuthConfig {
  const mode: UpstreamAuthMode = env['UPSTREAM_AUTH_MODE'] === 'upstream_token' ? 'upstream_token' : 'obo';
  return {
    mode,
    oboHeader: env['UPSTREAM_OBO_HEADER'] || 'X-Verify-OBO',
    upstreamToken: env['UPSTREAM_AUTH_TOKEN'] || undefined,
  };
}

/**
 * Build the southbound headers. The ephemeral X-DB-* creds always ride along
 * (harmless to a non-DB upstream). WHERE the OBO goes depends on the auth mode,
 * so a third-party upstream's Authorization is never clobbered by the OBO.
 * Pure + exported for unit testing.
 */
export function buildUpstreamHeaders(args: CallUpstreamToolArgs, auth: UpstreamAuthConfig): Record<string, string> {
  const headers: Record<string, string> = {
    'X-DB-Username': args.dbUser,
    'X-DB-Password': args.dbPass,
  };
  if (auth.mode === 'upstream_token') {
    headers[auth.oboHeader] = `Bearer ${args.obo}`;
    if (auth.upstreamToken) headers['Authorization'] = `Bearer ${auth.upstreamToken}`;
  } else {
    headers['Authorization'] = `Bearer ${args.obo}`;
  }
  return headers;
}

// ── callUpstreamTool ──────────────────────────────────────────

/**
 * Connect to the upstream MCP over Streamable HTTP, injecting the OBO
 * bearer + ephemeral DB credential as per-call headers, call
 * `tools/call { name, arguments }`, return the result, and always close the
 * client afterward (success or failure).
 */
export async function callUpstreamTool(
  args: CallUpstreamToolArgs,
  deps: CallUpstreamToolDeps = {},
): Promise<unknown> {
  const url = deps.url ?? process.env.UPSTREAM_MCP_URL ?? DEFAULT_MCP_URL;
  const headers = buildUpstreamHeaders(args, deps.authConfig ?? resolveUpstreamAuth());

  const { client, transport } = deps.clientFactory
    ? deps.clientFactory(url, headers)
    : defaultClientFactory(url, headers);

  try {
    await client.connect(transport);
    return await client.callTool({ name: args.name, arguments: args.arguments });
  } finally {
    await client.close().catch(() => undefined);
  }
}

function defaultClientFactory(url: string, headers: Record<string, string>): UpstreamClientBundle {
  const client = new Client({ name: 'mcp-gateway', version: '0.1.0' });
  const transport = new StreamableHTTPClientTransport(new URL(url), {
    requestInit: { headers },
  });
  return { client: client as unknown as UpstreamClient, transport };
}
