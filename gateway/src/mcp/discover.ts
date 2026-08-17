/**
 * `server/discover` pre-handler — Phase 0.
 *
 * The 2026-07-28 MCP spec has clients probe with a `server/discover` request
 * before falling back to legacy `initialize` negotiation. This repo's SDK
 * (@modelcontextprotocol/sdk) only speaks up to 2025-11-25 and has no
 * `server/discover` handler at all, so left alone it answers `-32601 Method
 * not found` — true, but unhelpful: a 2026-07-28 client has no way to learn
 * this server's actual (legacy) protocol surface and downgrade cleanly.
 *
 * `isDiscoverRequest` + `buildDiscoverResult` let the route layer (index.ts)
 * answer that probe honestly, BEFORE the request ever reaches the SDK
 * transport, without advertising a protocol version this gateway doesn't
 * actually speak.
 *
 * Both functions are pure and synchronous — no I/O, mirrors
 * mcp/header-validation.ts's style.
 */
import { SUPPORTED_PROTOCOL_VERSIONS } from '@modelcontextprotocol/sdk/types.js';

/**
 * The protocol versions this gateway's SDK (@modelcontextprotocol/sdk)
 * actually implements. Sourced from the SDK itself so this list stays true
 * automatically after the SDK is eventually bumped — see this module's doc
 * comment. Never includes '2026-07-28': that spec revision is not
 * implemented by the SDK this gateway runs, and discover must never claim
 * otherwise.
 */
const SUPPORTED_VERSIONS: readonly string[] = SUPPORTED_PROTOCOL_VERSIONS;

export interface DiscoverResult {
  resultType: 'complete';
  supportedVersions: readonly string[];
  capabilities: { tools: Record<string, never> };
  _meta: { 'io.modelcontextprotocol/serverInfo': { name: string; version: string } };
  instructions: string;
  ttlMs: number;
  cacheScope: 'public';
}

/**
 * True only for a well-formed `server/discover` JSON-RPC REQUEST — a
 * notification (no `id`) is not a request under JSON-RPC 2.0 and must fall
 * through to the SDK unchanged.
 */
export function isDiscoverRequest(
  body: unknown,
): body is { jsonrpc: '2.0'; id: string | number; method: 'server/discover'; params?: unknown } {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return false;
  const obj = body as Record<string, unknown>;
  if (obj['jsonrpc'] !== '2.0') return false;
  if (obj['method'] !== 'server/discover') return false;
  const id = obj['id'];
  return typeof id === 'string' || typeof id === 'number';
}

/**
 * Build the normative discover result. `serverInfo` must be the SAME
 * name/version the SDK's McpServer constructor was built with (index.ts's
 * GATEWAY_SERVER_INFO const), so discover and initialize can never disagree.
 *
 * cacheScope is 'public': this server's tool surface is config-static
 * (built once at module load from tools.json) and identical for every
 * caller, so a client-side cache keyed only by server identity is safe.
 */
export function buildDiscoverResult(serverInfo: { name: string; version: string }): DiscoverResult {
  return {
    resultType: 'complete',
    supportedVersions: SUPPORTED_VERSIONS,
    capabilities: { tools: {} },
    _meta: { 'io.modelcontextprotocol/serverInfo': serverInfo },
    instructions:
      'Identity-aware MCP gateway. Calls are authorized per-request via token exchange; sensitive tools may return a pending envelope that is resumed with the complete_hitl tool.',
    ttlMs: 3600000,
    cacheScope: 'public',
  };
}
