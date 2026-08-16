/**
 * SEP-2243 header validation (Mcp-Method / Mcp-Name) — Phase 0,
 * validate-if-present.
 *
 * The 2026-07-28 MCP spec makes `Mcp-Method` (every request) and `Mcp-Name`
 * (`tools/call`, `resources/read`, `prompts/get`) REQUIRED client headers,
 * and requires body-processing servers to reject a header/body mismatch
 * with HTTP 400 + JSON-RPC `-32020`. This repo stays on protocol
 * 2025-11-25, where neither header exists, so a legacy client sends
 * neither and nothing here fires for it (rule 1) — Phase 0 never REQUIRES
 * either header, it only catches one that lies about the request it is
 * attached to.
 *
 * Pure, synchronous, no I/O — mirrors auth/dpop-verify.ts's
 * verify-fail-closed style: a typed union result, never a throw, so the
 * caller (index.ts's /mcp route) can branch on `.ok` the same way it
 * already does for DPoP.
 */

export interface McpHeaderInput {
  mcpMethod?: string;
  mcpName?: string;
}

export type McpHeaderVerdict = { ok: true } | { ok: false; message: string };

const SENTINEL_RE = /^=\?base64\?(.*)\?=$/;

// Strict base64-alphabet check. Buffer.from(str, 'base64') is lenient — it
// silently drops characters outside the alphabet instead of throwing — so a
// malformed sentinel payload (rule 2) has to be caught here, before
// decoding, not by trusting Buffer to fail on bad input.
const BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})?$/;

/**
 * Decode one header value. A value matching the `=?base64?...?=` sentinel
 * wrapper (used when the real value would otherwise embed characters a bare
 * header can't carry) is base64-decoded to UTF-8; anything else is returned
 * unchanged. Returns undefined ONLY when the value matches the sentinel
 * pattern but its payload is not valid base64 — a malformed sentinel.
 */
export function decodeMcpHeaderValue(value: string): string | undefined {
  const match = SENTINEL_RE.exec(value);
  if (!match) return value;
  const payload = match[1] ?? '';
  if (!BASE64_RE.test(payload)) return undefined;
  return Buffer.from(payload, 'base64').toString('utf8');
}

/** Control characters per rule 3: code points < 0x20, or 0x7f (DEL). */
function hasControlChars(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

/**
 * The body value a given JSON-RPC method's Mcp-Name header is checked
 * against — params.name for tools/call and prompts/get, params.uri for
 * resources/read. Any other method has no name source (rule 5's "ignored"
 * case), including when params is missing/malformed or the field itself
 * isn't a string — we cannot know the client's intent in that case, so
 * validation is skipped rather than guessed at.
 */
function mcpNameSource(method: string, body: Record<string, unknown>): string | undefined {
  if (method !== 'tools/call' && method !== 'resources/read' && method !== 'prompts/get') return undefined;
  const params = body['params'];
  if (typeof params !== 'object' || params === null) return undefined;
  const key = method === 'resources/read' ? 'uri' : 'name';
  const value = (params as Record<string, unknown>)[key];
  return typeof value === 'string' ? value : undefined;
}

/**
 * Decode + control-char-check one header value, then compare it against its
 * expected body value. `headerName` is the exact display name (`Mcp-Method`
 * / `Mcp-Name`) used in every message this returns.
 */
function checkHeader(headerName: string, rawValue: string, expected: string): McpHeaderVerdict {
  const decoded = decodeMcpHeaderValue(rawValue);
  if (decoded === undefined) {
    return { ok: false, message: `Malformed ${headerName} header value: invalid base64 sentinel` };
  }
  if (hasControlChars(decoded)) {
    return { ok: false, message: `Malformed ${headerName} header value: contains a control character` };
  }
  if (decoded !== expected) {
    return {
      ok: false,
      message: `Header mismatch: ${headerName} header value '${decoded}' does not match body value '${expected}'`,
    };
  }
  return { ok: true };
}

/**
 * Validate Mcp-Method / Mcp-Name against the JSON-RPC body beneath them.
 * Rule 1: neither header present -> ok (nothing to validate). Rule 6: body
 * is not an object with a string `method` (batch arrays, malformed) -> ok,
 * skip validation entirely and let the SDK produce its own protocol error.
 */
export function validateMcpHeaders(input: McpHeaderInput, body: unknown): McpHeaderVerdict {
  if (input.mcpMethod === undefined && input.mcpName === undefined) return { ok: true };

  if (typeof body !== 'object' || body === null || Array.isArray(body)) return { ok: true };
  const bodyObj = body as Record<string, unknown>;
  const method = bodyObj['method'];
  if (typeof method !== 'string') return { ok: true };

  if (input.mcpMethod !== undefined) {
    const verdict = checkHeader('Mcp-Method', input.mcpMethod, method);
    if (!verdict.ok) return verdict;
  }

  if (input.mcpName !== undefined) {
    const expected = mcpNameSource(method, bodyObj);
    if (expected !== undefined) {
      const verdict = checkHeader('Mcp-Name', input.mcpName, expected);
      if (!verdict.ok) return verdict;
    }
  }

  return { ok: true };
}
