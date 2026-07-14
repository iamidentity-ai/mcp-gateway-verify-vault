// examples/naive-mcp/src/db.ts
//
// INTENTIONALLY INSECURE — the control the gateway protects. DO NOT add auth,
// Vault, Verify, or SSF plumbing here. That is precisely the gateway's job;
// this server is "what most MCP integrations look like in the wild."
//
// Connection resolver: if the caller forwards X-DB-Username / X-DB-Password
// headers, we use them uncritically — no validation, no scoping, no proof
// they belong to the caller (this is how the GATEWAY hands the naive server
// its per-request ephemeral Vault credential). If those headers are absent,
// we fall back to a single STATIC ADMIN credential from the environment —
// THAT fallback is the naive behavior: one shared, standing DB identity for
// every caller. See examples/db/naive-admin-role.sql for that role.

import pg from 'pg';

const DEFAULT_HOST = '127.0.0.1';
const DEFAULT_PORT = 5432;
const DEFAULT_DB = 'records';

/** Case-insensitive header lookup — Express lower-cases header names, but
 *  callers of resolvePool() in tests may pass mixed case. */
function header(headers: Record<string, string | undefined>, name: string): string | undefined {
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return headers[key];
  }
  return undefined;
}

/**
 * Build a pg.Pool for this request. THE FALLBACK IS THE NAIVE BEHAVIOR:
 * when the caller doesn't forward per-request DB credentials, we silently
 * reuse a single static admin credential for every caller, regardless of
 * who they are or what they're allowed to touch.
 */
export function resolvePool(headers: Record<string, string | undefined>): pg.Pool {
  const headerUser = header(headers, 'x-db-username');
  const headerPassword = header(headers, 'x-db-password');

  const user = headerUser && headerPassword ? headerUser : process.env['NAIVE_PG_USER'];
  const password = headerUser && headerPassword ? headerPassword : process.env['NAIVE_PG_PASSWORD'];

  return new pg.Pool({
    host: process.env['NAIVE_PG_HOST'] ?? DEFAULT_HOST,
    port: Number(process.env['NAIVE_PG_PORT'] ?? DEFAULT_PORT),
    database: process.env['NAIVE_PG_DB'] ?? DEFAULT_DB,
    user,
    password,
  });
}
