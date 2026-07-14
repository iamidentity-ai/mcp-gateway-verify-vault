// examples/naive-mcp/src/index.ts
//
// INTENTIONALLY INSECURE — the "records" example MCP server the gateway
// protects. No bearer gate, no Verify, no Vault, no SSF. Two transports share
// one dispatcher:
//   POST /tool  -> simple REST {name, arguments} -> JSON (curl-friendly)
//   POST /mcp   -> real MCP protocol over Streamable HTTP, stateless (fresh
//                  transport + server per request, sessionIdGenerator: undefined)
// Per-request DB credentials: resolvePool(headers) reads X-DB-Username /
// X-DB-Password off the inbound request (that is how the gateway hands over its
// ephemeral Vault credential) and falls back to a static admin credential when
// absent. Each dispatch opens its own pool and closes it in a finally block.
// DO NOT add auth here — that is the gateway's job.

import express, { type Request, type Response } from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type pg from 'pg';
import { z } from 'zod';
import { resolvePool } from './db.js';
import { getRecord } from './tools/get-record.js';
import { listRecords } from './tools/list-records.js';
import { getRecordHistory } from './tools/get-record-history.js';
import { getRecordDetail } from './tools/get-record-detail.js';
import { updateRecord } from './tools/update-record.js';
import { updateContact } from './tools/update-contact.js';
import { deleteRecord } from './tools/delete-record.js';

const PORT = Number(process.env['PORT'] ?? 3015);
const SERVICE = 'example-naive-mcp';

const app = express();
app.use(express.json({ limit: '1mb' }));

app.get('/healthz', (_req: Request, res: Response) => {
  res.json({ status: 'ok' });
});

/** Web-standard Headers and Node IncomingHttpHeaders can both carry multi-value
 *  entries as string[]; resolvePool wants single strings, so collapse to first. */
function toHeaderRecord(
  headers: Record<string, string | string[] | undefined> | undefined,
): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(headers ?? {})) {
    out[key] = Array.isArray(value) ? value[0] : value;
  }
  return out;
}

/** Shared by both transports: resolve a per-request pool from headers, run the
 *  named tool's pure-SQL function, then close the pool. */
async function dispatchTool(
  name: string,
  args: Record<string, unknown>,
  headers: Record<string, string | string[] | undefined>,
): Promise<unknown> {
  const pool: pg.Pool = resolvePool(toHeaderRecord(headers));
  try {
    switch (name) {
      case 'get_record':
        return await getRecord(pool, { recordId: args['recordId'] as string });
      case 'list_records':
        return await listRecords(pool, { ownerUpn: args['ownerUpn'] as string });
      case 'get_record_history':
        return await getRecordHistory(pool, { recordId: args['recordId'] as string });
      case 'get_record_detail':
        return await getRecordDetail(pool, { recordId: args['recordId'] as string });
      case 'update_record':
        return await updateRecord(pool, {
          recordId: args['recordId'] as string,
          field: args['field'] as string,
          value: args['value'] as string,
        });
      case 'update_contact':
        return await updateContact(pool, {
          recordId: args['recordId'] as string,
          email: args['email'] as string,
        });
      case 'delete_record':
        return await deleteRecord(pool, { recordId: args['recordId'] as string });
      default: {
        const err = new Error(`unknown_tool: ${name}`);
        (err as Error & { code?: string }).code = 'unknown_tool';
        throw err;
      }
    }
  } finally {
    await pool.end();
  }
}

// ── Transport 1: POST /tool (simple REST) ────────────────────────────────
app.post('/tool', async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const name = body['name'] as string | undefined;
  const args = (body['arguments'] ?? {}) as Record<string, unknown>;
  if (!name) return res.status(400).json({ error: 'missing_name' });
  try {
    const result = await dispatchTool(name, args, req.headers);
    res.json(result);
  } catch (err) {
    const e = err as Error & { code?: string };
    if (e.code === 'unknown_tool') return res.status(400).json({ error: 'unknown_tool', name });
    res.status(500).json({ error: 'tool_error', message: e.message });
  }
});

// ── Transport 2: POST /mcp (MCP protocol over Streamable HTTP) ───────────
function buildMcpServer(): McpServer {
  const server = new McpServer({ name: SERVICE, version: '0.1.0' });
  const text = (result: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(result) }] });

  server.registerTool(
    'get_record',
    { title: 'Get a record', description: 'Returns a single record by id.', inputSchema: { recordId: z.string() } },
    async (args, extra) => text(await dispatchTool('get_record', args, extra.requestInfo?.headers ?? {})),
  );
  server.registerTool(
    'list_records',
    { title: "List an owner's records", description: 'Records assigned to the given owner UPN.', inputSchema: { ownerUpn: z.string() } },
    async (args, extra) => text(await dispatchTool('list_records', args, extra.requestInfo?.headers ?? {})),
  );
  server.registerTool(
    'get_record_history',
    { title: 'Get record history', description: 'Events on a record, most recent first.', inputSchema: { recordId: z.string() } },
    async (args, extra) => text(await dispatchTool('get_record_history', args, extra.requestInfo?.headers ?? {})),
  );
  server.registerTool(
    'get_record_detail',
    { title: 'Get record detail lines', description: 'Category/value/status lines under a record.', inputSchema: { recordId: z.string() } },
    async (args, extra) => text(await dispatchTool('get_record_detail', args, extra.requestInfo?.headers ?? {})),
  );
  server.registerTool(
    'update_record',
    { title: 'Update a record detail', description: 'Set a detail category value.', inputSchema: { recordId: z.string(), field: z.string(), value: z.string() } },
    async (args, extra) => text(await dispatchTool('update_record', args, extra.requestInfo?.headers ?? {})),
  );
  server.registerTool(
    'update_contact',
    { title: 'Update contact email', description: 'Set a record contact email (PII).', inputSchema: { recordId: z.string(), email: z.string() } },
    async (args, extra) => text(await dispatchTool('update_contact', args, extra.requestInfo?.headers ?? {})),
  );
  server.registerTool(
    'delete_record',
    { title: 'Delete a record', description: 'Deletes a record (naive: unguarded).', inputSchema: { recordId: z.string() } },
    async (args, extra) => text(await dispatchTool('delete_record', args, extra.requestInfo?.headers ?? {})),
  );
  return server;
}

app.post('/mcp', async (req: Request, res: Response) => {
  const server = buildMcpServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on('close', () => {
    transport.close();
    server.close();
  });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[${SERVICE}] INTENTIONALLY INSECURE — listening on http://127.0.0.1:${PORT}`);
});
