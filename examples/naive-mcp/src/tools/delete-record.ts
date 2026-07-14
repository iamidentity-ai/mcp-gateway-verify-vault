// INTENTIONALLY INSECURE — a real, unguarded DELETE. This is exactly why a
// naive MCP server is dangerous: nothing here stops a caller from destroying a
// record. The gateway maps delete_record to Tier 4 and BLOCKS it before Token
// Exchange is ever attempted, so it never reaches this handler through the
// gateway — it can only be hit by calling the naive server directly (the
// "naive mode" contrast the example demonstrates).
import type pg from 'pg';

export interface DeleteRecordArgs {
  recordId: string;
}

export async function deleteRecord(pool: pg.Pool, args: DeleteRecordArgs): Promise<{ deleted: number }> {
  const { rowCount } = await pool.query('DELETE FROM records_demo.records WHERE record_id = $1', [args.recordId]);
  return { deleted: rowCount ?? 0 };
}
