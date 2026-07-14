// INTENTIONALLY INSECURE — updates a detail row with no authorization. The
// gateway maps this to Tier 2 (record_write): one Verify-policy approval push.
import type pg from 'pg';
import type { DetailRow } from './get-record-detail.js';

export interface UpdateRecordArgs {
  recordId: string;
  field: string; // the detail category to change, e.g. "coverage" / "plan"
  value: string;
}

export async function updateRecord(pool: pg.Pool, args: UpdateRecordArgs): Promise<DetailRow | null> {
  const { rows } = await pool.query(
    `UPDATE records_demo.record_details
        SET value = $3
      WHERE record_id = $1 AND category = $2
      RETURNING id, record_id, category, value, status`,
    [args.recordId, args.field, args.value],
  );
  return rows[0] ?? null;
}
