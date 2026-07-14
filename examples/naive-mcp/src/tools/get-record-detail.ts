// INTENTIONALLY INSECURE — plain SELECT by id, no authorization. The read
// counterpart to update_record.
import type pg from 'pg';

export interface GetRecordDetailArgs {
  recordId: string;
}

export interface DetailRow {
  id: number;
  record_id: string;
  category: string;
  value: string | null;
  status: string | null;
}

export async function getRecordDetail(pool: pg.Pool, args: GetRecordDetailArgs): Promise<DetailRow[]> {
  const { rows } = await pool.query(
    `SELECT id, record_id, category, value, status
       FROM records_demo.record_details
      WHERE record_id = $1
      ORDER BY category`,
    [args.recordId],
  );
  return rows;
}
