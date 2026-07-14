// INTENTIONALLY INSECURE — plain SELECT by id, no authorization.
import type pg from 'pg';

export interface GetRecordHistoryArgs {
  recordId: string;
}

export interface HistoryRow {
  id: number;
  record_id: string;
  occurred_at: string;
  kind: string | null;
  amount_cents: number | null;
  status: string | null;
  notes: string | null;
}

export async function getRecordHistory(pool: pg.Pool, args: GetRecordHistoryArgs): Promise<HistoryRow[]> {
  const { rows } = await pool.query(
    `SELECT id, record_id, occurred_at, kind, amount_cents, status, notes
       FROM records_demo.record_history
      WHERE record_id = $1
      ORDER BY occurred_at DESC`,
    [args.recordId],
  );
  return rows;
}
