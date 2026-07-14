// INTENTIONALLY INSECURE — plain SELECT by id, no authorization. The gateway
// (get_record, Tier 1) is what gates access; on a restricted record it runs a
// discovery read, sees classification='restricted', and forces a step-up before
// the caller ever gets the row.
import type pg from 'pg';

export interface GetRecordArgs {
  recordId: string;
}

export interface RecordRow {
  record_id: string;
  display_name: string;
  dob: string | null;
  email: string | null;
  classification: string;
}

export async function getRecord(pool: pg.Pool, args: GetRecordArgs): Promise<RecordRow> {
  const { rows } = await pool.query(
    'SELECT record_id, display_name, dob, email, classification FROM records_demo.records WHERE record_id = $1',
    [args.recordId],
  );
  if (!rows.length) throw new Error(`No record ${args.recordId}`);
  return rows[0];
}
