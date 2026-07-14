// INTENTIONALLY INSECURE — updates contact PII with no authorization. The
// gateway maps this to Tier 3 (record_write, sensitive): a fresh approval push
// on EVERY call.
import type pg from 'pg';

export interface UpdateContactArgs {
  recordId: string;
  email: string;
}

export interface UpdatedContact {
  record_id: string;
  display_name: string;
  email: string | null;
  classification: string;
}

export async function updateContact(pool: pg.Pool, args: UpdateContactArgs): Promise<UpdatedContact | null> {
  const { rows } = await pool.query(
    `UPDATE records_demo.records
        SET email = $2
      WHERE record_id = $1
      RETURNING record_id, display_name, email, classification`,
    [args.recordId, args.email],
  );
  return rows[0] ?? null;
}
