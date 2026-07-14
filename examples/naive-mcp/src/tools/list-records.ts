// INTENTIONALLY INSECURE — returns the records assigned to an owner UPN with
// no check that the CALLER is that owner. The gateway supplies the identity
// context; this server just runs the join.
import type pg from 'pg';

export interface ListRecordsArgs {
  ownerUpn: string;
}

/**
 * A LIST row deliberately carries NO PII (no dob/email) — bulk reads return
 * identifiers + vip_flag only. Personal data is available solely through the
 * single-record reads (get_record / get_record_detail / get_record_history),
 * which the gateway VIP-gates per record. This closes the bulk-PII path: a
 * caller cannot pull a VIP record's dob/email by LISTING instead of reading it.
 */
export interface ListRecordRow {
  record_id: string;
  display_name: string;
  vip_flag: boolean;
}

export async function listRecords(pool: pg.Pool, args: ListRecordsArgs): Promise<ListRecordRow[]> {
  const { rows } = await pool.query(
    `SELECT r.record_id, r.display_name, r.vip_flag
       FROM records_demo.records r
       JOIN records_demo.assignments a ON a.record_id = r.record_id
       JOIN records_demo.owners o ON o.id = a.owner_id
      WHERE o.upn = $1
      ORDER BY r.record_id`,
    [args.ownerUpn],
  );
  return rows;
}
