import { describe, it, expect, vi } from 'vitest';
import { getRecord } from './get-record.js';

describe('getRecord', () => {
  it('selects a record by id', async () => {
    const row = { record_id: 'REC-1001', display_name: 'Dana Reyes', dob: '1980-01-01', email: 'dana@example.com', classification: 'public' };
    const pool = { query: vi.fn().mockResolvedValue({ rows: [row] }) } as any;
    const result = await getRecord(pool, { recordId: 'REC-1001' });
    expect(pool.query).toHaveBeenCalledWith(expect.stringContaining('FROM records_demo.records'), ['REC-1001']);
    expect(result).toEqual(row);
  });

  it('throws when the record does not exist', async () => {
    const pool = { query: vi.fn().mockResolvedValue({ rows: [] }) } as any;
    await expect(getRecord(pool, { recordId: 'REC-9999' })).rejects.toThrow('No record REC-9999');
  });
});
