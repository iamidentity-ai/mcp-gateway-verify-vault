import { describe, it, expect, vi } from 'vitest';
import { updateContact } from './update-contact.js';

describe('updateContact', () => {
  it('updates the email and returns the row', async () => {
    const row = { record_id: 'REC-1001', display_name: 'Dana Reyes', email: 'new@example.com', vip_flag: false };
    const pool = { query: vi.fn().mockResolvedValue({ rows: [row] }) } as any;
    const result = await updateContact(pool, { recordId: 'REC-1001', email: 'new@example.com' });
    expect(pool.query).toHaveBeenCalledWith(expect.stringContaining('UPDATE records_demo.records'), ['REC-1001', 'new@example.com']);
    expect(result).toEqual(row);
  });

  it('returns null when the record does not exist', async () => {
    const pool = { query: vi.fn().mockResolvedValue({ rows: [] }) } as any;
    const result = await updateContact(pool, { recordId: 'REC-9999', email: 'x@example.com' });
    expect(result).toBeNull();
  });
});
