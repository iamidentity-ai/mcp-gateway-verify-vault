-- examples/db/seed.sql — a small, self-consistent "records" dataset.
-- 7 records (4 standard, 3 VIP) assigned to one owner. Idempotent.

INSERT INTO records_demo.owners (upn, display_name, is_vip_authorized) VALUES
  ('agent@example.com', 'Example Operator', TRUE),
  ('desk@example.com',  'Front Desk',       FALSE)
ON CONFLICT (upn) DO NOTHING;

INSERT INTO records_demo.records (record_id, display_name, dob, email, vip_flag) VALUES
  ('REC-1001', 'Dana Reyes',      '1980-03-14', 'dana.reyes@example.com',    FALSE),
  ('REC-1002', 'Marion Alvarez',  '1975-07-22', 'marion.alvarez@example.com',FALSE),
  ('REC-1003', 'Priya Nair',      '1990-11-05', 'priya.nair@example.com',    FALSE),
  ('REC-1004', 'Sam Whitfield',   '1968-01-30', 'sam.whitfield@example.com', FALSE),
  -- VIP records — the gateway forces a step-up MFA push before any read.
  ('REC-9001', 'Jordan Vance',    '1994-08-02', 'jordan.vance@example.com',  TRUE),
  ('REC-9002', 'Alex Okonkwo',    '1958-05-19', 'alex.okonkwo@example.com',  TRUE),
  ('REC-9003', 'Robin Castellano','1972-01-27', 'robin.castellano@example.com', TRUE)
ON CONFLICT (record_id) DO NOTHING;

-- Detail lines (category/value/status) — get_record_detail reads, update_record writes.
INSERT INTO records_demo.record_details (record_id, category, value, status)
SELECT v.record_id, v.category, v.value, v.status
FROM (VALUES
  ('REC-1001', 'plan',   'Standard',        'active'),
  ('REC-1001', 'region', 'US-East',         'active'),
  ('REC-1002', 'plan',   'Standard',        'active'),
  ('REC-1003', 'plan',   'Premium',         'active'),
  ('REC-1004', 'plan',   'Standard',        'active'),
  ('REC-9001', 'plan',   'Platinum',        'active'),
  ('REC-9001', 'region', 'US-West',         'active'),
  ('REC-9002', 'plan',   'Platinum',        'active'),
  ('REC-9003', 'plan',   'Platinum',        'active')
) AS v(record_id, category, value, status)
WHERE NOT EXISTS (
  SELECT 1 FROM records_demo.record_details d
  WHERE d.record_id = v.record_id AND d.category = v.category
);

-- A few history events for realism.
INSERT INTO records_demo.record_history (record_id, occurred_at, kind, amount_cents, status, notes)
SELECT v.record_id, v.occurred_at::timestamp, v.kind, v.amount_cents, v.status, v.notes
FROM (VALUES
  ('REC-1003', '2026-05-02 13:40', 'request',  32000,  'submitted',    'Standard request, pending review.'),
  ('REC-9001', '2026-05-10 10:30', 'request',  125000, 'under_review', 'High-value request, platinum tier.'),
  ('REC-9002', '2026-05-18 15:05', 'request',  340000, 'approved',     'Approved after review.')
) AS v(record_id, occurred_at, kind, amount_cents, status, notes)
WHERE NOT EXISTS (
  SELECT 1 FROM records_demo.record_history h
  WHERE h.record_id = v.record_id AND h.occurred_at = v.occurred_at::timestamp
);

-- Assign every record to the example operator.
INSERT INTO records_demo.assignments (owner_id, record_id)
SELECT o.id, r.record_id
FROM records_demo.owners o, records_demo.records r
WHERE o.upn = 'agent@example.com'
ON CONFLICT DO NOTHING;
