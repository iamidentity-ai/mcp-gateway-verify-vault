-- examples/db/schema.sql — the "records" example domain (generic, non-industry).
-- Applied by docker-compose's postgres init. Kept intentionally small.

CREATE SCHEMA IF NOT EXISTS records_demo;

-- Owners = the human operators who have records assigned to them.
CREATE TABLE IF NOT EXISTS records_demo.owners (
  id                 SERIAL PRIMARY KEY,
  upn                TEXT UNIQUE NOT NULL,          -- e.g. agent@example.com
  display_name       TEXT NOT NULL,
  is_vip_authorized  BOOLEAN DEFAULT FALSE
);

-- Records = the protected rows. vip_flag drives the gateway's step-up.
CREATE TABLE IF NOT EXISTS records_demo.records (
  record_id     TEXT PRIMARY KEY,                   -- e.g. REC-1001
  display_name  TEXT NOT NULL,
  dob           DATE,
  email         TEXT,
  vip_flag      BOOLEAN DEFAULT FALSE,              -- true -> gateway forces MFA step-up on read
  created_at    TIMESTAMP DEFAULT NOW()
);

-- Detail lines under a record (category/value/status) — the read/write pair
-- get_record_detail / update_record operate on these.
CREATE TABLE IF NOT EXISTS records_demo.record_details (
  id          SERIAL PRIMARY KEY,
  record_id   TEXT REFERENCES records_demo.records(record_id) ON DELETE CASCADE,
  category    TEXT NOT NULL,                        -- e.g. plan, tier, region
  value       TEXT,
  status      TEXT DEFAULT 'active'
);

-- Time-ordered events on a record (get_record_history).
CREATE TABLE IF NOT EXISTS records_demo.record_history (
  id            SERIAL PRIMARY KEY,
  record_id     TEXT REFERENCES records_demo.records(record_id) ON DELETE CASCADE,
  occurred_at   TIMESTAMP NOT NULL DEFAULT NOW(),
  kind          TEXT,
  amount_cents  INTEGER,
  status        TEXT,
  notes         TEXT
);

-- Which owner covers which record (list_records joins through this).
CREATE TABLE IF NOT EXISTS records_demo.assignments (
  owner_id    INTEGER REFERENCES records_demo.owners(id) ON DELETE CASCADE,
  record_id   TEXT REFERENCES records_demo.records(record_id) ON DELETE CASCADE,
  PRIMARY KEY (owner_id, record_id)
);
