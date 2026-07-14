-- examples/db/vault-roles.sql
--
-- The SECURE side: the pre-baked, NOLOGIN, least-privilege Postgres roles that
-- HashiCorp Vault's verify-rar plugin grants to the short-lived ephemeral users
-- it mints per gateway tool call. These roles have NO password and cannot log
-- in on their own — a Vault-minted ephemeral user is granted membership for a
-- ~5-minute lease, runs one query, and is dropped.
--
-- Mapping to the gateway's config/rar.json creds paths (bootstrap/vault.ts
-- generates the matching Vault roles; the pgRole is derived tier-driven by
-- classifyActions, NOT by a positional scan):
--   verify-rar/creds/records          -> records_read          (record_read)          — PUBLIC rows only (RLS)
--   verify-rar/creds/records-elevated -> records_read_elevated (record_read_elevated) — ALL rows (RLS permits)
--   verify-rar/creds/records-write    -> records_write         (record_write)
--
-- DEFENSE IN DEPTH (Row-Level Security, below): the base records_read role
-- CANNOT read restricted rows even if a caller reaches a read tool the gateway's
-- step-up discovery does not cover — restricted data is readable ONLY through
-- records_read_elevated, which the gateway mints ONLY after a completed Verify
-- step-up. The gateway's discovery probe reads through records_read; for a
-- restricted record RLS returns no row, shouldStepUp FAILS CLOSED, and the
-- gateway forces the step-up. Enforcement thus holds at BOTH the gateway
-- (primary) and the data layer (backstop).
--
-- NOTE: this RLS is validated against a live Postgres (bootstrap smoke / Task 7),
-- not by the offline unit suite.

DO $$
BEGIN
  -- Base read role: RLS (below) restricts it to PUBLIC rows.
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'records_read') THEN
    CREATE ROLE records_read NOLOGIN;
  END IF;
  GRANT USAGE ON SCHEMA records_demo TO records_read;
  GRANT SELECT ON ALL TABLES IN SCHEMA records_demo TO records_read;

  -- Elevated read role: same grants, but its RLS policy sees ALL rows. The
  -- gateway mints from this role ONLY after a Verify step-up
  -- (record_read_elevated action).
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'records_read_elevated') THEN
    CREATE ROLE records_read_elevated NOLOGIN;
  END IF;
  GRANT USAGE ON SCHEMA records_demo TO records_read_elevated;
  GRANT SELECT ON ALL TABLES IN SCHEMA records_demo TO records_read_elevated;

  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'records_write') THEN
    CREATE ROLE records_write NOLOGIN;
  END IF;
  GRANT USAGE ON SCHEMA records_demo TO records_write;
  GRANT SELECT ON ALL TABLES IN SCHEMA records_demo TO records_write;
  GRANT INSERT, UPDATE ON records_demo.records, records_demo.record_details TO records_write;
  GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA records_demo TO records_write;

  -- The verify-rar plugin connection user needs ADMIN OPTION to re-grant these.
  -- bootstrap/vault.ts sets VERIFY_RAR_DB_USER; grant to it if it already exists.
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'vault_rar_admin') THEN
    GRANT records_read          TO vault_rar_admin WITH ADMIN OPTION;
    GRANT records_read_elevated TO vault_rar_admin WITH ADMIN OPTION;
    GRANT records_write         TO vault_rar_admin WITH ADMIN OPTION;
  END IF;
END $$;

-- ── Row-Level Security: the DATA-LAYER classification boundary ──────────────
-- Idempotent (DROP POLICY IF EXISTS then CREATE). RLS applies to the ephemeral
-- users because they are granted membership in these roles and are neither the
-- table owner (the migration superuser) nor BYPASSRLS. The naive_admin fallback
-- is BYPASSRLS on purpose (naive-admin-role.sql) — the insecure control MUST
-- still see everything; that is the anti-pattern being demonstrated.
ALTER TABLE records_demo.records        ENABLE ROW LEVEL SECURITY;
ALTER TABLE records_demo.record_details ENABLE ROW LEVEL SECURITY;
ALTER TABLE records_demo.record_history ENABLE ROW LEVEL SECURITY;

-- records: base role sees only classification='public'; elevated + write roles see all.
DROP POLICY IF EXISTS records_public    ON records_demo.records;
DROP POLICY IF EXISTS records_elevated  ON records_demo.records;
DROP POLICY IF EXISTS records_write_all ON records_demo.records;
CREATE POLICY records_public    ON records_demo.records FOR SELECT TO records_read          USING (classification = 'public');
CREATE POLICY records_elevated  ON records_demo.records FOR ALL    TO records_read_elevated USING (true);
CREATE POLICY records_write_all ON records_demo.records FOR ALL    TO records_write         USING (true) WITH CHECK (true);

-- record_details / record_history: gate on the PARENT record's classification. The
-- inner SELECT runs under the same role, so records' own RLS already limits it
-- to public rows for records_read — the explicit classification='public' is belt-and-braces.
DROP POLICY IF EXISTS record_details_public   ON records_demo.record_details;
DROP POLICY IF EXISTS record_details_elevated ON records_demo.record_details;
DROP POLICY IF EXISTS record_details_write_all ON records_demo.record_details;
CREATE POLICY record_details_public ON records_demo.record_details FOR SELECT TO records_read
  USING (EXISTS (SELECT 1 FROM records_demo.records r WHERE r.record_id = record_details.record_id AND r.classification = 'public'));
CREATE POLICY record_details_elevated  ON records_demo.record_details FOR ALL TO records_read_elevated USING (true);
CREATE POLICY record_details_write_all ON records_demo.record_details FOR ALL TO records_write         USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS record_history_public   ON records_demo.record_history;
DROP POLICY IF EXISTS record_history_elevated ON records_demo.record_history;
CREATE POLICY record_history_public ON records_demo.record_history FOR SELECT TO records_read
  USING (EXISTS (SELECT 1 FROM records_demo.records r WHERE r.record_id = record_history.record_id AND r.classification = 'public'));
CREATE POLICY record_history_elevated ON records_demo.record_history FOR ALL TO records_read_elevated USING (true);
