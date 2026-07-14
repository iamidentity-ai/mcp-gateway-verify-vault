-- examples/db/naive-admin-role.sql
--
-- THE NAIVE MODE credential. This is the single, standing, broadly-privileged
-- LOGIN role the example naive MCP server falls back to when no per-request DB
-- credential is forwarded (see examples/naive-mcp/src/db.ts). It is deliberately
-- the anti-pattern the gateway exists to replace: one shared identity with
-- constant access to every row — compromise it once, exfiltrate everything.
--
-- The password here is a LOCAL-DEV placeholder; docker-compose sets it via env.
-- Never use naive mode against real data.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'naive_admin') THEN
    CREATE ROLE naive_admin LOGIN PASSWORD 'naive_admin_local_dev';
  END IF;
  GRANT USAGE ON SCHEMA records_demo TO naive_admin;
  GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA records_demo TO naive_admin;
  GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA records_demo TO naive_admin;
  -- BYPASSRLS on purpose: the naive fallback is the INSECURE CONTROL — it must
  -- keep seeing every row (VIP included) despite the Row-Level Security added in
  -- vault-roles.sql for the gateway's ephemeral roles. That "one identity sees
  -- everything" behaviour is exactly the anti-pattern the gateway replaces.
  ALTER ROLE naive_admin BYPASSRLS;
END $$;
