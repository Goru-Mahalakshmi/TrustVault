-- Idempotent. Run as the schema OWNER AFTER the tables exist (scripts/init_db.py does this).
-- With two roles: the app role gets row-level DML everywhere EXCEPT audit_logs, where it is INSERT + SELECT only.
-- On hosts that give a single database user (e.g. Render free tier) the app role does not exist; the grants are skipped
-- and ONLY the trigger protects the audit table (see THREATS.md, "Knowingly accepted").
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trustvault_app') THEN
    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM trustvault_app;
    GRANT USAGE ON SCHEMA public TO trustvault_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO trustvault_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM trustvault_app;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO trustvault_app;
  END IF;
END $$;

-- Immutability trigger: blocks UPDATE / DELETE / TRUNCATE even for the table owner. Only a role that can
-- DROP/DISABLE the trigger (owner or superuser) can bypass it, and that is a deliberate, visible act.
CREATE OR REPLACE FUNCTION audit_logs_immutable() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS audit_logs_no_change   ON audit_logs;
DROP TRIGGER IF EXISTS audit_logs_no_truncate ON audit_logs;
CREATE TRIGGER audit_logs_no_change   BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();
CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_immutable();
