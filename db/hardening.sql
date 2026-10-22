-- Idempotent. Run as trustvault_owner AFTER the tables exist (scripts/init_db.py does this).
-- The app role gets row-level DML everywhere EXCEPT audit_logs, where it is INSERT + SELECT only.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM trustvault_app;
GRANT USAGE ON SCHEMA public TO trustvault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO trustvault_app;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM trustvault_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO trustvault_app;

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
