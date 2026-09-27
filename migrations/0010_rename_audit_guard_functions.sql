-- Rename the append-only guard functions to the project's current name.
--
-- The earlier migrations are already applied, so their bytes must not change:
-- sqlx validates migration checksums, and editing an applied file makes the
-- database refuse to start. The rename therefore happens forward, in its own
-- checksummed migration, using the same statement style as 0003 so the statement
-- splitter handles it.

DROP TRIGGER IF EXISTS usage_events_append_only ON usage_events;
DROP TRIGGER IF EXISTS usage_events_reject_truncate ON usage_events;
DROP FUNCTION IF EXISTS agentforge_reject_usage_mutation();

CREATE OR REPLACE FUNCTION aiec_reject_usage_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'usage_events is append-only';
END;
$$;

CREATE TRIGGER usage_events_append_only
BEFORE UPDATE OR DELETE ON usage_events
FOR EACH ROW EXECUTE FUNCTION aiec_reject_usage_mutation();

CREATE TRIGGER usage_events_reject_truncate
BEFORE TRUNCATE ON usage_events
FOR EACH STATEMENT EXECUTE FUNCTION aiec_reject_usage_mutation();

-- The same rename for the security audit log's own guard, which 0008 declared
-- under the old name. Without this an `agentforge_`-named function would survive
-- in every existing database.
DROP TRIGGER IF EXISTS audit_log_append_only ON audit_log;
DROP TRIGGER IF EXISTS audit_log_reject_truncate ON audit_log;
DROP FUNCTION IF EXISTS agentforge_reject_audit_mutation();

CREATE OR REPLACE FUNCTION aiec_reject_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$;

CREATE TRIGGER audit_log_append_only
BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION aiec_reject_audit_mutation();

CREATE TRIGGER audit_log_reject_truncate
BEFORE TRUNCATE ON audit_log
FOR EACH STATEMENT EXECUTE FUNCTION aiec_reject_audit_mutation();
