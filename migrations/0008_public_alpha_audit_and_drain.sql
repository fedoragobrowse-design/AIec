-- Public alpha: a security audit trail and an explicit worker drain state.
-- `sandbox_events` records what happened to a sandbox; nothing recorded who asked
-- for it and whether it was allowed. `audit_log` is that record, and it is
-- append-only for the same reason `usage_events` is.

-- `tenant_id` deliberately carries no foreign key: audit history has to outlive
-- the tenant row it describes, otherwise deleting a tenant would silently delete
-- the record of what it did while it existed.
-- `detail` is an object and nothing more. It is not an audit-log secret store:
-- producers must never put API keys, key digests, tokens, sandbox payloads or
-- environment values in it. The store does not inspect it; the calling code owns
-- that contract.
CREATE TABLE IF NOT EXISTS audit_log (
  id uuid PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  tenant_id uuid,
  actor text NOT NULL CHECK (length(actor) > 0),
  action text NOT NULL CHECK (length(action) > 0),
  subject_type text NOT NULL CHECK (length(subject_type) > 0),
  subject_id text,
  result text NOT NULL CHECK (result IN ('success', 'denied', 'failure')),
  request_id uuid,
  remote_addr text,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(detail) = 'object')
);
CREATE INDEX IF NOT EXISTS audit_log_tenant_time_idx
  ON audit_log(tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_log_action_time_idx
  ON audit_log(action, occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_log_subject_idx
  ON audit_log(subject_type, subject_id);

-- Same semantics as usage_events: row triggers reject UPDATE and DELETE, and a
-- statement-level trigger closes the TRUNCATE bypass. Rewriting history is a
-- correction bug, not a feature: a mistake is answered with another append.
CREATE OR REPLACE FUNCTION agentforge_reject_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_log_append_only ON audit_log;
CREATE TRIGGER audit_log_append_only
BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION agentforge_reject_audit_mutation();

DROP TRIGGER IF EXISTS audit_log_reject_truncate ON audit_log;
CREATE TRIGGER audit_log_reject_truncate
BEFORE TRUNCATE ON audit_log
FOR EACH STATEMENT EXECUTE FUNCTION agentforge_reject_audit_mutation();

-- Draining is not the same thing as being unhealthy. `healthy = false` means
-- "this worker is not answering", which the reconciler treats as permission to
-- expire its leases and move its sandboxes elsewhere. Draining means "this
-- worker is answering and is working through what it already has": it stops
-- receiving new sandboxes, keeps running the ones it holds, and keeps reporting
-- healthy so that its existing leases are never swept out from under it.
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS accepting_sandboxes boolean NOT NULL DEFAULT true;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS drain_reason text;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'nodes_drain_reason_length') THEN
    ALTER TABLE nodes ADD CONSTRAINT nodes_drain_reason_length
      CHECK (drain_reason IS NULL OR length(drain_reason) <= 512);
  END IF;
END
$$;
