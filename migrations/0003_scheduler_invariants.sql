-- Preserve scheduler-owned capacity independently from worker observations.
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS observed_sandbox_count integer NOT NULL DEFAULT 0;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'nodes_observed_sandbox_count_nonnegative') THEN
    ALTER TABLE nodes ADD CONSTRAINT nodes_observed_sandbox_count_nonnegative
      CHECK (observed_sandbox_count >= 0);
  END IF;
END
$$;

-- Usage is a billing ledger. Row triggers reject UPDATE/DELETE; a separate
-- statement-level trigger closes the TRUNCATE bypass.
CREATE OR REPLACE FUNCTION agentforge_reject_usage_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'usage_events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS usage_events_append_only ON usage_events;
CREATE TRIGGER usage_events_append_only
BEFORE UPDATE OR DELETE ON usage_events
FOR EACH ROW EXECUTE FUNCTION agentforge_reject_usage_mutation();

DROP TRIGGER IF EXISTS usage_events_reject_truncate ON usage_events;
CREATE TRIGGER usage_events_reject_truncate
BEFORE TRUNCATE ON usage_events
FOR EACH STATEMENT EXECUTE FUNCTION agentforge_reject_usage_mutation();
