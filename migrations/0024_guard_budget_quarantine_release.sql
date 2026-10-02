-- An operator release is the one exit from a quarantine, and the budget's
-- quarantine mark is part of that latch: `guard.rs` stops offering windows for
-- a quarantined sandbox, and the durable mark is what a later read reports.
-- 0017 froze it monotone so that an ordinary budget write could never clear it,
-- which is right and was also, until now, the only thing the schema could do.
--
-- The release path therefore had nowhere sanctioned to go. It disabled the
-- latch trigger instead - catalog-scoped, so permanent for the table, and
-- irreversible from application code - and reached for a `quarantined` column
-- that was never created. The result was a release that could not commit.
--
-- This gives the escape the sandbox latch already has. The markers mirror
-- 0018's `guard_released_at`/`guard_released_by` and are set by the release
-- path in the same statement as the state change, so no other writer can
-- produce one. Clearing the mark still requires the sandbox to be released in
-- the same transaction: the trigger checks the sandbox row, which makes the
-- two halves of the release atomic in the way the latch intends. Every other
-- transition - ownership, ceilings, expiry, usage, and setting a marker on a
-- budget that was not quarantined - stays refused.
ALTER TABLE guard_budgets ADD COLUMN IF NOT EXISTS guard_released_at timestamptz;
ALTER TABLE guard_budgets ADD COLUMN IF NOT EXISTS guard_released_by text;

CREATE OR REPLACE FUNCTION aiec_guard_budget_monotone()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  released BOOLEAN := (OLD.payload->>'quarantined')::boolean
                     AND NOT (NEW.payload->>'quarantined')::boolean;
BEGIN
  IF NEW.sandbox_id <> OLD.sandbox_id
     OR NEW.tenant_id <> OLD.tenant_id
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.payload->'identity' IS DISTINCT FROM OLD.payload->'identity'
     OR NEW.payload->'expires_at' IS DISTINCT FROM OLD.payload->'expires_at'
     OR NEW.payload->'max_model_requests' IS DISTINCT FROM OLD.payload->'max_model_requests'
     OR NEW.payload->'max_bytes_in' IS DISTINCT FROM OLD.payload->'max_bytes_in'
     OR NEW.payload->'max_bytes_out' IS DISTINCT FROM OLD.payload->'max_bytes_out'
     OR (NEW.payload->>'model_requests')::numeric < (OLD.payload->>'model_requests')::numeric
     OR (NEW.payload->>'bytes_in')::numeric < (OLD.payload->>'bytes_in')::numeric
     OR (NEW.payload->>'bytes_out')::numeric < (OLD.payload->>'bytes_out')::numeric THEN
    RAISE EXCEPTION 'Guard budget ownership and limits are immutable; usage is monotone'
      USING ERRCODE = '23514';
  END IF;
  IF released THEN
    IF NEW.guard_released_at IS NULL OR NEW.guard_released_by IS NULL THEN
      RAISE EXCEPTION 'Guard budget quarantine requires explicit human release'
        USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM sandboxes
      WHERE id = NEW.sandbox_id
        AND tenant_id = NEW.tenant_id
        AND state = 'paused'
        AND guard_released_at IS NOT NULL
    ) THEN
      RAISE EXCEPTION 'Guard budget quarantine requires an already released sandbox'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  -- A marker is produced only by releasing a quarantined budget, once. It is
  -- never produced by an ordinary write and never carried forward by one.
  IF NEW.guard_released_at IS NOT NULL AND OLD.guard_released_at IS NULL THEN
    IF (OLD.payload->>'quarantined')::boolean IS NOT TRUE THEN
      RAISE EXCEPTION 'a release marker applies only to a quarantined budget'
        USING ERRCODE = '23514';
    END IF;
  ELSIF NEW.guard_released_at IS DISTINCT FROM OLD.guard_released_at
        OR NEW.guard_released_by IS DISTINCT FROM OLD.guard_released_by THEN
    RAISE EXCEPTION 'a Guard budget release marker is write-once'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;