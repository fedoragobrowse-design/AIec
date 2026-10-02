-- 0024 gave the quarantine release a sanctioned exit, but it replaced the whole
-- trigger body and in doing so re-froze `payload->'identity'` as a single
-- object - exactly the check 0023 had deliberately narrowed to the two fields
-- that are ownership (`sandbox_id` and `tenant_id`) so that an approved policy
-- could rebind the row to the sandbox's new policy hash. The release work did
-- not need that widening, and it silently undid the rebind: every observation,
-- heartbeat and reservation after an approved policy now failed closed with
-- "record violates a storage invariant", and the guard telemetry the sandbox
-- reads afterwards does not answer.
--
-- Nothing in memory saw this, because the in-memory repository has no trigger
-- to re-freeze the identity: the rebind is a schema property, and only a
-- schema-level test can hold it. The narrowing is restored here and the
-- release rules are carried over from 0024 unchanged - the migration table is
-- append-only, so the two corrections are two statements about the same
-- function rather than an edit to either published file.
--
-- What stays refused is unchanged: ownership, the ceilings, the expiry, usage
-- going backwards, clearing a quarantine without an explicit release of the
-- sandbox in the same transaction, and a release marker that is not produced
-- once by releasing a quarantined budget.
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
     OR (NEW.payload->'identity'->>'sandbox_id') IS DISTINCT FROM (OLD.payload->'identity'->>'sandbox_id')
     OR (NEW.payload->'identity'->>'tenant_id') IS DISTINCT FROM (OLD.payload->'identity'->>'tenant_id')
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
