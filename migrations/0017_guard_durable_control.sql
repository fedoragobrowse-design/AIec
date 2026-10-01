-- Guard durable control-plane state: model budgets, lifetime and incidents.
-- Budget usage is serialized as JSON so the entire u64 range round-trips
-- exactly; the checks below bound it to the caps it was initialized with.
-- Every Guard transaction locks owner lease, sandbox, budget and incident in
-- that order, the same order capacity release and recovery already use.
-- Every statement is safe to re-run so operators can repair partially applied
-- deployments.
CREATE TABLE IF NOT EXISTS guard_budgets (
  sandbox_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  payload jsonb NOT NULL,
  -- Expiration is duplicated as a real column so the reaper index-compares
  -- timestamps instead of casting a JSON string on every scan.
  expires_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (sandbox_id, tenant_id) REFERENCES sandboxes(id, tenant_id),
  CHECK ((payload->'identity'->>'sandbox_id')::uuid = sandbox_id),
  CHECK ((payload->'identity'->>'tenant_id')::uuid = tenant_id),
  CHECK (payload ?& ARRAY['identity','expires_at','max_model_requests','max_bytes_in','max_bytes_out','model_requests','bytes_in','bytes_out','quarantined']),
  CHECK (jsonb_typeof(payload->'quarantined') = 'boolean'),
  CHECK ((payload->>'max_model_requests')::numeric BETWEEN 0 AND 18446744073709551615),
  CHECK ((payload->>'max_bytes_in')::numeric BETWEEN 0 AND 18446744073709551615),
  CHECK ((payload->>'max_bytes_out')::numeric BETWEEN 0 AND 18446744073709551615),
  CHECK ((payload->>'model_requests')::numeric BETWEEN 0 AND (payload->>'max_model_requests')::numeric),
  CHECK ((payload->>'bytes_in')::numeric BETWEEN 0 AND (payload->>'max_bytes_in')::numeric),
  CHECK ((payload->>'bytes_out')::numeric BETWEEN 0 AND (payload->>'max_bytes_out')::numeric)
);
CREATE INDEX IF NOT EXISTS guard_budgets_tenant_idx ON guard_budgets(tenant_id, sandbox_id);
CREATE INDEX IF NOT EXISTS guard_budgets_expiry_idx ON guard_budgets(expires_at);

CREATE TABLE IF NOT EXISTS guard_incidents (
  sandbox_id uuid PRIMARY KEY REFERENCES guard_budgets(sandbox_id),
  tenant_id uuid NOT NULL,
  incident_id uuid NOT NULL UNIQUE,
  payload jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (sandbox_id, tenant_id) REFERENCES sandboxes(id, tenant_id),
  CHECK ((payload->'identity'->>'sandbox_id')::uuid = sandbox_id),
  CHECK ((payload->'identity'->>'tenant_id')::uuid = tenant_id),
  CHECK ((payload->>'id')::uuid = incident_id)
);
CREATE INDEX IF NOT EXISTS guard_incidents_pending_idx ON guard_incidents(tenant_id, sandbox_id)
  WHERE payload->>'completed_at' IS NULL;

-- Identity, caps and expiration are immutable once initialized; usage only
-- grows and a quarantine is never cleared by an ordinary budget write.
CREATE OR REPLACE FUNCTION aiec_guard_budget_monotone()
RETURNS trigger
LANGUAGE plpgsql
AS $$
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
     OR (NEW.payload->>'bytes_out')::numeric < (OLD.payload->>'bytes_out')::numeric
     OR ((OLD.payload->>'quarantined')::boolean AND NOT (NEW.payload->>'quarantined')::boolean) THEN
    RAISE EXCEPTION 'Guard budget identity and limits are immutable; usage and quarantine are monotone'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS guard_budget_monotone ON guard_budgets;
CREATE TRIGGER guard_budget_monotone BEFORE UPDATE ON guard_budgets
  FOR EACH ROW EXECUTE FUNCTION aiec_guard_budget_monotone();

-- No ordinary pause, resume, start, reassignment, reconciliation or delete can
-- clear a quarantine or discard a quarantined sandbox: lease expiry and machine
-- loss must not hand a quarantined workload back to a scheduler. Releasing one
-- is an explicit, separately authorized operator action.
CREATE OR REPLACE FUNCTION aiec_guard_quarantine_latched()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.state = 'quarantined' THEN
      RAISE EXCEPTION 'Guard quarantine requires explicit human release'
        USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
  END IF;
  IF OLD.state = 'quarantined' AND NEW.state <> 'quarantined' THEN
    RAISE EXCEPTION 'Guard quarantine requires explicit human release'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS guard_quarantine_latched ON sandboxes;
CREATE TRIGGER guard_quarantine_latched BEFORE UPDATE OR DELETE ON sandboxes
  FOR EACH ROW EXECUTE FUNCTION aiec_guard_quarantine_latched();

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sandboxes_state_guard_check') THEN
    ALTER TABLE sandboxes ADD CONSTRAINT sandboxes_state_guard_check CHECK (
      state IN ('creating','starting','running','paused','quarantined','stopping','stopped','snapshotting','restoring','failed','destroying','destroyed')
    );
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sandbox_events_to_state_guard_check') THEN
    ALTER TABLE sandbox_events ADD CONSTRAINT sandbox_events_to_state_guard_check CHECK (
      to_state IN ('creating','starting','running','paused','quarantined','stopping','stopped','snapshotting','restoring','failed','destroying','destroyed')
    );
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sandbox_events_from_state_guard_check') THEN
    ALTER TABLE sandbox_events ADD CONSTRAINT sandbox_events_from_state_guard_check CHECK (
      from_state IS NULL OR from_state IN ('creating','starting','running','paused','quarantined','stopping','stopped','snapshotting','restoring','failed','destroying','destroyed')
    );
  END IF;
END
$$;