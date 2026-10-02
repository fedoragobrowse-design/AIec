-- Durable policy proposals.
--
-- A proposal is a record of what an agent asked for and what a human decided.
-- It has to outlive the process that received it: a pending proposal that
-- vanished on restart would silently drop a decision an operator still has to
-- make. Identity, ownership and the request are immutable once written; only
-- the state advances, and only forward.

CREATE TABLE IF NOT EXISTS guard_proposals (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  sandbox_id uuid NOT NULL,
  agent_id text NOT NULL,
  request jsonb NOT NULL,
  base_policy_hash text NOT NULL,
  state jsonb NOT NULL,
  decided_by text,
  decided_at timestamptz,
  created_at timestamptz NOT NULL,
  CONSTRAINT guard_proposals_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  CONSTRAINT guard_proposals_agent_id_bounded CHECK (char_length(agent_id) BETWEEN 1 AND 64)
);

CREATE INDEX IF NOT EXISTS guard_proposals_by_sandbox
  ON guard_proposals (tenant_id, sandbox_id, created_at DESC);

-- An operator release is the one exit from a quarantine, and the latch has to
-- recognise exactly that one. The marker is set by the release path in the same
-- statement as the state change, so no other writer can produce it and no other
-- transition is permitted.
ALTER TABLE sandboxes ADD COLUMN IF NOT EXISTS guard_released_at timestamptz;
ALTER TABLE sandboxes ADD COLUMN IF NOT EXISTS guard_released_by text;

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
    IF NEW.guard_released_at IS NULL OR NEW.state <> 'paused' THEN
      RAISE EXCEPTION 'Guard quarantine requires explicit human release'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  IF TG_OP = 'UPDATE' AND NEW.guard_released_at IS NOT NULL AND OLD.guard_released_at IS NULL THEN
    IF OLD.state <> 'quarantined' THEN
      RAISE EXCEPTION 'a release marker applies only to a quarantined sandbox'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sandboxes_id_tenant_key') THEN
    ALTER TABLE sandboxes ADD CONSTRAINT sandboxes_id_tenant_key UNIQUE (id, tenant_id);
  END IF;
END
$$;

ALTER TABLE guard_proposals
  DROP CONSTRAINT IF EXISTS guard_proposals_sandbox_fk;
ALTER TABLE guard_proposals
  ADD CONSTRAINT guard_proposals_sandbox_fk
  FOREIGN KEY (sandbox_id, tenant_id) REFERENCES sandboxes(id, tenant_id) ON DELETE CASCADE;

-- A decision is a decision: a row that has been decided cannot be reopened,
-- and a pending row cannot already carry an operator or a decision time.
-- `state` is jsonb and `ProposalState::Pending` serialises as the JSON string
-- "pending", so the comparison is against a jsonb literal rather than text.
CREATE OR REPLACE FUNCTION aiec_guard_proposal_monotonic() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE'
     AND OLD.state IS DISTINCT FROM '"pending"'::jsonb
     AND NEW.state IS DISTINCT FROM OLD.state THEN
      RAISE EXCEPTION 'a decided policy proposal cannot change state';
  END IF;
  IF NEW.state = '"pending"'::jsonb
     AND (NEW.decided_by IS NOT NULL OR NEW.decided_at IS NOT NULL) THEN
    RAISE EXCEPTION 'a pending policy proposal cannot carry a decision';
  END IF;
  IF NEW.state <> '"pending"'::jsonb
     AND (NEW.decided_by IS NULL OR NEW.decided_at IS NULL) THEN
    RAISE EXCEPTION 'a decided policy proposal requires an operator and a time';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS guard_proposal_monotonic ON guard_proposals;
CREATE TRIGGER guard_proposal_monotonic BEFORE INSERT OR UPDATE ON guard_proposals
  FOR EACH ROW EXECUTE FUNCTION aiec_guard_proposal_monotonic();