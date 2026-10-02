-- What a human approved is fixed at write time.
--
-- 0018 made the proposal's decision one-way. This makes the request itself
-- immutable as well: a later writer - including a future refactor of the
-- repository statement, or direct SQL - must not be able to change what was
-- asked, or what it was measured against, while keeping the id that carries
-- the decision. A recorded decision cannot be rewritten either.
CREATE OR REPLACE FUNCTION aiec_guard_proposal_monotonic() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.sandbox_id IS DISTINCT FROM OLD.sandbox_id
       OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
       OR NEW.request IS DISTINCT FROM OLD.request
       OR NEW.base_policy_hash IS DISTINCT FROM OLD.base_policy_hash
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'a policy proposal cannot change what it asked for'
        USING ERRCODE = '23514';
    END IF;
    IF OLD.decided_by IS NOT NULL
       AND (NEW.decided_by IS DISTINCT FROM OLD.decided_by
            OR NEW.decided_at IS DISTINCT FROM OLD.decided_at) THEN
      RAISE EXCEPTION 'a recorded policy decision cannot be rewritten'
        USING ERRCODE = '23514';
    END IF;
    IF OLD.state IS DISTINCT FROM '"pending"'::jsonb
       AND NEW.state IS DISTINCT FROM OLD.state THEN
      RAISE EXCEPTION 'a decided policy proposal cannot change state';
    END IF;
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
$$;

DROP TRIGGER IF EXISTS guard_proposal_monotonic ON guard_proposals;
CREATE TRIGGER guard_proposal_monotonic BEFORE INSERT OR UPDATE ON guard_proposals
  FOR EACH ROW EXECUTE FUNCTION aiec_guard_proposal_monotonic();
