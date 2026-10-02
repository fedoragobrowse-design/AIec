-- A Guard budget is opened against one policy identity, and an approved
-- proposal changes that identity without changing the sandbox's lifecycle.
-- The trigger in 0017 froze the whole identity object, which made an approved
-- policy unreportable: every observation, heartbeat and reservation for the
-- sandbox afterwards failed closed against a policy that no longer existed.
--
-- The rebind is narrow on purpose. Ownership (sandbox and tenant), the
-- ceilings and the expiry stay immutable, usage stays monotone, and a
-- quarantine is still never cleared by an ordinary budget write. Only the
-- policy hash may move, and only to the hash the sandbox record now carries:
-- the control plane re-binds the row from the applied policy, so usage spent
-- under the previous policy is still spent and an approval cannot buy the
-- sandbox a second allowance.
CREATE OR REPLACE FUNCTION aiec_guard_budget_monotone()
RETURNS trigger
LANGUAGE plpgsql
AS $$
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
     OR (NEW.payload->>'bytes_out')::numeric < (OLD.payload->>'bytes_out')::numeric
     OR ((OLD.payload->>'quarantined')::boolean AND NOT (NEW.payload->>'quarantined')::boolean) THEN
    RAISE EXCEPTION 'Guard budget ownership and limits are immutable; usage and quarantine are monotone'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;