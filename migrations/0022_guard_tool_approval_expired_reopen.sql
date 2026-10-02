-- A pending approval whose window has closed can never be decided: the route
-- and `decide` both require an unexpired request. The live-request partial
-- index counts a row by `state`, not by whether anyone can still act on it, so
-- that expired row keeps holding the slot for its (tenant, sandbox, requester,
-- tool, digest). Every later retry of the same ask therefore got handed back a
-- request that no operator could grant and no consumer could spend, and the ask
-- was permanently unaskable.
--
-- The fix is to reopen the deadline on retry. That requires amending
-- `aiec_guard_tool_approval_monotonic`, which freezes `expires_at` on every
-- update. Applied migrations are not edited, so the function is replaced here
-- with exactly one clause narrowed:
--
--   * `expires_at` may move only when the row is still `pending` *and* its
--     window has already closed (`OLD.expires_at <= now()`). A request an
--     operator may currently be looking at keeps its original deadline, so a
--     retry cannot quietly push back a deadline a human is judging against.
--   * `created_at` stays frozen unconditionally. It is when the ask was made,
--     which is genuinely part of "what was asked", and leaving it stale also
--     keeps `expires_at > created_at` satisfied after a reopen.
--   * Everything else is unchanged: identity, digest, requester, label, detail
--     and tool remain immutable, and the state, decision, self-approval and
--     spend checks below are carried over verbatim.
--
-- The reopen is one-directional in practice: `get_or_put_guard_tool_approval`
-- only ever writes a strictly later deadline, so this cannot be used to shorten
-- a window or to re-arm a decided or spent approval.
CREATE OR REPLACE FUNCTION aiec_guard_tool_approval_monotonic() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.sandbox_id IS DISTINCT FROM OLD.sandbox_id
       OR NEW.tool IS DISTINCT FROM OLD.tool
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.detail IS DISTINCT FROM OLD.detail
       OR NEW.requested_by_key_id IS DISTINCT FROM OLD.requested_by_key_id
       OR NEW.requested_by_label IS DISTINCT FROM OLD.requested_by_label
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'what was asked cannot be rewritten'
        USING ERRCODE = '23514';
    END IF;
    -- The one relaxation: a deadline may be refreshed on a pending row whose
    -- window has already closed, so a retry is handed a request somebody can
    -- still act on. A row that is still open keeps its deadline.
    IF NEW.expires_at IS DISTINCT FROM OLD.expires_at
       AND NOT (OLD.state = 'pending' AND OLD.expires_at <= now()) THEN
      RAISE EXCEPTION 'an open approval keeps the deadline it was made with'
        USING ERRCODE = '23514';
    END IF;
    IF OLD.state <> 'pending' AND NEW.state IS DISTINCT FROM OLD.state THEN
      RAISE EXCEPTION 'a decided approval cannot change state'
        USING ERRCODE = '23514';
    END IF;
    -- Once decided, the decision itself is frozen. Without this a later write
    -- could keep `state = 'granted'` and rewrite who granted it or when, which
    -- would launder a decision through an identity that was never asked.
    IF OLD.state <> 'pending'
       AND (NEW.decided_by_key_id IS DISTINCT FROM OLD.decided_by_key_id
            OR NEW.decided_by_label IS DISTINCT FROM OLD.decided_by_label
            OR NEW.decided_at IS DISTINCT FROM OLD.decided_at) THEN
      RAISE EXCEPTION 'a decided approval cannot be re-decided'
        USING ERRCODE = '23514';
    END IF;
    IF OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at THEN
      RAISE EXCEPTION 'a spent approval cannot be re-armed'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  IF NEW.state = 'pending' THEN
    IF NEW.decided_by_key_id IS NOT NULL OR NEW.decided_at IS NOT NULL THEN
      RAISE EXCEPTION 'a pending request cannot carry a decision'
        USING ERRCODE = '23514';
    END IF;
  ELSE
    IF NEW.decided_by_key_id IS NULL OR NEW.decided_at IS NULL THEN
      RAISE EXCEPTION 'a decided request requires an operator and a time'
        USING ERRCODE = '23514';
    END IF;
    -- The check scope separation cannot make: one key may hold both
    -- `sandboxes:write` and `guard:approve`, and `admin` satisfies both.
    IF NEW.decided_by_key_id = NEW.requested_by_key_id THEN
      RAISE EXCEPTION 'a request cannot be decided by the identity that asked'
        USING ERRCODE = '23514';
    END IF;
    IF NEW.decided_at < NEW.created_at THEN
      RAISE EXCEPTION 'a decision cannot predate the request'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  IF NEW.consumed_at IS NOT NULL THEN
    IF NEW.state <> 'granted' THEN
      RAISE EXCEPTION 'only a granted approval can be spent'
        USING ERRCODE = '23514';
    END IF;
    IF NEW.decided_at IS NULL OR NEW.consumed_at < NEW.decided_at THEN
      RAISE EXCEPTION 'an approval cannot be spent before it was granted'
        USING ERRCODE = '23514';
    END IF;
    IF NEW.consumed_at > NEW.expires_at THEN
      RAISE EXCEPTION 'an expired approval cannot be spent'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;