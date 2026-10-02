-- Durable requests for high-risk tool calls, and the human decisions on them.
--
-- An approval answers "may I perform *this* call", not "this tool may be used
-- freely". So a row binds one sandbox, one tool, one digest of the call's
-- arguments, one requesting identity and one use.
--
-- It is two-phase on purpose. The asker inserts a `pending` row; only a
-- different authenticated identity may transition it to `granted` or `denied`.
-- The asker comes from the principal, never from the deciding request, so a
-- caller cannot nominate somebody else to approve on its behalf.
--
-- Identity is compared as UUIDs, not as strings. A reviewer label such as
-- `key:<uuid>/oncall` would make the same key look like a different identity
-- and walk straight past a self-approval check; the labels are kept only as
-- audit metadata.
--
-- Rows outlive the process that received them: an approval that vanished on
-- restart would either strand a call a human permitted or, worse, read as a
-- refusal nobody made.

CREATE TABLE IF NOT EXISTS guard_tool_approvals (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  sandbox_id uuid NOT NULL,
  tool text NOT NULL,
  request_digest text NOT NULL,
  detail text,
  requested_by_key_id uuid NOT NULL,
  requested_by_label text NOT NULL,
  state text NOT NULL DEFAULT 'pending',
  decided_by_key_id uuid,
  decided_by_label text,
  decided_at timestamptz,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL,
  CONSTRAINT guard_tool_approvals_tenant_fk
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  CONSTRAINT guard_tool_approvals_state_known
    CHECK (state IN ('pending', 'granted', 'denied')),
  CONSTRAINT guard_tool_approvals_tool_bounded
    CHECK (char_length(tool) BETWEEN 1 AND 64 AND tool = btrim(tool)),
  CONSTRAINT guard_tool_approvals_digest_bounded
    CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  CONSTRAINT guard_tool_approvals_label_bounded
    CHECK (char_length(requested_by_label) BETWEEN 1 AND 160),
  CONSTRAINT guard_tool_approvals_expiry_after_creation
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS guard_tool_approvals_by_sandbox
  ON guard_tool_approvals (tenant_id, sandbox_id, created_at DESC);

ALTER TABLE guard_tool_approvals
  DROP CONSTRAINT IF EXISTS guard_tool_approvals_sandbox_fk;
ALTER TABLE guard_tool_approvals
  ADD CONSTRAINT guard_tool_approvals_sandbox_fk
  FOREIGN KEY (sandbox_id, tenant_id)
  REFERENCES sandboxes(id, tenant_id) ON DELETE CASCADE;

-- What was asked is fixed once written, and only the decision advances. A
-- pending row carries no decision; a decided row carries both halves of one;
-- nobody may decide their own request; and a spent approval cannot be re-armed.
-- These live in the database rather than only in the route so that a future
-- writer cannot reintroduce self-approval by forgetting a check.
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
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'what was asked cannot be rewritten'
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

DROP TRIGGER IF EXISTS guard_tool_approval_monotonic ON guard_tool_approvals;
CREATE TRIGGER guard_tool_approval_monotonic BEFORE INSERT OR UPDATE ON guard_tool_approvals
  FOR EACH ROW EXECUTE FUNCTION aiec_guard_tool_approval_monotonic();