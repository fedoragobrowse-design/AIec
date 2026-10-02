-- Two additions to `guard_tool_approvals`, split out rather than folded into
-- 0020 so an already-migrated database is not asked to re-apply a version it
-- has already recorded a checksum for.
--
-- 1. One live request per ask. A refused call is retried, and without a
--    constraint every retry inserts another `pending` row for the same
--    (sandbox, requester, tool, arguments): the operator queue fills with copies
--    of one decision and the table grows at the retry rate.
--
--    Partial on `state = 'pending'`, so the live set stays at one row while
--    decided history accumulates freely. `denied` is deliberately excluded, so
--    asking again after a refusal is a new ask rather than a replay of the one
--    somebody already turned down.
--
-- 2. The reviewer label held to the same pending/decided rule as the reviewer
--    identity and the decision time. 0020 checks those two; leaving the label
--    out lets a pending row be written with a reviewer named on it, which reads
--    in the operator queue as somebody having already looked at it.
-- A database that has already been retried against holds duplicates that the
-- index below would refuse to be built over, so collapse them first, keeping
-- the oldest request of each group. The oldest is kept deliberately: it is the
-- one an operator may already have been shown, and its expiry is the earliest,
-- so nobody is left holding a decision whose window has already closed.
--
-- This only ever removes rows that say the same thing. Decided rows are not
-- touched; they are history, and two of them can legitimately share a key.
DELETE FROM guard_tool_approvals AS duplicate
  USING guard_tool_approvals AS keeper
  WHERE duplicate.state = 'pending'
    AND keeper.state = 'pending'
    AND duplicate.tenant_id = keeper.tenant_id
    AND duplicate.sandbox_id = keeper.sandbox_id
    AND duplicate.requested_by_key_id = keeper.requested_by_key_id
    AND duplicate.tool = keeper.tool
    AND duplicate.request_digest = keeper.request_digest
    AND (duplicate.created_at, duplicate.id) > (keeper.created_at, keeper.id);

CREATE UNIQUE INDEX IF NOT EXISTS guard_tool_approvals_one_live_request
  ON guard_tool_approvals (tenant_id, sandbox_id, requested_by_key_id, tool, request_digest)
  WHERE state = 'pending';

ALTER TABLE guard_tool_approvals
  ADD CONSTRAINT guard_tool_approvals_decided_label_bounded
  CHECK (decided_by_label IS NULL OR char_length(decided_by_label) BETWEEN 1 AND 160);

ALTER TABLE guard_tool_approvals
  ADD CONSTRAINT guard_tool_approvals_decided_label_present
  CHECK ((state = 'pending') = (decided_by_label IS NULL));