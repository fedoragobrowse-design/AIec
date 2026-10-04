-- Both Guard history listings are keyset pages, and neither index covers the
-- whole key.
--
-- `guard_proposals_by_sandbox` and `guard_tool_approvals_by_sandbox` were both
-- built as `(tenant_id, sandbox_id, created_at DESC)`. The paged routes order
-- and filter on `(created_at DESC, id DESC)`: the id is the tie-breaker, because
-- `created_at` alone is not unique and a keyset predicate has to compare the
-- whole tuple or it pages past and re-reads rows sharing a timestamp.
--
-- This is the same defect `0026_sandbox_list_keyset_index.sql` fixed for the
-- sandbox list, in two more places. Both halves are a prefix of the same idea
-- and the index is named for the query it was made for, so it does not read as
-- a mismatch in review. At runtime the plan can read the index only in
-- `created_at DESC` order and then has to sort whatever falls out of it, which
-- is every row tied on `created_at`. Neither table is ever pruned - a decided
-- tool approval is deliberately retained as history - so ties accumulate, and a
-- `LIMIT` does not help because the sort happens before the limit is applied.
--
-- Both are replaced rather than added beside the old ones. Two indexes on the
-- same prefix cost a write on every proposal and every approval request, which
-- for approvals is a request the sandbox itself can make repeatedly. A
-- migration is the one moment where dropping the old one is free, and the brief
-- lock it takes is on an index, not on a table.
--
-- The migration table is append-only: this corrects the published 0018 and 0020
-- rather than editing them, and a database created fresh from 0001 to 0027 ends
-- up with exactly the indexes a database upgraded from 0001 ends up with.
DROP INDEX IF EXISTS guard_proposals_by_sandbox;
CREATE INDEX guard_proposals_by_sandbox
  ON guard_proposals (tenant_id, sandbox_id, created_at DESC, id DESC);

DROP INDEX IF EXISTS guard_tool_approvals_by_sandbox;
CREATE INDEX guard_tool_approvals_by_sandbox
  ON guard_tool_approvals (tenant_id, sandbox_id, created_at DESC, id DESC);