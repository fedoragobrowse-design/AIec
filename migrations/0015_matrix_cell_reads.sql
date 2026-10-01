-- Reading a matrix back without reading it N times.
--
-- `runs_matrix_idx` from 0011 was written for "which runs belong to this
-- matrix", which is a lookup with no order in it. Recovering a matrix is not
-- that: it is one tenant's cells for one matrix, oldest first, a page at a
-- time, with the labels the caller submitted them under. That is a single
-- ordered scan when the index leads with the columns the query filters and
-- then the ones it orders by, and a bitmap plus a sort when it does not.
--
-- Tenant leads deliberately. Every read of this path is tenant-scoped, and a
-- tenant that has run many matrices must not have its page answered from an
-- index shared with every other tenant's matrices.
--
-- `id` is in the index because it is the tie-break in the ordering and the
-- cursor the next page starts from, so the boundary a caller pages on is a
-- value the index can seek to rather than one it has to scan to.


-- The cell a run was admitted as, on the run itself.
--
-- The axis values are what the caller asked for and nothing else in the store
-- can reproduce them, so they are written with the run's own INSERT rather than
-- beside it: a second copy could disagree with the run it describes, and a
-- matrix whose labels are only attached after the last cell finishes loses
-- every label belonging to a cell that failed or a process that restarted.
-- Nullable and unbackfilled, because a run that is not a matrix cell has no
-- cell to name.
ALTER TABLE runs ADD COLUMN IF NOT EXISTS matrix_cell jsonb;

CREATE INDEX IF NOT EXISTS runs_matrix_ordered_idx
  ON runs(tenant_id, matrix_id, requested_at, id)
  WHERE matrix_id IS NOT NULL;
