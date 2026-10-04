-- no-transaction
-- Build the complete descending keyset before 0030 removes 0011's timestamp-only
-- index. The ID tie-breaker prevents an unbounded sort of tied timestamps.
-- Exactly one statement: SQLx sends each file as one simple-query message;
-- multiple statements would create an implicit transaction that rejects CONCURRENTLY.
-- An interrupted build can leave an invalid index, or a valid index without the
-- migration record. Inspect and drop this replacement concurrently before retrying.
-- No IF NOT EXISTS: it must not silently accept an invalid interrupted build.
-- Concurrent DDL still waits for transactions/DDL and scans twice; it is not lock-free.
CREATE INDEX CONCURRENTLY runs_tenant_created_keyset_idx
  ON runs (tenant_id, requested_at DESC, id DESC);
