-- no-transaction
-- 0029 completed the replacement before removing the legacy index.
-- Exactly one statement, outside a transaction; see 0029.
-- Concurrent removal avoids ACCESS EXCLUSIVE on runs, but can still wait for readers.
DROP INDEX CONCURRENTLY IF EXISTS runs_tenant_created_idx;
