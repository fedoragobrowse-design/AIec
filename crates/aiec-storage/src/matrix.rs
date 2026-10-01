//! Recovering a matrix's cells as one bounded page.
//!
//! A matrix is a set of runs that were submitted together, so the honest way to
//! read it back is a group read: one ordered page of runs, each still carrying
//! the axis values it was submitted under. The alternative - a caller's
//! `matrix_id` turned into a loop of run reads - is the N+1 this module exists
//! to avoid, and it is the shape that made a large evaluation unaffordable to
//! recover after its response was lost.
//!
//! Two properties the query keeps:
//!
//! * **Bounded.** A page is a page. The caller asks for `limit` rows and is
//!   told where the next one starts, so a matrix of any size is read at a size
//!   the caller chose and the rows behind that page are never fetched.
//! * **Tenant-scoped.** The read filters on the owning tenant, so a matrix id
//!   belonging to somebody else is an empty result here, not a slower one.
//!
//! There is no write in this module, and that is the point: a cell's axis is
//! written with the run's own insert, so there is no second copy of the
//! membership that could disagree with the run it describes.

use aiec_core::{
    run::MatrixCellIdentity,
    storage::{MatrixCell, MatrixCellPage, MatrixCursor},
};
use uuid::Uuid;

#[cfg(test)]
use std::collections::BTreeMap;

use crate::{PostgresRepository, StoreError, database_error, postgres::run_from_row};

/// Largest page a caller may ask for.
///
/// A cell is a whole run, output included, so a page is a document rather than a
/// row. The ceiling bounds a response, not a matrix: a larger matrix is read in
/// more pages.
const MAX_PAGE: u32 = 256;

/// Reads one page of a matrix's cells, oldest first.
///
/// The page is the ordered run rows themselves: the cell a run was admitted as
/// is a column on that run, so reading a matrix is the one query it always was
/// rather than a query plus a per-cell lookup. The `LIMIT` is one row past the
/// page so `next` can say whether anything follows without a second count.
pub(crate) async fn list_matrix_cells(
    repository: &PostgresRepository,
    tenant: Uuid,
    matrix: Uuid,
    limit: u32,
    after: Option<MatrixCursor>,
) -> Result<MatrixCellPage, StoreError> {
    let limit = limit.clamp(1, MAX_PAGE);
    let (at, before) = match after {
        Some(cursor) => (Some(cursor.requested_at), Some(cursor.id)),
        None => (None, None),
    };
    let rows = sqlx::query(
        "SELECT * FROM runs \
         WHERE tenant_id = $1 AND matrix_id = $2 \
           AND ($3::timestamptz IS NULL OR (requested_at, id) > ($3::timestamptz, $4::uuid)) \
         ORDER BY requested_at, id LIMIT $5",
    )
    .bind(tenant)
    .bind(matrix)
    .bind(at)
    .bind(before)
    .bind(i64::from(limit) + 1)
    .fetch_all(&repository.pool)
    .await
    .map_err(database_error)?;

    let mut cells = Vec::with_capacity(rows.len().min(limit as usize));
    for row in rows.iter().take(limit as usize) {
        let run = run_from_row(row)?;
        // Absent labels are reported as absent. A run admitted without a cell
        // is a real thing to see, and inventing a position or an axis for it
        // would put a cell in the experiment that was never run in it.
        let (index, axis) = match &run.matrix_cell {
            Some(MatrixCellIdentity { index, axis }) => (Some(*index), Some(axis.clone())),
            None => (None, None),
        };
        cells.push(MatrixCell { run, index, axis });
    }
    // The cursor is the last cell this page returned, not the row held back to
    // prove another page exists: pointing at that row would skip it, and a
    // caller paging to the end would never be shown it at all.
    let next = match (rows.len() > limit as usize, cells.last()) {
        (true, Some(last)) => Some(MatrixCursor {
            requested_at: last.run.requested_at,
            id: last.run.id,
        }),
        _ => None,
    };
    Ok(MatrixCellPage { cells, next })
}

#[cfg(test)]
mod tests {
    use super::*;

    use aiec_core::{
        new_id,
        run::{Run, RunState, WorkloadSpec},
    };
    use chrono::{TimeZone, Utc};
    use sqlx::{PgPool, postgres::PgPoolOptions};

    struct Fixture {
        repository: PostgresRepository,
        admin: PgPool,
        schema: String,
    }

    impl Fixture {
        async fn new() -> Option<Self> {
            let url = std::env::var("DATABASE_URL")
                .ok()
                .filter(|url| !url.trim().is_empty())?;
            let admin = PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .unwrap();
            let schema = format!("matrix_test_{}", new_id().simple());
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&admin)
                .await
                .unwrap();
            let search_path = format!("SET search_path TO {schema}");
            let pool = PgPoolOptions::new()
                .max_connections(4)
                .after_connect(move |connection, _| {
                    let search_path = search_path.clone();
                    Box::pin(async move {
                        sqlx::query(&search_path).execute(connection).await?;
                        Ok(())
                    })
                })
                .connect(&url)
                .await
                .unwrap();
            let repository = PostgresRepository::from_pool(pool);
            repository.migrate().await.unwrap();
            Some(Self {
                repository,
                admin,
                schema,
            })
        }

        async fn tenant(&self) -> Uuid {
            let id = new_id();
            sqlx::query("INSERT INTO tenants(id,name) VALUES ($1,$2)")
                .bind(id)
                .bind(format!("matrix-{id}"))
                .execute(&self.repository.pool)
                .await
                .unwrap();
            id
        }

        /// Stores one cell exactly as admission does: the run and the cell it
        /// was admitted as, in the same insert.
        async fn run(&self, tenant: Uuid, matrix: Uuid, index: u32) -> Run {
            self.stored(tenant, matrix, index, Some(index)).await
        }

        /// Stores one run, with or without the cell it was admitted as.
        async fn stored(&self, tenant: Uuid, matrix: Uuid, index: u32, cell: Option<u32>) -> Run {
            let requested_at = Utc
                .timestamp_opt(1_700_000_000 + i64::from(index), 0)
                .single()
                .expect("a whole second");
            let run = Run {
                id: new_id(),
                tenant_id: tenant,
                state: RunState::Queued,
                requested_at,
                queued_at: Some(requested_at),
                started_at: None,
                completed_at: None,
                workload: WorkloadSpec {
                    command: vec!["true".into()],
                    ..Default::default()
                },
                resources: Default::default(),
                requirements: Default::default(),
                placement: Default::default(),
                results: Default::default(),
                failure_reason: None,
                retention: Default::default(),
                retained_sandbox_id: None,
                retained_until: None,
                idempotency_key: None,
                parent_run_id: None,
                matrix_id: Some(matrix),
                matrix_cell: cell.map(|index| MatrixCellIdentity {
                    index,
                    axis: axis(&format!("cell-{index}")),
                }),
            };
            let mut tx = self.repository.pool.begin().await.unwrap();
            let stored = crate::postgres::insert_run_tx(&mut tx, run).await.unwrap();
            tx.commit().await.unwrap();
            stored
        }

        async fn close(self) {
            self.repository.pool.close().await;
            sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
                .execute(&self.admin)
                .await
                .unwrap();
            self.admin.close().await;
        }
    }

    fn axis(task: &str) -> BTreeMap<String, String> {
        BTreeMap::from([("task".to_owned(), task.to_owned())])
    }

    /// A matrix comes back the way it went in: one bounded page, in submission
    /// order, each cell beside the axis it was submitted under, and the cursor
    /// naming a cell the next page starts after rather than one it repeats.
    #[tokio::test]
    async fn matrix_cells_are_paged_in_order_with_their_axes() {
        let Some(fixture) = Fixture::new().await else {
            return;
        };
        let tenant = fixture.tenant().await;
        let matrix = new_id();
        let mut runs = Vec::new();
        for index in 0..5u32 {
            runs.push(fixture.run(tenant, matrix, index).await);
        }
        let first = list_matrix_cells(&fixture.repository, tenant, matrix, 2, None)
            .await
            .unwrap();
        assert_eq!(first.cells.len(), 2);
        assert!(
            first.next.is_some(),
            "a page that is not the last one says so"
        );
        for (index, cell) in first.cells.iter().enumerate() {
            assert_eq!(cell.index, Some(index as u32));
            assert_eq!(cell.axis, Some(axis(&format!("cell-{index}"))));
            assert_eq!(cell.run.id, runs[index].id);
        }

        let second = list_matrix_cells(&fixture.repository, tenant, matrix, 2, first.next)
            .await
            .unwrap();
        assert_eq!(second.cells.len(), 2);
        for (index, cell) in second.cells.iter().enumerate() {
            let position = index + 2;
            assert_eq!(cell.axis, Some(axis(&format!("cell-{position}"))));
            assert_eq!(cell.run.id, runs[position].id);
        }

        let third = list_matrix_cells(&fixture.repository, tenant, matrix, 2, second.next)
            .await
            .unwrap();
        assert_eq!(third.cells.len(), 1, "the last page is the remainder");
        assert!(third.next.is_none(), "the last page has nothing after it");
        assert_eq!(third.cells[0].run.id, runs[4].id);

        // The labels live on the run rows, written by the same insert that
        // admitted the runs: nothing wrote them afterwards, so a cell whose
        // sibling failed, or an API that restarted mid-matrix, still has them.
        let labelled: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runs WHERE matrix_id = $1 AND matrix_cell IS NOT NULL",
        )
        .bind(matrix)
        .fetch_one(&fixture.repository.pool)
        .await
        .unwrap();
        assert_eq!(labelled, 5, "every admitted cell carries its own axis");
        fixture.close().await;
    }

    /// A run admitted under a matrix without a cell of its own reads back with
    /// no position and no axis rather than with a plausible guess: a reader
    /// told the labels are missing can go and look, and one handed an invented
    /// position reports on an experiment that was never run.
    #[tokio::test]
    async fn a_run_admitted_without_a_cell_reports_no_labels() {
        let Some(fixture) = Fixture::new().await else {
            return;
        };
        let tenant = fixture.tenant().await;
        let matrix = new_id();
        let labelled = fixture.run(tenant, matrix, 0).await;
        let unlabelled = fixture.stored(tenant, matrix, 1, None).await;

        let page = list_matrix_cells(&fixture.repository, tenant, matrix, 10, None)
            .await
            .unwrap();
        assert_eq!(page.cells.len(), 2);
        let cell = page
            .cells
            .iter()
            .find(|cell| cell.run.id == unlabelled.id)
            .expect("a run under this matrix is one of its cells");
        assert_eq!(cell.index, None);
        assert_eq!(cell.axis, None);
        let other = page
            .cells
            .iter()
            .find(|cell| cell.run.id == labelled.id)
            .expect("a run under this matrix is one of its cells");
        assert_eq!(other.index, Some(0));
        assert_eq!(other.axis, Some(axis("cell-0")));
        fixture.close().await;
    }

    /// Another tenant's matrix is an empty read rather than a slower one.
    #[tokio::test]
    async fn a_matrix_belonging_to_another_tenant_is_not_readable() {
        let Some(fixture) = Fixture::new().await else {
            return;
        };
        let owner = fixture.tenant().await;
        let stranger = fixture.tenant().await;
        let matrix = new_id();
        fixture.run(owner, matrix, 0).await;
        let page = list_matrix_cells(&fixture.repository, stranger, matrix, 10, None)
            .await
            .unwrap();
        assert!(
            page.cells.is_empty(),
            "another tenant's matrix must not be readable"
        );
        assert!(page.next.is_none());
        fixture.close().await;
    }
}
