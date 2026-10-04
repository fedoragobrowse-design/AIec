//! `GET /v1/runs` against a real store: the page ceiling, the cursor that
//! reaches past it, and the refusal of half a cursor.
//!
//! Runs live in PostgreSQL only — `MemoryRepository` answers `Unsupported` for
//! every run method, deliberately, so the in-process tests cannot stand in for
//! the store here. Paging a listing the store cannot even execute would prove
//! nothing about what the caller gets back, so this runs against the real thing
//! in its own schema.
use super::*;
use aiec_core::ApiKeyRecord;
use aiec_core::run::{Run, RunState, WorkloadSpec};
use aiec_core::storage::{MatrixCursor, MetadataStore, TenantRecord};
use aiec_storage::PostgresRepository;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

const TOTAL: u32 = 210;

struct Fixture {
    state: AppState,
    repository: Arc<PostgresRepository>,
    key: String,
    seeded: Vec<(Uuid, DateTime<Utc>)>,
    admin: sqlx::PgPool,
    pool: sqlx::PgPool,
    schema: String,
}

impl Fixture {
    async fn new() -> Option<Self> {
        let url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|url| !url.trim().is_empty())?;
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("run_paging_{}", new_id().simple());
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
        let repository = Arc::new(PostgresRepository::from_pool(pool.clone()));
        repository.migrate().await.unwrap();

        let tenant = new_id();
        repository
            .put_tenant(TenantRecord {
                id: tenant,
                name: format!("run-paging-{tenant}"),
                created_at: Utc::now(),
            })
            .await
            .unwrap();

        // Seed rows directly: execution is not part of listing coverage.
        // Seeded oldest-first and listed newest-first, so the page order is the
        // reverse of the insertion order: a listing that quietly fell back to
        // insertion order fails here rather than passing. The times are
        // distinct, so a `requested_at` tie cannot paper over a broken
        // predicate either.
        let now = Utc::now();
        let mut seeded = Vec::new();
        for index in (0..TOTAL).rev() {
            let requested_at = now - chrono::Duration::seconds(i64::from(index));
            let run = repository
                .create_run(Run {
                    id: new_id(),
                    tenant_id: tenant,
                    state: RunState::Succeeded,
                    requested_at,
                    queued_at: Some(requested_at),
                    started_at: None,
                    completed_at: None,
                    workload: WorkloadSpec {
                        image: Some("ubuntu".into()),
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
                    matrix_id: None,
                    matrix_cell: None,
                })
                .await
                .unwrap();
            seeded.push((run.id, run.requested_at));
        }
        // Newest first, which is the order the listing promises.
        seeded.reverse();

        let key = generate_api_key();
        repository
            .put_key(ApiKeyRecord {
                id: new_id(),
                tenant_id: tenant,
                digest: key_digest(&key),
                scopes: vec![Scope::SandboxesRead],
                expires_at: None,
                name: "run-paging".to_string(),
                created_at: Utc::now(),
                last_used_at: None,
                revoked_at: None,
            })
            .await
            .unwrap();

        let scheduler = Arc::new(aiec_storage::PostgresScheduler::new((*repository).clone()));
        let worker = Arc::new(
            HttpWorkerClient::new_secure("run-paging-fixture-not-a-worker-credential").unwrap(),
        );
        let runtime = Arc::new(WorkerRuntime::new(
            worker,
            scheduler.clone(),
            aiec_core::runtime::RuntimeCapabilities::default(),
        ));
        let platform = Platform::builder()
            .runtime(runtime)
            .scheduler(scheduler)
            .metadata_store(repository.clone())
            .build()
            .unwrap();
        Some(Self {
            state: AppState::new(platform),
            repository,
            key,
            seeded,
            admin,
            pool,
            schema,
        })
    }

    /// One `GET /v1/runs`, as the status and the parsed body.
    async fn get(&self, query: &str) -> (StatusCode, Value) {
        let response = router(self.state.clone())
            .oneshot(
                Request::get(format!("/v1/runs{query}"))
                    .header("authorization", format!("Bearer {}", self.key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// The `(id, requested_at)` pairs of a successful page.
    ///
    /// A bare array, not an envelope: a client that never pages is unaffected,
    /// and that is the compatibility this shape buys. Asserting it here means a
    /// future convenience envelope has to be a decision rather than a drift.
    async fn page(&self, query: &str) -> Vec<(String, String)> {
        let (status, body) = self.get(query).await;
        assert_eq!(status, StatusCode::OK, "{query} returned {body}");
        let rows = body.as_array().unwrap_or_else(|| {
            panic!("the run listing must stay a bare array, not an envelope: {body}")
        });
        rows.iter()
            .map(|run| {
                (
                    run["id"].as_str().unwrap().to_string(),
                    run["requested_at"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }
}

impl Fixture {
    async fn close(self) {
        self.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.admin)
            .await
            .unwrap();
        self.admin.close().await;
    }
}

#[tokio::test]
async fn a_run_history_is_paged_past_the_ceiling_at_the_route() {
    let Some(fixture) = Fixture::new().await else {
        eprintln!("DATABASE_URL is unset; the run listing is not exercised here");
        return;
    };

    let first = fixture.page("").await;
    assert_eq!(
        first.len(),
        50,
        "the default page should hold 50 runs: {}",
        first.len()
    );
    assert_eq!(
        first[0].0,
        fixture.seeded[0].0.to_string(),
        "the newest run must lead the page"
    );

    // The cursor names the last row of the previous page, so that row must not
    // come back as the first row of the next one. A cursor that repeats its own
    // boundary row is the failure mode of paging on a key, and a two-page walk
    // over distinct timestamps is exactly where it shows.
    let (boundary_id, boundary_at) = first.last().unwrap();
    let second = fixture
        .page(&format!(
            "?limit=200&after_requested_at={boundary_at}&after_id={boundary_id}"
        ))
        .await;
    assert_eq!(
        second.len(),
        160,
        "210 runs should be a page of 50 and a page of 160"
    );
    assert_ne!(
        second[0].0, *boundary_id,
        "the cursor row must not repeat as the first row of the next page"
    );

    let mut seen: Vec<String> = first
        .iter()
        .chain(second.iter())
        .map(|(id, _)| id.clone())
        .collect();
    assert_eq!(seen.len(), TOTAL as usize, "every run exactly once");
    seen.sort();
    let mut expected: Vec<String> = fixture
        .seeded
        .iter()
        .map(|(id, _)| id.to_string())
        .collect();
    expected.sort();
    assert_eq!(seen, expected, "every seeded run exactly once");

    // A limit above the ceiling is clamped, not refused: the caller gets a page
    // rather than an error, and no more than the maximum.
    assert_eq!(
        fixture.page("?limit=100000").await.len(),
        200,
        "the page must stop at the ceiling even when more rows exist"
    );
    assert_eq!(
        fixture.page("?limit=1").await.len(),
        1,
        "a page of one is still a page"
    );
    let (last_id, last_at) = second.last().unwrap();
    assert!(
        fixture
            .page(&format!("?after_requested_at={last_at}&after_id={last_id}"))
            .await
            .is_empty(),
        "the last cursor must exhaust the history"
    );
    fixture.close().await;
}

#[tokio::test]
async fn half_a_run_cursor_is_refused_rather_than_guessed_at() {
    let Some(fixture) = Fixture::new().await else {
        eprintln!("DATABASE_URL is unset; the run listing is not exercised here");
        return;
    };
    let page = fixture.page("?limit=1").await;
    let (boundary_id, boundary_at) = page[0].clone();

    // A timestamp alone names no row to start after and an id alone cannot order
    // a page that has not been read. Either guess is a different query wearing
    // the requested query's clothes, so both are refused with the reason.
    for query in [
        format!("?after_requested_at={boundary_at}"),
        format!("?after_id={boundary_id}"),
    ] {
        let (status, body) = fixture.get(&query).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a half cursor must be refused rather than guessed at: {query} -> {body}"
        );
        assert_eq!(
            body["error"]["code"], "invalid_request",
            "the refusal must name its cause: {body}"
        );
    }
    fixture.close().await;
}

#[tokio::test]
async fn a_run_page_stops_at_another_tenants_history() {
    let Some(fixture) = Fixture::new().await else {
        eprintln!("DATABASE_URL is unset; the run listing is not exercised here");
        return;
    };
    let other = new_id();
    fixture
        .repository
        .put_tenant(TenantRecord {
            id: other,
            name: format!("run-paging-other-{other}"),
            created_at: Utc::now(),
        })
        .await
        .unwrap();
    // Newer than every run in the fixture's tenant, so an unbounded listing
    // would lead with it. Paging past it is only possible by crossing a tenant.
    let theirs = fixture
        .repository
        .create_run(Run {
            id: new_id(),
            tenant_id: other,
            state: RunState::Succeeded,
            requested_at: Utc::now() + chrono::Duration::hours(1),
            queued_at: None,
            started_at: None,
            completed_at: None,
            workload: WorkloadSpec {
                image: Some("ubuntu".into()),
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
            matrix_id: None,
            matrix_cell: None,
        })
        .await
        .unwrap();

    for page in [fixture.page("").await, fixture.page("?limit=100000").await] {
        assert!(
            !page.iter().any(|(id, _)| id == &theirs.id.to_string()),
            "another tenant's run must not appear in this tenant's listing: {page:?}"
        );
    }
    fixture.close().await;
}

#[tokio::test]
async fn the_rust_client_traverses_run_history_over_http() {
    let Some(fixture) = Fixture::new().await else {
        eprintln!("DATABASE_URL is unset; the run client is not exercised here");
        return;
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let app = router(fixture.state.clone());
    let serving = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = aiec_client::AIecClient::new(&origin, &fixture.key).unwrap();
    assert!(
        client
            .list_runs(Some(RunState::Queued), Some(17), None)
            .await
            .unwrap()
            .is_empty()
    );
    let mut after = None;
    let mut seen = Vec::new();
    loop {
        let page = client
            .list_runs(Some(RunState::Succeeded), Some(17), after)
            .await
            .unwrap();
        let Some(last) = page.last() else {
            break;
        };
        after = Some(MatrixCursor {
            requested_at: last.requested_at,
            id: last.id,
        });
        seen.extend(page.iter().map(|run| run.id));
        assert!(seen.len() <= TOTAL as usize, "a cursor repeated rows");
    }
    assert_eq!(
        seen,
        fixture.seeded.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        "the client must preserve every run's exclusive keyset order"
    );
    serving.abort();
    fixture.close().await;
}
