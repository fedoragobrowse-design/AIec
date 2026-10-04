//! Parity for the public probe endpoints' backing queries.
//!
//! `/ready` and `/metrics` are unauthenticated and unthrottled, because a load
//! balancer and Prometheus both reach them without a credential. Their cost is
//! therefore paid by whoever sends the request. Both used to answer by reading a
//! whole table — every worker for readiness, every node for the metrics gauges
//! — and both now ask the database for exactly the answer they report.
//!
//! Changing *how* a number is computed is where this kind of optimisation goes
//! wrong: the aggregate has to apply the same predicate the listing did, or
//! `/metrics` starts reporting capacity the fleet has already given up. These
//! hold the two against each other on the same rows.

use super::*;
use crate::NODE_HEARTBEAT_TTL_SECONDS;
use aiec_core::Node;
use chrono::Duration as ChronoDuration;

async fn register_node(
    repository: &Arc<PostgresRepository>,
    suffix: &str,
    vcpus: u32,
    memory_bytes: u64,
    healthy: bool,
    heartbeat_age: ChronoDuration,
) -> Node {
    let node = Node {
        id: new_id(),
        name: format!("capacity-probe-{suffix}-{}", new_id().simple()),
        available_vcpus: vcpus,
        available_memory_bytes: memory_bytes,
        available_disk_bytes: 0,
        sandbox_count: 0,
        healthy,
        last_heartbeat: Utc::now() - heartbeat_age,
    };
    repository.register_node(node.clone()).await.unwrap();
    node
}

/// The totals `/metrics` reports are exactly the totals the fleet listing
/// would have been summed into, on the same rows and with the same predicate.
#[tokio::test]
async fn the_capacity_aggregate_equals_summing_the_fleet_listing() {
    let Some((repository, _tenant, _admin, _schema)) = isolated_repository_and_tenant().await
    else {
        return;
    };

    let healthy_fresh = ChronoDuration::seconds(1);
    let stale = ChronoDuration::seconds(NODE_HEARTBEAT_TTL_SECONDS + 60);
    register_node(&repository, "fresh-a", 2, 1_000, true, healthy_fresh).await;
    register_node(&repository, "fresh-b", 3, 2_000, true, healthy_fresh).await;
    register_node(&repository, "unhealthy", 64, 64_000, false, healthy_fresh).await;
    register_node(&repository, "stale", 128, 128_000, true, stale).await;

    let nodes = repository.list_nodes().await.unwrap();
    let expected_vcpus: u32 = nodes.iter().map(|node| node.available_vcpus).sum();
    let expected_memory: u64 = nodes.iter().map(|node| node.available_memory_bytes).sum();

    let totals = repository.node_capacity_totals().await.unwrap();
    assert_eq!(
        totals.available_vcpus, expected_vcpus,
        "the aggregate counted a different set of nodes than the listing"
    );
    assert_eq!(totals.available_memory_bytes, expected_memory);

    // The comparison above would also pass if both returned nothing, so pin
    // that the healthy, fresh fleet is actually counted.
    assert_eq!(
        expected_vcpus, 5,
        "the fixture did not register as expected"
    );
    assert_eq!(expected_memory, 3_000);
    assert_eq!(totals.available_vcpus, 5);
}

/// An empty fleet reports zero rather than an error or a null, because a
/// `/metrics` scrape during a rollout must still answer.
#[tokio::test]
async fn capacity_totals_are_zero_on_an_empty_fleet() {
    let Some((repository, _tenant, _admin, _schema)) = isolated_repository_and_tenant().await
    else {
        return;
    };
    let totals = repository.node_capacity_totals().await.unwrap();
    assert_eq!(totals.available_vcpus, 0);
    assert_eq!(totals.available_memory_bytes, 0);
}

/// Readiness asks whether the store answers. On a live database that is a
/// success, and it must not be answered by a listing that could fail for an
/// unrelated reason.
#[tokio::test]
async fn the_store_answers_a_ping_on_a_live_database() {
    let Some((repository, _tenant, _admin, _schema)) = isolated_repository_and_tenant().await
    else {
        return;
    };
    repository.ping().await.unwrap();
}
