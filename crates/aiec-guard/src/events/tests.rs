//! Behavioural tests for the Guard event journal.
//!
//! These exercise the properties the journal is supposed to have - tamper
//! detection, chain continuity under concurrency, bounded replay, bounded
//! metadata, and honest remote delivery - rather than restating the
//! implementation.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use tokio::sync::{Notify, mpsc};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::remote::{RemoteAck, RemoteEventSink, RemoteQueueConfig};
use super::{Category, Decision, GENESIS_HASH, GuardEvent, MAX_REASON_BYTES};
use super::{
    EventInput, EventSink, FileEventSink, HttpEventSink, HttpEventSinkConfig, MAX_JOURNAL_BYTES,
    RemoteQueue, verify_chain, verify_file,
};
use crate::GuardError;

/// Throwaway directory for one test's journal.
struct TempJournal {
    directory: PathBuf,
}

impl TempJournal {
    fn new(tag: &str) -> Self {
        let mut directory = std::env::temp_dir();
        directory.push(format!("aiec-guard-events-{tag}-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("create temp directory");
        Self { directory }
    }

    fn path(&self) -> PathBuf {
        self.directory.join("events.jsonl")
    }
}

impl Drop for TempJournal {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn decision_input(category: Category, decision: Decision) -> EventInput {
    EventInput {
        sandbox_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        policy_hash: "b".repeat(64),
        category,
        decision,
        reason: "destination matches the compiled policy".to_string(),
        destination: Some("api.example.com:443".to_string()),
        request_bytes: 128,
        response_bytes: 4096,
        duration_ms: 42,
    }
}

fn sink_for(journal: &TempJournal) -> FileEventSink {
    FileEventSink::open(journal.path()).expect("open journal")
}

fn append_many(sink: &FileEventSink, count: usize) -> Vec<GuardEvent> {
    (0..count)
        .map(|index| {
            sink.append_blocking(decision_input(Category::Model, Decision::Allow))
                .unwrap_or_else(|err| panic!("append {index} failed: {err}"))
        })
        .collect()
}

fn lines_of(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .expect("read journal")
        .lines()
        .map(str::to_string)
        .collect()
}

fn rewrite(path: &Path, lines: &[String]) {
    let mut body = String::new();
    for line in lines {
        body.push_str(line);
        body.push('\n');
    }
    fs::write(path, body).expect("rewrite journal");
}

fn integrity_error<T>(result: crate::Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected an integrity failure"),
        Err(GuardError::Integrity(message)) => message,
        Err(other) => panic!("expected GuardError::Integrity, got {other}"),
    }
}

#[test]
fn appended_records_form_a_verified_chain() {
    let journal = TempJournal::new("chain");
    let sink = sink_for(&journal);
    let appended = append_many(&sink, 5);

    let replayed = verify_file(&journal.path()).expect("verify");
    assert_eq!(replayed, 5);
    assert_eq!(appended[0].previous_hash, GENESIS_HASH);
    for pair in appended.windows(2) {
        assert_eq!(pair[1].previous_hash, pair[0].current_hash);
    }

    let head = sink.head().expect("journal state is sound");
    assert_eq!(head.count, 5);
    assert_eq!(head.head_hash, appended[4].current_hash);
    assert_eq!(lines_of(&journal.path()).len(), 5);
}

#[test]
fn tampered_record_is_rejected() {
    let journal = TempJournal::new("tamper");
    let sink = sink_for(&journal);
    append_many(&sink, 3);

    let mut lines = lines_of(&journal.path());
    // Same shape, one changed byte of evidence.
    lines[1] = lines[1].replace("destination matches the compiled policy", "policy allowed");
    rewrite(&journal.path(), &lines);

    let message = integrity_error(verify_file(&journal.path()));
    assert!(
        message.contains("record 2") && message.contains("does not hash to its current_hash"),
        "unexpected message: {message}"
    );
    integrity_error(super::read_events(&journal.path()));
}

#[test]
fn reordered_records_are_rejected() {
    let journal = TempJournal::new("reorder");
    let sink = sink_for(&journal);
    append_many(&sink, 3);

    let mut lines = lines_of(&journal.path());
    lines.swap(1, 2);
    rewrite(&journal.path(), &lines);

    // Each record still hashes to its own content, so only the chain catches it.
    let message = integrity_error(verify_file(&journal.path()));
    assert!(
        message.contains("chains to"),
        "unexpected message: {message}"
    );
}

#[test]
fn missing_interior_record_is_rejected() {
    let journal = TempJournal::new("missing");
    let sink = sink_for(&journal);
    append_many(&sink, 4);

    let mut lines = lines_of(&journal.path());
    lines.remove(2);
    rewrite(&journal.path(), &lines);

    let message = integrity_error(verify_file(&journal.path()));
    assert!(
        message.contains("chains to"),
        "unexpected message: {message}"
    );
}

#[test]
fn truncated_final_record_is_rejected() {
    let journal = TempJournal::new("truncated");
    let sink = sink_for(&journal);
    append_many(&sink, 3);

    let mut body = fs::read_to_string(journal.path()).unwrap();
    body.truncate(body.len() - 40);
    fs::write(journal.path(), body).unwrap();

    let message = integrity_error(verify_file(&journal.path()));
    assert!(
        message.contains("truncated"),
        "unexpected message: {message}"
    );
}

#[test]
fn blank_record_is_rejected() {
    let journal = TempJournal::new("blank");
    let sink = sink_for(&journal);
    append_many(&sink, 2);

    let lines = lines_of(&journal.path());
    rewrite(
        &journal.path(),
        &[lines[0].clone(), String::new(), lines[1].clone()],
    );

    let message = integrity_error(verify_file(&journal.path()));
    assert!(message.contains("empty"), "unexpected message: {message}");
}

#[test]
fn a_tampered_journal_is_not_extended() {
    let journal = TempJournal::new("fail-closed");
    let sink = sink_for(&journal);
    append_many(&sink, 2);
    drop(sink);

    let lines = lines_of(&journal.path());
    rewrite(
        &journal.path(),
        &[lines[0].clone(), lines[1].replace("\"allow\"", "\"deny\"")],
    );
    let before = fs::read_to_string(journal.path()).unwrap();

    assert!(FileEventSink::open(journal.path()).is_err());
    assert_eq!(fs::read_to_string(journal.path()).unwrap(), before);
}

#[test]
fn tail_truncation_needs_an_external_anchor() {
    let journal = TempJournal::new("tail");
    let sink = sink_for(&journal);
    let appended = append_many(&sink, 3);
    drop(sink);

    let mut lines = lines_of(&journal.path());
    lines.pop();
    rewrite(&journal.path(), &lines);

    // Documented limit: a chain proves the records it still has are unaltered
    // and in order. Losing only the tail leaves a valid chain, so operators
    // anchor the head somewhere the guest cannot reach.
    let replayed = super::read_events(&journal.path()).expect("shorter chain still verifies");
    assert_eq!(replayed.len(), 2);
    assert_ne!(replayed[1].current_hash, appended[2].current_hash);
}

#[test]
fn oversized_journal_is_refused() {
    let journal = TempJournal::new("bound");
    let path = journal.path();
    let file = fs::File::create(&path).unwrap();
    file.set_len(MAX_JOURNAL_BYTES + 1).unwrap();
    drop(file);

    let message = integrity_error(super::read_events(&path));
    assert!(
        message.contains("replay bound"),
        "unexpected message: {message}"
    );
    integrity_error(super::read_events_page(&path, 0, 16));
}

#[test]
fn rotation_seals_verified_evidence_and_starts_a_new_chain() {
    let journal = TempJournal::new("rotate");
    let sink = sink_for(&journal);
    let appended = append_many(&sink, 3);

    let rotation = sink.rotate(".1").expect("rotate");
    assert_eq!(rotation.records, 3);
    assert_eq!(
        rotation.previous_head.as_deref(),
        Some(appended[2].current_hash.as_str())
    );
    assert_eq!(
        rotation.archive,
        journal.directory.join("events.jsonl.1"),
        "the sealed segment keeps its own name"
    );

    // The sealed segment still verifies on its own...
    assert_eq!(verify_file(&rotation.archive).expect("archive verifies"), 3);
    assert_eq!(
        lines_of(&rotation.archive).len(),
        3,
        "rotation moves evidence, it never rewrites it"
    );
    // ...and the live journal starts a fresh chain at genesis.
    assert_eq!(verify_file(&journal.path()).expect("fresh journal"), 0);
    let head = sink.head().expect("journal state is sound");
    assert_eq!(head.count, 0);
    assert_eq!(head.head_hash, GENESIS_HASH);
    let fresh = append_many(&sink, 2);
    assert_eq!(fresh[0].previous_hash, GENESIS_HASH);
    assert_eq!(
        verify_file(&journal.path()).expect("new segment verifies"),
        2
    );
    assert!(rotation.archive.exists());
}

#[test]
fn rotation_refuses_to_move_evidence_that_does_not_verify() {
    let journal = TempJournal::new("rotate-bad");
    let sink = sink_for(&journal);
    append_many(&sink, 2);
    let before = fs::read_to_string(journal.path()).unwrap();
    let mut lines = lines_of(&journal.path());
    lines[0] = lines[0].replace("\"allow\"", "\"deny\"");
    rewrite(&journal.path(), &lines);
    let tampered = fs::read_to_string(journal.path()).unwrap();

    assert!(sink.rotate(".1").is_err());
    assert!(
        !journal.directory.join("events.jsonl.1").exists(),
        "a journal that does not verify must not be sealed as if it did"
    );
    assert_eq!(fs::read_to_string(journal.path()).unwrap(), tampered);
    assert_ne!(before, tampered);
}

#[test]
fn a_rotation_that_fails_after_the_rename_leaves_the_sink_unusable() {
    let journal = TempJournal::new("rotate-halfway");
    let sink = sink_for(&journal);
    let appended = append_many(&sink, 2);
    let archive = journal.directory.join("events.jsonl.1");

    sink.fail_next_rotate_for_fault_injection();
    assert!(matches!(sink.rotate(".1"), Err(GuardError::Unavailable(_))));
    let sealed = fs::read_to_string(&archive).expect("the segment was renamed before the failure");
    assert_eq!(lines_of(&archive).len(), 2);

    // The sink no longer owns a journal at its own path, so it must refuse to
    // write rather than append into the archive behind the operator's back.
    let message =
        integrity_error(sink.append_blocking(decision_input(Category::Lifecycle, Decision::Allow)));
    assert!(
        message.contains("unusable"),
        "unexpected message: {message}"
    );
    assert!(
        sink.rotate(".2").is_err(),
        "a broken sink does not rotate again"
    );
    assert_eq!(
        fs::read_to_string(&archive).expect("archive untouched"),
        sealed,
        "no record may be written into the sealed segment after the failure"
    );
    assert_eq!(verify_file(&archive).expect("archive still verifies"), 2);
    drop(sink);

    // Recovery is a restart: the operator sees the sealed segment, and the
    // fresh journal at the live path starts its own chain.
    let reopened = FileEventSink::open(journal.path()).expect("restart");
    assert_eq!(reopened.head().expect("sound").count, 0);
    let next = reopened
        .append_blocking(decision_input(Category::Lifecycle, Decision::Allow))
        .expect("append after restart");
    assert_eq!(next.previous_hash, GENESIS_HASH);
    assert_eq!(
        appended[1].current_hash,
        super::read_events(&archive)
            .expect("archive replay")
            .last()
            .expect("last archived record")
            .current_hash
    );
}

#[test]
fn rotation_never_overwrites_an_existing_archive() {
    let journal = TempJournal::new("rotate-clash");
    let sink = sink_for(&journal);
    append_many(&sink, 1);
    let archive = journal.directory.join("events.jsonl.1");
    fs::write(&archive, "operator evidence").unwrap();

    assert!(matches!(sink.rotate(".1"), Err(GuardError::Denied(_))));
    assert_eq!(fs::read_to_string(&archive).unwrap(), "operator evidence");
    assert_eq!(verify_file(&journal.path()).expect("journal intact"), 1);
}

#[test]
fn rotation_suffixes_cannot_escape_the_journal_directory() {
    let journal = TempJournal::new("rotate-escape");
    let sink = sink_for(&journal);
    append_many(&sink, 1);

    for suffix in ["", "../evil", "a/b", &"x".repeat(33)] {
        assert!(
            sink.rotate(suffix).is_err(),
            "suffix {suffix:?} must be refused"
        );
    }
    assert_eq!(verify_file(&journal.path()).expect("journal intact"), 1);
}

#[test]
fn an_interrupted_append_fails_closed_until_the_journal_is_replayed() {
    let journal = TempJournal::new("poison");
    let sink = sink_for(&journal);
    let appended = append_many(&sink, 2);

    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sink.poison_for_fault_injection();
    }));
    assert!(poisoned.is_err(), "the fault must have unwound the append");

    // The in-memory head may now be behind the file, so nothing more may be
    // written from it: that would fork the chain.
    let message =
        integrity_error(sink.append_blocking(decision_input(Category::Network, Decision::Deny)));
    assert!(
        message.contains("poisoned"),
        "unexpected message: {message}"
    );
    assert!(matches!(
        sink.append_blocking(decision_input(Category::Network, Decision::Deny)),
        Err(GuardError::Integrity(_))
    ));
    integrity_error(sink.head());
    assert!(sink.remote_stats().is_err());
    assert_eq!(
        verify_file(&journal.path()).expect("evidence intact"),
        2,
        "a refused append must not have written anything"
    );
    drop(sink);

    // Recovery is a restart plus a full replay, which rebuilds the head.
    let reopened = FileEventSink::open(journal.path()).expect("reopen after replay");
    let head = reopened.head().expect("journal state is sound");
    assert_eq!(head.count, 2);
    assert_eq!(head.head_hash, appended[1].current_hash);
    let next = reopened
        .append_blocking(decision_input(Category::Network, Decision::Deny))
        .expect("append after replay");
    assert_eq!(next.previous_hash, appended[1].current_hash);
    assert_eq!(verify_file(&journal.path()).expect("chain continues"), 3);
}

#[tokio::test]
async fn replacing_a_remote_queue_returns_the_previous_one() {
    let journal = TempJournal::new("requeue");
    let sink = FileEventSink::open(journal.path()).expect("open");
    let first = remote_queue(RecordingSink::new());
    let second = remote_queue(RecordingSink::new());

    assert!(
        sink.attach_remote(first).expect("attach first").is_none(),
        "the first queue has no predecessor"
    );
    let replaced = sink
        .attach_remote(second)
        .expect("attach second")
        .expect("the previous queue is handed back, not dropped");
    let stats = replaced.stats();
    assert_eq!(stats.queued, 0);
    replaced.shutdown().await.expect("previous worker stops");
    assert!(sink.detach_remote().expect("detach").is_some());
}

#[test]
fn page_replay_is_bounded_and_contiguous() {
    let journal = TempJournal::new("page");
    let sink = sink_for(&journal);
    let appended = append_many(&sink, 5);

    let page = super::read_events_page(&journal.path(), 2, 2).expect("page");
    assert_eq!(page.offset, 2);
    assert_eq!(page.events.len(), 2);
    assert!(page.has_more);
    assert_eq!(
        page.first_previous_hash.as_deref(),
        Some(appended[1].current_hash.as_str())
    );
    assert_eq!(
        page.last_hash.as_deref(),
        Some(appended[3].current_hash.as_str())
    );

    let tail = super::read_events_page(&journal.path(), 4, 2).expect("last page");
    assert!(!tail.has_more);
    assert_eq!(tail.events.len(), 1);

    // A page cannot verify standalone - it has no genesis - which is why the
    // previous page's head hash is part of the result.
    assert!(verify_chain(&page.events).is_err());
    assert_eq!(page.events[0].current_hash, appended[2].current_hash);

    assert!(super::read_events_page(&journal.path(), 0, 0).is_err());
    assert!(super::read_events_page(&journal.path(), 0, super::MAX_PAGE_EVENTS + 1).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_appends_form_one_chain() {
    let journal = TempJournal::new("concurrent");
    let sink = Arc::new(sink_for(&journal));

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let sink = Arc::clone(&sink);
        tasks.push(tokio::spawn(async move {
            for _ in 0..5 {
                sink.append(decision_input(Category::Network, Decision::Deny))
                    .await
                    .expect("concurrent append");
            }
        }));
    }
    for task in tasks {
        task.await.expect("append task");
    }

    let replayed = super::read_events(&journal.path()).expect("verify chain");
    assert_eq!(replayed.len(), 40);
    let ids: BTreeSet<Uuid> = replayed.iter().map(|event| event.event_id).collect();
    assert_eq!(ids.len(), 40, "event ids must be unique");
    assert_eq!(sink.head().expect("journal state is sound").count, 40);
    assert_eq!(
        sink.head().expect("journal state is sound").head_hash,
        replayed.last().expect("last record").current_hash
    );
}

#[test]
fn metadata_bounds_are_enforced() {
    let journal = TempJournal::new("metadata");
    let sink = sink_for(&journal);

    let mut oversized = decision_input(Category::Dns, Decision::Deny);
    oversized.reason = "x".repeat(MAX_REASON_BYTES + 1);
    assert!(matches!(
        sink.append_blocking(oversized),
        Err(GuardError::Denied(_))
    ));

    let mut newline = decision_input(Category::Dns, Decision::Deny);
    newline.reason = "allowed\n{\"decision\":\"allow\"}".to_string();
    assert!(matches!(
        sink.append_blocking(newline),
        Err(GuardError::Denied(_))
    ));

    let mut non_ascii = decision_input(Category::Dns, Decision::Deny);
    non_ascii.reason = "policy é".to_string();
    assert!(matches!(
        sink.append_blocking(non_ascii),
        Err(GuardError::Denied(_))
    ));

    let mut spaced = decision_input(Category::Dns, Decision::Deny);
    spaced.destination = Some("api.example.com 443".to_string());
    assert!(matches!(
        sink.append_blocking(spaced),
        Err(GuardError::Denied(_))
    ));

    let mut empty = decision_input(Category::Dns, Decision::Deny);
    empty.destination = Some(String::new());
    assert!(matches!(
        sink.append_blocking(empty),
        Err(GuardError::Denied(_))
    ));

    let mut long_policy = decision_input(Category::Dns, Decision::Deny);
    long_policy.policy_hash = "a".repeat(super::MAX_POLICY_HASH_BYTES + 1);
    assert!(matches!(
        sink.append_blocking(long_policy),
        Err(GuardError::Denied(_))
    ));

    assert_eq!(
        verify_file(&journal.path()).expect("empty journal verifies"),
        0
    );
}

#[test]
fn schema_carries_no_credential_or_prompt_fields() {
    let journal = TempJournal::new("schema");
    let sink = sink_for(&journal);
    let event = sink
        .append_blocking(decision_input(Category::Model, Decision::Allow))
        .unwrap();

    let value: serde_json::Value =
        serde_json::from_slice(&serde_json::to_vec(&event).unwrap()).unwrap();
    let keys: BTreeSet<String> = value
        .as_object()
        .expect("record is an object")
        .keys()
        .cloned()
        .collect();
    let expected: BTreeSet<String> = [
        "timestamp",
        "event_id",
        "sandbox_id",
        "tenant_id",
        "policy_hash",
        "category",
        "decision",
        "reason",
        "destination",
        "request_bytes",
        "response_bytes",
        "duration_ms",
        "previous_hash",
        "current_hash",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(keys, expected);

    for forbidden in [
        "authorization",
        "x-api-key",
        "api_key",
        "credential",
        "secret",
        "token",
        "prompt",
        "request_body",
        "response_body",
        "headers",
    ] {
        assert!(!keys.contains(forbidden), "{forbidden} is not allowed");
        let json = format!("{{\"{forbidden}\":\"leak\"}}");
        assert!(
            serde_json::from_str::<GuardEvent>(&json).is_err(),
            "{forbidden} must not deserialize into an event"
        );
        let json = format!("{{\"{forbidden}\":\"leak\"}}");
        assert!(
            serde_json::from_str::<EventInput>(&json).is_err(),
            "{forbidden} must not deserialize into event input"
        );
    }
}

#[test]
fn journal_file_is_owner_only_and_exclusive() {
    let journal = TempJournal::new("mode");
    let path = journal.path();
    fs::write(&path, "").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    let sink = FileEventSink::open(&path).expect("open existing journal");
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "journal must not be group or world readable");

    // A second owner would fork the chain.
    assert!(matches!(
        FileEventSink::open(&path),
        Err(GuardError::Unavailable(_))
    ));
    drop(sink);
    FileEventSink::open(&path).expect("re-open after the owner is gone");
}

#[test]
fn symlinked_journal_is_refused() {
    let journal = TempJournal::new("symlink");
    let target = journal.directory.join("real.jsonl");
    fs::write(&target, "").unwrap();
    let link = journal.directory.join("link.jsonl");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    assert!(matches!(
        FileEventSink::open(&link),
        Err(GuardError::Integrity(_))
    ));
}

// --- remote delivery -------------------------------------------------------

/// A remote sink that acknowledges correctly and lets tests observe delivery.
struct RecordingSink {
    batches: Mutex<Vec<Vec<GuardEvent>>>,
    seen: Mutex<Option<mpsc::Sender<GuardEvent>>>,
}

impl RecordingSink {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            batches: Mutex::new(Vec::new()),
            seen: Mutex::new(None),
        })
    }

    /// Streams every delivered record to the returned receiver.
    fn watch(&self) -> mpsc::Receiver<GuardEvent> {
        let (sender, receiver) = mpsc::channel(64);
        *self.seen.lock().expect("watch lock") = Some(sender);
        receiver
    }
}

#[async_trait::async_trait]
impl RemoteEventSink for RecordingSink {
    async fn deliver(&self, batch: &[GuardEvent]) -> crate::Result<RemoteAck> {
        let sender = self.seen.lock().expect("watch lock").clone();
        for event in batch {
            if let Some(sender) = sender.as_ref() {
                let _ = sender.try_send(event.clone());
            }
        }
        self.batches
            .lock()
            .expect("recording lock")
            .push(batch.to_vec());
        RemoteAck::for_batch(batch)
            .ok_or_else(|| GuardError::Integrity("empty batch delivered".to_string()))
    }

    fn describe(&self) -> String {
        "recording sink".to_string()
    }
}

fn remote_queue(sink: Arc<RecordingSink>) -> RemoteQueue {
    RemoteQueue::start(sink, RemoteQueueConfig::default()).expect("start delivery worker")
}

struct FailingSink;

#[async_trait::async_trait]
impl RemoteEventSink for FailingSink {
    async fn deliver(&self, _batch: &[GuardEvent]) -> crate::Result<RemoteAck> {
        Err(GuardError::Unavailable(
            "remote collector refused the batch".to_string(),
        ))
    }

    fn describe(&self) -> String {
        "failing sink".to_string()
    }
}

struct BlockingSink {
    release: Arc<Notify>,
}

#[async_trait::async_trait]
impl RemoteEventSink for BlockingSink {
    async fn deliver(&self, batch: &[GuardEvent]) -> crate::Result<RemoteAck> {
        self.release.notified().await;
        RemoteAck::for_batch(batch)
            .ok_or_else(|| GuardError::Integrity("empty batch delivered".to_string()))
    }

    fn describe(&self) -> String {
        "blocking sink".to_string()
    }
}

#[tokio::test]
async fn remote_delivery_keeps_journal_order() {
    let journal = TempJournal::new("remote-order");
    let sink = Arc::new(sink_for(&journal));
    let recorder = RecordingSink::new();
    let mut received = recorder.watch();
    let queue = remote_queue(Arc::clone(&recorder));
    sink.attach_remote(queue).expect("attach remote");

    let appended = append_many(&sink, 5);

    let mut delivered = Vec::new();
    for _ in 0..5 {
        delivered.push(received.recv().await.expect("delivered event"));
    }
    let queue = sink
        .detach_remote()
        .expect("journal state is sound")
        .expect("queue attached");
    queue.shutdown().await.expect("worker stopped");

    // Every record arrived exactly once, in journal order.
    assert_eq!(
        delivered
            .iter()
            .map(|e| e.current_hash.clone())
            .collect::<Vec<_>>(),
        appended
            .iter()
            .map(|e| e.current_hash.clone())
            .collect::<Vec<_>>()
    );
    let batches = recorder.batches.lock().unwrap();
    assert!(!batches.is_empty());
    for batch in batches.iter() {
        for pair in batch.windows(2) {
            assert_eq!(pair[1].previous_hash, pair[0].current_hash);
        }
    }
}

#[tokio::test]
async fn remote_failure_does_not_weaken_the_local_journal() {
    let journal = TempJournal::new("remote-fail");
    let sink = Arc::new(sink_for(&journal));
    let queue =
        RemoteQueue::start(Arc::new(FailingSink), RemoteQueueConfig::default()).expect("queue");
    sink.attach_remote(queue).expect("attach remote");

    let appended = append_many(&sink, 4);
    let queue = sink
        .detach_remote()
        .expect("journal state is sound")
        .expect("queue attached");
    let stats = queue.shutdown().await.expect("worker stopped");

    // Local evidence is complete and verifiable regardless of the remote.
    let replayed = super::read_events(&journal.path()).expect("local chain intact");
    assert_eq!(replayed.len(), 4);
    assert_eq!(replayed[3].current_hash, appended[3].current_hash);

    assert_eq!(stats.queued, 4);
    assert_eq!(stats.delivered_events, 0);
    assert!(
        stats.undelivered_events >= 1,
        "undelivered records must be counted"
    );
    assert!(stats.failed_attempts >= 1);
    assert!(
        stats.last_acknowledged_hash.is_none(),
        "nothing was acknowledged"
    );
    assert!(
        stats
            .last_error
            .as_ref()
            .is_some_and(|error| error.contains("refused")),
        "unexpected error: {:?}",
        stats.last_error
    );
}

#[tokio::test]
async fn a_full_remote_queue_is_reported_not_hidden() {
    let journal = TempJournal::new("remote-full");
    let sink = Arc::new(sink_for(&journal));
    let release = Arc::new(Notify::new());
    let blocker = Arc::new(BlockingSink {
        release: Arc::clone(&release),
    });
    let queue = RemoteQueue::start(
        blocker,
        RemoteQueueConfig {
            capacity: 1,
            max_batch_events: 1,
            max_attempts: 1,
        },
    )
    .expect("queue");
    sink.attach_remote(queue).expect("attach remote");

    // A stalled remote must not grow Guard's memory, and it must not make a
    // durable local append look unrecorded either: the caller is told the
    // record is in the journal, and the gap is counted for the operator.
    for _ in 0..10 {
        sink.append(decision_input(Category::Dns, Decision::Allow))
            .await
            .expect("local append stays successful");
    }

    let replayed = super::read_events(&journal.path()).expect("local chain intact");
    assert_eq!(replayed.len(), 10);

    let stats = sink
        .remote_stats()
        .expect("journal state is sound")
        .expect("remote attached");
    assert_eq!(stats.queued + stats.unqueued_events, 10);
    assert!(
        stats.unqueued_events > 0,
        "a stalled remote must not grow without bound"
    );
    assert_eq!(stats.delivered_events, 0);
    assert!(
        stats
            .last_error
            .as_ref()
            .is_some_and(|error| error.contains("durable locally")),
        "unexpected error: {:?}",
        stats.last_error
    );
    release.notify_waiters();
}

// --- HTTP sink -------------------------------------------------------------

#[derive(Default)]
struct Captured {
    headers: Mutex<Vec<(String, String)>>,
    body: Mutex<Vec<u8>>,
}

async fn spawn_endpoint(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}/v1/events")
}

async fn acknowledging_endpoint() -> (String, Arc<Captured>) {
    let captured = Arc::new(Captured::default());
    let app = Router::new()
        .route("/v1/events", post(acknowledge_endpoint))
        .with_state(Arc::clone(&captured));
    (spawn_endpoint(app).await, captured)
}

async fn acknowledge_endpoint(
    State(captured): State<Arc<Captured>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    acknowledge(&captured, headers, body).await
}

/// A correct remote: it echoes the count and the head hash it stored.
async fn acknowledge(state: &Captured, headers: HeaderMap, body: Bytes) -> Response {
    *state.headers.lock().expect("headers lock") = headers
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    *state.body.lock().expect("body lock") = body.to_vec();
    let text = String::from_utf8_lossy(&body).to_string();
    let records: Vec<serde_json::Value> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    let head = records
        .last()
        .and_then(|record| record.get("current_hash"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let payload = serde_json::json!({
        "accepted": records.len(),
        "head_hash": head,
        "request_id": "req-test",
    });
    (StatusCode::OK, axum::Json(payload)).into_response()
}

async fn fixed_endpoint(status: StatusCode, body: String) -> String {
    let app = Router::new().route(
        "/v1/events",
        post(move || {
            let body = body.clone();
            async move { (status, body).into_response() }
        }),
    );
    spawn_endpoint(app).await
}

fn http_sink(endpoint: &str) -> HttpEventSink {
    HttpEventSink::new_insecure_loopback_for_tests(HttpEventSinkConfig {
        endpoint: endpoint.to_string(),
        header_name: "authorization".to_string(),
        token: Zeroizing::new("Bearer operator-token".to_string()),
        ..HttpEventSinkConfig::default()
    })
    .expect("build sink")
}

fn chained_batch(journal: &TempJournal, count: usize) -> Vec<GuardEvent> {
    let sink = sink_for(journal);
    append_many(&sink, count)
}

#[tokio::test]
async fn http_sink_delivers_ndjson_and_requires_an_exact_ack() {
    let batch = chained_batch(&TempJournal::new("http-ok"), 2);
    let (endpoint, captured) = acknowledging_endpoint().await;
    let sink = http_sink(&endpoint);

    let ack = sink.deliver(&batch).await.expect("acknowledged delivery");
    assert_eq!(ack.accepted, 2);
    assert_eq!(ack.head_hash, batch[1].current_hash);
    assert_eq!(ack.request_id.as_deref(), Some("req-test"));

    let headers = captured.headers.lock().unwrap().clone();
    assert!(
        headers
            .iter()
            .any(|(name, value)| name == "authorization" && value == "Bearer operator-token"),
        "the configured credential header must be sent exactly once"
    );
    let body = captured.body.lock().unwrap().clone();
    let sent: Vec<serde_json::Value> = String::from_utf8(body.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).expect("NDJSON line"))
        .collect();
    assert_eq!(sent.len(), 2);
    assert_eq!(
        sent[0]["current_hash"],
        serde_json::json!(batch[0].current_hash)
    );
    assert_eq!(
        sent[1]["previous_hash"],
        serde_json::json!(batch[0].current_hash)
    );
}

#[tokio::test]
async fn malformed_acknowledgements_never_claim_durability() {
    let journal = TempJournal::new("http-bad-ack");
    let batch = chained_batch(&journal, 2);
    let good_hash = batch[1].current_hash.clone();
    let other_hash = "0".repeat(64);

    let cases: Vec<(StatusCode, String, &str)> = vec![
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "boom".to_string(),
            "unavailable",
        ),
        (
            StatusCode::OK,
            serde_json::json!({"accepted": 1, "head_hash": good_hash}).to_string(),
            "integrity",
        ),
        (
            StatusCode::OK,
            serde_json::json!({"accepted": 2, "head_hash": other_hash}).to_string(),
            "integrity",
        ),
        (
            StatusCode::OK,
            serde_json::json!({"accepted": 2, "head_hash": "not-a-hash"}).to_string(),
            "integrity",
        ),
        (
            StatusCode::OK,
            serde_json::json!({"accepted": 2, "head_hash": good_hash, "stored": false}).to_string(),
            "integrity",
        ),
        (StatusCode::OK, "OK".to_string(), "integrity"),
        (
            StatusCode::OK,
            serde_json::json!({"accepted": 2, "head_hash": good_hash, "request_id": "r"})
                .to_string()
                + " trailing",
            "integrity",
        ),
        (
            StatusCode::OK,
            "x".repeat(super::remote::MAX_ACK_BYTES + 64),
            "unavailable",
        ),
        (
            StatusCode::FOUND,
            serde_json::json!({"accepted": 2, "head_hash": good_hash}).to_string(),
            "unavailable",
        ),
    ];

    for (status, body, expected) in cases {
        let endpoint = fixed_endpoint(status, body.clone()).await;
        let sink = http_sink(&endpoint);
        match sink.deliver(&batch).await {
            Ok(ack) => panic!(
                "status {status} body {body:?} was accepted as durable (head {})",
                ack.head_hash
            ),
            Err(GuardError::Unavailable(message)) => {
                assert_eq!(expected, "unavailable", "status {status}: {message}");
            }
            Err(GuardError::Integrity(message)) => {
                assert_eq!(expected, "integrity", "status {status}: {message}");
            }
            Err(other) => panic!("unexpected error for {status}: {other}"),
        }
    }
}

#[tokio::test]
async fn a_non_chaining_batch_is_never_sent() {
    let journal = TempJournal::new("http-unordered");
    let chained = chained_batch(&journal, 2);
    let other = chained_batch(&TempJournal::new("http-unordered-2"), 1);
    let mut batch = chained.clone();
    batch.push(other[0].clone());

    let (endpoint, captured) = acknowledging_endpoint().await;
    let sink = http_sink(&endpoint);
    assert!(matches!(
        sink.deliver(&batch).await,
        Err(GuardError::Integrity(_))
    ));
    assert!(
        captured.body.lock().unwrap().is_empty(),
        "a batch that does not chain must not reach the network"
    );
}

#[test]
fn remote_endpoint_configuration_is_strict() {
    let token = || Zeroizing::new("Bearer token".to_string());
    let config = |endpoint: &str| HttpEventSinkConfig {
        endpoint: endpoint.to_string(),
        token: token(),
        ..HttpEventSinkConfig::default()
    };

    // Plaintext is refused unless the operator explicitly uses the loopback
    // constructor, and even then only for a loopback IP literal.
    assert!(HttpEventSink::new(config("http://collector.example.com/v1/events")).is_err());
    assert!(
        HttpEventSink::new_insecure_loopback_for_tests(config("http://collector.example.com/x"))
            .is_err()
    );
    assert!(HttpEventSink::new(config("ftp://127.0.0.1/x")).is_err());
    assert!(HttpEventSink::new(config("https://user:pass@collector/x")).is_err());
    assert!(HttpEventSink::new(config("https://collector/x?token=y")).is_err());
    assert!(HttpEventSink::new(config("")).is_err());
    assert!(HttpEventSink::new(config("https://collector.example.com/v1/events")).is_ok());

    assert!(
        HttpEventSink::new(HttpEventSinkConfig {
            header_name: "cookie".to_string(),
            ..config("https://collector.example.com/x")
        })
        .is_err()
    );
    assert!(
        HttpEventSink::new(HttpEventSinkConfig {
            token: Zeroizing::new(String::new()),
            ..config("https://collector.example.com/x")
        })
        .is_err()
    );
    assert!(
        HttpEventSink::new(HttpEventSinkConfig {
            token: Zeroizing::new("Bearer bad\r\nX-Injected: 1".to_string()),
            ..config("https://collector.example.com/x")
        })
        .is_err()
    );
}

#[test]
fn configuration_debug_redacts_the_token() {
    let config = HttpEventSinkConfig {
        endpoint: "https://collector.example.com/v1/events".to_string(),
        token: Zeroizing::new("Bearer super-secret".to_string()),
        ..HttpEventSinkConfig::default()
    };
    let rendered = format!("{config:?}");
    assert!(!rendered.contains("super-secret"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

#[tokio::test]
async fn acknowledged_head_is_recorded_for_anchoring() {
    let journal = TempJournal::new("anchor");
    let sink = sink_for(&journal);
    let (endpoint, _captured) = acknowledging_endpoint().await;
    let queue = RemoteQueue::start(
        Arc::new(http_sink(&endpoint)),
        RemoteQueueConfig {
            max_batch_events: 1,
            ..RemoteQueueConfig::default()
        },
    )
    .expect("queue");
    sink.attach_remote(queue).expect("attach remote");
    let appended = append_many(&sink, 3);
    let queue = sink
        .detach_remote()
        .expect("journal state is sound")
        .expect("queue attached");
    let stats = queue.shutdown().await.expect("worker stopped");

    assert_eq!(stats.delivered_events, 3);
    assert_eq!(stats.undelivered_events, 0);
    assert_eq!(
        stats.last_acknowledged_hash.as_deref(),
        Some(appended[2].current_hash.as_str())
    );
}

#[tokio::test]
async fn queue_configuration_is_bounded() {
    let sink = RecordingSink::new();
    assert!(RemoteQueue::start(sink.clone(), RemoteQueueConfig::default()).is_ok());
    assert!(
        RemoteQueue::start(
            sink.clone(),
            RemoteQueueConfig {
                capacity: 0,
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(
        RemoteQueue::start(
            sink,
            RemoteQueueConfig {
                capacity: 65_537,
                ..Default::default()
            }
        )
        .is_err()
    );
}

#[tokio::test]
async fn remote_statistics_track_transport_failures() {
    // An endpoint that is not listening stands in for an unreachable remote.
    let journal = TempJournal::new("unreachable");
    let sink = sink_for(&journal);
    let queue = RemoteQueue::start(
        Arc::new(http_sink("http://127.0.0.1:1/v1/events")),
        RemoteQueueConfig {
            max_attempts: 1,
            ..RemoteQueueConfig::default()
        },
    )
    .expect("queue");
    sink.attach_remote(queue).expect("attach remote");
    append_many(&sink, 2);
    let queue = sink
        .detach_remote()
        .expect("journal state is sound")
        .expect("queue attached");
    let stats = queue.shutdown().await.expect("worker stopped");

    assert_eq!(stats.delivered_events, 0);
    assert!(stats.failed_attempts >= 1);
    assert!(
        stats
            .last_error
            .as_ref()
            .is_some_and(|error| error.contains("unreachable") || error.contains("HTTP")),
        "unexpected error: {:?}",
        stats.last_error
    );
    assert!(stats.last_acknowledged_hash.is_none());
}

#[test]
fn a_verified_snapshot_anchors_a_bounded_continuation_and_refuses_to_skip_evidence() {
    let journal = TempJournal::new("snapshot");
    let sink = sink_for(&journal);
    let (cold, head) = sink.verified_snapshot(0).expect("cold snapshot");
    assert_eq!(head.count, 0);
    assert_eq!(head.head_hash, GENESIS_HASH);
    assert!(cold.events.is_empty());

    let appended = append_many(&sink, 5);
    let (page, head) = sink.verified_snapshot(2).expect("continuation");
    assert_eq!(head.count, 5);
    assert_eq!(head.head_hash, appended[4].current_hash);
    assert_eq!(page.offset, 2);
    assert_eq!(
        page.first_previous_hash.as_deref(),
        Some(appended[1].current_hash.as_str()),
        "the caller can verify continuity from its own anchor"
    );
    assert_eq!(page.events.len(), 3);
    assert_eq!(
        page.last_hash.as_deref(),
        Some(appended[4].current_hash.as_str())
    );
    assert!(
        sink.verified_snapshot(9).is_err(),
        "a future cursor has no evidence"
    );

    // A hostile on-disk edit outside the owning writer is detected.
    let mut text = fs::read_to_string(journal.path()).unwrap();
    text.push_str(&format!("{}\n", serde_json::json!({"timestamp": chrono::Utc::now(),"event_id": Uuid::new_v4(),"sandbox_id": Uuid::new_v4(),"tenant_id": Uuid::new_v4(),"policy_hash":"b","category":"model","decision":"allow","reason":"injected","destination":null,"request_bytes":0,"response_bytes":0,"duration_ms":0,"previous_hash":GENESIS_HASH,"current_hash":"0".repeat(64)})));
    fs::write(journal.path(), text).unwrap();
    assert!(
        sink.verified_snapshot(0).is_err(),
        "an edited journal is never reported as verified"
    );
}
