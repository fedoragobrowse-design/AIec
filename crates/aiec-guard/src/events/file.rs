//! Bounded append-only local journal.
//!
//! The journal is newline-delimited JSON: one record per line, appended with
//! `O_APPEND`, fsynced before the caller is told the record is durable, and
//! kept at mode `0600`. Opening one verifies the whole chain first, so a
//! tampered journal is never extended.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use super::{
    EventInput, EventSink, GENESIS_HASH, GuardEvent, JournalHead, MAX_EVENTS, MAX_JOURNAL_BYTES,
    MAX_LINE_BYTES, MAX_PAGE_EVENTS, RemoteQueue, RemoteStatsSnapshot, Rotation,
};
use crate::{GuardError, Result};

/// Append-only, fsynced, mode `0600` event journal.
///
/// One process may own a journal: the file is locked with an advisory
/// `flock` for the lifetime of the sink, and a second opener fails rather than
/// forking two chains into one file. Concurrent `append` calls from any number
/// of tasks are serialized, so the journal is always one valid chain.
pub struct FileEventSink {
    path: PathBuf,
    journal: Arc<Mutex<Journal>>,
}

struct Journal {
    file: File,
    head: String,
    count: u64,
    remote: Option<RemoteQueue>,
    /// Set when this sink can no longer be trusted to own a journal, with the
    /// reason. A broken journal is never written to again.
    broken: Option<String>,
    /// Test-only: makes the next rotation fail just after the rename.
    #[cfg(test)]
    fail_next_rotate: bool,
}

/// Refuses to touch a sink whose journal ownership was lost.
fn refuse_if_broken(journal: &Journal) -> Result<()> {
    match &journal.broken {
        Some(reason) => Err(GuardError::Integrity(format!(
            "event journal is unusable: {reason}; reopen and replay it"
        ))),
        None => Ok(()),
    }
}

impl FileEventSink {
    /// Opens, or creates, the journal at `path`.
    ///
    /// Fails closed: a symlink, a non-regular file, a journal above the replay
    /// bound, or any record that does not chain is refused, and an existing file
    /// with looser permissions is tightened to `0600` instead of being trusted.
    /// A journal that has reached the replay bound is a [`Self::rotate`] away
    /// from recovery; it is never deleted here.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let existed = journal_exists(&path)?;
        reject_unusable_path(&path)?;
        let file = open_journal(&path)?;
        if !existed {
            // Make the new directory entry itself durable, not just its bytes.
            sync_parent(&path)?;
        }
        advisory_lock(&file)?;
        let existing = read_events(&path)?;
        let (head, count) = match existing.last() {
            Some(last) => (last.current_hash.clone(), existing.len() as u64),
            None => (GENESIS_HASH.to_string(), 0),
        };
        Ok(Self {
            path,
            journal: Arc::new(Mutex::new(Journal {
                file,
                head,
                count,
                remote: None,
                broken: None,
                #[cfg(test)]
                fail_next_rotate: false,
            })),
        })
    }

    /// Path of this journal.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Current head of this sink's chain.
    pub fn head(&self) -> Result<JournalHead> {
        let journal = lock(&self.journal)?;
        Ok(JournalHead {
            count: journal.count,
            head_hash: journal.head.clone(),
        })
    }

    /// Routes committed records to a remote sink, in chain order.
    ///
    /// The record is enqueued while the journal lock is held, so the remote
    /// observes exactly the order the journal committed. Any previously
    /// attached queue is returned rather than dropped, because its worker and
    /// its undelivered records still need the caller's attention.
    pub fn attach_remote(&self, queue: RemoteQueue) -> Result<Option<RemoteQueue>> {
        Ok(lock(&self.journal)?.remote.replace(queue))
    }

    /// Stops remote delivery. The local journal is unaffected.
    pub fn detach_remote(&self) -> Result<Option<RemoteQueue>> {
        Ok(lock(&self.journal)?.remote.take())
    }

    /// Remote delivery counters, when a remote sink is attached.
    pub fn remote_stats(&self) -> Result<Option<RemoteStatsSnapshot>> {
        Ok(lock(&self.journal)?.remote.as_ref().map(RemoteQueue::stats))
    }

    /// Appends one record without needing an async runtime.
    ///
    /// Same durability contract as [`EventSink::append`].
    pub fn append_blocking(&self, input: EventInput) -> Result<GuardEvent> {
        append_locked(&self.journal, input)
    }

    /// Seals the current journal and starts a fresh one at the same path.
    ///
    /// The journal is replayed and its chain verified first, so evidence is
    /// never moved because a check was skipped; the file is then fsynced,
    /// renamed to `<journal><suffix>`, and replaced with a new empty journal
    /// whose chain starts at genesis. Each segment verifies standalone, so an
    /// operator replays segments oldest first and compares
    /// [`Rotation::previous_head`] with the preceding segment's head to prove
    /// none is missing.
    ///
    /// Records still queued for remote delivery keep their place: the queue is
    /// not detached, and it is fed while this method holds the journal lock.
    pub fn rotate(&self, suffix: &str) -> Result<Rotation> {
        let suffix = validated_suffix(suffix)?;
        let archive = self.path.with_file_name(format!(
            "{}{suffix}",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("events.jsonl")
        ));
        if archive.exists() {
            return Err(GuardError::Denied(format!(
                "journal archive {} already exists; refusing to overwrite evidence",
                archive.display()
            )));
        }
        let mut guard = lock(&self.journal)?;
        refuse_if_broken(&guard)?;
        // Verify before moving anything, and while still exclusively owned.
        let sealed = read_events(&self.path)?;
        guard.file.sync_all()?;
        let previous_head = sealed.last().map(|event| event.current_hash.clone());
        fs::rename(&self.path, &archive)?;
        // From here the live path no longer names this sink's file. If anything
        // fails now, keeping the old handle would send the next append into the
        // archive, so the sink is marked broken and refuses to write until it is
        // reopened and replayed.
        if let Err(err) = reopen_after_rename(&mut guard, &self.path) {
            guard.broken = Some(format!(
                "rotation to {} failed after the rename ({err})",
                archive.display()
            ));
            return Err(err);
        }
        Ok(Rotation {
            archive,
            records: sealed.len(),
            previous_head,
        })
    }

    /// Simulates an unwind inside the append critical section.
    ///
    /// Test-only: this exercises the fail-closed behaviour after an interrupted
    /// append without deliberately corrupting a real journal.
    #[cfg(test)]
    pub(crate) fn poison_for_fault_injection(&self) {
        let guard = self
            .journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = &guard.head;
        panic!("simulated unwind between fsync and the chain-head update");
    }

    /// Makes the next rotation fail immediately after it renames the journal.
    ///
    /// Test-only: this is how the fail-closed behaviour on a half-finished
    /// rotation is exercised.
    #[cfg(test)]
    pub(crate) fn fail_next_rotate_for_fault_injection(&self) {
        lock(&self.journal)
            .expect("journal state is sound")
            .fail_next_rotate = true;
    }
}

/// Puts a fresh, exclusively owned journal in place after a rotation rename.
fn reopen_after_rename(journal: &mut Journal, path: &Path) -> Result<()> {
    #[cfg(test)]
    if journal.fail_next_rotate {
        journal.fail_next_rotate = false;
        return Err(GuardError::Unavailable(
            "injected failure after the rotation rename".to_string(),
        ));
    }
    let file = open_journal(path)?;
    advisory_lock(&file)?;
    sync_parent(path)?;
    // Replaces the old handle, releasing its lock on the archived segment.
    journal.file = file;
    journal.head = GENESIS_HASH.to_string();
    journal.count = 0;
    Ok(())
}

#[async_trait]
impl EventSink for FileEventSink {
    async fn append(&self, input: EventInput) -> Result<GuardEvent> {
        // Journal work is a short bounded write plus fsync; it runs on the
        // blocking pool so a slow disk cannot stall the gateway's tasks.
        match tokio::runtime::Handle::try_current() {
            Ok(_) => {
                let journal = Arc::clone(&self.journal);
                tokio::task::spawn_blocking(move || append_locked(&journal, input))
                    .await
                    .map_err(|err| {
                        GuardError::Unavailable(format!("event append task failed: {err}"))
                    })?
            }
            Err(_) => append_locked(&self.journal, input),
        }
    }
}

/// Takes the journal lock, or fails closed.
///
/// A poisoned lock means a previous append unwound somewhere inside the
/// critical section. If that happened between the fsync and the in-memory
/// chain-head update, the head this sink holds is stale, and appending from it
/// would write a record that forks the journal. So a poisoned journal is never
/// recovered and never written to again: every call fails with
/// [`GuardError::Integrity`] until the process reopens the journal and replays
/// it, which rebuilds the head from the file.
fn lock(journal: &Arc<Mutex<Journal>>) -> Result<MutexGuard<'_, Journal>> {
    journal.lock().map_err(|_| {
        GuardError::Integrity(
            "event journal state is poisoned after an interrupted append; reopen and replay the \
             journal before recording again"
                .to_string(),
        )
    })
}

fn append_locked(journal: &Arc<Mutex<Journal>>, input: EventInput) -> Result<GuardEvent> {
    input.validate()?;
    let mut guard = lock(journal)?;
    refuse_if_broken(&guard)?;
    let event = GuardEvent::new(Utc::now(), Uuid::new_v4(), input, guard.head.clone())?;
    let line = serde_json::to_vec(&event)?;
    if line.len() + 1 > MAX_LINE_BYTES {
        return Err(GuardError::Denied(format!(
            "serialized event is {} bytes, record bound is {MAX_LINE_BYTES}",
            line.len() + 1
        )));
    }
    let mut record = Vec::with_capacity(line.len() + 1);
    record.extend_from_slice(&line);
    record.push(b'\n');
    guard.file.write_all(&record)?;
    // fsync before the record counts as durable or is offered to a remote sink.
    guard.file.sync_all()?;
    guard.head.clone_from(&event.current_hash);
    guard.count += 1;
    if let Some(remote) = &guard.remote {
        // Enqueued while the journal lock is held, so the remote observes
        // journal order. A record the queue will not take is counted by the
        // queue; it never turns a durable local append into a failure.
        remote.enqueue(&event);
    }
    Ok(event)
}

/// Replays a whole journal and verifies its chain.
///
/// Bounded by [`MAX_JOURNAL_BYTES`] and [`MAX_EVENTS`]; a larger journal is
/// refused rather than loaded. An absent journal replays as an empty chain.
pub fn read_events(path: &Path) -> Result<Vec<GuardEvent>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(GuardError::Integrity(format!(
            "event journal {} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > MAX_JOURNAL_BYTES {
        return Err(GuardError::Integrity(format!(
            "event journal {} is {} bytes, replay bound is {MAX_JOURNAL_BYTES}",
            path.display(),
            metadata.len()
        )));
    }
    let mut records = RecordReader::new(BufReader::new(file));
    let mut events = Vec::new();
    while let Some(record) = records.next_record()? {
        if events.len() >= MAX_EVENTS {
            return Err(GuardError::Integrity(format!(
                "event journal {} holds more than {MAX_EVENTS} records",
                path.display()
            )));
        }
        events.push(parse_record(records.index(), &record)?);
    }
    super::verify_chain(&events)?;
    Ok(events)
}

/// One bounded slice of a journal, for operator inspection of a large file.
///
/// Each returned record is checked against its own hash. Chain continuity
/// across the page boundary is not implied: compare [`EventPage::first_previous_hash`]
/// with the `last_hash` of the preceding page, or replay the whole journal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventPage {
    /// Zero-based index of the first returned record.
    pub offset: usize,
    /// Records in `[offset, offset + limit)`.
    pub events: Vec<GuardEvent>,
    /// `previous_hash` of the first returned record, for cross-page chaining.
    pub first_previous_hash: Option<String>,
    /// `current_hash` of the last returned record.
    pub last_hash: Option<String>,
    /// Whether more records follow this page.
    pub has_more: bool,
}

/// Replays at most [`MAX_PAGE_EVENTS`] records starting at `offset`.
///
/// Memory is bounded by `limit`, not by the journal size.
pub fn read_events_page(path: &Path, offset: usize, limit: usize) -> Result<EventPage> {
    if limit == 0 || limit > MAX_PAGE_EVENTS {
        return Err(GuardError::Denied(format!(
            "page limit must be between 1 and {MAX_PAGE_EVENTS}"
        )));
    }
    if offset >= MAX_EVENTS {
        return Err(GuardError::Denied(format!(
            "page offset must be below {MAX_EVENTS}"
        )));
    }
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(EventPage {
                offset,
                has_more: false,
                ..EventPage::default()
            });
        }
        Err(err) => return Err(err.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(GuardError::Integrity(format!(
            "event journal {} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > MAX_JOURNAL_BYTES {
        return Err(GuardError::Integrity(format!(
            "event journal {} is {} bytes, replay bound is {MAX_JOURNAL_BYTES}",
            path.display(),
            metadata.len()
        )));
    }
    let mut records = RecordReader::new(BufReader::new(file));
    let mut events: Vec<GuardEvent> = Vec::new();
    let mut skipped = 0usize;
    let mut has_more = false;
    while let Some(record) = records.next_record()? {
        let index = records.index();
        if skipped < offset {
            skipped += 1;
            continue;
        }
        if events.len() == limit {
            has_more = true;
            break;
        }
        let event = parse_record(index, &record)?;
        events.push(event);
    }
    Ok(EventPage {
        offset,
        first_previous_hash: events.first().map(|event| event.previous_hash.clone()),
        last_hash: events.last().map(|event| event.current_hash.clone()),
        events,
        has_more,
    })
}

/// Replays and verifies a journal, returning its record count.
pub fn verify_file(path: &Path) -> Result<usize> {
    Ok(read_events(path)?.len())
}

/// Reads newline-delimited records, refusing anything that is not a complete
/// record so that a torn final append fails closed instead of being dropped.
struct RecordReader<R: BufRead> {
    reader: R,
    index: usize,
}

impl<R: BufRead> RecordReader<R> {
    fn new(reader: R) -> Self {
        Self { reader, index: 0 }
    }

    fn index(&self) -> usize {
        self.index
    }

    fn next_record(&mut self) -> Result<Option<Vec<u8>>> {
        let mut buffer = Vec::new();
        if self.reader.read_until(b'\n', &mut buffer)? == 0 {
            return Ok(None);
        }
        self.index += 1;
        if buffer.last() != Some(&b'\n') {
            return Err(GuardError::Integrity(format!(
                "record {} is truncated: the journal ends mid-record",
                self.index
            )));
        }
        buffer.pop();
        if buffer.is_empty() {
            return Err(GuardError::Integrity(format!(
                "record {} is empty",
                self.index
            )));
        }
        if buffer.len() > MAX_LINE_BYTES {
            return Err(GuardError::Integrity(format!(
                "record {} is {} bytes, record bound is {MAX_LINE_BYTES}",
                self.index,
                buffer.len()
            )));
        }
        Ok(Some(buffer))
    }
}

fn parse_record(index: usize, record: &[u8]) -> Result<GuardEvent> {
    // The serde error text is deliberately dropped: it can echo an offending
    // value, and a journal may have been tampered with.
    let event: GuardEvent = serde_json::from_slice(record).map_err(|err| {
        GuardError::Integrity(format!(
            "record {index} is not a Guard event ({:?} at line {} column {})",
            err.classify(),
            err.line(),
            err.column()
        ))
    })?;
    event.verify_bounds()?;
    event
        .verify_self_hash()
        .map_err(|err| GuardError::Integrity(format!("record {index}: {err}")))?;
    Ok(event)
}

fn reject_unusable_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(GuardError::Integrity(format!(
                    "event journal {} is a symlink",
                    path.display()
                )));
            }
            if !metadata.is_file() {
                return Err(GuardError::Integrity(format!(
                    "event journal {} is not a regular file",
                    path.display()
                )));
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Whether a journal file is already there.
fn journal_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Makes a create or rename in the journal's directory durable.
fn sync_parent(path: &Path) -> Result<()> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    // A read-only directory handle is enough for fsync on Linux.
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Accepts a short archive suffix that cannot escape the journal directory.
fn validated_suffix(suffix: &str) -> Result<&str> {
    if suffix.is_empty() || suffix.len() > 32 {
        return Err(GuardError::Denied(
            "journal archive suffix must be between 1 and 32 bytes".to_string(),
        ));
    }
    if !suffix
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-' || byte == b'_')
    {
        return Err(GuardError::Denied(
            "journal archive suffix must be ASCII alphanumeric with '.', '-' or '_'".to_string(),
        ));
    }
    Ok(suffix)
}

fn open_journal(path: &Path) -> Result<File> {
    // `append` maps to O_APPEND, so a record is written as one atomic step at
    // the end of the file even if another writer appears.
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

/// Advisory single-writer lock; released when the file handle is closed.
fn advisory_lock(file: &File) -> Result<()> {
    // SAFETY: `flock` only needs a valid descriptor, which `as_raw_fd` borrows
    // for the duration of the call.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(GuardError::Unavailable(format!(
            "event journal is already owned by another process ({:?})",
            err.kind()
        )));
    }
    Ok(())
}
