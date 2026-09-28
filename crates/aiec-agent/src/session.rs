//! Resuming a run after the agent died.
//!
//! A VM is disposable but it is not instantaneous, and a model that was
//! mid-task when the process was killed should not have to start over. The
//! transcript is appended as it goes rather than written at the end, because
//! the common case is the process dying before the end.

use std::path::{Path, PathBuf};

use crate::model::Message;
use crate::task::HarnessError;

/// The on-disk transcript.
pub struct Session {
    path: PathBuf,
    messages: Vec<Message>,
    /// How many messages are held before the file is rewritten. Rewriting on
    /// every turn would be a small write per turn, which is nothing, but
    /// rewriting is also the only way a truncated or corrupt file gets repaired.
    since_flush: usize,
}

impl Session {
    /// Opens, or creates, a session under `dir`.
    pub fn open(dir: &Path) -> Result<Self, HarnessError> {
        std::fs::create_dir_all(dir)
            .map_err(|error| HarnessError::Io(format!("creating session: {error}")))?;
        let path = dir.join("transcript.json");
        let messages = read(&path).unwrap_or_default();
        Ok(Self {
            path,
            messages,
            since_flush: 0,
        })
    }

    /// Appends a message, flushing when it is worth it.
    pub fn push(&mut self, message: Message) -> Result<(), HarnessError> {
        self.messages.push(message);
        self.since_flush += 1;
        if self.since_flush >= 8 {
            self.flush()?;
        }
        Ok(())
    }

    /// Writes the transcript now.
    pub fn flush(&mut self) -> Result<(), HarnessError> {
        self.since_flush = 0;
        write(&self.path, &self.messages)
    }

    /// Everything recorded so far, for resuming.
    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    /// Whether there is anything to resume.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

fn read(path: &Path) -> Option<Vec<Message>> {
    let bytes = std::fs::read(path).ok()?;
    // A corrupt transcript must not stop a run: starting fresh is always
    // possible, refusing to start is not.
    serde_json::from_slice(&bytes).ok()
}

fn write(path: &Path, messages: &[Message]) -> Result<(), HarnessError> {
    let bytes = serde_json::to_vec(messages)
        .map_err(|error| HarnessError::Io(format!("encoding: {error}")))?;
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, &bytes)
        .map_err(|error| HarnessError::Io(format!("writing session: {error}")))?;
    std::fs::rename(&temporary, path)
        .map_err(|error| HarnessError::Io(format!("publishing session: {error}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_round_trips() {
        let dir = std::env::temp_dir().join(format!("aiec-session-{}", uuid::Uuid::now_v7()));
        {
            let mut session = Session::open(&dir).expect("opened");
            session
                .push(Message::User {
                    content: "hello".to_owned(),
                })
                .expect("pushed");
            session.flush().expect("flushed");
            assert!(!session.is_empty());
        }
        let reopened = Session::open(&dir).expect("reopened");
        assert_eq!(reopened.messages().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_corrupt_transcript_starts_fresh_rather_than_failing() {
        let dir = std::env::temp_dir().join(format!("aiec-session-bad-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("transcript.json"), b"{not json").unwrap();
        let session = Session::open(&dir).expect("a corrupt file must not stop a run");
        assert!(session.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
