//! Task budgets. When one runs out the session stops cleanly and still writes a
//! result: an aborted run with evidence is worth far more than a run killed
//! where it stood.

use std::time::{Duration, Instant};

use crate::model::Stop;
use crate::task::Limits;

/// Counts the things that are limited, and answers when to stop.
pub struct Budget {
    limits: Limits,
    started: Instant,
    requests: u32,
}

/// Why the loop stopped, in the caller's terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exhaustion {
    Requests,
    WallClock,
}

impl Budget {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            started: Instant::now(),
            requests: 0,
        }
    }

    pub fn requests(&self) -> u32 {
        self.requests
    }

    pub fn remaining_requests(&self) -> u32 {
        self.limits.max_model_requests.saturating_sub(self.requests)
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Checked before spending a request, so the last one is never started when
    /// there is no budget for its answer.
    pub fn check(&self) -> Result<u32, Stop> {
        if self.requests >= self.limits.max_model_requests {
            return Err(Stop::MaxRequests);
        }
        if self.elapsed_ms() >= self.limits.wall_seconds * 1000 {
            return Err(Stop::WallClock);
        }
        Ok(self.requests + 1)
    }

    /// Called after a request is actually issued.
    pub fn record_request(&mut self) {
        self.requests = self.requests.saturating_add(1);
    }

    /// How much wall time is left, for bounding an in-flight operation.
    pub fn remaining(&self) -> Duration {
        Duration::from_secs(self.limits.wall_seconds).saturating_sub(self.started.elapsed())
    }

    pub fn describe(&self) -> Option<Exhaustion> {
        if self.requests >= self.limits.max_model_requests {
            Some(Exhaustion::Requests)
        } else if self.elapsed_ms() >= self.limits.wall_seconds * 1000 {
            Some(Exhaustion::WallClock)
        } else {
            None
        }
    }
}

/// Peak resident set size, read from the kernel rather than estimated.
///
/// Linux-only by construction: this binary runs in a Linux guest, and a missing
/// number is reported as absent rather than guessed.
pub fn peak_rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return None;
    }
    Some(pages as u64 * page_size as u64)
}

/// User plus system CPU time for this process, so the result can separate our
/// cost from the model's wait.
pub fn cpu_time_ms() -> u64 {
    // SAFETY: getrusage writes a plain struct through the pointer we supply.
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) != 0 {
            return 0;
        }
        let user = usage.ru_utime.tv_sec as u64 * 1000 + usage.ru_utime.tv_usec as u64 / 1000;
        let sys = usage.ru_stime.tv_sec as u64 * 1000 + usage.ru_stime.tv_usec as u64 / 1000;
        user + sys
    }
}
