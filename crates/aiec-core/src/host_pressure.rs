//! What the machine actually has, measured.
//!
//! A worker's declared capacity is an allocation: the operator's answer to "how
//! much of this host is mine". It is arithmetic, it is stored in the ledger, and
//! it must stay consistent with the allocations it came from. It is not a
//! measurement, and it is deliberately never rewritten by one - a heartbeat that
//! resized capacity would race the scheduler's debit and release and leave the
//! ledger disagreeing with itself.
//!
//! Pressure is the separate thing: what the host reports about itself right now,
//! after a reserve is held back for the operating system, the page cache, the
//! worker's own processes, logs and workspace archives. It moves every few
//! seconds, it can recover, and it gates *admission* - whether this host may
//! take another sandbox - without touching a single ledger counter and without
//! disturbing the sandboxes already running.
//!

//! One of those measurements is not like the others. Memory and disk are
//! stores: what a running sandbox holds, it gives back when it exits, so a
//! host's headroom recovers on its own. Logical CPUs are a ceiling: two
//! workers on one machine can each honestly read every vCPU free, both be
//! right about their own worker, and together still promise more than the
//! machine has. So CPU is aggregated against a measured ceiling instead of
//! summed into a budget that grows with the cluster - nothing is oversubscribed
//! automatically, and a host that could not be asked how many logical CPUs it
//! has admits no CPU work at all, because a ceiling nobody measured is not an
//! unlimited one.
//!
//! Three rules hold everywhere this is used:
//!
//! * A measurement below the reserve saturates to zero. It is a real reading of
//!   a host that has no headroom left, not a missing reading, and it must not be
//!   confused with one.
//! * A measurement that could not be taken is missing, and missing fails closed
//!   for production admission. Guessing is the failure this replaces.
//! * The worker only ever *reports*. Whether a report is fresh enough to admit
//!   work is the scheduler's decision, over [`host_admission_budget`].

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Bytes in a mebibyte.
pub const MIB: u64 = 1024 * 1024;
/// Bytes in a gibibyte.
pub const GIB: u64 = 1024 * MIB;

/// Host headroom held back before any sandbox is admitted.
///
/// Memory covers the operating system, the page cache and the worker's own
/// processes; disk covers logs, images and the workspace archives a snapshot
/// writes. Scheduling a host to its last byte is how a machine starts refusing
/// I/O in the middle of running somebody's job, so these are subtracted from
/// what the host reports rather than being spent on work.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct HostReserves {
    /// Bytes of memory kept off the table.
    pub memory_bytes: u64,
    /// Bytes of disk kept off the table.
    pub disk_bytes: u64,
}

impl Default for HostReserves {
    fn default() -> Self {
        Self {
            memory_bytes: 512 * MIB,
            disk_bytes: 2 * GIB,
        }
    }
}

impl HostReserves {
    /// Builds reserves from mebibytes, which is how operators state them.
    ///
    /// `saturating_mul` because a reserve is a subtraction, not an allocation:
    /// an operator who asks for more reserve than a `u64` can express gets a
    /// host that admits nothing, which is a refusal rather than a wrap.
    pub fn from_mib(memory_mib: u64, disk_mib: u64) -> Self {
        Self {
            memory_bytes: memory_mib.saturating_mul(MIB),
            disk_bytes: disk_mib.saturating_mul(MIB),
        }
    }
}

/// A host's own report about itself, at a moment in time.
///
/// Every measurement is optional because each one can independently fail to be
/// taken, and an absent measurement means something different from a zero one:
/// zero is a host with no headroom left, absent is a host nobody asked. Both
/// refuse admission; only the second is worth an operator's attention.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct HostPressure {
    /// Stable digest of this machine, shared by every worker on it.
    pub host_id: String,
    /// When the measurement was taken.
    pub observed_at: DateTime<Utc>,
    /// Logical CPUs this host may run at once, as the calling process is
    /// actually allowed to use them: its affinity mask and cgroup quota, not
    /// every core the machine has installed.
    ///
    /// `serde(default)` because this field postdates the first workers: an
    /// older reading still parses, and [`Self::complete`] refuses it, which is
    /// the same answer a failed measurement gets.
    #[serde(default)]
    pub total_vcpus: Option<u32>,
    /// The same ceiling less what the machine is already running.
    #[serde(default)]
    pub available_vcpus: Option<u32>,
    /// Bytes of memory the kernel reports in total.
    pub total_memory_bytes: Option<u64>,
    /// `MemAvailable`, minus the memory reserve.
    pub memory_available_bytes: Option<u64>,
    /// Bytes on the filesystem backing the worker's state directory.
    pub total_disk_bytes: Option<u64>,
    /// Bytes available to an unprivileged writer there, minus the disk reserve.
    pub disk_available_bytes: Option<u64>,
    /// Reserve this reading was taken against.
    pub reserves: HostReserves,
}

/// The figures one reading is assembled from.
///
/// Its own type rather than nine positional parameters: a caller that supplies
/// the byte counts in the wrong order gets a reading that is plausible and
/// wrong, and there is no compiler error to notice it by.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostMeasurements {
    /// See [`HostPressure::total_vcpus`].
    pub total_vcpus: Option<u32>,
    /// See [`HostPressure::available_vcpus`].
    pub available_vcpus: Option<u32>,
    /// See [`HostPressure::total_memory_bytes`].
    pub total_memory_bytes: Option<u64>,
    /// See [`HostPressure::memory_available_bytes`].
    pub memory_available_bytes: Option<u64>,
    /// See [`HostPressure::total_disk_bytes`].
    pub total_disk_bytes: Option<u64>,
    /// See [`HostPressure::disk_available_bytes`].
    pub disk_available_bytes: Option<u64>,
}

impl HostMeasurements {
    /// A reading with nothing measured, which [`HostPressure::complete`] refuses.
    pub fn unmeasured() -> Self {
        Self::default()
    }
}

impl HostPressure {
    /// Reads the host now, holding back `reserves`.
    ///
    /// `workspace` is the directory whose filesystem is measured rather than
    /// `/`. They are the same filesystem on an ordinary host and emphatically
    /// not the same in a container, where `/` is the image's overlay and the
    /// workspaces live on a mounted volume. Measuring `/` there would describe
    /// storage the workloads cannot use, and a node would keep accepting
    /// sandboxes while the volume they actually need was full.
    pub fn measure(workspace: &Path, reserves: HostReserves) -> Self {
        let (total_vcpus, available_vcpus) = measure_cpu();
        let (total_memory_bytes, memory_available_bytes) = measure_memory(reserves.memory_bytes);
        let (total_disk_bytes, disk_available_bytes) = measure_disk(workspace, reserves.disk_bytes);
        Self {
            host_id: host_id(),
            observed_at: Utc::now(),
            total_vcpus,
            available_vcpus,
            total_memory_bytes,
            memory_available_bytes,
            total_disk_bytes,
            disk_available_bytes,
            reserves,
        }
    }

    /// Builds a reading from figures already in hand.
    ///
    /// [`Self::measure`] is the only thing that reads the host; this is how a
    /// reading is assembled from an existing one, and how a reading is
    /// constructed in a test that must not depend on the machine it runs on.
    pub fn from_measurements(
        host_id: impl Into<String>,
        observed_at: DateTime<Utc>,
        measurements: HostMeasurements,
        reserves: HostReserves,
    ) -> Self {
        Self {
            host_id: host_id.into(),
            observed_at,
            total_vcpus: measurements.total_vcpus,
            available_vcpus: measurements.available_vcpus,
            total_memory_bytes: measurements.total_memory_bytes,
            memory_available_bytes: measurements.memory_available_bytes,
            total_disk_bytes: measurements.total_disk_bytes,
            disk_available_bytes: measurements.disk_available_bytes,
            reserves,
        }
    }

    /// Whether every measurement this admission needs was taken.
    ///
    /// A partial reading is not a smaller reading. Half a host's state is not
    /// enough to admit a sandbox on, because the half that is missing is
    /// exactly the half that would have refused it.
    pub fn complete(&self) -> bool {
        self.available_vcpus.is_some()
            && self.total_vcpus.is_some()
            && self.memory_available_bytes.is_some()
            && self.disk_available_bytes.is_some()
    }

    /// Whether the host can take `vcpus` logical CPUs, `memory_bytes` of memory
    /// and `disk_bytes` of disk right now.
    ///
    /// Fails closed: an incomplete reading, a zero reading and a reading too
    /// small for the demand are all refusals, and only the last two are the
    /// host's own answer. This is the check a worker re-runs immediately before
    /// it materialises a VM, because a host can fill between the heartbeat that
    /// admitted the placement and the boot that spends it.
    ///
    /// The CPU half of this is one worker's view of a machine it shares, and it
    /// is deliberately not the whole answer: what the *other* workers on this
    /// host have already committed is only known to the scheduler, over
    /// [`host_admission_budget`]. Refusing here is the floor under that, never
    /// a substitute for it.
    pub fn admits(
        &self,
        vcpus: u32,
        memory_bytes: u64,
        disk_bytes: u64,
    ) -> Result<(), crate::CoreError> {
        if !self.complete() {
            return Err(crate::CoreError::Unavailable(format!(
                "host {} pressure could not be measured; refusing to admit",
                self.host_id
            )));
        }
        let cpu = self.available_vcpus.unwrap_or_default();
        let memory = self.memory_available_bytes.unwrap_or_default();
        let disk = self.disk_available_bytes.unwrap_or_default();
        if cpu < vcpus || memory < memory_bytes || disk < disk_bytes {
            return Err(crate::CoreError::Unavailable(format!(
                "host {} has {} vcpus, {} memory and {} disk available above its reserve, \
                 needs {}, {} and {}",
                self.host_id, cpu, memory, disk, vcpus, memory_bytes, disk_bytes
            )));
        }
        Ok(())
    }

    /// The JSON object published under `pressure` in worker metadata.
    ///
    /// Bounded by construction: the shape is this struct, so nothing about the
    /// host beyond a digest, two CPU counts, four byte counts and a reserve
    /// can reach the control plane through it.
    pub fn to_metadata(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }

    /// Reads a reading back out of stored worker metadata.
    ///
    /// Returns `None` for metadata that carries no reading at all, which is what
    /// a worker predating this reports, and what a scheduler must therefore
    /// refuse to admit work on.
    pub fn from_metadata(metadata: &serde_json::Value) -> Option<Self> {
        serde_json::from_value(metadata.get("pressure")?.clone()).ok()
    }
}

/// The host headroom a scheduler may spend, after everything already reserved.
///
/// Four workers on one host each read the same figures and each declared them,
/// so the cluster came to believe thirty-five gigabytes existed where the host
/// had twenty-six. Aggregate accounting is what stops that: the observations
/// are combined per machine before any of them is trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostAdmissionBudget {
    /// Logical CPUs that may still be committed on this host.
    ///
    /// Bounded by the machine, not by the number of workers reporting it: two
    /// eight-vCPU workers on a sixteen-vCPU host have eight between them, not
    /// sixteen, and this is the figure that says so.
    pub vcpus: u32,
    /// Memory bytes that may still be committed on this host.
    pub memory_bytes: u64,
    /// Disk bytes that may still be committed on this host.
    pub disk_bytes: u64,
    /// Whether any usable observation backed this budget.
    pub observed: bool,
}

/// One worker's contribution to its host's accounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostObservation {
    /// Machine this observation describes.
    pub host_id: String,
    /// When it was taken.
    pub observed_at: DateTime<Utc>,
    /// Measured headroom, or `None` when the measurement failed.
    pub total_vcpus: Option<u32>,
    /// Measured headroom, or `None` when the measurement failed.
    pub available_vcpus: Option<u32>,
    /// Measured headroom, or `None` when the measurement failed.
    pub memory_available_bytes: Option<u64>,
    /// Measured headroom, or `None` when the measurement failed.
    pub disk_available_bytes: Option<u64>,
    /// Capacity this node still owes the ledger: `total - available`.
    pub reserved_memory_bytes: u64,
    /// Capacity this node still owes the ledger: `total - available`.
    pub reserved_disk_bytes: u64,
    /// Capacity this node still owes the ledger: `total - available`.
    pub reserved_vcpus: u32,
}

impl HostObservation {
    /// Builds an observation from a reported reading and a node's ledger.
    pub fn new(
        pressure: &HostPressure,
        reserved_vcpus: u32,
        reserved_memory_bytes: u64,
        reserved_disk_bytes: u64,
    ) -> Self {
        Self {
            host_id: pressure.host_id.clone(),
            observed_at: pressure.observed_at,
            total_vcpus: pressure.total_vcpus,
            available_vcpus: pressure.available_vcpus,
            memory_available_bytes: pressure.memory_available_bytes,
            disk_available_bytes: pressure.disk_available_bytes,
            reserved_vcpus,
            reserved_memory_bytes,
            reserved_disk_bytes,
        }
    }
}

/// Aggregates every worker's observations of one machine into one budget.
///
/// `observations` may cover any number of hosts; only `host_id` is considered.
/// `max_age` is the window within which an observation counts, and the caller
/// passes its own heartbeat TTL: a worker that stopped reporting must stop
/// contributing, or its stale reading holds capacity nobody can spend.
///
/// The arithmetic is deliberately pessimistic in three places, and the cost is
/// stated rather than hidden:
///
/// * The *least* favourable fresh observation wins, not the newest. Two
///   workers reading the same kernel milliseconds apart differ by whatever the
///   rest of the machine did in between, and the smaller answer is the one the
///   host is more likely to agree with when the demand lands.
/// * Every node's outstanding reservation is subtracted from the observed
///   headroom, even though the memory those sandboxes already hold is *inside*
///   that headroom and is therefore counted twice. The double count is the
///   price of refusing to reason about which worker's sandboxes the reading was
///   taken with in front of them, and it under-books a busy host rather than
///   over-booking it. On a host whose sandboxes hold most of its memory the
///   budget approaches zero while real headroom remains, so the host is used to
///   roughly `available / (available + held)` of what it could have taken. An
///   idle host pays nothing; a host carrying work is refused new work earlier
///   than strictly necessary. That is the intended direction to be wrong in.
/// * CPU is a ceiling and is treated as one. Every worker's held vCPUs
///   (`total - available` on that node's ledger) are subtracted from the
///   *least* favourable fresh measured ceiling, never from a sum of readings:
///   two workers each reporting eight free vCPUs on a sixteen-vCPU host do not
///   make sixteen vCPUs exist, and adding their readings is exactly the
///   oversubscription this refuses to perform automatically. A host whose
///   ceiling nobody measured lends no CPU at all, whatever it measured for
///   memory and disk - one missing measurement is a missing measurement, and
///   this arithmetic is not applied per resource in opposite directions.
///
/// A host with no usable observation has no budget. There is no reading, so
/// there is no admission, and `observed` is false so the caller can tell that
/// apart from a host measured at zero.
pub fn host_admission_budget(
    observations: &[HostObservation],
    host_id: &str,
    now: DateTime<Utc>,
    max_age: ChronoDuration,
) -> HostAdmissionBudget {
    let mut vcpus: Option<u32> = None;
    let mut memory_bytes: Option<u64> = None;
    let mut disk_bytes: Option<u64> = None;
    let mut held_vcpus: u32 = 0;
    let mut held_memory: u64 = 0;
    let mut held_disk: u64 = 0;
    let mut observed = false;
    for observation in observations.iter().filter(|o| o.host_id == host_id) {
        let fresh = now.signed_duration_since(observation.observed_at) <= max_age;
        if !fresh {
            continue;
        }
        held_vcpus = held_vcpus.saturating_add(observation.reserved_vcpus);
        held_memory = held_memory.saturating_add(observation.reserved_memory_bytes);
        held_disk = held_disk.saturating_add(observation.reserved_disk_bytes);
        let (Some(total), Some(available), Some(available_memory), Some(available_disk)) = (
            observation.total_vcpus,
            observation.available_vcpus,
            observation.memory_available_bytes,
            observation.disk_available_bytes,
        ) else {
            // A stale-but-fresh-enough reading that failed to measure still
            // holds its reservations: something was promised against this
            // host, and forgetting the promise would make room for more.
            continue;
        };
        observed = true;
        // The ceiling is what the demand is capped against and the measured
        // availability is what is left of it, so the smaller of the two is the
        // honest answer to "how many more vCPUs does this machine have".
        vcpus = Some(vcpus.map_or(available.min(total), |v: u32| v.min(available).min(total)));
        memory_bytes =
            Some(memory_bytes.map_or(available_memory, |m: u64| m.min(available_memory)));
        disk_bytes = Some(disk_bytes.map_or(available_disk, |d: u64| d.min(available_disk)));
    }
    HostAdmissionBudget {
        vcpus: vcpus.unwrap_or_default().saturating_sub(held_vcpus),
        memory_bytes: memory_bytes.unwrap_or_default().saturating_sub(held_memory),
        disk_bytes: disk_bytes.unwrap_or_default().saturating_sub(held_disk),
        observed,
    }
}

/// Whether `demand` fits in `budget`, refusing an unobserved host.
pub fn budget_admits(
    budget: &HostAdmissionBudget,
    vcpus: u32,
    memory_bytes: u64,
    disk_bytes: u64,
) -> bool {
    budget.observed
        && budget.vcpus >= vcpus
        && budget.memory_bytes >= memory_bytes
        && budget.disk_bytes >= disk_bytes
}

/// Subtracts a reserve from a reading, saturating at zero.
///
/// `raw < reserve` is a host with no headroom above the reserve, which is a
/// measurement of zero and must stay one. Returning `None` here - which is what
/// `checked_sub` did - made a full host indistinguishable from a host nobody
/// could measure, and the caller fell back to claiming its allocation.
fn after_reserve(raw: Option<u64>, reserve: u64) -> Option<u64> {
    raw.map(|value| value.saturating_sub(reserve))
}

/// Logical CPUs this host may run at once, and what is left of them.
///
/// The ceiling is `available_parallelism`, which on Linux counts the CPUs this
/// process is actually allowed to use - its affinity mask, and the CPU quota
/// of the cgroup it is in - rather than every core the machine has installed.
/// That is the honest number for a worker in a container limited to four of a
/// host's twelve: a scheduler that believed in twelve would oversubscribe the
/// host by eight, and the operator who set the quota would be the last to know.
///
/// What the machine is already running is a second, separate observation, and
/// the kernel's is the one-minute load average: a runnable task queue that the
/// load reports is work a new guest would queue behind rather than run. The
/// load is rounded *up*, so a third of a busy CPU costs a whole one - the same
/// direction as the memory reserve, and the reason a burst of parallel boots
/// refuses the next placement instead of queueing somebody's job behind it.
/// The average decays on its own, so the reading recovers without a heartbeat
/// having to rewrite anything.
///
/// Unlike memory there is no reserve to hold back: a vCPU is not a store the
/// kernel hands out, and the ceiling *is* the bound.
fn measure_cpu() -> (Option<u32>, Option<u32>) {
    let Ok(parallelism) = std::thread::available_parallelism() else {
        return (None, None);
    };
    let Ok(total) = u32::try_from(parallelism.get()) else {
        return (None, None);
    };
    let Some(available) = load_one_minute().map(|load| total.saturating_sub(load.ceil() as u32))
    else {
        return (Some(total), None);
    };
    (Some(total), Some(available))
}

/// The one-minute load average, or `None` where the kernel does not publish it.
fn load_one_minute() -> Option<f64> {
    let loadavg = std::fs::read_to_string("/proc/loadavg").ok()?;
    loadavg.split_whitespace().next()?.parse::<f64>().ok()
}

/// Memory the kernel says is available, not `MemFree`.
///
/// `MemFree` is memory nothing happens to be using, which on a healthy host is
/// near zero precisely because the page cache is doing its job. `MemAvailable`
/// is the estimate of what a new allocation can actually get.
fn measure_memory(reserve: u64) -> (Option<u64>, Option<u64>) {
    let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") else {
        return (None, None);
    };
    let mut total = None;
    let mut available = None;
    for line in meminfo.lines() {
        let Some((field, rest)) = line.split_once(':') else {
            continue;
        };
        let Ok(kilobytes) = rest
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .parse::<u64>()
        else {
            continue;
        };
        // A kilobyte figure that cannot be widened is a host reporting
        // nonsense; treat the reading as absent rather than wrap it.
        let Some(bytes) = kilobytes.checked_mul(1024) else {
            continue;
        };
        match field {
            "MemTotal" => total = Some(bytes),
            "MemAvailable" => available = Some(bytes),
            _ => {}
        }
    }
    (total, after_reserve(available, reserve))
}

/// Bytes on the filesystem holding `path`, and what is left of them.
///
/// `path` need not exist. A worker is given a state directory that is created
/// lazily, so the first admission of a worker's life measures a path with
/// nothing under it yet - and a bare `statvfs` there answers "could not be
/// measured", which reads as a broken host and refuses the first sandbox. The
/// nearest existing ancestor shares the filesystem, so that is what is
/// measured.
fn measure_disk(path: &Path, reserve: u64) -> (Option<u64>, Option<u64>) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let mut existing = path;
    while !existing.exists() {
        match existing.parent() {
            Some(parent) => existing = parent,
            None => return (None, None),
        }
    }
    let Ok(c_path) = CString::new(existing.as_os_str().as_bytes().to_vec()) else {
        return (None, None);
    };
    // SAFETY: `stat` is zeroed before the call, `c_path` is a valid,
    // NUL-terminated string that outlives it, and `statvfs` only writes through
    // the pointer it is handed.
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) != 0 {
            return (None, None);
        }
        let total = stat.f_blocks.checked_mul(stat.f_frsize);
        // `f_bavail` rather than `f_bfree`: blocks reserved for root are not
        // available to a workload.
        let available = stat.f_bavail.checked_mul(stat.f_frsize);
        (total, after_reserve(available, reserve))
    }
}

/// A stable, non-secret identifier for this machine.
///
/// Every worker on a host must produce the same value, which is what makes
/// aggregate accounting possible at all, and no worker may learn anything about
/// another from it. So it is a truncated SHA-256 of a machine identifier that
/// is stable across reboots - never the identifier itself, which is a raw host
/// credential that has no business travelling to a control plane.
///
/// The sources are tried in order of how well they identify a *machine* rather
/// than an installation: `/etc/machine-id` is the same across duplicated images
/// of the same disk, which is what two workers on one host share, while the DMI
/// product UUID follows the motherboard. A host with neither falls back to its
/// hostname, and a host with nothing at all gets a per-process id that
/// aggregates nothing - which under-protects a busy host rather than
/// stranding an idle one.
pub fn host_id() -> String {
    if let Some(material) =
        read_identity("/etc/machine-id").or_else(|| read_identity("/sys/class/dmi/id/product_uuid"))
    {
        return digest(&material);
    }
    match hostname() {
        Some(name) => digest(&name),
        None => uuid::Uuid::now_v7().to_string(),
    }
}

/// Digests host identity material into a fixed-width, non-reversible token.
fn digest(material: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(material.trim().as_bytes());
    hex::encode(&hasher.finalize()[..16])
}

fn read_identity(path: &str) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    let trimmed = contents.trim();
    // A missing or placeholder identifier identifies nothing, and hashing it
    // would give every such host the same confident-looking id.
    let placeholder = trimmed.is_empty()
        || matches!(
            trimmed.to_ascii_lowercase().as_str(),
            "none" | "unknown" | "not set" | "to be filled by o.e.m."
        );
    (!placeholder).then(|| trimmed.to_owned())
}

fn hostname() -> Option<String> {
    // SAFETY: `buf` is a live, correctly sized buffer and `gethostname` only
    // writes through it, NUL-terminating within its length.
    unsafe {
        // `c_char` is `i8` on x86_64 and `u8` on aarch64, so a hardcoded `i8`
        // buffer only compiles on the architecture that was built on.
        let mut buf = [0 as libc::c_char; 256];
        if libc::gethostname(buf.as_mut_ptr(), buf.len()) != 0 {
            return None;
        }
        std::ffi::CStr::from_ptr(buf.as_ptr())
            .to_str()
            .ok()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoreError;

    const GIB: u64 = 1024 * MIB;

    /// The logical CPUs of the machine these fixtures stand in for.
    const HOST_VCPUS: u32 = 16;

    fn reading(memory: Option<u64>, disk: Option<u64>) -> HostPressure {
        reading_on_cpu(Some(HOST_VCPUS), Some(HOST_VCPUS), memory, disk)
    }

    /// A reading whose CPU figures are stated on their own, because the
    /// questions CPU raises - a missing ceiling, a host measured at zero - are
    /// questions about CPU alone and would be hidden behind memory and disk.
    fn reading_on_cpu(
        total_vcpus: Option<u32>,
        available_vcpus: Option<u32>,
        memory: Option<u64>,
        disk: Option<u64>,
    ) -> HostPressure {
        HostPressure::from_measurements(
            "host-under-test",
            Utc::now(),
            HostMeasurements {
                total_vcpus,
                available_vcpus,
                total_memory_bytes: Some(GIB * 100),
                memory_available_bytes: memory,
                total_disk_bytes: Some(GIB * 500),
                disk_available_bytes: disk,
            },
            HostReserves::default(),
        )
    }

    /// A worker's state directory does not exist when it starts, and admission
    /// measures it before anything has created it. A bare `statvfs` there
    /// answers "could not be measured", which reads as a broken host and
    /// refuses the first sandbox the worker ever takes - so the measurement
    /// walks to the nearest existing ancestor, which shares the filesystem.
    #[test]
    fn a_path_that_does_not_exist_yet_still_yields_its_filesystem() {
        let root = std::env::temp_dir().join(format!("aiec-pressure-{}", std::process::id()));
        let absent = root.join("not").join("created").join("yet");
        assert!(!absent.exists(), "the fixture must start absent");
        let (total, available) = measure_disk(&absent, 0);
        assert!(total.is_some(), "an absent path still has a filesystem");
        assert!(available.is_some(), "and has free space to report");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The reading a lazily-created state directory produces has to satisfy the
    /// same completeness check as any other, or admission refuses the sandbox.
    #[test]
    fn a_worker_can_admit_with_a_state_directory_it_has_not_created_yet() {
        let root = std::env::temp_dir().join(format!("aiec-pressure-{}", std::process::id()));
        let (total, available) = measure_disk(&root.join("never-created"), 0);
        let pressure = HostPressure::from_measurements(
            "host-under-test",
            Utc::now(),
            HostMeasurements {
                total_vcpus: Some(HOST_VCPUS),
                available_vcpus: Some(HOST_VCPUS),
                total_memory_bytes: Some(GIB * 100),
                memory_available_bytes: Some(GIB * 50),
                total_disk_bytes: total,
                disk_available_bytes: available,
            },
            HostReserves::default(),
        );
        assert!(
            pressure.complete(),
            "a lazily-created state directory must not read as an unmeasurable host"
        );
    }

    /// A host that has less free than the reserve has not lost its reading, it
    /// has answered zero. The two must stay distinguishable or the caller falls
    /// back to declaring an allocation it never measured.
    #[test]
    fn a_below_reserve_reading_is_zero_and_not_a_missing_one() {
        let reserve = 512 * MIB;
        assert_eq!(after_reserve(Some(reserve - 1), reserve), Some(0));
        assert_eq!(after_reserve(Some(reserve), reserve), Some(0));
        assert_eq!(after_reserve(Some(reserve + 1), reserve), Some(1));
        assert_eq!(after_reserve(None, reserve), None);

        let full = reading(Some(0), Some(0));
        assert!(full.complete(), "zero is a measurement, not a gap");
        let refused = full
            .admits(1, 1, 1)
            .expect_err("a full host admits nothing");
        assert!(matches!(refused, CoreError::Unavailable(_)));
    }

    /// A measurement that could not be taken has to refuse, because the whole
    /// point of measuring is that an unmeasured host is not an unlimited one.
    #[test]
    fn a_missing_reading_fails_closed_for_admission() {
        for (memory, disk) in [(None, Some(GIB)), (Some(GIB), None), (None, None)] {
            let partial = reading(memory, disk);
            assert!(!partial.complete());
            let error = partial
                .admits(1, 1, 1)
                .expect_err("unmeasured host admits nothing");
            assert!(
                matches!(&error, CoreError::Unavailable(reason) if reason.contains("could not be measured")),
                "unexpected refusal: {error}"
            );
        }

        // A reading published by a worker that predates CPU measurement is old,
        // not malformed: it parses, and it refuses, because nobody ever
        // observed that host's ceiling.
        let current = reading(Some(GIB), Some(GIB)).to_metadata();
        let legacy = serde_json::json!({
            "pressure": {
                "host_id": current["host_id"],
                "observed_at": current["observed_at"],
                "total_memory_bytes": current["total_memory_bytes"],
                "memory_available_bytes": current["memory_available_bytes"],
                "total_disk_bytes": current["total_disk_bytes"],
                "disk_available_bytes": current["disk_available_bytes"],
                "reserves": current["reserves"],
            }
        });
        let parsed = HostPressure::from_metadata(&legacy)
            .expect("a reading without CPU figures still parses");
        assert_eq!(parsed.total_vcpus, None);
        assert!(!parsed.complete());
        assert!(
            parsed.admits(1, 1, 1).is_err(),
            "a ceiling nobody measured is not an unlimited one"
        );
    }

    /// A host that measured honestly admits what fits in it and refuses the
    /// next byte, so a sandbox is stopped before it starts rather than at boot.
    #[test]
    fn a_measured_budget_admits_exactly_what_it_holds() {
        let host = reading(Some(GIB), Some(4 * GIB));
        assert!(
            host.admits(1, GIB, 4 * GIB).is_ok(),
            "the whole budget is spendable"
        );
        assert!(
            host.admits(1, GIB + 1, 4 * GIB).is_err(),
            "one byte past the reading must be refused"
        );
        assert!(
            host.admits(1, GIB, 4 * GIB + 1).is_err(),
            "one byte of disk past the reading must be refused"
        );
        assert!(
            host.admits(HOST_VCPUS, GIB, 4 * GIB).is_ok(),
            "every measured vCPU is spendable"
        );
        assert!(
            host.admits(HOST_VCPUS + 1, GIB, 4 * GIB).is_err(),
            "one vCPU past the ceiling must be refused"
        );
    }

    /// Two workers on one machine read the same kernel and would each spend the
    /// whole reading, which is how a cluster comes to believe in thirty-five
    /// gigabytes on a host with twenty-six. The budget is shared, and the
    /// outstanding reservations are counted against it even though they are
    /// already inside the reading.
    #[test]
    fn a_shared_host_aggregates_its_workers_reservations() {
        let now = Utc::now();
        let pressure = reading(Some(10 * GIB), Some(20 * GIB));
        // Worker A holds 6 GiB, 6 vCPUs it has been promised; worker B holds
        // 2 GiB and 2 vCPUs.
        let observations = [
            HostObservation::new(&pressure, 6, 6 * GIB, 12 * GIB),
            HostObservation::new(&pressure, 2, 2 * GIB, 4 * GIB),
        ];
        let budget = host_admission_budget(
            &observations,
            "host-under-test",
            now,
            ChronoDuration::seconds(15),
        );
        assert!(budget.observed);
        assert_eq!(
            budget.memory_bytes,
            2 * GIB,
            "10 GiB seen, 8 GiB promised away"
        );
        assert_eq!(budget.disk_bytes, 4 * GIB);
        assert_eq!(budget.vcpus, HOST_VCPUS - 8, "16 seen, 8 promised away");
        assert!(budget_admits(&budget, 8, 2 * GIB, 4 * GIB));
        assert!(!budget_admits(&budget, 9, 2 * GIB, 4 * GIB));
        assert!(!budget_admits(&budget, 8, 2 * GIB + 1, 4 * GIB));

        // A third worker on another machine is a different budget entirely.
        let other = HostObservation {
            host_id: "some-other-host".into(),
            ..HostObservation::new(&pressure, 6, 6 * GIB, 12 * GIB)
        };
        let mut mixed = observations.to_vec();
        mixed.push(other);
        assert_eq!(
            host_admission_budget(&mixed, "host-under-test", now, ChronoDuration::seconds(15)),
            budget
        );
    }

    /// A worker that stopped reporting, or that reported without measuring, must
    /// not hold capacity and must not lend the host a reading it does not have.
    #[test]
    fn an_unobserved_or_stale_host_has_no_budget() {
        let now = Utc::now();
        let pressure = reading(Some(GIB), Some(GIB));

        let stale = HostObservation {
            observed_at: now - ChronoDuration::seconds(60),
            ..HostObservation::new(&pressure, 0, 0, 0)
        };
        let stale_budget = host_admission_budget(
            &[stale],
            "host-under-test",
            now,
            ChronoDuration::seconds(15),
        );
        assert!(!stale_budget.observed);
        assert!(!budget_admits(&stale_budget, 1, 1, 1));

        // Measured a moment ago but missing a figure: its reservation still
        // holds, and it still lends no reading.
        let unmeasured = HostObservation {
            memory_available_bytes: None,
            ..HostObservation::new(&pressure, 3, 3 * GIB, 0)
        };
        let unmeasured_budget = host_admission_budget(
            &[unmeasured],
            "host-under-test",
            now,
            ChronoDuration::seconds(15),
        );
        assert!(!unmeasured_budget.observed);
        assert!(!budget_admits(&unmeasured_budget, 1, 1, 1));

        // A host whose CPU ceiling could not be observed lends no CPU at all,
        // however perfectly it measured memory and disk: one missing
        // measurement is a missing measurement.
        let unmeasured_cpu = HostObservation {
            total_vcpus: None,
            available_vcpus: None,
            ..HostObservation::new(&pressure, 3, 3 * GIB, 0)
        };
        let cpu_budget = host_admission_budget(
            &[unmeasured_cpu],
            "host-under-test",
            now,
            ChronoDuration::seconds(15),
        );
        assert!(!cpu_budget.observed);
        assert_eq!(cpu_budget.vcpus, 0);
        assert!(!budget_admits(&cpu_budget, 1, 1, 1));
        assert!(
            !budget_admits(&cpu_budget, 1, GIB, GIB),
            "an unmeasured host has no budget, whatever it did measure"
        );

        // A stale reading that *did* measure its CPU lends nothing either: the
        // host it described is not a host anybody has asked about lately.
        let stale_cpu = HostObservation {
            observed_at: now - ChronoDuration::seconds(60),
            ..HostObservation::new(&pressure, 4, 0, 0)
        };
        assert!(
            !host_admission_budget(
                &[stale_cpu],
                "host-under-test",
                now,
                ChronoDuration::seconds(15),
            )
            .observed
        );

        // A worker whose reading failed must not be able to admit work even
        // when a sibling on the same host can.
        let refused = reading(None, None);
        assert!(refused.admits(1, 1, 1).is_err());
    }

    /// Two workers on one machine each read every vCPU free, and each is right
    /// about its own worker. Together they would promise more than the host
    /// has, so the demand is capped at the measured ceiling rather than at the
    /// sum of the readings - and the ceiling comes back whole, once, when the
    /// reservation that spent it is released.
    #[test]
    fn two_workers_that_each_look_free_cannot_exceed_the_hosts_ceiling() {
        let now = Utc::now();
        let ceiling = 8;
        let pressure = reading_on_cpu(
            Some(ceiling),
            Some(ceiling),
            Some(100 * GIB),
            Some(200 * GIB),
        );
        // Worker A has three vCPUs committed and worker B none, so the host has
        // five left of eight and B is individually sitting on eight free ones.
        let mut observations = vec![
            HostObservation::new(&pressure, 3, 6 * GIB, 12 * GIB),
            HostObservation::new(&pressure, 0, 0, 0),
        ];
        let budget = host_admission_budget(
            &observations,
            "host-under-test",
            now,
            ChronoDuration::seconds(15),
        );
        assert_eq!(budget.vcpus, ceiling - 3);
        assert!(
            budget_admits(&budget, 5, 2 * GIB, 4 * GIB),
            "five vCPUs still fit the machine"
        );

        // A takes all five. B is still free, on its own reading, and the
        // machine is not: the sixth vCPU does not exist.
        observations[0] = HostObservation::new(&pressure, 8, 6 * GIB, 12 * GIB);
        let spent = host_admission_budget(
            &observations,
            "host-under-test",
            now,
            ChronoDuration::seconds(15),
        );
        assert_eq!(
            spent.vcpus, 0,
            "eight committed vCPUs on an eight-vCPU host"
        );
        assert!(
            !budget_admits(&spent, 1, 1, 1),
            "a host at its ceiling admits no more CPU, whatever a sibling sees"
        );

        // Releasing A's five gives them back exactly once: the whole ceiling is
        // spendable again, and not one vCPU more than it.
        observations[0] = HostObservation::new(&pressure, 3, 6 * GIB, 12 * GIB);
        let released = host_admission_budget(
            &observations,
            "host-under-test",
            now,
            ChronoDuration::seconds(15),
        );
        assert_eq!(released.vcpus, ceiling - 3, "the released vCPUs came back");
        assert!(budget_admits(&released, 5, 2 * GIB, 4 * GIB));
        assert!(
            !budget_admits(&released, 6, 2 * GIB, 4 * GIB),
            "the ceiling is still the ceiling"
        );
    }

    /// The ceiling a real host is measured against is the CPUs this process may
    /// use, and what is left of them is what the machine is already running -
    /// never more than the ceiling, and never a reading of a host that could
    /// not be asked.
    #[test]
    fn a_measured_ceiling_never_exceeds_the_process_and_never_invents_a_reading() {
        let (total, available) = measure_cpu();
        let total = total.expect("a Linux host with an affinity mask is measurable");
        assert!(total >= 1, "a host with no usable CPU is still a host");
        let available = available.expect("a Linux host publishes a load average");
        assert!(available <= total, "availability is a share of the ceiling");

        // Rounding a load up means a fraction of a busy CPU costs a whole one,
        // which is the same direction as the memory reserve.
        assert!(load_one_minute().is_some_and(|load| load >= 0.0));
    }

    /// The identity two workers on one machine share, and the one thing they
    /// must not carry: the raw host identifier.
    #[test]
    fn the_host_id_is_a_digest_of_something_stable() {
        let material = "9f2c1d4b7a6e5f3c8d0a1b2c3d4e5f60";
        let first = digest(material);
        assert_eq!(
            first,
            digest(&format!("  {material}\n")),
            "whitespace is not identity"
        );
        assert_eq!(first.len(), 32, "a fixed-width token, not a variable one");
        assert!(!first.contains(material));
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        // Two workers reading the same machine identifier agree, and neither
        // learns the identifier itself.
        let path = std::env::temp_dir().join(format!("aiec-machine-id-{}", uuid::Uuid::now_v7()));
        std::fs::write(&path, format!("  {material}\n")).unwrap();
        let read = read_identity(path.to_str().unwrap()).expect("a real identifier reads");
        assert_eq!(digest(&read), first);
        let _ = std::fs::remove_file(&path);

        // An empty or placeholder identifier names no machine, and hashing one
        // would hand every such host the same confident-looking id.
        for placeholder in ["", "   \n", "none", "Unknown", "not set"] {
            let path =
                std::env::temp_dir().join(format!("aiec-machine-id-{}", uuid::Uuid::now_v7()));
            std::fs::write(&path, placeholder).unwrap();
            assert_eq!(
                read_identity(path.to_str().unwrap()),
                None,
                "{placeholder:?} is an identity"
            );
            let _ = std::fs::remove_file(&path);
        }
    }

    /// What reaches the control plane is the reading and nothing else, so a
    /// scheduler can find it by the same key the worker wrote it under.
    #[test]
    fn a_reading_survives_the_metadata_it_is_published_in() {
        let original = reading(Some(GIB), Some(2 * GIB));
        let stored =
            serde_json::json!({ "state_dir": "/var/lib/aiec", "pressure": original.to_metadata() });
        assert_eq!(HostPressure::from_metadata(&stored), Some(original));
        assert_eq!(
            HostPressure::from_metadata(&serde_json::json!({ "state_dir": "/var/lib/aiec" })),
            None,
            "a worker that reports no reading must parse as no reading"
        );
    }
}
