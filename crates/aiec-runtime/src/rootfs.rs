//! Per-sandbox disk image materialization for the Firecracker runtime.
//!
//! Every sandbox needs its own writable disk image derived from an immutable
//! base image. The cheap correct way to produce one is a copy-on-write clone
//! (`FICLONE`): the filesystem shares the base's extents and only copies the
//! blocks the guest actually writes, so the base and every sibling sandbox are
//! untouched by construction.
//!
//! Reflink support is a property of the kernel and the filesystem, not an
//! assumption this crate may make, so the capability is probed for every
//! materialization and an ordinary copy is used when the kernel reports the
//! clone unsupported. A hard link is never used: it would hand the guest a
//! second writer on the base image, and `resize2fs`/guest writes would corrupt
//! the image every other sandbox starts from.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

/// How a sandbox disk image was produced from the base image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// Copy-on-write clone (`FICLONE`) of the base image.
    Reflink,
    /// Full byte copy, used when the kernel or filesystem cannot clone.
    Copy,
}

/// Size of the buffer the full-copy fallback streams through.
///
/// The fallback exists precisely for filesystems that cannot clone, so its cost
/// is a real read and write of the whole image. Copying in bounded chunks keeps
/// memory flat regardless of image size, and the chunk boundary is also where
/// cancellation is observed: an abandoned copy stops within one chunk instead of
/// running to the end of the image.
const COPY_CHUNK: usize = 4 * 1024 * 1024;

impl fmt::Display for Method {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Reflink => "reflink",
            Self::Copy => "copy",
        })
    }
}

/// How a materialization is allowed to produce its image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    /// Ask the filesystem for a copy-on-write clone and fall back to a full
    /// copy when it cannot clone. This is what every runtime create uses.
    Auto,
    /// Never attempt a clone, and always stream a full copy.
    ///
    /// This is the cost a create pays on a filesystem without reflink support,
    /// asked for on purpose. It exists so the fallback can be measured instead
    /// of assumed: the forced copy is the same path an unsupported filesystem
    /// takes, not a second implementation of it that could drift from the first.
    Copy,
}

/// The result of materializing one sandbox disk image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Materialized {
    /// Size of the materialized image, in bytes.
    pub bytes: u64,
    /// Whether the image was a copy-on-write clone or a full copy.
    pub method: Method,
}

/// Signature of the clone attempt, so the clone branch and the fallback can be
/// exercised deterministically on any host filesystem.
type Reflink = fn(&File, &File) -> io::Result<()>;

/// A cooperative cancellation flag shared with a blocking materialization.
///
/// A blocking thread cannot be killed and this does not try: the copy is writing
/// a file the guest has not been given yet, so what matters is that it stops
/// soon and that what it created is removed. The flag is the ownership of that
/// decision - the caller holds one, the materialization holds a clone, and a
/// caller that goes away requests cancellation.
#[derive(Clone, Debug, Default)]
pub struct Cancel {
    cancelled: Arc<AtomicBool>,
}

impl Cancel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks the materialization to stop at its next check.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Whether a materialization has been asked to stop.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// The error a cancelled materialization reports.
fn cancelled() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "rootfs materialization was cancelled before the image was complete",
    )
}

/// Materializes an independent writable disk image at `destination`.
///
/// The work runs on the blocking pool, so awaiting this future never occupies a
/// runtime worker thread. Dropping it requests cancellation: a caller that times
/// out, or abandons the create for any other reason, must not leave a copy still
/// running against a destination its own cleanup has already removed. The
/// blocking thread is not interrupted mid-`write`; it observes the flag between
/// chunks and removes the destination it created.
pub struct Materialization {
    cancel: Cancel,
    task: tokio::task::JoinHandle<io::Result<Materialized>>,
}

impl Future for Materialization {
    type Output = io::Result<Materialized>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.get_mut().task).poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(format!(
                "rootfs materialization task failed: {error}"
            )))),
        }
    }
}

impl Drop for Materialization {
    fn drop(&mut self) {
        // A finished task either produced the image or already removed it, so
        // there is nothing left to cancel.
        if self.task.is_finished() {
            return;
        }
        tracing::debug!(
            stage = "rootfs_copy_cancelled",
            "rootfs materialization abandoned by its caller"
        );
        self.cancel.cancel();
    }
}

/// Starts materializing a sandbox disk image without blocking a runtime worker.
///
/// `destination` must not exist. An existing path is reported as an error rather
/// than truncated, so a stale or foreign image is never destroyed and never
/// silently reused as this sandbox's disk.
pub fn materialize(source: &Path, destination: &Path) -> Materialization {
    materialize_with_strategy(source, destination, Strategy::Auto)
}

/// Starts materializing a sandbox disk image under an explicit [`Strategy`].
///
/// [`Strategy::Auto`] is [`materialize`] unchanged. [`Strategy::Copy`] makes the
/// same clone attempt a filesystem without reflink support makes, so the
/// destination is still truncated, filled through the same bounded-chunk copy,
/// cancelled the same way, and still reported as [`Method::Copy`].
pub fn materialize_with_strategy(
    source: &Path,
    destination: &Path,
    strategy: Strategy,
) -> Materialization {
    let (source, destination) = (source.to_path_buf(), destination.to_path_buf());
    let cancel = Cancel::new();
    let task = tokio::task::spawn_blocking({
        let cancel = cancel.clone();
        move || match strategy {
            Strategy::Auto => materialize_blocking(&source, &destination, &cancel),
            Strategy::Copy => materialize_with_cancel(&source, &destination, uncloneable, &cancel),
        }
    });
    Materialization { cancel, task }
}

/// The kernel's answer on a filesystem that cannot clone.
fn uncloneable(_base: &File, _image: &File) -> io::Result<()> {
    Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
}

/// Materializes a disk image on the calling thread.
fn materialize_blocking(
    source: &Path,
    destination: &Path,
    cancel: &Cancel,
) -> io::Result<Materialized> {
    materialize_with_cancel(source, destination, reflink, cancel)
}

/// Materializes with an injected clone strategy and nothing to cancel, so the
/// clone and fallback paths can be exercised on any host filesystem.
#[cfg(test)]
fn materialize_with(
    source: &Path,
    destination: &Path,
    reflink: Reflink,
) -> io::Result<Materialized> {
    materialize_with_cancel(source, destination, reflink, &Cancel::new())
}

/// Materializes a disk image, stopping early when `cancel` is requested.
///
/// Every exit that is not a complete image the caller is still waiting for
/// removes the destination, the cancelled ones included. A short image that
/// survived would be booted by the next create for the same sandbox, and the
/// exclusive create would report `AlreadyExists` for a file that is not a disk;
/// a complete one nobody is waiting for is just as useless, and the caller's
/// own cleanup is about to remove its directory anyway.
fn materialize_with_cancel(
    source: &Path,
    destination: &Path,
    reflink: Reflink,
    cancel: &Cancel,
) -> io::Result<Materialized> {
    let mut base = File::open(source).map_err(|error| at(source, "base image", error))?;
    // `create_new` is the safety property: the destination either does not
    // exist or this fails. `File::create` would truncate a path that another
    // sandbox or a half-finished run still owns.
    let mut image = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| at(destination, "sandbox image", error))?;
    match produce(&mut base, &mut image, reflink, cancel) {
        // The copy can finish between the caller's last chunk boundary and its
        // decision to give up. An image that arrives after the caller walked
        // away is an abandoned one.
        Ok(_) if cancel.is_cancelled() => {
            discard(destination);
            Err(cancelled())
        }
        Ok(materialized) => match inherit_permissions(&image, &base) {
            Ok(()) => Ok(materialized),
            Err(error) => {
                discard(destination);
                Err(error)
            }
        },
        Err(error) => {
            discard(destination);
            Err(error)
        }
    }
}

/// Names the path an operation failed on while keeping the error kind, so a
/// stale sandbox image is reported as something an operator can act on rather
/// than a bare `File exists`.
fn at(path: &Path, what: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{what} {}: {error}", path.display()))
}

/// Fills `image` from `base`, reporting which strategy produced it.
fn produce(
    base: &mut File,
    image: &mut File,
    reflink: Reflink,
    cancel: &Cancel,
) -> io::Result<Materialized> {
    if cancel.is_cancelled() {
        return Err(cancelled());
    }
    match reflink(base, image) {
        Ok(()) => Ok(Materialized {
            bytes: base.metadata()?.len(),
            method: Method::Reflink,
        }),
        // A capability answer, not a failure: fall back to an ordinary copy.
        Err(error) if is_unsupported(&error) => {
            // A rejected clone can leave the destination holding shared extents.
            // Truncating drops them; the base keeps its own references.
            image.set_len(0)?;
            let written = copy_in_chunks(base, image, cancel)?;
            Ok(Materialized {
                bytes: written,
                method: Method::Copy,
            })
        }
        Err(error) => Err(error),
    }
}

/// Copies `base` into `image` through one bounded buffer.
///
/// `io::copy` performs the same I/O, but a buffer that is negotiated inside it is
/// not a place cancellation can be observed, and an image-sized allocation is
/// exactly what a worker that also runs the guest cannot afford. The base is only
/// ever read.
fn copy_in_chunks(base: &mut File, image: &mut File, cancel: &Cancel) -> io::Result<u64> {
    let mut buffer = vec![0u8; COPY_CHUNK];
    let mut written = 0u64;
    loop {
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        let read = base.read(&mut buffer)?;
        if read == 0 {
            return Ok(written);
        }
        image.write_all(&buffer[..read])?;
        written += read as u64;
    }
}

/// Asks the filesystem to clone `base` onto `image` copy-on-write.
///
/// The error is returned raw; [`produce`] decides whether it means "this
/// filesystem cannot clone" or "the materialization failed".
#[cfg(target_os = "linux")]
fn reflink(base: &File, image: &File) -> io::Result<()> {
    // `FICLONE` takes the source descriptor as the ioctl argument and clones
    // the whole file, leaving the destination a separate inode.
    let cloned = unsafe { libc::ioctl(image.as_raw_fd(), libc::FICLONE, base.as_raw_fd()) };
    if cloned == 0 {
        return Ok(());
    }
    Err(io::Error::last_os_error())
}

#[cfg(not(target_os = "linux"))]
fn reflink(_base: &File, _image: &File) -> io::Result<()> {
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}

/// Errors the kernel and filesystems use to say "cloning is not possible here".
///
/// This is the same set `cp --reflink=always` treats as unsupported: the ioctl
/// is not implemented, the filesystem has no clone support, the two files live
/// on different filesystems, or the arguments are not clonable. Anything else
/// (`ENOSPC`, `EIO`, `EACCES`, …) is a real failure.
fn is_unsupported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::ENOTTY
                | libc::EOPNOTSUPP
                | libc::ENOSYS
                | libc::EXDEV
                | libc::EINVAL
                | libc::ETXTBSY
        )
    )
}

/// Gives the materialized image the permissions it needs to be a usable disk.
///
/// The guest image is read by the runtime process and rewritten locally when
/// the sandbox asks for a different disk size, so the owner must keep read and
/// write even when the published base is read-only. Only the permission bits
/// move: ownership, timestamps and extended attributes of the base say nothing
/// about a per-sandbox scratch disk.
fn inherit_permissions(image: &File, base: &File) -> io::Result<()> {
    let mut mode = base.metadata()?.permissions().mode() & 0o7777;
    mode |= 0o600;
    image.set_permissions(std::fs::Permissions::from_mode(mode))
}

/// Removes a destination this call created but could not fill, or could not
/// finish preparing.
///
/// Best effort: a leftover partial image would make the next attempt for the
/// same path fail with `AlreadyExists` rather than retrying cleanly, and a
/// multi-gigabyte image left on a worker for a create that already failed is
/// disk nobody is going to boot. Visible to the caller because once
/// materialization has returned `Ok` the cleanup responsibility is the caller's:
/// everything after that point in a create can still fail.
pub(crate) fn discard(destination: &Path) {
    let _ = std::fs::remove_file(destination);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::FileExt;
    use std::path::PathBuf;
    use std::sync::PoisonError;
    use uuid::Uuid;

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("af-rootfs-{label}-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        dir
    }

    /// Materializes on the calling thread the way the runtime's own blocking
    /// path does, with a cancellation flag nobody requests.
    fn blocking(source: &Path, destination: &Path) -> io::Result<Materialized> {
        materialize_blocking(source, destination, &Cancel::new())
    }

    /// A clone attempt that fails the way ext4 and tmpfs fail: the ioctl is
    /// answered with "not supported", so the fallback must run on any host.
    fn not_supported(_base: &File, _image: &File) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }

    /// The kernel's answer when the two files live on different filesystems.
    fn cross_device(_base: &File, _image: &File) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::EXDEV))
    }

    /// A real I/O failure that must never be reported as "cannot clone".
    fn out_of_space(_base: &File, _image: &File) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSPC))
    }

    /// A clone that succeeds the way a copy-on-write clone does: the
    /// destination becomes an independent file holding the base's content.
    fn cloned(base: &File, image: &File) -> io::Result<()> {
        let mut image = image.try_clone()?;
        image.set_len(0)?;
        io::copy(&mut { base }, &mut image)?;
        Ok(())
    }

    fn write_base(dir: &Path, contents: &[u8]) -> PathBuf {
        let path = dir.join("rootfs.ext4");
        std::fs::write(&path, contents).expect("base image");
        path
    }

    #[test]
    fn one_sandbox_writes_are_invisible_to_its_sibling_and_to_the_base() {
        let dir = scratch("isolation");
        let base = write_base(&dir, b"immutable base image");
        let first = dir.join("a.rootfs.ext4");
        let second = dir.join("b.rootfs.ext4");
        let original = b"immutable base image".to_vec();
        // What the guest's write produces: the first nine bytes replaced,
        // everything behind them untouched.
        let mut written = original.clone();
        written[..9].copy_from_slice(b"SANDBOX A");

        materialize_with(&base, &first, not_supported).expect("first sandbox image");
        materialize_with(&base, &second, not_supported).expect("second sandbox image");

        // A guest writing to its own disk.
        let handle = OpenOptions::new()
            .write(true)
            .open(&first)
            .expect("sandbox image");
        handle.write_at(b"SANDBOX A", 0).expect("guest write");
        drop(handle);

        assert_eq!(std::fs::read(&first).expect("first"), written);
        assert_eq!(std::fs::read(&second).expect("second"), original.as_slice());
        assert_eq!(std::fs::read(&base).expect("base"), original.as_slice());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_native_materialization_path_keeps_the_same_isolation() {
        let dir = scratch("native-isolation");
        let base = write_base(&dir, b"immutable base image");
        let first = dir.join("a.rootfs.ext4");
        let second = dir.join("b.rootfs.ext4");
        let original = b"immutable base image".to_vec();

        let one = blocking(&base, &first).expect("first sandbox image");
        let two = blocking(&base, &second).expect("second sandbox image");
        assert_eq!(one.bytes, original.len() as u64);
        assert_eq!(two.bytes, original.len() as u64);
        // Whatever the host filesystem supports, the two sandboxes and the
        // base must be three separate inodes: a hard link would alias them.
        let inodes = [&base, &first, &second].map(|path| {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(path).expect("metadata").ino()
        });
        assert!(inodes[0] != inodes[1] && inodes[0] != inodes[2] && inodes[1] != inodes[2]);

        // A guest writing to its own disk. What the write produces: the first
        // nine bytes replaced, everything behind them untouched.
        let mut written = original.clone();
        written[..9].copy_from_slice(b"SANDBOX A");

        let handle = OpenOptions::new()
            .write(true)
            .open(&first)
            .expect("sandbox image");
        handle.write_at(b"SANDBOX A", 0).expect("guest write");
        drop(handle);

        assert_eq!(std::fs::read(&first).expect("first"), written);
        assert_eq!(std::fs::read(&second).expect("second"), original.as_slice());
        assert_eq!(std::fs::read(&base).expect("base"), original.as_slice());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unsupported_clone_falls_back_to_a_full_copy() {
        let dir = scratch("fallback");
        let base = write_base(&dir, vec![0x5a; 512 * 1024].as_slice());
        let image = dir.join("sandbox.rootfs.ext4");
        let original = std::fs::read(&base).expect("base");

        let materialized =
            materialize_with(&base, &image, not_supported).expect("fallback must still succeed");

        assert_eq!(materialized.method, Method::Copy);
        assert_eq!(materialized.bytes, original.len() as u64);
        assert_eq!(std::fs::read(&image).expect("image"), original);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_successful_clone_reports_a_reflink_and_writes_no_fallback_bytes() {
        let dir = scratch("reflink");
        let base = write_base(&dir, b"immutable base image");
        let image = dir.join("sandbox.rootfs.ext4");

        let materialized = materialize_with(&base, &image, cloned).expect("cloned image");

        assert_eq!(materialized.method, Method::Reflink);
        assert_eq!(materialized.bytes, "immutable base image".len() as u64);
        assert_eq!(
            std::fs::read(&image).expect("image"),
            b"immutable base image"
        );
        assert_eq!(std::fs::read(&base).expect("base"), b"immutable base image");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cross_filesystem_clone_answer_also_falls_back() {
        let dir = scratch("cross-device");
        let base = write_base(&dir, b"immutable base image");
        let image = dir.join("sandbox.rootfs.ext4");

        let materialized = materialize_with(&base, &image, cross_device)
            .expect("a different filesystem is a capability answer, not a failure");

        assert_eq!(materialized.method, Method::Copy);
        assert_eq!(
            std::fs::read(&image).expect("image"),
            b"immutable base image"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_real_io_error_is_reported_rather_than_replaced_by_a_full_copy() {
        let dir = scratch("io-error");
        let base = write_base(&dir, b"immutable base image");
        let image = dir.join("sandbox.rootfs.ext4");

        let error = materialize_with(&base, &image, out_of_space)
            .expect_err("a full disk must not be retried as a full copy");

        assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
        assert!(
            !image.exists(),
            "a failed materialization must not leave an image behind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_existing_destination_is_rejected_and_left_untouched() {
        let dir = scratch("existing");
        let base = write_base(&dir, b"immutable base image");
        let image = dir.join("sandbox.rootfs.ext4");
        std::fs::write(&image, b"another sandbox's disk").expect("foreign image");

        let error = materialize_with(&base, &image, not_supported)
            .expect_err("an existing image must never be truncated and reused");

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&image).expect("foreign image"),
            b"another sandbox's disk"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stale_image_left_by_a_crashed_create_is_reported_with_its_path() {
        let dir = scratch("stale");
        let base = write_base(&dir, b"immutable base image");
        let image = dir.join("sandbox.rootfs.ext4");
        // What a create that died mid-materialization leaves behind: a short
        // file that must not be silently truncated and then booted.
        std::fs::write(&image, b"partial").expect("stale image");

        let error = materialize_with(&base, &image, not_supported)
            .expect_err("a stale image must stop the create, not be reused");

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(
            error.to_string().contains(&image.display().to_string()),
            "the operator must be told which file to remove: {error}"
        );
        assert_eq!(std::fs::read(&image).expect("stale image"), b"partial");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_unsupported_errno_set_is_exactly_the_cp_reflink_always_set() {
        for errno in [
            libc::ENOTTY,
            libc::EOPNOTSUPP,
            libc::ENOSYS,
            libc::EXDEV,
            libc::EINVAL,
            libc::ETXTBSY,
        ] {
            let error = io::Error::from_raw_os_error(errno);
            assert!(
                is_unsupported(&error),
                "errno {errno} must fall back to a copy"
            );
        }
        // Everything else is a real failure. A full disk or a permission
        // problem must surface, not be retried as a copy that hides it.
        for errno in [
            libc::ENOSPC,
            libc::EIO,
            libc::EACCES,
            libc::EPERM,
            libc::EROFS,
        ] {
            let error = io::Error::from_raw_os_error(errno);
            assert!(
                !is_unsupported(&error),
                "errno {errno} must not be disguised as unsupported"
            );
        }
    }

    #[test]
    fn a_read_only_base_still_produces_a_disk_the_runtime_can_resize() {
        let dir = scratch("permissions");
        let base = write_base(&dir, b"immutable base image");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o444))
            .expect("read-only base");
        let image = dir.join("sandbox.rootfs.ext4");

        blocking(&base, &image).expect("materialized image");

        // The grow path in the runtime opens the image for writing.
        OpenOptions::new()
            .write(true)
            .open(&image)
            .expect("the materialized image must be writable for resize2fs");
        let mode = std::fs::metadata(&image)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o600,
            0o600,
            "owner read/write is required: {mode:o}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_base_image_is_reported_and_creates_nothing() {
        let dir = scratch("missing-base");
        let base = dir.join("absent.ext4");
        let image = dir.join("sandbox.rootfs.ext4");

        let error = blocking(&base, &image).expect_err("missing base must fail");

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(!image.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A copy that has been told to stop must not keep filling a destination the
    /// caller has already given up on, and must not leave that destination
    /// behind: the next create for the same sandbox would find it and report a
    /// stale image rather than materializing a disk.
    #[test]
    fn a_cancelled_copy_writes_nothing_and_leaves_no_image() {
        let dir = scratch("cancelled");
        let base = write_base(&dir, vec![0x5a; 3 * COPY_CHUNK].as_slice());
        let image = dir.join("sandbox.rootfs.ext4");
        let cancel = Cancel::new();
        cancel.cancel();

        let error = materialize_with_cancel(&base, &image, not_supported, &cancel)
            .expect_err("a cancelled materialization must not report an image");

        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(
            !image.exists(),
            "an abandoned materialization must not leave a disk behind"
        );
        assert_eq!(
            std::fs::metadata(&base).expect("base").len(),
            3 * COPY_CHUNK as u64,
            "the base image is only ever read"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A cancellation requested while the copy is already running is the case
    /// that matters: the caller has timed out and is deleting the sandbox
    /// directory, so a copy that keeps going is both wasted work and a writer
    /// against a path that no longer describes a sandbox.
    ///
    /// The image is several chunks long, and the cancellation is requested only
    /// once a chunk has actually been written, so the copy is observed between
    /// chunks with work still to do rather than racing to the end.
    #[test]
    fn a_copy_cancelled_midway_stops_and_removes_its_destination() {
        let dir = scratch("cancel-midway");
        let chunks = 16usize;
        let base = write_base(&dir, &vec![0x5a; COPY_CHUNK * chunks]);
        let image = dir.join("sandbox.rootfs.ext4");
        let cancel = Cancel::new();
        let (base_path, image_path, flag) = (base.clone(), image.clone(), cancel.clone());
        let copy = std::thread::spawn(move || {
            materialize_with_cancel(&base_path, &image_path, not_supported, &flag)
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::fs::metadata(&image)
            .map(|meta| meta.len())
            .unwrap_or(0)
            < COPY_CHUNK as u64
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        cancel.cancel();
        let outcome = copy.join().expect("copy thread");

        assert!(
            outcome.is_err(),
            "a copy stopped part way must not report a complete image: {outcome:?}"
        );
        assert!(
            !image.exists(),
            "the destination a cancelled copy created must be removed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A caller that times out owns exactly one lever: it drops the future. The
    /// blocking thread is already detached from that handle, so before this
    /// existed nothing told the copy to stop and it ran to completion against a
    /// destination the timeout path had already cleaned up.
    ///
    /// Whichever side wins the race, the end state is one the next create can
    /// use: a complete image or no image at all, never a short one.
    #[tokio::test]
    async fn dropping_the_materialization_future_stops_the_copy() {
        let dir = scratch("cancel-drop");
        let chunks = 16usize;
        let base = write_base(&dir, &vec![0x5a; COPY_CHUNK * chunks]);
        let image = dir.join("sandbox.rootfs.ext4");
        let cancel = Cancel::new();
        // What the detached task did. The drop throws away the handle, so the
        // task records its own outcome where the test can still read it.
        let observed: Arc<std::sync::Mutex<Option<(bool, u64)>>> =
            Arc::new(std::sync::Mutex::new(None));
        let record = observed.clone();
        let (source, destination, flag) = (base.clone(), image.clone(), cancel.clone());
        let task = tokio::task::spawn_blocking(move || {
            let outcome = materialize_with_cancel(&source, &destination, not_supported, &flag);
            *record.lock().unwrap_or_else(PoisonError::into_inner) = match &outcome {
                Ok(materialized) => Some((true, materialized.bytes)),
                Err(_) => Some((false, 0)),
            };
            outcome
        });
        let materialization = Materialization {
            cancel: cancel.clone(),
            task,
        };

        drop(materialization);
        assert!(
            cancel.is_cancelled(),
            "a dropped materialization must ask its copy to stop"
        );

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while observed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none()
        {
            assert!(
                std::time::Instant::now() < deadline,
                "an abandoned copy must stop, not run to the end of the image"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let (completed, bytes) = observed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .expect("the detached copy recorded its outcome");
        if completed {
            // The copy finished before the drop was observed. What it produced
            // is still a complete, independent image of the whole base.
            assert_eq!(bytes, (COPY_CHUNK * chunks) as u64);
            assert_eq!(std::fs::metadata(&image).expect("image").len(), bytes);
        } else {
            assert!(
                !image.exists(),
                "a copy stopped by a dropped future must not leave a disk behind"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_forced_copy_strategy_copies_where_a_clone_would_have_worked() {
        let dir = scratch("forced-copy");
        let base = write_base(&dir, vec![0x37; 2 * 1024 * 1024].as_slice());
        let original = std::fs::read(&base).expect("base");

        // The auto arm of the same benchmark would clone on a filesystem that
        // can, so only asking for a copy explicitly can say which happened. The
        // other half of that claim - that the clone still isolates writes - is
        // `the_native_materialization_path_keeps_the_same_isolation`.
        let forced = dir.join("forced.rootfs.ext4");
        let materialized = materialize_with_strategy(&base, &forced, Strategy::Copy)
            .await
            .expect("forced copy");
        assert_eq!(materialized.method, Method::Copy);
        assert_eq!(materialized.bytes, original.len() as u64);
        assert_eq!(std::fs::read(&forced).expect("image"), original);

        // The two strategies differ in what they ask the kernel for and in
        // nothing else: a forced copy is a usable disk with the same bytes.
        let auto = dir.join("auto.rootfs.ext4");
        let materialized = materialize_with_strategy(&base, &auto, Strategy::Auto)
            .await
            .expect("auto materialization");
        assert!(matches!(
            materialized.method,
            Method::Reflink | Method::Copy
        ));
        assert_eq!(materialized.bytes, original.len() as u64);
        assert_eq!(std::fs::read(&auto).expect("image"), original);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
