//! Compare the shipping full-copy and automatic reflink paths on a real image.
//! cargo run --release -p aiec-runtime --example rootfs_materialize_bench -- \
//!   <base-rootfs> <scratch-parent> --samples 20 --out <report.json>
//! Scratch images are never booted. Each pair proves inode and write isolation.

use aiec_runtime::rootfs::{self, Method, Strategy};
use serde_json::{Value, json};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileExt, MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
};

const MARKER: &[u8] = b"AIEC-BENCH-MARKER";

struct Options {
    source: PathBuf,
    parent: PathBuf,
    samples: usize,
    timeout: u64,
    label: String,
    output: Option<PathBuf>,
}

fn options() -> Result<Options, String> {
    let mut args = std::env::args().skip(1);
    let usage = "<base-rootfs> <scratch-parent> [--samples N] [--timeout-seconds N] [--label NAME] [--out PATH]";
    let source = args.next().ok_or(usage)?.into();
    let parent = args.next().ok_or(usage)?.into();
    let mut options = Options {
        source,
        parent,
        samples: 20,
        timeout: 120,
        label: "local".into(),
        output: None,
    };
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--samples" => options.samples = value.parse().map_err(|_| "invalid samples")?,
            "--timeout-seconds" => {
                options.timeout = value.parse().map_err(|_| "invalid timeout")?
            }
            "--label" => options.label = value,
            "--out" => options.output = Some(value.into()),
            _ => return Err(format!("unknown option {flag}; {usage}")),
        }
    }
    if !(1..=100).contains(&options.samples) || !(1..=600).contains(&options.timeout) {
        return Err("samples must be 1..=100; timeout-seconds must be 1..=600".into());
    }
    Ok(options)
}

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn identity(path: &Path) -> io::Result<(u64, u64)> {
    let metadata = fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn source_state(path: &Path) -> io::Result<Value> {
    let metadata = fs::metadata(path)?;
    Ok(json!({
        "device": metadata.dev(), "inode": metadata.ino(), "bytes": metadata.len(),
        "allocated_bytes": metadata.blocks() * 512, "mode": metadata.mode(),
        "mtime": [metadata.mtime(), metadata.mtime_nsec()],
        "ctime": [metadata.ctime(), metadata.ctime_nsec()],
    }))
}

fn window(path: &Path, offset: u64) -> io::Result<[u8; 64]> {
    let mut bytes = [0; 64];
    File::open(path)?.read_exact_at(&mut bytes, offset)?;
    Ok(bytes)
}

fn filesystem(path: &Path) -> io::Result<Value> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    let mut value = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // The C path is NUL-terminated; statfs initializes the struct on success.
    if unsafe { libc::statfs(path.as_ptr(), value.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let value = unsafe { value.assume_init() };
    Ok(
        json!({ "type": format!("0x{:x}", value.f_type), "block_bytes": value.f_bsize,
        "available_bytes": value.f_bavail.saturating_mul(value.f_bsize as u64) }),
    )
}

#[derive(Default)]
struct Arm {
    durations: Vec<f64>,
    copies: usize,
    reflinks: usize,
    image_bytes_written: u64,
    samples: Vec<Value>,
}

async fn measure_pair(
    options: &Options,
    source: &Path,
    scratch: &Path,
    strategy: Strategy,
    arm: &mut Arm,
    iteration: usize,
    probe: (u64, &[u8; 64]),
) -> Result<(), Box<dyn std::error::Error>> {
    let (offset, expected) = probe;
    let available_before = filesystem(scratch)?;
    let a = scratch.join("a.ext4");
    let b = scratch.join("b.ext4");
    let mut timings = Vec::with_capacity(2);
    let mut methods = Vec::with_capacity(2);
    for destination in [&a, &b] {
        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(options.timeout),
            rootfs::materialize_with_strategy(source, destination, strategy),
        )
        .await??;
        let elapsed = started.elapsed().as_secs_f64() * 1000.0;
        timings.push(elapsed);
        arm.durations.push(elapsed);
        methods.push(result.method.to_string());
        match result.method {
            Method::Copy => {
                arm.copies += 1;
                arm.image_bytes_written += result.bytes;
            }
            Method::Reflink => arm.reflinks += 1,
        }
    }
    let ids = [identity(source)?, identity(&a)?, identity(&b)?];
    let distinct = ids[0] != ids[1] && ids[0] != ids[2] && ids[1] != ids[2];
    if !distinct || window(&a, offset)? != *expected || window(&b, offset)? != *expected {
        return Err("materialization did not produce two independent copies of the base".into());
    }
    let before = [
        fs::metadata(&a)?.blocks() * 512,
        fs::metadata(&b)?.blocks() * 512,
    ];
    let file = OpenOptions::new().write(true).open(&a)?;
    file.write_all_at(MARKER, offset)?;
    file.sync_data()?;
    let written = window(&a, offset)?;
    let isolated = written.starts_with(MARKER)
        && window(&b, offset)? == *expected
        && window(source, offset)? == *expected;
    arm.samples.push(json!({ "iteration": iteration, "materialization_ms": timings,
        "methods": methods, "allocated_before_write": before,
        "scratch_space_before": available_before, "scratch_space_after_write": filesystem(scratch)?,
        "allocated_after_write": [fs::metadata(&a)?.blocks() * 512, fs::metadata(&b)?.blocks() * 512],
        "distinct_inodes": distinct, "write_isolated": isolated }));
    if !isolated {
        return Err("a guest write reached the sibling or immutable base".into());
    }
    drop(file);
    fs::remove_file(a)?;
    fs::remove_file(b)?;
    Ok(())
}

fn statistics(values: &[f64]) -> Value {
    if values.is_empty() {
        return json!({"count": 0});
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    let median = if sorted.len().is_multiple_of(2) {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    };
    let mut result = json!({ "count": sorted.len(), "median_ms": median,
        "min_ms": sorted[0], "max_ms": sorted[sorted.len() - 1],
        "mean_ms": sorted.iter().sum::<f64>() / sorted.len() as f64 });
    if sorted.len() >= 20 {
        for (name, percentile) in [("p50_ms", 0.5), ("p95_ms", 0.95), ("p99_ms", 0.99)] {
            result[name] = json!(sorted[(percentile * sorted.len() as f64).ceil() as usize - 1]);
        }
    } else {
        result["percentiles_withheld"] = json!("fewer than 20 materializations");
    }
    result
}

fn arm_report(arm: &Arm) -> Value {
    json!({ "statistics": statistics(&arm.durations), "copies": arm.copies,
        "reflinks": arm.reflinks, "image_bytes_written": arm.image_bytes_written,
        "samples": arm.samples })
}

async fn run(options: &Options) -> Result<Value, Box<dyn std::error::Error>> {
    let source = fs::canonicalize(&options.source)?;
    let parent = fs::canonicalize(&options.parent)?;
    let metadata = fs::metadata(&source)?;
    if !metadata.is_file() || metadata.len() < 2 * 1024 * 1024 || !parent.is_dir() {
        return Err("need a regular image >=2MiB and an existing scratch directory".into());
    }
    let offset = metadata.len() / 2 / 4096 * 4096;
    let expected = window(&source, offset)?;
    if expected.starts_with(MARKER) {
        return Err("base already contains the benchmark marker".into());
    }
    let before = source_state(&source)?;
    let source_fs = filesystem(&source)?;
    let scratch_fs = filesystem(&parent)?;
    let scratch = Scratch(parent.join(format!("aiec-rootfs-bench-{}", uuid::Uuid::now_v7())));
    fs::create_dir(&scratch.0)?;
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o700))?;
    let mut forced = Arm::default();
    let mut auto = Arm::default();
    let mut failure = None;
    for iteration in 0..options.samples {
        // Both arms see the same host. Reverse the order every iteration to
        // avoid consistently giving one arm the warmer page cache.
        let strategies = if iteration.is_multiple_of(2) {
            [Strategy::Copy, Strategy::Auto]
        } else {
            [Strategy::Auto, Strategy::Copy]
        };
        for strategy in strategies {
            let arm = match strategy {
                Strategy::Copy => &mut forced,
                Strategy::Auto => &mut auto,
            };
            if let Err(error) = measure_pair(
                options,
                &source,
                &scratch.0,
                strategy,
                arm,
                iteration,
                (offset, &expected),
            )
            .await
            {
                failure = Some(error.to_string());
                break;
            }
        }
        if failure.is_some() {
            break;
        }
    }
    let after = source_state(&source)?;
    let unchanged = before == after && window(&source, offset)? == expected;
    let cleanup_error = fs::remove_dir_all(&scratch.0)
        .err()
        .map(|error| error.to_string());
    let removed = !scratch.0.exists();
    let verified = failure.is_none() && unchanged && removed && cleanup_error.is_none();
    let speedup = if verified && auto.copies == 0 && auto.reflinks > 0 {
        Some(
            statistics(&forced.durations)["median_ms"]
                .as_f64()
                .unwrap_or(0.0)
                / statistics(&auto.durations)["median_ms"]
                    .as_f64()
                    .unwrap_or(f64::INFINITY),
        )
    } else {
        None
    };
    Ok(
        json!({ "label": options.label, "verified": verified, "failure": failure,
            "source": source, "source_before": before, "source_after": after,
            "source_unchanged": unchanged, "source_filesystem": source_fs,
            "scratch_filesystem": scratch_fs, "scratch_removed": removed, "cleanup_error": cleanup_error,
            "iterations_per_arm": options.samples, "marker_offset": offset,
            "kernel": fs::read_to_string("/proc/sys/kernel/osrelease").ok().map(|v| v.trim().to_owned()),
            "architecture": std::env::consts::ARCH,
            "cache_conditions": "page cache not dropped; arm order alternates; raw samples retained",
            "forced_copy": arm_report(&forced), "auto": arm_report(&auto),
            "median_speedup": speedup,
            "speedup_withheld": if speedup.is_none() { Some("auto used full-copy fallback, or verification failed; no reflink speedup claimed") } else { None },
        }),
    )
}

fn main() -> ExitCode {
    let result = (|| -> Result<(Options, Value), Box<dyn std::error::Error>> {
        let options = options().map_err(io::Error::other)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let report = runtime.block_on(run(&options))?;
        drop(runtime); // Join cancelled blocking copies before reporting cleanup.
        Ok((options, report))
    })();
    match result {
        Ok((options, report)) => {
            let output = serde_json::to_string_pretty(&report).expect("JSON values serialize");
            if let Some(path) = options.output
                && let Err(error) = fs::write(path, &output)
            {
                eprintln!("writing report failed: {error}");
                return ExitCode::FAILURE;
            }
            println!("{output}");
            if let Some(reason) = report["speedup_withheld"].as_str() {
                eprintln!("{reason}");
            }
            if report["verified"] == true {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("rootfs benchmark failed: {error}");
            ExitCode::FAILURE
        }
    }
}
