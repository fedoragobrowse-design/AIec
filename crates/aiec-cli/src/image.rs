//! `aiec image`: issuing and checking the signed manifest a deployment boots
//! against.
//!
//! The runtime enforces image trust with a gate that verifies a signed
//! manifest against the bytes it is about to boot, but nothing on the operator
//! side produced one. An operator could enforce `required` and have no way to
//! satisfy it that the product itself had written. These subcommands close that
//! gap with the same `TrustedImageManifest::sign` and `ImageTrustGate::admit`
//! the runtime uses, so a manifest produced here is one the runtime accepts by
//! construction rather than by a reimplementation of its encoding.
use aiec_core::image_trust::{
    ImageTrustGate, ImageTrustRequirement, TRUSTED_IMAGE_FILE, TrustedImageManifest,
};
use aiec_runtime::control_identity::file_digest;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Args, Subcommand};
use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

/// Writes with owner-only permissions from the first byte.
///
/// The manifest names a key and its validity, and the key file holds the secret
/// behind that signature. A file created with the process umask would be
/// readable by every local account for as long as it exists, and the manifest
/// is what a stolen key turns into a bootable image.
fn write_owner_only(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    Ok(())
}

#[derive(Subcommand)]
pub enum ImageCommand {
    /// Signs the manifest a worker checks before booting these bytes.
    Sign(SignArgs),
    /// Checks a signed manifest against the images on this machine.
    Verify(VerifyArgs),
}

#[derive(Args)]
pub struct SignArgs {
    /// Where the signed manifest is written. Defaults to the rootfs's directory,
    /// which is where the runtime looks for it.
    #[arg(long)]
    pub out_dir: Option<PathBuf>,
    /// The operator key id. The same id must be in the worker's trust store.
    #[arg(long, default_value = "default")]
    pub key_id: String,
    /// The signing key. Hex or raw bytes, at least 32.
    #[arg(long)]
    pub key_file: PathBuf,
    /// Also writes the worker's `key_id=hex` trust-store entry here.
    #[arg(long)]
    pub keys_out: Option<PathBuf>,
    /// The image reference this manifest is about.
    #[arg(long, default_value = "aiec/firecracker")]
    pub reference: String,
    #[arg(long)]
    pub kernel: PathBuf,
    #[arg(long)]
    pub rootfs: PathBuf,
    /// Hours from now until the manifest expires. A manifest with no expiry
    /// stays acceptable to the gate forever, which is a signing decision, not
    /// a default this command should make on the operator's behalf.
    #[arg(long)]
    pub expires_in_hours: Option<i64>,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// The directory holding `image-trust.json`.
    #[arg(long)]
    pub artifact_dir: PathBuf,
    /// The worker's `key_id=hex` trust store.
    #[arg(long)]
    pub keys_file: PathBuf,
    #[arg(long)]
    pub kernel: PathBuf,
    #[arg(long)]
    pub rootfs: PathBuf,
}

/// Reads a signing key: hex if it decodes, otherwise the file's own bytes.
/// A raw 32-byte key file is not rare, and refusing it would push operators
/// toward a weaker key to keep the tool usable.
fn read_key(path: &Path) -> Result<Vec<u8>> {
    let contents = std::fs::read(path)
        .with_context(|| format!("reading the signing key {}", path.display()))?;
    let text = String::from_utf8(contents.clone()).ok();
    match text.as_deref().map(str::trim) {
        Some(value) if !value.is_empty() && value.len() % 2 == 0 => {
            if let Ok(secret) = hex::decode(value) {
                return Ok(secret);
            }
            Ok(contents)
        }
        _ => Ok(contents),
    }
}

/// The runtime's own trust-store parser, so this tool accepts exactly the file
/// format a worker reads.
fn read_trust_store(path: &Path) -> Result<ImageTrustGate> {
    let mut gate = ImageTrustGate::new(ImageTrustRequirement::REQUIRED);
    let document = std::fs::read_to_string(path)
        .with_context(|| format!("reading the trust store {}", path.display()))?;
    for (number, line) in document.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key_id, secret) = line
            .split_once('=')
            .with_context(|| format!("{} line {} is not key_id=hex", path.display(), number + 1))?;
        let secret = hex::decode(secret.trim()).with_context(|| {
            format!("{} line {} is not hexadecimal", path.display(), number + 1)
        })?;
        gate.insert_key(key_id.trim(), &secret)
            .with_context(|| format!("{} line {}", path.display(), number + 1))?;
    }
    Ok(gate)
}

pub async fn image_command(command: ImageCommand) -> Result<()> {
    match command {
        ImageCommand::Sign(args) => sign(args),
        ImageCommand::Verify(args) => verify(args),
    }
}

fn sign(args: SignArgs) -> Result<()> {
    let secret = read_key(&args.key_file)?;
    let kernel_sha256 =
        file_digest(&args.kernel).with_context(|| format!("hashing {}", args.kernel.display()))?;
    let rootfs_sha256 =
        file_digest(&args.rootfs).with_context(|| format!("hashing {}", args.rootfs.display()))?;
    let now: DateTime<Utc> = Utc::now();
    // No expiry is a signing decision, not a default: a manifest without one
    // stays acceptable to the gate forever, so it is asked for explicitly, and
    // a window in the past is refused rather than signed already-expired.
    let expires_at = match args.expires_in_hours {
        None => None,
        Some(hours) if hours <= 0 => {
            anyhow::bail!(
                "--expires-in-hours must be positive; omit the flag to sign a manifest with no expiry"
            )
        }
        Some(hours) => {
            Some(now + chrono::TimeDelta::try_hours(hours).context("expiry is out of range")?)
        }
    };
    let manifest = TrustedImageManifest::sign(
        &args.key_id,
        &secret,
        &args.reference,
        &kernel_sha256,
        &rootfs_sha256,
        now,
        expires_at,
    )?;
    let out_dir = args
        .out_dir
        .clone()
        .unwrap_or_else(|| args.rootfs.parent().unwrap_or(Path::new(".")).to_path_buf());
    std::fs::create_dir_all(&out_dir)?;
    let manifest_path = out_dir.join(TRUSTED_IMAGE_FILE);
    write_owner_only(&manifest_path, &serde_json::to_vec_pretty(&manifest)?)?;

    if let Some(keys_out) = args.keys_out.as_ref() {
        write_owner_only(
            keys_out,
            format!("{}={}\n", args.key_id, hex::encode(&secret)).as_bytes(),
        )?;
    }

    // Sign and stop would leave the operator holding a manifest nobody has ever
    // checked. Admitting it through the gate here proves the encoding, the key
    // and the digests agree before the manifest reaches a worker.
    let mut gate = ImageTrustGate::new(ImageTrustRequirement::REQUIRED);
    gate.insert_key(&args.key_id, &secret)?;
    let verified = gate.admit(Some(&manifest), &kernel_sha256, &rootfs_sha256, now)?;
    println!(
        "{} admits {} at kernel {kernel_sha256} rootfs {rootfs_sha256} (key {}, valid until {})",
        manifest_path.display(),
        verified.reference(),
        verified.key_id(),
        manifest
            .expires_at
            .map(|at| at.to_rfc3339())
            .unwrap_or_else(|| "never".to_string()),
    );
    Ok(())
}

fn verify(args: VerifyArgs) -> Result<()> {
    let gate = read_trust_store(&args.keys_file)?;
    let manifest_path = args.artifact_dir.join(TRUSTED_IMAGE_FILE);
    let manifest: Option<TrustedImageManifest> = std::fs::read(&manifest_path)
        .ok()
        .map(|bytes| serde_json::from_slice(&bytes))
        .transpose()
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let kernel_sha256 =
        file_digest(&args.kernel).with_context(|| format!("hashing {}", args.kernel.display()))?;
    let rootfs_sha256 =
        file_digest(&args.rootfs).with_context(|| format!("hashing {}", args.rootfs.display()))?;
    let verified = gate.admit(
        manifest.as_ref(),
        &kernel_sha256,
        &rootfs_sha256,
        Utc::now(),
    )?;
    println!(
        "verified: {} at kernel {kernel_sha256} rootfs {rootfs_sha256} (key {})",
        verified.reference(),
        verified.key_id(),
    );
    Ok(())
}
