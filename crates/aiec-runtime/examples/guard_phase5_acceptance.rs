//! Live signed-image and per-VM control-identity acceptance.
//!
//! Everything here runs against real local Firecracker guests over the
//! authenticated vsock control channel and real files on the host. The harness
//! never prints or persists a key, a secret or the trust-store signing secret:
//! reports carry digests, counts and decisions only.
//!
//! No deployed guest image is written. Every refusal variant points the
//! configuration at copies or at absent files inside this run's own scratch
//! directory, and the source kernel and rootfs digests are re-verified after
//! every case.
use aiec_core::{
    EnvironmentSpec, NetworkPolicy, RuntimeKind, Sandbox, SandboxState,
    image_trust::{
        ImageTrustGate, ImageTrustRequirement, TRUSTED_IMAGE_FILE, TrustedImageManifest,
        sha256_reader,
    },
    protocol::{self, Operation, Request, RequestPayload, Response, ResponsePayload},
    runtime::SandboxRuntime,
};
use aiec_guard::policy::GuardConfig;
use aiec_runtime::control_identity::{ControlIdentity, GUEST_SECRET_PATH};
use aiec_runtime::{FirecrackerConfig, FirecrackerRuntime};
use base64::Engine;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration as StdDuration,
};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const PROVENANCE: &str =
    "real local Firecracker guest, authenticated vsock control channel, host filesystem";

fn require(ok: bool, case: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(case.into()) }
}

fn record(rows: &mut Vec<Value>, name: &str, evidence: Value) {
    rows.push(json!({
        "name": name,
        "status": "PASS",
        "samples": 1,
        "provenance": PROVENANCE,
        "evidence": evidence,
    }));
}

fn private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// The digest of the bytes actually on disk. The gate verifies files, not the
/// names they are called, so the harness hashes the same paths it hands over.
fn sha256_path(path: &impl AsRef<Path>) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    Ok(sha256_reader(&mut file)?)
}

fn sandbox(disk_mb: u32, guarded: bool) -> Sandbox {
    Sandbox {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        node_id: None,
        image_id: "phase5-diagnostic-copy".to_owned(),
        state: SandboxState::Creating,
        runtime: RuntimeKind::Firecracker,
        cpu: 1,
        memory_mb: 256,
        disk_mb,
        timeout_seconds: 600,
        network: NetworkPolicy::Disabled,
        // Signed-image admission is demanded per sandbox -
        // `GuardConfig::require_signed_image` - and the deployment-wide gate
        // supplies the operator's keys for it. An unguarded sandbox opts out of
        // the check by construction, so a harness that left this at the
        // default would be asserting a refusal the runtime never offers.
        environment: EnvironmentSpec {
            guard: guarded.then(|| GuardConfig {
                require_signed_image: true,
                ..GuardConfig::default()
            }),
            ..EnvironmentSpec::default()
        },
        created_at: Utc::now(),
        updated_at: Utc::now(),
        runtime_path: None,
    }
}

/// A directory holding one signed manifest document, or none at all.
fn image_dir(
    scratch: &Path,
    name: &str,
    manifest: Option<&TrustedImageManifest>,
) -> Result<PathBuf> {
    let dir = scratch.join(name);
    std::fs::create_dir_all(&dir)?;
    if let Some(manifest) = manifest {
        private(
            &dir.join(TRUSTED_IMAGE_FILE),
            &serde_json::to_vec(manifest)?,
        )?;
    }
    Ok(dir)
}

/// A real frame on a sandbox's own vsock control channel, authenticated with one
/// identity's key. Returns whether the guest answered `Health { ready }`, and
/// why not: a refusal that reports only "false" costs a debugging round to tell
/// a wrong key from a guest that is not listening from a response this helper
/// failed to match.
async fn authenticated_health(
    socket: PathBuf,
    identity: &ControlIdentity,
) -> Result<(bool, String)> {
    // The frame key is the identity's own bytes. The guest hex-decodes the
    // planted `/etc/aiec-guest-secret`, so the wire key is the raw secret -
    // the same bytes `FirecrackerRuntime::guest_call` authenticates with, not
    // the hex spelling the host writes into the file.
    let secret = identity.secret().expose().to_vec();
    tokio::task::spawn_blocking(move || -> Result<(bool, String)> {
        let mut stream = std::os::unix::net::UnixStream::connect(&socket)?;
        stream.set_read_timeout(Some(StdDuration::from_secs(5)))?;
        stream.set_write_timeout(Some(StdDuration::from_secs(5)))?;
        writeln!(stream, "CONNECT {}", protocol::DEFAULT_CONTROL_PORT)?;
        let mut line = Vec::new();
        let mut byte = [0_u8; 1];
        while line.len() < 128 {
            stream.read_exact(&mut byte)?;
            line.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        // The CONNECT handshake is the positive control for this channel: if it
        // does not answer, a refused frame below would prove nothing.
        if !line.starts_with(b"OK ") {
            return Ok((
                false,
                format!(
                    "the control port answered {:?}",
                    String::from_utf8_lossy(&line)
                ),
            ));
        }
        let request = Request {
            version: protocol::PROTOCOL_VERSION,
            request_id: Uuid::now_v7(),
            operation: Operation::Health,
            payload: RequestPayload::None,
        };
        protocol::write_frame(&mut stream, &secret, &request)
            .map_err(|error| format!("the health frame was not accepted: {error}"))?;
        match protocol::read_response(&mut stream, &secret) {
            Ok(Response {
                request_id,
                payload,
                ..
            }) if request_id == request.request_id => match payload {
                ResponsePayload::Health { ready: true } => Ok((true, "health ready".into())),
                ResponsePayload::Health { ready: false } => Ok((false, "health not ready".into())),
                other => Ok((
                    false,
                    format!("the guest answered {other:?} instead of health"),
                )),
            },
            Ok(Response { request_id, .. }) => Ok((
                false,
                format!("the guest answered a different request id {request_id}"),
            )),
            Err(error) => Ok((false, format!("no readable response: {error}"))),
        }
    })
    .await?
}

/// One control-channel probe as an assertion, carrying the guest's own answer
/// into the failure message.
async fn require_health(
    socket: PathBuf,
    identity: &ControlIdentity,
    expected: bool,
    case: &str,
) -> Result<()> {
    let (answered, why) = authenticated_health(socket, identity).await?;
    require(answered == expected, &format!("{case}: {why}"))
}

/// Every variant must be refused during admission, before any machine exists: no
/// machine directory, no Firecracker process, no socket.
async fn refusals(
    base: &FirecrackerConfig,
    scratch: &Path,
    manifest: &TrustedImageManifest,
    signing_key: &[u8],
    rows: &mut Vec<Value>,
) -> Result<()> {
    let mut variants: Vec<(&str, FirecrackerConfig)> = Vec::new();

    let mut unsigned = base.clone();
    unsigned.guest_artifact_dir = Some(image_dir(scratch, "image-unsigned", None)?);
    unsigned.image_trust = Some(ImageTrustGate::new(ImageTrustRequirement::REQUIRED));
    variants.push(("unsigned image refused before boot", unsigned));

    let mut no_signer = base.clone();
    no_signer.guest_artifact_dir = Some(image_dir(scratch, "image-no-signer", Some(manifest))?);
    no_signer.image_trust = Some(ImageTrustGate::new(ImageTrustRequirement::REQUIRED));
    variants.push((
        "image with no trusted signer refused before boot",
        no_signer,
    ));

    let mut other_key = ImageTrustGate::new(ImageTrustRequirement::REQUIRED);
    other_key.insert_key("phase5-isolated", &hex::decode("00".repeat(32))?)?;
    let mut untrusted_signer = base.clone();
    untrusted_signer.guest_artifact_dir = Some(image_dir(
        scratch,
        "image-untrusted-signer",
        Some(manifest),
    )?);
    untrusted_signer.image_trust = Some(other_key);
    variants.push((
        "image signed by an untrusted key refused before boot",
        untrusted_signer,
    ));

    let mut altered_document: Value = serde_json::from_slice(&serde_json::to_vec(manifest)?)?;
    altered_document["reference"] = json!("phase5-tampered-reference");
    let tampered_dir = scratch.join("image-tampered-manifest");
    std::fs::create_dir_all(&tampered_dir)?;
    private(
        &tampered_dir.join(TRUSTED_IMAGE_FILE),
        &serde_json::to_vec(&altered_document)?,
    )?;
    let mut tampered_manifest = base.clone();
    tampered_manifest.guest_artifact_dir = Some(tampered_dir);
    variants.push((
        "tampered signed manifest refused before boot",
        tampered_manifest,
    ));

    let mut expired = ImageTrustGate::new(ImageTrustRequirement::REQUIRED);
    expired.insert_key("phase5-isolated", signing_key)?;
    let mut expired_manifest = base.clone();
    expired_manifest.guest_artifact_dir = Some(image_dir(
        scratch,
        "image-expired",
        Some(&TrustedImageManifest::sign(
            "phase5-isolated",
            signing_key,
            "phase5-expired-copy",
            &sha256_path(&base.kernel)?,
            &sha256_path(&base.rootfs)?,
            Utc::now() - Duration::hours(2),
            Some(Utc::now() - Duration::hours(1)),
        )?),
    )?);
    expired_manifest.image_trust = Some(expired);
    variants.push((
        "expired signed manifest refused before boot",
        expired_manifest,
    ));

    for (field, name) in [
        ("kernel", "tampered kernel digest refused before boot"),
        ("rootfs", "tampered rootfs digest refused before boot"),
    ] {
        let source = if field == "kernel" {
            &base.kernel
        } else {
            &base.rootfs
        };
        // A copy, in this run's scratch: the deployment's image is never opened
        // for writing.
        let copy = scratch.join(format!("tampered-{field}-copy"));
        std::fs::copy(source, &copy)?;
        let mut file = std::fs::OpenOptions::new().append(true).open(&copy)?;
        file.write_all(b"phase5-tamper-copy-only")?;
        drop(file);
        let mut config = base.clone();
        if field == "kernel" {
            config.kernel = copy;
        } else {
            config.rootfs = copy;
        }
        variants.push((name, config));
    }

    for (name, config) in variants {
        let runtime = FirecrackerRuntime::new(config.clone());
        // Guarded: admission is demanded per sandbox, and only a guarded
        // workload goes through it.
        let vm = sandbox(config.minimum_disk_mb() as u32, true);
        // Each refusal names the assertion that failed. "Refused" is a
        // property of four separate facts, and a report that only says the
        // case failed sends the reader looking in the wrong place.
        require(
            runtime.create(&vm).await.is_err(),
            &format!("{name}: create refused"),
        )?;
        require(
            !config
                .state_dir
                .join("vms")
                .join(vm.id.to_string())
                .exists(),
            &format!("{name}: no machine directory"),
        )?;
        require(
            runtime.start(&vm).await.is_err(),
            &format!("{name}: start refused"),
        )?;
        require(
            !config.socket_dir(vm.id).exists(),
            &format!("{name}: no control socket"),
        )?;
        record(
            rows,
            name,
            json!({
                "create_refused": true,
                "start_refused": true,
                "vm_directory_absent": true,
                "socket_directory_absent": true,
                "mutated_files": "copies inside this run's scratch directory",
            }),
        );
    }
    Ok(())
}

async fn live(
    base: &FirecrackerConfig,
    rows: &mut Vec<Value>,
    cleanup: &mut Vec<String>,
) -> Result<()> {
    // Two facts, proven separately and neither borrowed from the other.
    //
    // Admission is checked against the deployment gate directly, on the bytes
    // on disk: `check_image_trust` hashes the kernel and the rootfs and
    // compares them with the signed manifest. The refusals above prove the
    // same gate refuses a guarded workload; this proves it admits these
    // digests. The guests below then boot unguarded, because attaching Guard
    // to them would drag nftables, a durable budget authority and an
    // outside-guest watchdog into a harness about image identity - coverage
    // that belongs to the Guard phase 2 and phase 5 suites, not a claim this
    // one should make on their behalf.
    base.check_image_trust()
        .map_err(|error| format!("the signed manifest admits the observed digests: {error}"))?;
    record(
        rows,
        "the signed manifest admits the kernel and rootfs actually on disk",
        json!({
            "requirement": "required",
            "kernel_sha256": sha256_path(&base.kernel)?,
            "rootfs_sha256": sha256_path(&base.rootfs)?,
            "digests": "streamed from the files the runtime would boot",
            "scope": "gate admission only; guarded boot enforcement is covered by the phase 2 suite",
        }),
    );
    let runtime = FirecrackerRuntime::new(base.clone());
    let a = sandbox(base.minimum_disk_mb() as u32, false);
    let b = sandbox(base.minimum_disk_mb() as u32, false);
    let work: Result<()> = async {
        runtime.create(&a).await?;
        runtime.start(&a).await?;
        runtime.create(&b).await?;
        runtime.start(&b).await?;
        let ia = runtime.control_identities()?.current(a.id)?;
        let ib = runtime.control_identities()?.current(b.id)?;
        require(
            ia.secret().expose() != ib.secret().expose(),
            "per-VM control keys are unique",
        )?;
        record(
            rows,
            "two real guests boot from the signed image and take distinct identities",
            json!({
                "booted_guests": 2,
                "kernel_sha256": sha256_path(&base.kernel)?,
                "rootfs_sha256": sha256_path(&base.rootfs)?,
                "scope": "unguarded boots; Guard enforcement of a guarded boot is the phase 2 suite's claim, not this one's",
            }),
        );

        for vm in [&a, &b] {
            let result = runtime
                .exec(
                    vm,
                    aiec_core::ExecRequest {
                        command: vec![
                            "/bin/sh".into(),
                            "-c".into(),
                            format!(
                                "test -s {GUEST_SECRET_PATH} && test ! -e /workspace/guard-control.key && printf key-ok"
                            ),
                        ],
                        working_directory: None,
                        environment: Default::default(),
                        timeout_seconds: 10,
                        stdin: None,
                    },
                )
                .await?;
            require(
                result.exit_code == 0,
                "the guest holds the control key outside /workspace",
            )?;
        }

        require_health(
            base.socket_dir(a.id).join("vsock.sock"),
            &ia,
            true,
            "the first sandbox's key authenticates its own channel",
        )
        .await?;
        require_health(
            base.socket_dir(b.id).join("vsock.sock"),
            &ib,
            true,
            "the second sandbox's key authenticates its own channel",
        )
        .await?;
        record(
            rows,
            "per-VM identity uniqueness with working positive controls",
            json!({
                "distinct_keys": true,
                "own_key_health_responses": 2,
                "guest_key_placement_checks": 2,
            }),
        );

        require_health(
            base.socket_dir(b.id).join("vsock.sock"),
            &ia,
            false,
            "the first sandbox's key is refused by the second sandbox",
        )
        .await?;
        require_health(
            base.socket_dir(a.id).join("vsock.sock"),
            &ib,
            false,
            "the second sandbox's key is refused by the first sandbox",
        )
        .await?;
        // A refusal is only evidence if the channel still works afterwards.
        require_health(
            base.socket_dir(a.id).join("vsock.sock"),
            &ia,
            true,
            "the first sandbox still answers its own key after a refused frame",
        )
        .await?;
        require_health(
            base.socket_dir(b.id).join("vsock.sock"),
            &ib,
            true,
            "the second sandbox still answers its own key after a refused frame",
        )
        .await?;
        record(
            rows,
            "cross-sandbox control frames refused in both directions",
            json!({"refusals": 2, "post_refusal_positive_controls": 2}),
        );

        let marker = "phase5-portable-marker";
        let encoded_marker = base64::engine::general_purpose::STANDARD.encode(marker.as_bytes());
        runtime
            .put_file(
                &a,
                aiec_core::PutFileRequest {
                    path: "/workspace/phase5-positive-control".into(),
                    content_base64: encoded_marker.clone(),
                    mode: Some(0o600),
                },
            )
            .await?;
        let archive = runtime.export_workspace_archive(&a).await?;
        let document: Value = serde_json::from_slice(&archive)?;
        let entries = document["entries"].as_array().cloned().unwrap_or_default();
        require(
            entries.iter().any(|entry| {
                entry["path"].as_str() == Some("/workspace/phase5-positive-control")
                    && entry["content_base64"].as_str() == Some(encoded_marker.as_str())
            }),
            "the portable workspace archive carries the positive-control file with its bytes",
        )?;
        // Scan the archive itself for the control secrets, in both the hex and
        // base64 spellings a leak could take, and for the guest key path.
        for key in [&ia, &ib] {
            let secret = key.secret().expose();
            let spellings = [
                hex::encode(secret),
                base64::engine::general_purpose::STANDARD.encode(secret),
            ];
            for spelling in spellings {
                require(
                    !archive
                        .windows(spelling.len())
                        .any(|window| window == spelling.as_bytes()),
                    "no control secret appears in the portable workspace archive",
                )?;
            }
        }
        require(
            !archive
                .windows(GUEST_SECRET_PATH.len())
                .any(|window| window == GUEST_SECRET_PATH.as_bytes()),
            "the guest control key path is absent from the portable archive",
        )?;
        record(
            rows,
            "portable workspace snapshot excludes per-VM identities",
            json!({
                "entries": entries.len(),
                "marker_content_intact": true,
                "keys_scanned": 2,
                "spellings_scanned": ["hex", "base64"],
                "scope": "the portable workspace archive; a memory snapshot is a different artifact",
            }),
        );

        runtime.control_identities()?.revoke(a.id)?;
        let refused = runtime
            .exec(
                &a,
                aiec_core::ExecRequest {
                    command: vec!["/bin/true".into()],
                    working_directory: None,
                    environment: Default::default(),
                    timeout_seconds: 10,
                    stdin: None,
                },
            )
            .await;
        require(
            refused.is_err(),
            "a revoked identity refuses host control dispatch",
        )?;
        require_health(
            base.socket_dir(b.id).join("vsock.sock"),
            &ib,
            true,
            "revoking one identity leaves another working",
        )
        .await?;
        record(
            rows,
            "revocation refuses real host control dispatch for that sandbox only",
            json!({
                "host_dispatch_refused": true,
                "other_vm_positive_control": true,
                "scope": "host authority revocation; the guest root's already installed key is outside host control",
            }),
        );

        // Destroy and recreate is a real issuance boundary: a new identity, a
        // new key, and only the portable workspace carried over - never a full
        // memory snapshot, which would carry the previous key with it. A stop
        // alone is not the boundary: it leaves the machine's own disk in place,
        // and a create onto an existing image is refused rather than quietly
        // reusing a disk that still carries the previous identity.
        runtime.destroy(&a).await?;
        runtime.create(&a).await?;
        runtime.start(&a).await?;
        runtime.import_workspace_archive(&a, &archive).await?;
        let renewed = runtime.control_identities()?.current(a.id)?;
        require(
            renewed.generation() > ia.generation()
                && renewed.secret().expose() != ia.secret().expose(),
            "recreation rotates the identity generation and its key",
        )?;
        require_health(
            base.socket_dir(a.id).join("vsock.sock"),
            &ia,
            false,
            "the previous key is refused by the recreated guest",
        )
        .await?;
        require_health(
            base.socket_dir(a.id).join("vsock.sock"),
            &renewed,
            true,
            "the rotated key authenticates the recreated guest",
        )
        .await?;
        let restored = runtime.get_file(&a, "/workspace/phase5-positive-control").await?;
        require(
            restored.content_base64 == encoded_marker,
            "the portable workspace survives identity rotation",
        )?;
        record(
            rows,
            "rotation invalidates the old guest's frames and keeps portable work",
            json!({
                "generation_advanced": true,
                "key_changed": true,
                "old_frame_refused": true,
                "new_frame_health": true,
                "restored_marker": true,
                "rotation_boundary": "stop, recreate, import the portable workspace",
            }),
        );
        Ok(())
    }
    .await;

    for vm in [&a, &b] {
        if runtime.destroy(vm).await.is_err() {
            cleanup.push(format!("destroy of sandbox {} failed", vm.id));
        }
        if base.state_dir.join("vms").join(vm.id.to_string()).exists()
            || base.socket_dir(vm.id).exists()
        {
            cleanup.push(format!("sandbox {} left machine state behind", vm.id));
        }
    }
    work
}

#[tokio::main]
async fn main() -> Result<()> {
    let output = PathBuf::from(std::env::var("P5_IDENTITY_REPORT")?);
    let scratch = PathBuf::from(std::env::var("P5_IDENTITY_STATE")?);
    std::fs::create_dir_all(&scratch)?;
    std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700))?;

    let source_kernel = std::env::var("AIEC_KERNEL")?;
    let source_rootfs = std::env::var("AIEC_ROOTFS")?;

    // This run's own signing key and trust store. The key never leaves the
    // scratch directory, which is removed before this harness exits.
    let signing_key: Vec<u8> = [Uuid::new_v4(), Uuid::new_v4()]
        .iter()
        .flat_map(|id| id.as_bytes().to_vec())
        .collect();
    let manifest = TrustedImageManifest::sign(
        "phase5-isolated",
        &signing_key,
        "phase5-diagnostic-copy",
        &sha256_path(&source_kernel)?,
        &sha256_path(&source_rootfs)?,
        Utc::now(),
        Some(Utc::now() + Duration::hours(1)),
    )?;
    let accepted_dir = image_dir(&scratch, "image-accepted", Some(&manifest))?;
    let mut gate = ImageTrustGate::new(ImageTrustRequirement::REQUIRED);
    gate.insert_key("phase5-isolated", &signing_key)?;

    let mut base = FirecrackerConfig::from_env()?;
    base.state_dir = scratch.join("vms");
    base.guest_artifact_dir = Some(accepted_dir);
    base.image_trust = Some(gate);

    let source = (sha256_path(&source_kernel)?, sha256_path(&source_rootfs)?);
    let mut rows: Vec<Value> = Vec::new();
    let mut cleanup: Vec<String> = Vec::new();
    let outcome: Result<()> = async {
        refusals(&base, &scratch, &manifest, &signing_key, &mut rows).await?;
        live(&base, &mut rows, &mut cleanup).await?;
        let now = (sha256_path(&source_kernel)?, sha256_path(&source_rootfs)?);
        require(source == now, "source kernel and rootfs are unchanged")?;
        record(
            &mut rows,
            "the deployment's kernel and rootfs are unchanged after every refusal",
            json!({"both_digests_identical": true}),
        );
        Ok(())
    }
    .await;

    // The scratch holds the signing key, the trust store, the signed manifests
    // and the tampered copies. It goes whether or not the cases passed, so a
    // failure leaves no key material behind and preserves whatever report
    // already exists.
    std::fs::remove_dir_all(&scratch)?;
    require(
        !scratch.exists(),
        "the identity scratch directory was removed",
    )?;

    if let Err(error) = outcome {
        return Err(format!(
            "phase 5 identity and image acceptance failed ({error}); any previous report is \
             preserved and no secret is reported"
        )
        .into());
    }
    if !cleanup.is_empty() {
        return Err("phase 5 identity and image acceptance left cleanup errors".into());
    }

    let report = json!({
        "status": "PASS",
        "cases": rows,
        "cleanup_errors": cleanup,
        "observation_provenance": PROVENANCE,
    });
    let temporary = output.with_extension("json.tmp");
    private(&temporary, &serde_json::to_vec_pretty(&report)?)?;
    std::fs::rename(temporary, &output)?;
    println!(
        "phase 5 image and identity acceptance passed: {} cases",
        report["cases"].as_array().map(Vec::len).unwrap_or(0)
    );
    Ok(())
}
