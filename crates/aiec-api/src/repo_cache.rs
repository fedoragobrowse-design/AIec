//! Opt-in, process-local reuse of anonymous Git objects, never workspaces.
//!
//! Git and all staging files stay inside the assigned sandbox. Only a bounded
//! portable archive of a newly-created bare repository reaches this process.

use aiec_core::{
    CoreError, ExecRequest, ExecResult, Sandbox, TenantId,
    runtime::SandboxRuntime,
    snapshots::{PortableWorkspaceArchive, PortableWorkspaceEntry},
};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Semaphore, watch};

const MIRROR: &str = "/workspace/.aiec-repo-objects";
const MIRROR_PREFIX: &str = "/workspace/.aiec-repo-objects/";
const CHECKOUT: &str = "/workspace/repository";
const MAX_ENTRY_BYTES: usize = 16 * 1024 * 1024;
const MAX_CACHE_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 16;
const MAX_MEMBERS: usize = 4096;
const TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct Key {
    tenant: TenantId,
    repo: String,
    commit: String,
    shallow: bool,
    // Archive compatibility and policy are part of validity, not just the URL.
    runtime: &'static str,
    node: Option<uuid::Uuid>,
    image: String,
    network: String,
}

struct Entry {
    bytes: Arc<Vec<u8>>,
    created: Instant,
    used: Instant,
}

#[derive(Clone)]
enum FlightResult {
    Loading,
    Ready(Arc<Vec<u8>>),
    // A repository outside archive limits still gets its ordinary checkout.
    Uncached,
    Failed(Arc<str>),
}

#[derive(Default)]
struct State {
    entries: HashMap<Key, Entry>,
    flights: HashMap<Key, watch::Sender<FlightResult>>,
    bytes: usize,
}

impl State {
    fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, entry| {
            let keep = now.duration_since(entry.created) < TTL;
            if !keep {
                self.bytes -= entry.bytes.len();
            }
            keep
        });
    }

    fn insert(&mut self, key: Key, bytes: Arc<Vec<u8>>, now: Instant) {
        if bytes.len() > MAX_ENTRY_BYTES {
            return;
        }
        if let Some(previous) = self.entries.remove(&key) {
            self.bytes -= previous.bytes.len();
        }
        self.prune(now);
        while self.entries.len() >= MAX_ENTRIES || self.bytes + bytes.len() > MAX_CACHE_BYTES {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.used)
                .map(|(key, _)| key.clone());
            let Some(oldest) = oldest else { break };
            if let Some(entry) = self.entries.remove(&oldest) {
                self.bytes -= entry.bytes.len();
            }
        }
        self.bytes += bytes.len();
        self.entries.insert(
            key,
            Entry {
                bytes,
                created: now,
                used: now,
            },
        );
    }
}

/// A fill belongs to the caller's future, not a detached task. Dropping that
/// future releases the slot and gives every waiter a terminal cancellation.
struct Fill<'a> {
    cache: &'a RepositoryCache,
    key: Option<Key>,
}

impl Fill<'_> {
    fn finish(mut self, result: FlightResult) {
        if let Some(key) = self.key.take() {
            let mut state = self.cache.state.lock();
            if let FlightResult::Ready(bytes) = &result {
                state.insert(key.clone(), bytes.clone(), Instant::now());
            }
            if let Some(sender) = state.flights.remove(&key) {
                sender.send_replace(result);
            }
        }
    }
}

impl Drop for Fill<'_> {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            let mut state = self.cache.state.lock();
            if let Some(sender) = state.flights.remove(&key) {
                sender.send_replace(FlightResult::Failed(Arc::from(
                    "repository cache fill cancelled",
                )));
            }
        }
    }
}

pub(crate) struct RepositoryCache {
    enabled: bool,
    state: Mutex<State>,
    // Bounds concurrent archive copies, pinned evicted entries, downloads and
    // imports. Waiting Runs do not retain archive-sized allocations.
    operations: Semaphore,
}

impl RepositoryCache {
    pub(crate) fn from_env() -> Self {
        Self::new(matches!(
            std::env::var("AIEC_REPO_CACHE_ENABLED").as_deref(),
            Ok("1" | "true")
        ))
    }

    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            state: Mutex::new(State::default()),
            operations: Semaphore::new(2),
        }
    }

    /// Returns false before workspace mutation when ordinary clone should be
    /// used. Call only on a fresh sandbox before layers, setup or task execution.
    /// `authorization_present` must include Run secrets and caller-provided exec
    /// environment; this cache has no private-repository authorization identity.
    pub(crate) async fn prepare(
        &self,
        runtime: &dyn SandboxRuntime,
        sandbox: &Sandbox,
        repo: &str,
        reference: Option<&str>,
        shallow: bool,
        authorization_present: bool,
    ) -> Result<bool, CoreError> {
        if !self.enabled
            || authorization_present
            || !sandbox.network.is_enabled()
            || !runtime.capabilities().portable_workspace
            || !runtime.capabilities().files
            || !runtime.capabilities().exec
        {
            return Ok(false);
        }
        let Some(repo) = anonymous_repo(repo) else {
            return Ok(false);
        };
        let _permit = self
            .operations
            .acquire()
            .await
            .map_err(|_| CoreError::Unavailable("repository cache closed".into()))?;
        // Anonymous access is rechecked even for immutable commits. A previous
        // public repository becoming private must not remain accessible by hit.
        let Some(commit) = resolve_commit(runtime, sandbox, &repo, reference).await? else {
            return Ok(false);
        };
        let key = Key {
            tenant: sandbox.tenant_id,
            repo: repo.clone(),
            commit: commit.clone(),
            shallow,
            runtime: sandbox.runtime.as_str(),
            node: sandbox.node_id,
            image: sandbox.image_id.clone(),
            network: hex::encode(Sha256::digest(
                serde_json::to_vec(&sandbox.network)
                    .map_err(|e| CoreError::Backend(e.to_string()))?,
            )),
        };
        enum Lookup<'a> {
            Hit(Arc<Vec<u8>>),
            Wait(watch::Receiver<FlightResult>),
            Fill(Fill<'a>),
        }
        let lookup = {
            let mut state = self.state.lock();
            let now = Instant::now();
            state.prune(now);
            if let Some(entry) = state.entries.get_mut(&key) {
                entry.used = now;
                Lookup::Hit(entry.bytes.clone())
            } else if let Some(sender) = state.flights.get(&key) {
                Lookup::Wait(sender.subscribe())
            } else {
                let (sender, _) = watch::channel(FlightResult::Loading);
                state.flights.insert(key.clone(), sender);
                Lookup::Fill(Fill {
                    cache: self,
                    key: Some(key),
                })
            }
        };
        let archive = match lookup {
            Lookup::Hit(bytes) => Some(bytes),
            Lookup::Wait(mut receiver) => loop {
                let result = receiver.borrow_and_update().clone();
                match result {
                    FlightResult::Loading => {
                        receiver.changed().await.map_err(|_| {
                            CoreError::Backend(
                                "repository cache fill ended without a result".into(),
                            )
                        })?;
                    }
                    FlightResult::Ready(bytes) => break Some(bytes),
                    FlightResult::Uncached => return Ok(false),
                    FlightResult::Failed(error) => {
                        return Err(CoreError::Backend(error.to_string()));
                    }
                }
            },
            Lookup::Fill(fill) => {
                let result = self.fill(runtime, sandbox, &repo, &commit, shallow).await;
                match result {
                    Ok(bytes) => {
                        fill.finish(bytes.as_ref().map_or(FlightResult::Uncached, |bytes| {
                            FlightResult::Ready(bytes.clone())
                        }));
                        // The leader already owns a private staging mirror.
                        materialize(runtime, sandbox, &repo, &commit).await?;
                        return Ok(true);
                    }
                    Err(CoreError::Unsupported(_)) => {
                        fill.finish(FlightResult::Uncached);
                        return Ok(false);
                    }
                    Err(error) => {
                        fill.finish(FlightResult::Failed(Arc::from(error.to_string())));
                        // Teardown on failure/cancellation belongs to the parent
                        // Run attempt, which owns the fresh sandbox.
                        return Err(error);
                    }
                }
            }
        };
        if let Some(bytes) = archive {
            runtime.import_workspace_archive(sandbox, &bytes).await?;
            materialize(runtime, sandbox, &repo, &commit).await?;
        }
        Ok(true)
    }

    async fn fill(
        &self,
        runtime: &dyn SandboxRuntime,
        sandbox: &Sandbox,
        repo: &str,
        commit: &str,
        shallow: bool,
    ) -> Result<Option<Arc<Vec<u8>>>, CoreError> {
        // Keep fetched objects packed (one pack plus its index), and bound each
        // written file in the sandbox. POSIX shells express -f in 512/1024-byte
        // units: 8192 caps at 8 MiB even on the larger-unit implementations.
        // The ordinary checkout remains subject to the existing sandbox quota.
        let mut init = git(["init", "--bare", "--template="]);
        if commit.len() == 64 {
            init.push("--object-format=sha256".into());
        }
        init.push(MIRROR.into());
        checked(runtime, sandbox, init).await?;
        let mut fetch = git([
            "-C",
            MIRROR,
            "-c",
            "fetch.fsckObjects=true",
            "-c",
            "fetch.unpackLimit=0",
            "-c",
            "gc.auto=0",
            "fetch",
            "--no-tags",
        ]);
        if shallow {
            fetch.extend(["--depth".into(), "1".into()]);
        }
        fetch.extend(["--".into(), repo.into(), commit.into()]);
        let mut bounded_fetch = vec![
            "/bin/sh".into(),
            "-c".into(),
            "ulimit -f 8192 || exit 77; exec \"$@\"".into(),
            "aiec-repo-fetch".into(),
        ];
        bounded_fetch.extend(fetch);
        let fetched = exec(runtime, sandbox, bounded_fetch).await?;
        if fetched.timed_out {
            return Err(CoreError::Backend(
                "repository object download timed out".into(),
            ));
        }
        if fetched.exit_code != 0 {
            // A fetch that cannot complete under the bound, or cannot complete
            // at all, is not this optimization's failure to report: the
            // ordinary clone is authoritative and reports the real reason.
            discard_mirror(runtime, sandbox).await?;
            return Err(CoreError::Unsupported(
                "repository object download is unavailable".into(),
            ));
        }
        let actual = checked(
            runtime,
            sandbox,
            git([
                "-C",
                MIRROR,
                "rev-parse",
                "--verify",
                &format!("{commit}^{{commit}}"),
            ]),
        )
        .await?;
        if actual.stdout.trim() != commit {
            return Err(CoreError::Conflict(
                "repository did not resolve to the requested commit".into(),
            ));
        }
        checked(
            runtime,
            sandbox,
            git(["-C", MIRROR, "update-ref", "refs/heads/aiec-cache", commit]),
        )
        .await?;
        checked(
            runtime,
            sandbox,
            git([
                "-C",
                MIRROR,
                "symbolic-ref",
                "HEAD",
                "refs/heads/aiec-cache",
            ]),
        )
        .await?;
        // FETCH_HEAD includes the URL; even a credential-free URL is unnecessary
        // cache content. Templates are disabled, so hooks are never introduced.
        checked(
            runtime,
            sandbox,
            vec!["rm".into(), "-f".into(), format!("{MIRROR}/FETCH_HEAD")],
        )
        .await?;
        match object_archive(runtime, sandbox).await {
            Ok(bytes) => Ok(Some(Arc::new(bytes))),
            // A capture that gives up falls back to the ordinary clone, which
            // is correct but silent: the cache then costs a fetch on every run
            // and looks like it is saving nothing. Saying so is the difference
            // between a diagnosable miss and a mystery.
            Err(error @ (CoreError::LimitExceeded(_) | CoreError::Unsupported(_))) => {
                tracing::warn!(
                    repo_commit_prefix = %&commit[..commit.len().min(12)],
                    "repository object capture declined, falling back to clone: {error}"
                );
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

fn anonymous_repo(repo: &str) -> Option<String> {
    let url = reqwest::Url::parse(repo).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
        || url.path() == "/"
        || repo.bytes().any(|b| b.is_ascii_control())
    {
        return None;
    }
    Some(url.to_string())
}

fn immutable_commit(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn advertised_commit(output: &str, reference: Option<&str>) -> Option<String> {
    let desired = reference.unwrap_or("HEAD");
    let refs: HashMap<_, _> = output
        .lines()
        .filter_map(|line| {
            let (commit, name) = line.split_once('\t')?;
            immutable_commit(commit).then_some((name, commit))
        })
        .collect();
    let commit = if immutable_commit(desired) {
        // The response must still demonstrate current anonymous access.
        if refs.is_empty() {
            return None;
        }
        desired
    } else if desired == "HEAD" || desired.starts_with("refs/") {
        refs.get(format!("{desired}^{{}}").as_str())
            .or_else(|| refs.get(desired))
            .copied()?
    } else {
        refs.get(format!("refs/heads/{desired}").as_str())
            .or_else(|| refs.get(format!("refs/tags/{desired}^{{}}").as_str()))
            .or_else(|| refs.get(format!("refs/tags/{desired}").as_str()))
            .copied()?
    };
    Some(commit.to_ascii_lowercase())
}

async fn resolve_commit(
    runtime: &dyn SandboxRuntime,
    sandbox: &Sandbox,
    repo: &str,
    reference: Option<&str>,
) -> Result<Option<String>, CoreError> {
    let desired = reference.unwrap_or("HEAD");
    if desired.starts_with('-')
        || desired.len() > 1024
        || desired.bytes().any(|b| b.is_ascii_control())
    {
        return Ok(None);
    }
    let mut command = git(["ls-remote", "--", repo]);
    if immutable_commit(desired) || desired == "HEAD" {
        command.push("HEAD".into());
    } else if desired.starts_with("refs/") {
        command.extend([desired.into(), format!("{desired}^{{}}")]);
    } else {
        command.extend([
            format!("refs/heads/{desired}"),
            format!("refs/tags/{desired}"),
            format!("refs/tags/{desired}^{{}}"),
        ]);
    }
    let result = exec(runtime, sandbox, command).await;
    match result {
        Ok(result) if result.exit_code == 0 && !result.timed_out => {
            Ok(advertised_commit(&result.stdout, reference))
        }
        // Private/unsupported anonymous access must use the ordinary path, never
        // an old entry. The caller can then use its normal authorization design.
        Ok(_) | Err(CoreError::Unsupported(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

fn git<const N: usize>(args: [&str; N]) -> Vec<String> {
    let mut command: Vec<String> = [
        "env",
        "-u",
        "GIT_DIR",
        "-u",
        "GIT_WORK_TREE",
        "-u",
        "GIT_OBJECT_DIRECTORY",
        "-u",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "-u",
        "GIT_INDEX_FILE",
        "-u",
        "GIT_COMMON_DIR",
        "-u",
        "GIT_SHALLOW_FILE",
        "git",
        "-c",
        "credential.helper=",
        "-c",
        "http.extraHeader=",
        "-c",
        "http.cookieFile=",
        "-c",
        "http.saveCookies=false",
        "-c",
        "http.followRedirects=false",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "-c",
        "protocol.file.allow=always",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    command.extend(args.into_iter().map(str::to_owned));
    command
}

async fn exec(
    runtime: &dyn SandboxRuntime,
    sandbox: &Sandbox,
    command: Vec<String>,
) -> Result<ExecResult, CoreError> {
    let environment: BTreeMap<_, _> = [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_SYSTEM", "/dev/null"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_COUNT", "0"),
        ("GIT_CONFIG_PARAMETERS", ""),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_ASKPASS", "/bin/false"),
        ("GIT_TEMPLATE_DIR", "/dev/null"),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect();
    runtime
        .exec(
            sandbox,
            ExecRequest {
                command,
                working_directory: Some("/workspace".into()),
                environment,
                timeout_seconds: 300,
                stdin: None,
            },
        )
        .await
}

async fn checked(
    runtime: &dyn SandboxRuntime,
    sandbox: &Sandbox,
    command: Vec<String>,
) -> Result<ExecResult, CoreError> {
    let result = exec(runtime, sandbox, command).await?;
    if result.exit_code != 0 || result.timed_out {
        // No remote output in shared failure state: diagnostics can carry remote
        // identity or credentials even when the request URL itself is clean.
        return Err(CoreError::Backend(format!(
            "repository preparation failed (exit {}, timeout {})",
            result.exit_code, result.timed_out
        )));
    }
    Ok(result)
}

async fn materialize(
    runtime: &dyn SandboxRuntime,
    sandbox: &Sandbox,
    repo: &str,
    commit: &str,
) -> Result<(), CoreError> {
    checked(
        runtime,
        sandbox,
        git([
            "clone",
            "--no-hardlinks",
            "--no-checkout",
            "--template=",
            "--",
            MIRROR,
            CHECKOUT,
        ]),
    )
    .await?;
    checked(
        runtime,
        sandbox,
        git(["-C", CHECKOUT, "remote", "set-url", "origin", repo]),
    )
    .await?;
    checked(
        runtime,
        sandbox,
        git(["-C", CHECKOUT, "checkout", "--detach", commit]),
    )
    .await?;
    discard_mirror(runtime, sandbox).await
}

/// Removal of the staging mirror. It must not survive as untracked workspace
/// content when the ordinary clone path takes over from this cache.
async fn discard_mirror(runtime: &dyn SandboxRuntime, sandbox: &Sandbox) -> Result<(), CoreError> {
    checked(
        runtime,
        sandbox,
        vec!["rm".into(), "-rf".into(), "--".into(), MIRROR.into()],
    )
    .await?;
    Ok(())
}

fn mirror_member(path: &str, directory: bool) -> bool {
    let Some(relative) = path.strip_prefix(MIRROR_PREFIX) else {
        return path == MIRROR && directory;
    };
    if relative
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return false;
    }
    if directory {
        return matches!(
            relative,
            "objects" | "objects/pack" | "objects/info" | "refs" | "refs/heads" | "refs/tags"
        ) || (relative.len() == 10
            && relative.starts_with("objects/")
            && relative[8..].bytes().all(|b| b.is_ascii_hexdigit()));
    }
    // A bare mirror holding one ref has nothing else to pack, so `packed-refs`
    // can only name the ref this cache created.
    if matches!(
        relative,
        "HEAD" | "config" | "shallow" | "packed-refs" | "refs/heads/aiec-cache"
    ) {
        return true;
    }
    // `objects/info/packs` and `objects/info/commit-graph` name packs that are
    // already in the archive; nothing else under `info/` is ever kept.
    if matches!(relative, "objects/info/packs" | "objects/info/commit-graph") {
        return true;
    }
    let Some(object) = relative.strip_prefix("objects/") else {
        return false;
    };
    if let Some(pack) = object.strip_prefix("pack/pack-") {
        let Some((hash, extension)) = pack.rsplit_once('.') else {
            return false;
        };
        return immutable_commit(hash) && matches!(extension, "pack" | "idx" | "rev");
    }
    let Some((prefix, hash)) = object.split_once('/') else {
        return false;
    };
    prefix.len() == 2
        && matches!(hash.len(), 38 | 62)
        && prefix
            .bytes()
            .chain(hash.bytes())
            .all(|b| b.is_ascii_hexdigit())
}

/// Reuse the canonical archive format but enumerate only the safe mirror. A
/// general SnapshotProvider capture would copy every workspace file and leave
/// persistent local snapshot files with no bounded-deletion contract.
async fn object_archive(
    runtime: &dyn SandboxRuntime,
    sandbox: &Sandbox,
) -> Result<Vec<u8>, CoreError> {
    let mut pending = vec![MIRROR.to_owned()];
    let mut seen = HashSet::from([MIRROR.to_owned()]);
    let mut entries = vec![PortableWorkspaceEntry {
        path: MIRROR.into(),
        directory: true,
        content_base64: String::new(),
    }];
    let mut encoded_bytes = 0_usize;
    while let Some(directory) = pending.pop() {
        for file in runtime.list_files(sandbox, &directory).await? {
            if file.path != format!("{directory}/{}", file.name)
                || file.name.contains('/')
                || !matches!(file.kind.as_str(), "file" | "directory")
                || !mirror_member(&file.path, file.kind == "directory")
                || !seen.insert(file.path.clone())
            {
                return Err(CoreError::Conflict(
                    "repository mirror contains an unexpected member".into(),
                ));
            }
            if seen.len() > MAX_MEMBERS {
                return Err(CoreError::LimitExceeded(
                    "repository cache member limit".into(),
                ));
            }
            let is_directory = file.kind == "directory";
            let content_base64 = if is_directory {
                pending.push(file.path.clone());
                String::new()
            } else {
                let expected = usize::try_from(file.size)
                    .ok()
                    .and_then(|size| size.checked_add(2))
                    .and_then(|size| (size / 3).checked_mul(4))
                    .ok_or_else(|| CoreError::LimitExceeded("repository object size".into()))?;
                if expected > MAX_ENTRY_BYTES.saturating_sub(encoded_bytes) {
                    return Err(CoreError::LimitExceeded(
                        "repository cache byte limit".into(),
                    ));
                }
                let content = runtime.get_file(sandbox, &file.path).await?;
                if content.path != file.path
                    || content.content_base64.len() != expected
                    || content.content_base64.len() > MAX_ENTRY_BYTES.saturating_sub(encoded_bytes)
                {
                    return Err(CoreError::Conflict(
                        "repository object size changed during capture".into(),
                    ));
                }
                content.content_base64
            };
            encoded_bytes = encoded_bytes
                .checked_add(content_base64.len() + file.path.len() + 80)
                .ok_or_else(|| CoreError::LimitExceeded("repository archive size".into()))?;
            if encoded_bytes > MAX_ENTRY_BYTES {
                return Err(CoreError::LimitExceeded(
                    "repository cache byte limit".into(),
                ));
            }
            entries.push(PortableWorkspaceEntry {
                path: file.path,
                directory: is_directory,
                content_base64,
            });
        }
    }
    let bytes = serde_json::to_vec(&PortableWorkspaceArchive {
        version: 1,
        entries,
    })
    .map_err(|e| CoreError::Backend(e.to_string()))?;
    if bytes.len() > MAX_ENTRY_BYTES {
        return Err(CoreError::LimitExceeded(
            "repository cache byte limit".into(),
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tenant: TenantId, commit: &str) -> Key {
        Key {
            tenant,
            repo: "https://example.com/repo.git".into(),
            commit: commit.into(),
            shallow: true,
            runtime: "docker",
            node: None,
            image: "image-a".into(),
            network: "network-a".into(),
        }
    }

    #[test]
    fn mutable_refs_resolve_exactly_and_tags_are_peeled() {
        let branch = "a".repeat(40);
        let tag = "b".repeat(40);
        let peeled = "c".repeat(40);
        let output = format!(
            "{branch}\trefs/heads/release\n{tag}\trefs/tags/release\n{peeled}\trefs/tags/release^{{}}\n"
        );
        assert_eq!(advertised_commit(&output, Some("release")), Some(branch));
        assert_eq!(
            advertised_commit(&output, Some("refs/tags/release")),
            Some(peeled)
        );
        assert_eq!(advertised_commit(&output, Some("missing")), None);
        assert_eq!(advertised_commit("", Some(&tag)), None);
    }

    #[test]
    fn archives_exclude_workspace_state_credentials_and_alternates() {
        for relative in [
            "index",
            "FETCH_HEAD",
            "hooks/post-checkout",
            "objects/info/alternates",
            "../repository/.git/config",
            "objects/aa/../../secret",
            "logs/HEAD",
            "worktree/file",
        ] {
            assert!(!mirror_member(&format!("{MIRROR}/{relative}"), false));
        }
        assert!(mirror_member(
            &format!("{MIRROR}/objects/aa/{}", "b".repeat(38)),
            false
        ));
        assert!(mirror_member(
            &format!("{MIRROR}/objects/pack/pack-{}.pack", "a".repeat(40)),
            false
        ));
        for url in [
            "https://user:pass@example.com/repo",
            "https://example.com/repo?token=secret",
            "ssh://git@example.com/repo",
            "file:///workspace/repo",
        ] {
            assert!(anonymous_repo(url).is_none());
        }
    }

    #[tokio::test]
    async fn cancelled_fill_unblocks_waiters_and_allows_a_new_fill() {
        let cache = RepositoryCache::new(true);
        let key = key(TenantId::new_v4(), &"a".repeat(40));
        let (sender, mut receiver) = watch::channel(FlightResult::Loading);
        cache.state.lock().flights.insert(key.clone(), sender);
        let fill = Fill {
            cache: &cache,
            key: Some(key.clone()),
        };
        drop(fill);
        receiver.changed().await.unwrap();
        assert!(
            matches!(&*receiver.borrow(), FlightResult::Failed(error) if error.contains("cancelled"))
        );
        assert!(!cache.state.lock().flights.contains_key(&key));
        assert!(cache.state.lock().entries.is_empty());
        let (sender, _) = watch::channel(FlightResult::Loading);
        cache.state.lock().flights.insert(key.clone(), sender);
        Fill {
            cache: &cache,
            key: Some(key.clone()),
        }
        .finish(FlightResult::Ready(Arc::new(b"archive".to_vec())));
        assert_eq!(
            cache.state.lock().entries[&key].bytes.as_slice(),
            b"archive"
        );
    }

    #[test]
    fn eviction_ttl_and_tenant_identity_bound_reuse() {
        let tenant = TenantId::new_v4();
        let now = Instant::now();
        let mut state = State::default();
        let oldest = key(tenant, "oldest");
        for index in 0..=MAX_ENTRIES {
            let current = if index == 0 {
                oldest.clone()
            } else {
                key(tenant, &index.to_string())
            };
            state.insert(
                current,
                Arc::new(b"objects".to_vec()),
                now + Duration::from_millis(index as u64),
            );
        }
        assert!(!state.entries.contains_key(&oldest));
        assert_eq!(state.entries.len(), MAX_ENTRIES);
        assert!(!state.entries.contains_key(&key(TenantId::new_v4(), "1")));
        state.prune(now + TTL + Duration::from_secs(1));
        assert!(state.entries.is_empty());
        assert_eq!(state.bytes, 0);
    }

    #[test]
    fn byte_pressure_evicts_even_when_entry_capacity_remains() {
        let tenant = TenantId::new_v4();
        let now = Instant::now();
        let mut state = State::default();
        let bytes = Arc::new(vec![0; MAX_ENTRY_BYTES]);
        for index in 0..=MAX_CACHE_BYTES / MAX_ENTRY_BYTES {
            state.insert(
                key(tenant, &index.to_string()),
                bytes.clone(),
                now + Duration::from_millis(index as u64),
            );
        }
        assert!(!state.entries.contains_key(&key(tenant, "0")));
        assert_eq!(state.bytes, MAX_CACHE_BYTES);
        assert_eq!(state.entries.len(), MAX_CACHE_BYTES / MAX_ENTRY_BYTES);
    }
}
