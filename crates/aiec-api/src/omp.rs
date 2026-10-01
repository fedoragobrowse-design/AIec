//! The OMP adapter: a thin layer over the generic run machinery.
//!
//! OMP is the first serious user of this platform, not a special case in it.
//! Everything here expands an OMP-shaped request into ordinary runs and reads
//! the results back, so the next agent to evaluate costs a small adapter rather
//! than a second scheduler. Nothing below this module knows what OMP is.
//!
//! The adapter never decides which revision is better. It reports what each side
//! did; picking a metric is the caller's job, because "better" depends on what
//! the caller is optimising for and an evaluation that quietly picks for them is
//! one they cannot trust.

use std::collections::{BTreeMap, BTreeSet};

use aiec_core::TenantId;
use aiec_core::network::NetworkPolicy;
use aiec_core::run::{
    CapabilityRequirements, RepoSpec, ResourceRequirements, RetentionPolicy, Run, RunState,
    WorkloadSpec,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::eval_matrix::{MatrixCell, MatrixSpec, run_matrix};
use crate::runs::RunRequest;
use crate::{AppState, CoreError};

/// One OMP evaluation: a revision of the agent, against a task.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OmpRunSpec {
    /// The agent repository, cloned and built inside the sandbox.
    pub omp_repo: String,
    /// The revision under evaluation.
    pub omp_ref: String,
    /// The task, in natural language, handed to the agent.
    pub task: String,
    /// The repository the agent works in.
    pub target_repo: String,
    #[serde(default)]
    pub target_ref: Option<String>,
    /// Prepares the target repository after the agent checkout is ready.
    #[serde(default)]
    pub setup_command: Option<Vec<String>>,
    /// Builds the agent in its checkout. Defaults to `bun install && bun run build`.
    #[serde(default)]
    pub build_command: Option<Vec<String>>,
    /// Runs the checkout's Bun launcher in print mode, with the task as an argument.
    #[serde(default)]
    pub omp_command: Option<Vec<String>>,
    /// Checked after the agent finishes. All of them run, even after one fails.
    #[serde(default)]
    pub validations: Vec<Vec<String>>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub runtime: Option<String>,
    #[serde(default)]
    pub resources: Option<ResourceRequirements>,
    /// Extra hosts the run may reach, beyond the two it clones.
    ///
    /// An evaluation drives an agent loop and builds a project, so it usually
    /// needs a model endpoint and a package registry that nothing in the
    /// repository URL says. Deriving only the clone hosts would produce a
    /// policy that compiles and then fails at the first model call, which is
    /// worse than being asked to name the destinations.
    ///
    /// This is a convenience for the *derived* policy, not a second way to
    /// state one. `resources` wins: if it carries a `guard`, that policy is
    /// used as-is and this list is ignored. Reach for `resources.guard` when
    /// you need to say something a host list cannot - a credentialed model
    /// binding, a non-https destination, a method or path restriction.
    #[serde(default)]
    pub network_hosts: Vec<String>,
    #[serde(default)]
    pub requirements: CapabilityRequirements,
    #[serde(default)]
    pub retention: Option<RetentionPolicy>,
    #[serde(default)]
    pub retained_seconds: Option<i64>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    /// Tenant secret references only, never credential values.
    #[serde(default)]
    pub secrets: Vec<String>,
}

fn default_repetitions() -> u32 {
    1
}
fn default_parallel() -> usize {
    2
}

/// Two revisions of the same agent, measured against the same task.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OmpComparisonSpec {
    pub baseline: OmpRunSpec,
    pub candidate: OmpRunSpec,
    /// How many times each side runs. An agent is nondeterministic, so one run
    /// of each is an anecdote.
    #[serde(default = "default_repetitions")]
    pub repetitions: u32,
    #[serde(default = "default_parallel")]
    pub max_parallel: usize,
}

/// The default agent invocation.
///
/// Documented rather than clever: a caller overrides it when the agent's CLI
/// differs, and the command that actually ran is visible in the run's results
/// so nobody has to guess.
pub const DEFAULT_OMP_COMMAND: &[&str] = &[
    "/bin/sh",
    "/workspace/omp/packages/coding-agent/scripts/omp",
    "--print",
    "--",
];

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Resources for an evaluation run, governed by the hosts it needs.
///
/// An evaluation needs the network: it clones two repositories and runs a
/// build. Asking for bare `NetworkPolicy::Internet` used to work, and no longer
/// does on a Guard worker, which refuses an ungoverned attachment - so the
/// default silently broke the very deployments Guard targets.
///
/// The clone hosts are derivable; the rest are not. An evaluation also drives
/// an agent loop and builds a project, so it usually needs a model endpoint and
/// a package registry that no repository URL names, and those belong in
/// `OmpRunSpec::network_hosts`. Without them the run gets a policy permitting
/// its clones and nothing else, which is correct as far as it goes and fails at
/// the first model call rather than at admission.
fn evaluation_resources(spec: &OmpRunSpec) -> ResourceRequirements {
    // Two repositories on one host - a fork and its upstream - are one
    // destination, not two, and Guard refuses a policy that names the same
    // destination twice.
    let mut hosts: Vec<String> = Vec::new();
    for repo in [spec.omp_repo.as_str(), spec.target_repo.as_str()] {
        if let Some(host) = aiec_core::https_repository_host(repo)
            && !hosts.contains(&host)
        {
            hosts.push(host);
        }
    }
    for host in &spec.network_hosts {
        if !hosts.contains(host) {
            hosts.push(host.clone());
        }
    }
    ResourceRequirements {
        cpu: 2,
        memory_mb: 2048,
        disk_mb: 2048,
        network: NetworkPolicy::Disabled,
        guard: Some(evaluation_guard(hosts)),
    }
}

/// A Guard policy permitting exactly the named hosts, and the methods a clone
/// needs.
///
/// Built as an explicit document rather than from a template, because neither
/// shipped template can express this. `read-only-api` refuses a rule carrying
/// `POST` by design, which is right for an API and wrong here: `git clone`
/// fetches its pack with `POST /<repo>/git-upload-pack`. `model-plus-allowlist`
/// accepts per-rule methods but demands a model endpoint, and an evaluation has
/// none. The document below is what a governed clone actually is: a hostname,
/// and the verbs that host needs to serve one.
fn evaluation_guard(allowlist: Vec<String>) -> aiec_guard::policy::GuardConfig {
    use aiec_guard::policy::{
        DnsPolicy, EgressRule, GuardConfig, GuardPolicy, NetworkPolicy, PolicyTemplate, Topology,
    };
    // Zones come from the same deduplicated list as the rules: a DNS name with
    // no route behind it widens resolution for no reason, and a route with no
    // zone never resolves at all.
    let zones = allowlist.clone();
    GuardConfig {
        topology: Topology::Inside,
        policy_template: PolicyTemplate::NoNetwork,
        policy: Some(GuardPolicy {
            version: 1,
            network: NetworkPolicy {
                dns: DnsPolicy {
                    allowed_zones: zones,
                    allowed_record_types: vec!["A".into(), "AAAA".into()],
                },
                egress: allowlist
                    .into_iter()
                    .map(|host| EgressRule {
                        host,
                        port: 443,
                        protocol: "tcp".to_string(),
                        // POST because a clone is a read that uses POST as its
                        // transport verb. The read-only property is carried by
                        // the host and the path, not by the verb, which for
                        // smart HTTP says nothing about mutation.
                        allowed_methods: vec!["GET".into(), "HEAD".into(), "POST".into()],
                        allowed_paths: Vec::new(),
                    })
                    .collect(),
            },
            model: None,
            credentials: Vec::new(),
            limits: Default::default(),
        }),
        model_endpoint: None,
        allowlist: Vec::new(),
    }
}

/// Turns an OMP run into an ordinary workload.
///
/// The agent is cloned and built as *setup*, the task is the *command*, and the
/// checks are *validations* - three things the platform already schedules. The
/// only OMP-specific part left is the command itself.
pub fn to_run_request(spec: &OmpRunSpec) -> Result<RunRequest, CoreError> {
    let agent = RepoSpec {
        url: spec.omp_repo.clone(),
        reference: Some(spec.omp_ref.clone()),
        ..Default::default()
    };
    agent.validate()?;
    let target = RepoSpec {
        url: spec.target_repo.clone(),
        reference: spec.target_ref.clone(),
        ..Default::default()
    };
    target.validate()?;
    // The generic repository admission rejects HTTPS credentials; SSH remotes
    // also must not smuggle a password into a durable workload or its logs.
    for repo in [&agent, &target] {
        if repo.url.contains('\0')
            || repo.url.strip_prefix("ssh://").is_some_and(|url| {
                url.split('/')
                    .next()
                    .unwrap_or_default()
                    .split_once('@')
                    .is_some_and(|(user, _)| user.contains(':'))
            })
        {
            return Err(CoreError::InvalidRequest(
                "a repository URL must not carry credentials or null bytes".into(),
            ));
        }
    }
    if spec.task.trim().is_empty() || spec.task.contains('\0') || spec.omp_ref.is_empty() {
        return Err(CoreError::InvalidRequest(
            "task and OMP revision must be non-empty and contain no null bytes".into(),
        ));
    }

    // Fetch rather than clone --branch: commit hashes, branches and tags all work.
    // Cloning is never skipped by an override to the build or target setup.
    let mut setup = vec![vec![
        "/bin/sh".into(),
        "-c".into(),
        format!(
            "set -e; mkdir -p /workspace/omp; git init -q /workspace/omp; \
                 git -C /workspace/omp remote add origin {repo}; \
                 git -C /workspace/omp fetch --depth 1 -- origin {revision}; \
                 git -C /workspace/omp checkout --detach FETCH_HEAD",
            repo = shell_quote(&spec.omp_repo),
            revision = shell_quote(&spec.omp_ref),
        ),
    ]];
    let build = spec.build_command.clone().unwrap_or_else(|| {
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "bun install && bun run build".into(),
        ]
    });
    if build.is_empty() {
        return Err(CoreError::InvalidRequest(
            "the OMP build command is empty".into(),
        ));
    }
    let mut build_in_checkout = vec![
        "/bin/sh".into(),
        "-c".into(),
        "cd /workspace/omp && exec \"$@\"".into(),
        "omp-build".into(),
    ];
    build_in_checkout.extend(build);
    setup.push(build_in_checkout);
    if let Some(command) = &spec.setup_command {
        setup.push(command.clone());
    }
    setup.push(vec![
        "git".into(),
        "-C".into(),
        "/workspace/omp".into(),
        "rev-parse".into(),
        "HEAD".into(),
    ]);

    let command = if let Some(command) = &spec.omp_command {
        if command.is_empty() {
            return Err(CoreError::InvalidRequest("the OMP command is empty".into()));
        }
        // WorkloadSpec has no stdin field. A constant wrapper delivers task
        // bytes to overrides without interpolating them into shell syntax.
        let mut wrapped = vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf '%s' \"$OMP_TASK\" | \"$@\"".into(),
            "omp-task".into(),
        ];
        wrapped.extend(command.clone());
        wrapped
    } else {
        let mut command: Vec<String> = DEFAULT_OMP_COMMAND
            .iter()
            .map(|part| (*part).into())
            .collect();
        command.push(spec.task.clone());
        command
    };
    let mut environment = spec.environment.clone();
    environment
        .entry("HOME".into())
        .or_insert_with(|| "/workspace/omp-home".into());
    environment
        .entry("BUN_INSTALL_CACHE_DIR".into())
        .or_insert_with(|| "/workspace/omp-cache".into());
    environment.insert("OMP_REPO".into(), "/workspace/omp".into());
    environment.insert("OMP_REF".into(), spec.omp_ref.clone());
    environment.insert("OMP_TARGET_REPO".into(), "/workspace/repository".into());
    if let Some(reference) = &spec.target_ref {
        environment.insert("OMP_TARGET_REF".into(), reference.clone());
    }
    environment.insert("OMP_TASK".into(), spec.task.clone());

    let request = RunRequest {
        workload: WorkloadSpec {
            repo: Some(target),
            setup,
            command,
            validations: spec.validations.clone(),
            environment,
            secrets: spec.secrets.clone(),
            git_evidence: true,
            timeout_seconds: spec.timeout_seconds.or(Some(1800)),
            ..Default::default()
        },
        resources: spec
            .resources
            .clone()
            .unwrap_or_else(|| evaluation_resources(spec)),
        requirements: spec.requirements.clone(),
        requested_runtime: spec.runtime.clone(),
        retention: spec.retention.unwrap_or(RetentionPolicy::KeepOnFailure),
        retained_seconds: spec.retained_seconds,
        ..Default::default()
    };
    request.workload.validate()?;
    Ok(request)
}

/// One side's measurements across its repetitions.
#[derive(Clone, Debug, Serialize)]
pub struct OmpSideReport {
    pub label: String,
    pub revision: String,
    pub total_runs: u32,
    pub successful_runs: u32,
    pub failed_runs: u32,
    /// One slot per run. Null means the task never executed.
    pub exit_codes: Vec<Option<i32>>,
    /// Sum of observed settled wall times; absent if any run lacks timestamps.
    pub wall_time_ms: Option<u64>,
    pub phase_ms: BTreeMap<String, u64>,
    pub setup_failures: u32,
    pub validation_failures: u32,
    pub missing_task_runs: u32,
    pub actual_omp_revisions: Vec<Option<String>>,
    /// Authoritative durable outcomes, including git evidence and cleanup failures.
    pub runs: Vec<Run>,
    /// Sandboxes retained for debugging, so a failure can be opened.
    pub retained_sandbox_ids: Vec<Uuid>,
}

/// A comparison, reported as measurements and nothing more.
#[derive(Clone, Debug, Serialize)]
pub struct OmpComparisonReport {
    pub evaluation_id: Uuid,
    pub requested_at: DateTime<Utc>,
    pub baseline: OmpSideReport,
    pub candidate: OmpSideReport,
    pub max_parallel: usize,
}

impl OmpComparisonReport {
    /// Success counts per side. Deliberately no winner.
    pub fn counts(&self) -> BTreeMap<&'static str, (u32, u32)> {
        BTreeMap::from([
            (
                "baseline",
                (self.baseline.successful_runs, self.baseline.total_runs),
            ),
            (
                "candidate",
                (self.candidate.successful_runs, self.candidate.total_runs),
            ),
        ])
    }
}

/// Runs a baseline and a candidate against the same task.
pub async fn compare(
    state: &AppState,
    tenant: TenantId,
    spec: &OmpComparisonSpec,
) -> Result<OmpComparisonReport, CoreError> {
    if spec.repetitions == 0 {
        return Err(CoreError::InvalidRequest(
            "repetitions must be at least one".into(),
        ));
    }
    if spec.baseline.task != spec.candidate.task {
        return Err(CoreError::InvalidRequest(
            "a comparison must give both sides the same task".into(),
        ));
    }

    let evaluation_id = Uuid::now_v7();
    let mut cells: Vec<MatrixCell> = Vec::new();
    for repetition in 0..spec.repetitions {
        for (label, side) in [("baseline", &spec.baseline), ("candidate", &spec.candidate)] {
            let mut axis = BTreeMap::new();
            axis.insert("side".to_owned(), label.to_owned());
            axis.insert("revision".to_owned(), side.omp_ref.clone());
            axis.insert("repetition".to_owned(), repetition.to_string());
            let mut request = to_run_request(side)?;
            request.matrix_id = Some(evaluation_id);
            // Every cell gets its own key: a shared one would hand the second
            // repetition the first one's run, and nothing would execute.
            request.idempotency_key = Some(format!("eval-{evaluation_id}-{label}-{repetition}"));
            cells.push(MatrixCell { axis, request });
        }
    }

    let matrix = MatrixSpec {
        cells,
        options: aiec_core::run::BatchOptions {
            max_parallel: spec.max_parallel.max(1),
        },
    };
    let result = run_matrix(state, tenant, &matrix).await?;

    let mut baseline = Vec::new();
    let mut candidate = Vec::new();
    for cell in result.results {
        // A cell that never became a run is kept as an error on its own side
        // rather than dropped: a comparison that silently compared one sample
        // because the other side was refused is a comparison of the wrong
        // experiment.
        let run = match (cell.run, cell.error) {
            (Some(run), _) => run,
            (None, Some(error)) => {
                let side = cell
                    .axis
                    .get("side")
                    .cloned()
                    .unwrap_or_else(|| "unlabelled".to_owned());
                return Err(CoreError::InvalidRequest(format!(
                    "the {side} side did not run: {error}"
                )));
            }
            (None, None) => {
                return Err(CoreError::InvalidRequest(
                    "OMP matrix cell produced neither a run nor an error".into(),
                ));
            }
        };
        match cell.axis.get("side").map(String::as_str) {
            Some("baseline") => baseline.push(run),
            Some("candidate") => candidate.push(run),
            _ => {
                return Err(CoreError::InvalidRequest(
                    "OMP matrix cell lost its side axis".into(),
                ));
            }
        }
    }
    Ok(OmpComparisonReport {
        evaluation_id: result.matrix_id,
        requested_at: result.requested_at,
        baseline: summarise("baseline", &spec.baseline.omp_ref, baseline),
        candidate: summarise("candidate", &spec.candidate.omp_ref, candidate),
        max_parallel: matrix.options.max_parallel,
    })
}

/// The actual checked-out agent revision, from its recorded setup command.
pub fn actual_omp_revision(run: &Run) -> Option<String> {
    run.results
        .setup
        .iter()
        .rev()
        .find(|step| {
            step.ok
                && step.command.iter().map(String::as_str).eq([
                    "git",
                    "-C",
                    "/workspace/omp",
                    "rev-parse",
                    "HEAD",
                ])
        })
        .map(|step| step.stdout.trim().to_owned())
        .filter(|revision| !revision.is_empty())
}

/// Whole-run elapsed time from authoritative timestamps, never an invented zero.
pub fn wall_time_ms(run: &Run) -> Option<u64> {
    let completed = run.completed_at?;
    u64::try_from((completed - run.requested_at).num_milliseconds()).ok()
}

fn summarise(label: &str, revision: &str, runs: Vec<Run>) -> OmpSideReport {
    let mut report = OmpSideReport {
        label: label.to_owned(),
        revision: revision.to_owned(),
        total_runs: runs.len() as u32,
        successful_runs: 0,
        failed_runs: 0,
        exit_codes: Vec::with_capacity(runs.len()),
        wall_time_ms: if runs.is_empty() { None } else { Some(0) },
        phase_ms: BTreeMap::new(),
        setup_failures: 0,
        validation_failures: 0,
        missing_task_runs: 0,
        actual_omp_revisions: Vec::with_capacity(runs.len()),
        retained_sandbox_ids: Vec::new(),
        runs,
    };
    let mut seen = BTreeSet::new();
    for run in &report.runs {
        if run.state == RunState::Succeeded {
            report.successful_runs += 1;
        } else {
            report.failed_runs += 1;
        }
        if let Some(sandbox) = run.retained_sandbox_id
            && seen.insert(sandbox)
        {
            report.retained_sandbox_ids.push(sandbox);
        }
        report
            .exit_codes
            .push(run.results.task.as_ref().map(|task| task.exit_code));
        report.missing_task_runs += u32::from(run.results.task.is_none());
        report.setup_failures += run.results.setup.iter().filter(|step| !step.ok).count() as u32;
        report.validation_failures += run
            .results
            .validations
            .iter()
            .filter(|step| !step.ok)
            .count() as u32;
        report.actual_omp_revisions.push(actual_omp_revision(run));
        report.wall_time_ms = report
            .wall_time_ms
            .zip(wall_time_ms(run))
            .map(|(total, elapsed)| total.saturating_add(elapsed));
        for (phase, elapsed) in &run.results.phase_ms {
            let total = report.phase_ms.entry(phase.clone()).or_default();
            *total = total.saturating_add(*elapsed);
        }
    }
    report
}

/// Loads a suite from a reviewable JSON document.
///
/// Not a bespoke language: a suite has to be readable in a pull request, and a
/// format nobody can read is a format nobody reviews.
pub fn load_suite(contents: &str) -> Result<OmpComparisonSpec, CoreError> {
    serde_json::from_str(contents)
        .map_err(|error| CoreError::InvalidRequest(format!("invalid suite: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> OmpRunSpec {
        OmpRunSpec {
            omp_repo: "https://github.com/can1357/oh-my-pi".into(),
            omp_ref: "v18.3.5".into(),
            task: "fix the flaky test".into(),
            target_repo: "https://github.com/me/fixture".into(),
            target_ref: None,
            setup_command: None,
            build_command: None,
            omp_command: None,
            validations: vec![vec!["bun".into(), "test".into()]],
            timeout_seconds: None,
            runtime: None,
            resources: None,
            network_hosts: Vec::new(),
            requirements: Default::default(),
            retention: None,
            retained_seconds: None,
            environment: BTreeMap::new(),
            secrets: Vec::new(),
        }
    }

    #[test]
    fn credential_urls_are_rejected_before_a_run_can_be_recorded() {
        for remote in [
            "https://token@github.com/me/private",
            "ssh://user:password@github.com/me/private",
        ] {
            let mut request = spec();
            request.omp_repo = remote.into();
            assert!(to_run_request(&request).is_err());
            request = spec();
            request.target_repo = remote.into();
            assert!(to_run_request(&request).is_err());
        }
    }

    /// The default resources have to be a policy Guard will actually accept.
    ///
    /// This is a regression, not a formality: the first version of this default
    /// used the `read-only-api` template with `GET`/`HEAD`, which compiles and
    /// then cannot clone, because `git clone` fetches its pack with
    /// `POST /<repo>/git-upload-pack`. `effective_policy` is what the API
    /// validates at admission, so running it here is the same check.
    #[test]
    fn the_derived_default_is_a_policy_guard_accepts() {
        let request = to_run_request(&spec()).expect("a valid spec builds");
        let guard = request
            .resources
            .guard
            .as_ref()
            .expect("the default carries a Guard selection");
        let effective = guard.effective_policy().expect("the policy compiles");
        assert!(
            effective
                .network
                .egress
                .iter()
                .all(|rule| rule.allowed_methods.iter().any(|m| m == "POST")),
            "a governed clone needs POST, whatever the template says"
        );
        // And it reaches exactly the two repositories the run clones.
        let hosts: Vec<&str> = effective
            .network
            .egress
            .iter()
            .map(|rule| rule.host.as_str())
            .collect();
        assert!(hosts.contains(&"github.com"), "{hosts:?}");
    }

    #[test]
    fn a_suite_loads_from_reviewable_json() {
        let comparison = OmpComparisonSpec {
            baseline: spec(),
            candidate: spec(),
            repetitions: 3,
            max_parallel: 2,
        };
        let json = serde_json::to_string(&comparison).expect("serialises");
        let loaded = load_suite(&json).expect("round-trips");
        assert_eq!(loaded.repetitions, 3);
        assert_eq!(loaded.baseline.omp_ref, "v18.3.5");
    }
}
