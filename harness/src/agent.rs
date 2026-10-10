//! The loop. One turn is: ask the model, run what it asked for, feed the
//! observations back, repeat until the model stops or a budget runs out.
//!
//! The loop is the only place that knows the order of operations. Everything it
//! touches is a component with one job, which is what keeps the whole thing
//! small enough to hold in a VM and reason about.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::budget::{Budget, cpu_time_ms, peak_rss_bytes};
use crate::context::{Budget as ContextBudget, Context, ToolResult};
use crate::events::{Event, EventLog};
use crate::loop_guard::{LoopGuard, Progress, classify};
use crate::model::{Completion, Message, ModelProvider, Response, Stop, Usage};
use crate::result::{
    GitEvidence, Metrics, Provenance, Result as RunResult, Status, ValidationOutcome,
};
use crate::session::SessionState;
use crate::task::{Limits, Task, Validation};
use crate::tools::{Phase, ToolContext};
use crate::{HarnessError, prompt};

/// Everything the loop needs, assembled once at startup.
pub struct Agent<'a> {
    pub task: &'a Task,
    pub provider: &'a dyn ModelProvider,
    pub events: &'a EventLog,
    pub context: Context,
    pub budget: Budget,
    pub state: SessionState,
    metrics: Metrics,
    /// Repository facts, read once at startup via git rather than by walking.
    git: Git,
    root: PathBuf,
    /// Paths this run created for itself. They are excluded from the git
    /// evidence, which otherwise reports the harness's own bookkeeping as the
    /// agent's work.
    own_artifacts: Vec<String>,
    /// Where steering notes arrive, checked once per turn.
    steer_path: PathBuf,
    /// Bound in `run`, where the caller states it, so the terminal state can be
    /// written at the same place the in-flight one is.
    state_path: PathBuf,
    cpu_start_ms: u64,
    started: Instant,
}

struct Git {
    root: PathBuf,
    is_repository: bool,
    head: Option<String>,
    branch: Option<String>,
}

impl<'a> Agent<'a> {
    pub fn new(
        task: &'a Task,
        provider: &'a dyn ModelProvider,
        events: &'a EventLog,
        resumed: Option<SessionState>,
    ) -> Result<Self, HarnessError> {
        let root = task.workspace_root()?;
        let steer_path = crate::events::default_steer_path(&root);
        let git = inspect_repository(&root);
        let cpu_start_ms = cpu_time_ms();

        let (context, state) = match resumed {
            Some(state) if state.matches(task) => {
                let restored = state.state.clone();
                // A resume continues the recorded state. The transcript is
                // deliberately not restored: the model's own memory did not
                // survive the crash, and pretending otherwise would put
                // messages in the conversation it never saw.
                let mut context = Context::new(
                    task.instruction.clone(),
                    ContextBudget::new(
                        task.limits.max_context_tokens,
                        task.limits.max_output_tokens,
                    ),
                );
                // The structured state is what a resume actually restores. The
                // transcript is not, because the model's memory did not survive
                // the crash either.
                context.state = restored;
                (context, state)
            }
            _ => (
                Context::new(
                    task.instruction.clone(),
                    ContextBudget::new(
                        task.limits.max_context_tokens,
                        task.limits.max_output_tokens,
                    ),
                ),
                SessionState::new(
                    task,
                    &provider.config().model,
                    provider.config().provider.as_str(),
                ),
            ),
        };

        Ok(Self {
            task,
            provider,
            events,
            context,
            budget: Budget::new(task.limits),
            state,
            metrics: Metrics::default(),
            git,
            root,
            own_artifacts: Vec::new(),
            steer_path,
            state_path: PathBuf::new(),
            cpu_start_ms,
            started: Instant::now(),
        })
    }

    /// Registers a file this run created, so it is not reported as agent work.
    ///
    /// A relative path is resolved against the workspace root rather than
    /// dropped. A caller passing `--events events.jsonl` is doing the obvious
    /// thing, and `strip_prefix` against an absolute root simply fails for it,
    /// which silently put the event stream back into the agent's changed files.
    pub fn note_artifact(&mut self, path: &Path) {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        };
        // Compared lexically: the file may not exist yet, and canonicalising
        // would mean refusing to register a file for that reason.
        if let Ok(relative) = absolute.strip_prefix(&self.root) {
            let name = relative.to_string_lossy().into_owned();
            if !name.is_empty() {
                self.own_artifacts.push(name);
            }
        }
    }

    pub async fn run(mut self, state_path: &Path) -> RunResult {
        self.state_path = state_path.to_path_buf();
        self.events.emit(Event::SessionStarted {
            task_id: &self.task.task_id,
            provider: self.provider.config().provider.as_str(),
            model: &self.provider.config().model,
            protocol: crate::PROTOCOL_VERSION,
        });
        self.events.emit(Event::RepositoryInspected {
            root: &self.git.root.display().to_string(),
            is_repository: self.git.is_repository,
            branch: self.git.branch.as_deref(),
            head: self.git.head.as_deref(),
            dirty: false,
        });

        let mode = self.task.gui;
        // Fail fast when the task asks for a screen the guest cannot back:
        // running blind wastes the whole model budget on calls that fail.
        // `run` returns a result, not a Result, so the refusal is a terminal
        // error result through the existing `for_error` path.
        let avail = crate::tools::gui_available();
        let missing = match mode {
            crate::task::GuiMode::Off => None,
            crate::task::GuiMode::Browser | crate::task::GuiMode::Playwright => {
                if avail.browser {
                    None
                } else {
                    Some(
                        "task requests a browser-capable guest (chromedriver + chromium) \
                         but the guest has neither; rebuild with a GUI browser profile",
                    )
                }
            }
            crate::task::GuiMode::Desktop => {
                if avail.browser && avail.desktop {
                    None
                } else {
                    Some(
                        "task requests a desktop guest (chromedriver + chromium + Xvfb + xdotool) \
                         but the guest is missing them; rebuild with the desktop GUI profile",
                    )
                }
            }
        };
        if let Some(reason) = missing {
            return RunResult::for_error(&self.task.task_id, self.provenance(), reason);
        }
        let tools = crate::tools::registry_for(mode);
        let tool_specs = tools.specs();
        let mut guard = LoopGuard::new(4);
        let mut last_text: Option<String> = None;

        let stop: Stop = loop {
            let turn = match self.budget.check() {
                Ok(turn) => turn,
                Err(why) => {
                    break why;
                }
            };

            let request = Completion {
                messages: self.build_messages(&last_text),
                tools: tool_specs.clone(),
                model: self.provider.config().model.clone(),
                reasoning: self.provider.config().reasoning,
                max_output_tokens: self.task.limits.max_output_tokens,
            };

            self.events.emit(Event::ModelRequestStarted {
                turn,
                context_tokens: self.context.tokens(),
                message_count: request.messages.len(),
            });

            // A note dropped by the caller since the last turn becomes part of
            // this request, so steering lands before the next model call rather
            // than after it.
            if let Some(note) = crate::events::take_steering(&self.steer_path) {
                self.events
                    .emit(Event::SteeringApplied { turn, note: &note });
                self.context.messages.push(Message::User {
                    content: crate::prompt::steering_turn(&note),
                });
            }

            self.budget.record_request();
            let before_cpu = cpu_time_ms();
            let response = match self.provider.complete(&request).await {
                Ok(r) => r,
                Err(HarnessError::RetriesExhausted(_reason)) => {
                    self.events.emit(Event::SessionCompleted {
                        status: "error",
                        stop_reason: "model_error",
                        wall_ms: self.elapsed(),
                    });
                    let validations =
                        run_validations(self.task, &self.root, &self.task.limits).await;
                    return self.finish(Stop::ModelError, validations, last_text);
                }
                Err(e) => {
                    let validations =
                        run_validations(self.task, &self.root, &self.task.limits).await;
                    let mut result = self.finish(Stop::ModelError, validations, last_text);
                    result.status = Status::Error;
                    result.failure = Some(crate::redaction::scrub(&e.to_string()));
                    return result;
                }
            };

            self.metrics.harness_cpu_ms += cpu_time_ms().saturating_sub(before_cpu);
            self.record_model(&response);
            self.events.emit(Event::ModelRequestFinished {
                turn,
                latency_ms: response.latency_ms,
                input_tokens: response.usage.input_tokens,
                output_tokens: response.usage.output_tokens,
                tool_calls: response.tool_calls.len(),
            });

            // A model with nothing to call is done. Anything else continues.
            if response.tool_calls.is_empty() {
                last_text = response.text.clone();
                self.context.push_turn(&response, &[]);
                self.state.last_summary = last_text.clone();
                break response.stop;
            }

            let observations = self.run_calls(&response, &tools, turn).await;

            let pairs: Vec<(String, bool)> = observations
                .iter()
                .map(|r| (r.content.clone(), r.ok))
                .collect();
            let progress: Vec<Progress> = classify(&response, &pairs);
            guard.record_progress(&progress);
            for p in &progress {
                match p {
                    Progress::FileChanged(path) => {
                        self.context.state.files_changed.insert(path.clone());
                    }
                    Progress::NewFileInspected(path) => {
                        self.context.state.files_read.insert(path.clone());
                    }
                    _ => {}
                }
            }

            if guard.observe_turn(&response, &pairs) {
                break Stop::NoProgress;
            }

            if self.context.push_turn(&response, &observations) {
                self.events.emit(Event::ContextCompacted {
                    turn,
                    before_tokens: self.context.peak_tokens(),
                    after_tokens: self.context.tokens(),
                });
            }

            self.state.turns_completed = turn;
            self.state.tool_calls = self.metrics.tool_calls.values().sum();
            self.state.usage = self.current_usage();
            self.persist(state_path);

            if self.budget.remaining_requests() == 0 {
                break Stop::MaxRequests;
            }
        };

        self.events.emit(Event::SessionCompleted {
            status: "finished",
            stop_reason: stop_name(stop),
            wall_ms: self.elapsed(),
        });

        // The caller's validation runs here, after the agent, whatever the
        // model said. It lives inside `run` rather than beside it so a result
        // document is never emitted without the evidence that decides it, no
        // matter which entry point produced it.
        let validations = run_validations(self.task, &self.root, &self.task.limits).await;
        self.events.emit(Event::ValidationsStarted {
            count: validations.len(),
        });
        for (index, outcome) in validations.iter().enumerate() {
            self.events.emit(Event::ValidationFinished {
                index,
                argv: &outcome.argv,
                ok: outcome.ok,
                exit_code: outcome.exit_code,
                duration_ms: outcome.duration_ms,
            });
        }

        self.finish(stop, validations, last_text)
    }

    /// Builds the messages for one request.
    ///
    /// The system prompt and the progress block lead every time, in the same
    /// order, so the provider's prefix cache has something stable to key on.
    fn build_messages(&self, last_text: &Option<String>) -> Vec<Message> {
        let mut messages = vec![Message::System {
            content: prompt::system_prompt(&self.context.state),
        }];
        messages.push(Message::User {
            content: prompt::opening_turn(&self.task.instruction).to_owned(),
        });
        messages.extend(self.context.messages.iter().cloned());
        if let Some(text) = last_text {
            messages.push(Message::Assistant {
                text: Some(text.clone()),
                tool_calls: Vec::new(),
            });
            messages.push(Message::User {
                content: prompt::DONE_CONTRACT.to_owned(),
            });
        }
        messages
    }

    async fn run_calls(
        &mut self,
        response: &Response,
        tools: &crate::tools::Registry,
        turn: u32,
    ) -> Vec<ToolResult> {
        let ctx = ToolContext {
            root: self.root.clone(),
            limits: self.task.limits,
            phase: Phase::Working,
        };
        let mut observations: Vec<ToolResult> = Vec::new();

        for call in &response.tool_calls {
            self.events.emit(Event::ToolStarted {
                turn,
                name: &call.name,
            });
            *self
                .metrics
                .tool_calls
                .entry(call.name.clone())
                .or_insert(0) += 1;

            let outcome = tools.dispatch(call, &ctx).await;
            let (text, images, ok) = match outcome {
                Ok(output) => {
                    // Bounded here as well as in the tool: a tool that forgets is
                    // still not allowed to fill the context.
                    // Scrubbed before anything else sees it: the bounded text
                    // below becomes the model's next-turn context, so a secret
                    // here would be sent to the provider on the next request.
                    let scrubbed = crate::redaction::scrub(&output.content);
                    let bounded = crate::context::compress_output(
                        &scrubbed,
                        self.task.limits.max_tool_output_bytes,
                    );
                    // Images never compress: base64 truncated is a corrupt
                    // image. Oversize is refused at the tool; the cap check
                    // here is the backstop for a tool that forgot.
                    let total: usize = output.images.iter().map(|i| i.data_base64.len()).sum();
                    if total > crate::context::MAX_SCREENSHOT_BASE64 {
                        self.metrics.tool_failures += 1;
                        let text = format!(
                            "screenshots refused: {} bytes exceeds the {} byte cap; retake at lower quality",
                            total,
                            crate::context::MAX_SCREENSHOT_BASE64,
                        );
                        (text, Vec::new(), false)
                    } else {
                        let images = output
                            .images
                            .into_iter()
                            .map(|i| crate::model::ImageBlock {
                                media_type: i.media_type.to_owned(),
                                data_base64: i.data_base64,
                            })
                            .collect();
                        self.metrics.bytes_read += output.bytes;
                        (bounded, images, true)
                    }
                }
                Err(failure) => {
                    self.metrics.tool_failures += 1;
                    (
                        format!("{} failed: {}", failure.name, failure.message),
                        Vec::new(),
                        false,
                    )
                }
            };
            self.context.note_tool_output(text.len() as u64);
            self.metrics.bytes_written += text.len() as u64;
            self.events.emit(Event::ToolFinished {
                turn,
                name: &call.name,
                ok,
                bytes: text.len() as u64,
                detail: if ok { None } else { Some(&text) },
            });
            observations.push(ToolResult {
                call_id: call.id.clone(),
                name: call.name.clone(),
                content: text,
                images,
                ok,
            });
        }
        observations
    }

    fn record_model(&mut self, response: &Response) {
        self.metrics.model_requests += 1;
        self.metrics.model_latency_ms += response.latency_ms;
        let u = &response.usage;
        self.metrics.input_tokens += u.input_tokens;
        self.metrics.output_tokens += u.output_tokens;
        self.metrics.cache_read_tokens += u.cache_read_tokens;
        self.metrics.cache_write_tokens += u.cache_write_tokens;
    }

    fn current_usage(&self) -> Usage {
        Usage {
            input_tokens: self.metrics.input_tokens,
            output_tokens: self.metrics.output_tokens,
            cache_read_tokens: self.metrics.cache_read_tokens,
            cache_write_tokens: self.metrics.cache_write_tokens,
        }
    }

    /// Writes the session file from the LIVE structured state.
    ///
    /// `SessionState` holds a copy purely so it can be serialised; the copy is
    /// refreshed from `Context` here so the file can never disagree with the
    /// state the loop is actually using.
    fn persist(&self, path: &Path) {
        let mut snapshot = self.state.clone();
        snapshot.state = self.context.state.clone();
        let _ = snapshot.save(path);
    }

    fn elapsed(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Assembles the result document. This runs on every exit path, including
    /// the ones where something went wrong, because a failed run that produced
    /// no result is the worst possible outcome.
    fn finish(
        &mut self,
        stop: Stop,
        validations: Vec<ValidationOutcome>,
        _last_text: Option<String>,
    ) -> RunResult {
        let git = self.git_evidence();
        let passed = validations.iter().all(|v| v.ok);

        self.metrics.wall_ms = self.elapsed();
        self.metrics.harness_cpu_ms = self
            .metrics
            .harness_cpu_ms
            .max(cpu_time_ms().saturating_sub(self.cpu_start_ms));
        self.metrics.peak_rss_bytes = peak_rss_bytes();
        self.metrics.compactions = self.context.compactions();
        self.metrics.context_peak_tokens = self.context.peak_tokens();
        self.metrics.shell_commands = self.metrics.tool_calls.get("bash").copied().unwrap_or(0);

        let status = if !passed {
            Status::Failed
        } else if matches!(stop, Stop::ModelError) {
            Status::Error
        } else {
            Status::Success
        };

        // "Completed" means the TASK finished, not that the process exited.
        // A run stopped by its budget, by the no-progress detector, or by a
        // model error has left work undone, and refusing to resume it would
        // throw away a session that a second attempt could continue.
        self.state.completed = matches!(stop, Stop::ModelFinished) && passed;
        self.state.state = self.context.state.clone();
        // Written at exit as well as during the run. Without this a finished
        // session keeps its last in-flight marker, and since `load` refuses to
        // resume a completed one, a task that is already done still looks
        // resumable and gets run again.
        self.persist(&self.state_path);

        RunResult {
            task_id: self.task.task_id.clone(),
            status,
            stop_reason: stop_name(stop).to_owned(),
            validation: validations,
            git,
            metrics: self.metrics.clone(),
            provenance: self.provenance(),
            failure: None,
        }
    }

    /// Whether a changed path is the harness's own bookkeeping.
    fn is_own_artifact(&self, path: &str) -> bool {
        path.starts_with(".aiec-agent/") || self.own_artifacts.iter().any(|own| own == path)
    }

    fn provenance(&self) -> Provenance {
        let config = self.provider.config();
        let config_digest = crate::redaction::digest(&format!(
            "{}|{}|{}|{}",
            config.provider.as_str(),
            config.model,
            config.reasoning.as_str(),
            config.context_window
        ));
        Provenance {
            harness_version: crate::VERSION.to_owned(),
            protocol: crate::PROTOCOL_VERSION,
            provider: config.provider.as_str().to_owned(),
            model: config.model.clone(),
            task_digest: self.task.digest.clone(),
            config_digest,
            repository_start_commit: self.git.head.clone(),
        }
    }

    /// Reads the repository's final state through git, never by walking it.
    fn git_evidence(&self) -> GitEvidence {
        let mut evidence = GitEvidence {
            is_repository: self.git.is_repository,
            head_before: self.git.head.clone(),
            branch: self.git.branch.clone(),
            ..Default::default()
        };
        if !self.git.is_repository {
            return evidence;
        }
        evidence.head_after = git_output(&self.git.root, &["rev-parse", "HEAD"]);
        for line in git_output(&self.git.root, &["status", "--porcelain"])
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
        {
            // Porcelain is `XY path`; the path is what matters.
            let path = line.get(3..).unwrap_or(line).trim().to_owned();
            if self.is_own_artifact(&path) {
                evidence.harness_artifacts.push(path);
            } else {
                evidence.changed_files.push(path);
            }
        }

        let diff = git_output(&self.git.root, &["diff", "HEAD"]).unwrap_or_default();
        const MAX_DIFF: usize = 256 * 1024;
        if diff.len() > MAX_DIFF {
            evidence.diff_truncated = true;
            evidence.diff = crate::context::compress_output(&diff, MAX_DIFF);
        } else {
            evidence.diff = diff;
        }
        evidence
    }
}

/// Runs the caller's validation, after the agent, whatever the agent said.
///
/// This is the independence the whole result rests on: a model declaring success
/// is not evidence, and the exit status of a command is.
pub async fn run_validations(task: &Task, root: &Path, limits: &Limits) -> Vec<ValidationOutcome> {
    let mut out = Vec::new();
    for Validation { argv } in &task.validation {
        let start = Instant::now();
        let outcome = run_one(argv, root, limits).await;
        out.push(ValidationOutcome {
            argv: argv.clone(),
            duration_ms: start.elapsed().as_millis() as u64,
            ..outcome
        });
    }
    out
}

async fn run_one(argv: &[String], root: &Path, limits: &Limits) -> ValidationOutcome {
    let Some((program, args)) = argv.split_first() else {
        return ValidationOutcome {
            argv: argv.to_vec(),
            exit_code: -1,
            timed_out: false,
            duration_ms: 0,
            stdout: String::new(),
            stderr: "empty validation command".into(),
            ok: false,
        };
    };

    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .current_dir(root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);

    let child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ValidationOutcome {
                argv: argv.to_vec(),
                exit_code: -1,
                timed_out: false,
                duration_ms: 0,
                stdout: String::new(),
                stderr: format!("could not start {program}: {e}"),
                ok: false,
            };
        }
    };

    let timeout = std::time::Duration::from_secs(
        limits
            .command_timeout_seconds
            .min(limits.wall_seconds)
            .max(1),
    );
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(output)) => {
            let stdout = bound(
                &String::from_utf8_lossy(&output.stdout),
                limits.max_tool_output_bytes,
            );
            let stderr = bound(
                &String::from_utf8_lossy(&output.stderr),
                limits.max_tool_output_bytes,
            );
            ValidationOutcome {
                argv: argv.to_vec(),
                exit_code: output.status.code().unwrap_or(-1),
                timed_out: false,
                duration_ms: 0,
                stdout: crate::redaction::scrub(&stdout),
                stderr: crate::redaction::scrub(&stderr),
                ok: output.status.success(),
            }
        }
        Ok(Err(e)) => ValidationOutcome {
            argv: argv.to_vec(),
            exit_code: -1,
            timed_out: false,
            duration_ms: 0,
            stdout: String::new(),
            stderr: format!("validation failed: {e}"),
            ok: false,
        },
        Err(_) => ValidationOutcome {
            argv: argv.to_vec(),
            exit_code: -1,
            timed_out: true,
            duration_ms: timeout.as_millis() as u64,
            stdout: String::new(),
            stderr: format!("validation exceeded {}s", timeout.as_secs()),
            ok: false,
        },
    }
}

fn bound(text: &str, limit: usize) -> String {
    crate::context::compress_output(text, limit)
}

fn stop_name(stop: Stop) -> &'static str {
    match stop {
        Stop::ModelFinished => "model_finished",
        Stop::MaxRequests => "request_budget_exhausted",
        Stop::WallClock => "wall_clock_exhausted",
        Stop::NoProgress => "no_progress",
        Stop::ContextExhausted => "context_exhausted",
        Stop::ModelError => "model_error",
    }
}

/// Reads repository identity through git. Four cheap commands, no traversal.
fn inspect_repository(root: &Path) -> Git {
    let inside = git_output(root, &["rev-parse", "--is-inside-work-tree"])
        .is_some_and(|s| s.trim() == "true");
    if !inside {
        return Git {
            root: root.to_path_buf(),
            is_repository: false,
            head: None,
            branch: None,
        };
    }
    Git {
        root: root.to_path_buf(),
        is_repository: true,
        head: git_output(root, &["rev-parse", "HEAD"]),
        branch: git_output(root, &["rev-parse", "--abbrev-ref", "HEAD"]),
    }
}

/// One git invocation. A failure is `None`, not a panic: a workspace that is not
/// a repository is a supported case, not an exceptional one.
pub(crate) fn git_output(root: &Path, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(root)
        .stdin(std::process::Stdio::null())
        // Git can be chatty on stderr for harmless conditions; discarding it
        // keeps the tool output clean.
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Tool-call counts, for the result.
pub type ToolCounts = BTreeMap<String, u64>;
