//! Measuring the harness itself, with the model taken out of the picture.
//!
//! An agent task is dominated by waiting on a provider, so a single wall-clock
//! number says almost nothing about a harness. These measurements are the ones
//! that do: process start to ready, dispatch latency, context preparation, and
//! the cost of building a request body. They are all local and deterministic,
//! which is exactly why they can be compared honestly between two harnesses.

use std::time::{Duration, Instant};

use crate::context::ToolResult;
use crate::context::{Budget as ContextBudget, Context, compress_output};
use crate::model::{Completion, Message};
use crate::tools::registry;

/// A stand-in tool result, for driving the context engine without a registry.
fn tool_result(content: String, ok: bool) -> ToolResult {
    ToolResult {
        call_id: "bench".to_owned(),
        name: "bench".to_owned(),
        content,
        ok,
    }
}

/// The median of a set of samples, which is the number to quote: a first run
/// pays page faults and lazy binding that later runs do not.
pub fn median(samples: &mut [Duration]) -> Duration {
    if samples.is_empty() {
        return Duration::ZERO;
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}

pub fn percentile(samples: &mut [Duration], p: usize) -> Duration {
    if samples.is_empty() {
        return Duration::ZERO;
    }
    samples.sort_unstable();
    let index = (samples.len() - 1) * p.min(100) / 100;
    samples[index]
}

/// Everything measured, in one report.
#[derive(Debug, Default)]
pub struct Report {
    pub rows: Vec<Row>,
}

#[derive(Debug)]
pub struct Row {
    pub name: String,
    pub median: Duration,
    pub p95: Duration,
    pub note: String,
}

impl Report {
    pub fn add(&mut self, name: &str, samples: Vec<Duration>, note: &str) {
        let median = median(&mut samples.clone());
        let p95 = percentile(&mut samples.clone(), 95);
        self.rows.push(Row {
            name: name.to_owned(),
            median,
            p95,
            note: note.to_owned(),
        });
    }

    /// One line per measurement, so a run is diffable against another run.
    pub fn render(&self) -> String {
        let mut out = String::from("measurement                              median        p95\n");
        for row in &self.rows {
            out.push_str(&format!(
                "{:<40} {:>9.3} ms {:>9.3} ms  {}\n",
                row.name,
                row.median.as_secs_f64() * 1000.0,
                row.p95.as_secs_f64() * 1000.0,
                row.note
            ));
        }
        out
    }
}

/// Runs the whole suite. Every measurement is local; nothing here touches a
/// network, so the numbers describe the harness and only the harness.
pub fn run(iterations: usize) -> Report {
    let n = iterations.clamp(5, 200);
    let mut report = Report::default();

    // --- building the tool set: paid once per session, in every request after.
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let start = Instant::now();
        let registry = registry();
        let specs = registry.specs();
        std::hint::black_box(specs.len());
        samples.push(start.elapsed());
    }
    report.add("tool schema build", samples, "once per session");

    // --- the prompt is re-encoded every turn; the schemas ride along with it.
    let tools = registry();
    let specs = tools.specs();
    let schema_bytes = serde_json::to_string(&specs).map(|s| s.len()).unwrap_or(0);
    let prompt = crate::prompt::system_prompt(&crate::context::TaskState::new("x"));

    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let request = Completion {
            messages: vec![Message::System {
                content: prompt.clone(),
            }],
            tools: specs.clone(),
            model: "m".to_owned(),
            reasoning: crate::model::Reasoning::Off,
            max_output_tokens: 1024,
        };
        let start = Instant::now();
        let body = serde_json::to_string(&request).expect("serialises");
        std::hint::black_box(body.len());
        samples.push(start.elapsed());
    }
    report.add(
        "request json encode",
        samples,
        &format!("{schema_bytes} bytes of tool schema"),
    );

    // --- context accounting, which runs before every request.
    let mut ctx = Context::new("objective", ContextBudget::new(200_000, 8_192));
    for i in 0..40 {
        ctx.push_turn(
            &crate::model::Response {
                text: Some(format!("turn {i}")),
                tool_calls: Vec::new(),
                usage: Default::default(),
                stop: crate::model::Stop::ModelFinished,
                latency_ms: 0,
            },
            &[tool_result("observation ".repeat(20), true)],
        );
    }
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let start = Instant::now();
        std::hint::black_box(ctx.tokens());
        samples.push(start.elapsed());
    }
    report.add("context size estimate", samples, "per turn");

    // --- compaction, the most expensive thing the loop ever does.
    let mut samples = Vec::with_capacity(n.min(50));
    for _ in 0..n.min(50) {
        let mut big = Context::new("objective", ContextBudget::new(1_000, 100));
        for _ in 0..30 {
            big.push_turn(
                &crate::model::Response {
                    text: None,
                    tool_calls: vec![crate::model::ToolCall {
                        id: "1".into(),
                        name: "read".into(),
                        arguments: "{}".into(),
                    }],
                    usage: Default::default(),
                    stop: crate::model::Stop::ModelFinished,
                    latency_ms: 0,
                },
                &[tool_result("x".repeat(3_000), false)],
            );
        }
        let start = Instant::now();
        big.compact();
        samples.push(start.elapsed());
    }
    report.add("context compaction", samples, "rare, but the worst case");

    // --- bounding a large tool result, which happens on every big observation.
    let big = "compiler output line\n".repeat(20_000);
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let start = Instant::now();
        let squeezed = compress_output(&big, 32 * 1024);
        std::hint::black_box(squeezed.len());
        samples.push(start.elapsed());
    }
    report.add(
        "output compression",
        samples,
        &format!("{} KiB in", big.len() / 1024),
    );

    // --- result encoding, the last thing that happens.
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let document = crate::result::Result::for_error(
            "t",
            crate::result::Provenance {
                harness_version: crate::VERSION.to_owned(),
                protocol: crate::PROTOCOL_VERSION,
                provider: "bench".to_owned(),
                model: "bench".to_owned(),
                task_digest: "d".repeat(64),
                config_digest: "c".repeat(64),
                repository_start_commit: Some("a".repeat(40)),
            },
            "benchmark",
        );
        let start = Instant::now();
        let bytes = serde_json::to_vec(&document).expect("serialises");
        std::hint::black_box(bytes.len());
        samples.push(start.elapsed());
    }
    report.add("result encode", samples, "once, at exit");

    report
}

/// Cold start, measured from outside: how long from exec to the first byte of
/// useful output. This is the number a scheduler actually feels.
pub fn cold_start() -> Duration {
    let start = Instant::now();
    let output = std::process::Command::new(std::env::current_exe().unwrap_or_default())
        .arg("capabilities")
        .output();
    match output {
        Ok(_) => start.elapsed(),
        Err(_) => Duration::ZERO,
    }
}

/// Peak and current RSS for this process, in bytes.
pub fn rss() -> (Option<u64>, Option<u64>) {
    (crate::budget::peak_rss_bytes(), current_rss_bytes())
}

fn current_rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().next()?.parse().ok()?;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return None;
    }
    Some(pages as u64 * page_size as u64)
}
