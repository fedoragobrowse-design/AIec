//! The task document: the only thing the harness is told before it starts.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A command the caller wants run to decide whether the task actually passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Validation {
    pub argv: Vec<String>,
}

impl Validation {
    pub fn new(argv: Vec<String>) -> Self {
        Self { argv }
    }
}

/// Which GUI profile the guest carries, if any. Defaults to Off: a task that
/// does not ask for a screen gets the nine text tools and nothing else.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuiMode {
    #[default]
    Off,
    Browser,
    Desktop,
    Playwright,
}

/// Hard ceilings. The caller's numbers are treated as a request; the ones the
/// harness itself imposes can only ever be lower.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    #[serde(default = "default_wall_seconds")]
    pub wall_seconds: u64,
    #[serde(default = "default_model_requests")]
    pub max_model_requests: u32,
    #[serde(default = "default_output_tokens")]
    pub max_output_tokens: u32,
    #[serde(default = "default_context_tokens")]
    pub max_context_tokens: u32,
    #[serde(default = "default_tool_output_bytes")]
    pub max_tool_output_bytes: usize,
    #[serde(default = "default_command_seconds")]
    pub command_timeout_seconds: u64,
}

fn default_wall_seconds() -> u64 {
    1800
}
fn default_model_requests() -> u32 {
    100
}
fn default_output_tokens() -> u32 {
    8192
}
fn default_context_tokens() -> u32 {
    200_000
}
fn default_tool_output_bytes() -> usize {
    32 * 1024
}
fn default_command_seconds() -> u64 {
    600
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            wall_seconds: default_wall_seconds(),
            max_model_requests: default_model_requests(),
            max_output_tokens: default_output_tokens(),
            max_context_tokens: default_context_tokens(),
            max_tool_output_bytes: default_tool_output_bytes(),
            command_timeout_seconds: default_command_seconds(),
        }
    }
}

/// What the caller wants done, where, and how it will be judged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    /// Optional in the document: a caller that does not care gets one derived.
    #[serde(default)]
    pub task_id: String,

    pub instruction: String,

    /// The repository root. Every path a tool touches is resolved inside it.
    pub workspace: PathBuf,

    #[serde(default)]
    pub validation: Vec<Validation>,

    #[serde(default)]
    pub limits: Limits,

    /// Which GUI profile the guest carries, if any. Defaults to Off: a task
    /// that does not ask for a screen gets the nine text tools and nothing else.
    #[serde(default)]
    pub gui: GuiMode,

    /// Computed by the harness, never read from the document.
    ///
    /// This is deliberately not a required field. The digest is derived FROM
    /// this document, so demanding it on input would mean every task file had
    /// to carry a value the harness is about to overwrite — and a caller that
    /// omitted it would be rejected for a field it has no way to know.
    #[serde(default, skip_deserializing)]
    pub digest: String,
}

impl Task {
    /// Reads and validates a task document.
    ///
    /// Every failure here is a refusal, never a panic: this file is written by
    /// whatever scheduled the VM, and it is as untrusted as a model reply.
    pub fn load(path: &Path) -> Result<Self, crate::HarnessError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| crate::HarnessError::io(path.display().to_string(), e))?;
        Self::parse(&raw)
    }

    pub fn parse(raw: &str) -> Result<Self, crate::HarnessError> {
        let mut task: Task = serde_json::from_str(raw)
            .map_err(|e| crate::HarnessError::invalid("task document", e.to_string()))?;

        if task.instruction.trim().is_empty() {
            return Err(crate::HarnessError::invalid("task", "instruction is empty"));
        }
        if task.task_id.trim().is_empty() {
            task.task_id = format!("task-{}", uuid::Uuid::now_v7());
        }
        for v in &task.validation {
            if v.argv.is_empty() {
                return Err(crate::HarnessError::invalid(
                    "task",
                    "a validation entry has an empty argv",
                ));
            }
        }
        // The digest is computed over the fields that determine the work, so a
        // result can be checked against the task that produced it.
        task.digest = task.compute_digest()?;
        Ok(task)
    }

    /// The workspace, canonicalised once, so path checks compare real prefixes.
    pub fn workspace_root(&self) -> Result<PathBuf, crate::HarnessError> {
        std::fs::canonicalize(&self.workspace)
            .map_err(|e| crate::HarnessError::io(self.workspace.display().to_string(), e))
    }

    fn compute_digest(&self) -> Result<String, crate::HarnessError> {
        let mut hasher = digest::Sha256::new();
        hasher.update(self.task_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.instruction.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.workspace.as_os_str().as_encoded_bytes());
        for v in &self.validation {
            hasher.update(b"\0");
            for arg in &v.argv {
                hasher.update(arg.as_bytes());
                hasher.update(b"\x1f");
            }
        }
        // The mode decides which tools exist, so a result earned with a
        // browser must never verify against a text-only task.
        hasher.update(b"\0");
        hasher.update(format!("{:?}", self.gui).as_bytes());
        Ok(hasher.finish_hex())
    }
}

/// A 60-line sha256, enough to tie a result to its task without dragging in a
/// crypto dependency for sixteen lines of hashing.
pub(crate) mod digest {
    pub struct Sha256([u32; 8]);

    impl Sha256 {
        pub fn new() -> Self {
            Self([
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ])
        }

        pub fn update(&mut self, data: &[u8]) {
            let mut block = [0u8; 64];
            for chunk in data.chunks(64) {
                block[..chunk.len()].copy_from_slice(chunk);
                let mut w = [0u32; 64];
                for (i, word) in w.iter_mut().take(16).enumerate() {
                    let j = i * 4;
                    *word =
                        u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
                }
                for i in 16..64 {
                    let s0 =
                        w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                    let s1 =
                        w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 6);
                    w[i] = w[i - 16]
                        .wrapping_add(s0)
                        .wrapping_add(w[i - 7])
                        .wrapping_add(s1);
                }
                let [mut a, mut b, mut c, mut d, e, f, g, h] = self.0;
                for i in 0..64 {
                    let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                    let ch = (e & f) ^ ((!e) & g);
                    let t1 = h
                        .wrapping_add(s1)
                        .wrapping_add(ch)
                        .wrapping_add(K[i])
                        .wrapping_add(w[i]);
                    let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                    let maj = (a & b) ^ (a & c) ^ (b & c);
                    let t2 = s0.wrapping_add(maj);
                    d = c;
                    c = b;
                    b = a;
                    a = t1.wrapping_add(t2);
                }
                for (s, v) in self.0.iter_mut().zip([a, b, c, d, e, f, g, h]) {
                    *s = s.wrapping_add(v);
                }
            }
        }

        pub fn finish_hex(self) -> String {
            self.0.iter().map(|w| format!("{w:08x}")).collect()
        }

        /// One-shot hex digest, so a caller can hash a single string without
        /// constructing a `Sha256` itself.
        pub fn hash(data: &str) -> String {
            let mut h = Sha256::new();
            h.update(data.as_bytes());
            h.finish_hex()
        }
    }

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
}
