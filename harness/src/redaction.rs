//! Keeping credentials out of everything that leaves the process.
//!
//! The rule is blunt: a secret that reaches the result, the event stream, the
//! session file, or a log line is a secret that has been persisted somewhere
//! this binary does not control. Redaction is therefore applied at the boundary,
//! not at the definition.

/// Environment variables whose values are treated as secrets if they appear in
/// any text. Read dynamically, so a caller can add one without a rebuild.
const SECRET_ENV_NAMES: &[&str] = &[
    "AIEC_AGENT_API_KEY",
    "AIEC_API_KEY",
    "AIEC_API_CA",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AIEC_MCP_TOKEN",
    "AIEC_CONTROL_PLANE_TOKEN",
    "AIEC_CONTROL_PLANE_URL",
    "DATABASE_URL",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
];

/// Replaces any known secret found in `text` with a marker.
///
/// The values are looked up once per call from the environment rather than
/// cached, so a key rotated mid-session is picked up and cannot be missed.
pub fn scrub(text: &str) -> String {
    let mut out = text.to_owned();
    for name in SECRET_ENV_NAMES {
        let Ok(value) = std::env::var(name) else {
            continue;
        };
        // A one or two character "secret" would match everywhere and shred the
        // output; those are not credentials in any meaningful sense.
        if value.len() < 8 {
            continue;
        }
        if out.contains(&value) {
            out = out.replace(&value, &format!("[redacted:{name}]"));
        }
    }
    out
}

/// Scrubs a serde value by walking it. Used on the result and session documents,
/// where a secret could arrive inside a tool output.
pub fn scrub_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => *s = scrub(s),
        serde_json::Value::Array(items) => items.iter_mut().for_each(scrub_value),
        serde_json::Value::Object(map) => map.values_mut().for_each(scrub_value),
        _ => {}
    }
}

/// The digest of a value, for including it in a result without the value.
///
/// The point is that a result can prove two runs used the same configuration
/// without the configuration, which may hold a secret, ever being written down.
pub fn digest(value: &str) -> String {
    crate::task::digest::Sha256::hash(value)
}
