//! The local authentication boundary.
//!
//! The server binds to loopback, which is not an authorisation boundary: any
//! process on the machine, and any web page able to reach localhost, can open a
//! connection. A bearer token is therefore required on every MCP request.
//!
//! The token is generated on first use and stored with mode 0600. It is never
//! written to a log: only a short fingerprint is exposed, so an operator can
//! confirm which token is in use without the value appearing in a terminal
//! scrollback or a captured log.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::{ErrorCode, McpError};

/// The on-disk location of the token.
pub fn token_path() -> PathBuf {
    if let Ok(explicit) = std::env::var("AIEC_MCP_TOKEN_FILE")
        && !explicit.trim().is_empty()
    {
        return PathBuf::from(explicit);
    }
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|home| PathBuf::from(home).join(".config"))
        })
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("aiec").join("mcp-token")
}

/// Returns the token to use, generating and persisting one on first run.
pub fn resolve_token() -> Result<Zeroizing<String>, McpError> {
    if let Ok(value) = std::env::var("AIEC_MCP_TOKEN")
        && !value.trim().is_empty()
    {
        return Ok(Zeroizing::new(value.trim().to_owned()));
    }
    load_or_create(&token_path())
}

/// Loads the stored token, creating it with restrictive permissions if absent.
pub fn load_or_create(path: &Path) -> Result<Zeroizing<String>, McpError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let token = contents.trim().to_owned();
            if token.is_empty() {
                return Err(McpError::new(
                    ErrorCode::AuthFailed,
                    format!(
                        "the token file {} is empty; delete it to regenerate",
                        path.display()
                    ),
                ));
            }
            // A token readable by other users is not a boundary.
            ensure_private(path)?;
            Ok(Zeroizing::new(token))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let token = generate_token()?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    McpError::new(
                        ErrorCode::AuthFailed,
                        format!("create {}: {error}", parent.display()),
                    )
                })?;
                restrict_dir(parent);
            }
            write_private(path, &token)?;
            Ok(Zeroizing::new(token))
        }
        Err(error) => Err(McpError::new(
            ErrorCode::AuthFailed,
            format!("read {}: {error}", path.display()),
        )),
    }
}

/// Generates 256 bits of randomness, URL-safe encoded.
fn generate_token() -> Result<String, McpError> {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    Ok(base64url(&bytes))
}

/// Encodes without padding so the token is safe in a header.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let bits = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(bits >> 18) as usize & 63] as char);
        out.push(ALPHABET[(bits >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(bits >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[bits as usize & 63] as char);
        }
    }
    out
}

/// Writes the token so that only the owner can read it.
///
/// The file is created with the mode already set rather than created and then
/// chmod-ed, so it is never briefly world-readable.
fn write_private(path: &Path, token: &str) -> Result<(), McpError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            McpError::new(
                ErrorCode::AuthFailed,
                format!("create {}: {error}", path.display()),
            )
        })?;
    file.write_all(token.as_bytes()).map_err(|error| {
        McpError::new(
            ErrorCode::AuthFailed,
            format!("write {}: {error}", path.display()),
        )
    })?;
    Ok(())
}

fn ensure_private(path: &Path) -> Result<(), McpError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path).map_err(|error| {
        McpError::new(
            ErrorCode::AuthFailed,
            format!("stat {}: {error}", path.display()),
        )
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(McpError::new(
            ErrorCode::AuthFailed,
            format!(
                "{} is mode {:o}; it must not be readable by other users",
                path.display(),
                mode
            ),
        ));
    }
    Ok(())
}

fn restrict_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

/// Constant-time comparison, so a wrong token cannot be found byte by byte.
pub fn token_matches(expected: &str, presented: &str) -> bool {
    let expected = expected.as_bytes();
    let presented = presented.as_bytes();
    if expected.len() != presented.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in expected.iter().zip(presented) {
        difference |= a ^ b;
    }
    difference == 0
}

/// A short, non-reversible fingerprint for logs.
pub fn fingerprint(token: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in token.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aiec-mcp-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    #[test]
    fn a_token_is_generated_then_reused() {
        let path = temp_path("token");
        let first = load_or_create(&path).unwrap();
        let second = load_or_create(&path).unwrap();
        assert_eq!(&*first, &*second, "the token must be stable across calls");
        assert!(first.len() >= 43, "expected 256 bits of base64url");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn generated_tokens_are_distinct() {
        let a = generate_token().unwrap();
        let b = generate_token().unwrap();
        assert_ne!(a, b);
        assert!(!a.contains('='), "padding would break header use");
    }

    #[test]
    fn the_token_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("mode");
        let token = load_or_create(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the token must not be group or world readable");
        // And a world-readable token is refused rather than silently accepted.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_or_create(&path).is_err());
        let _ = std::fs::remove_file(&path);
        drop(token);
    }

    #[test]
    fn comparison_rejects_wrong_and_partial_tokens() {
        let token = generate_token().unwrap();
        assert!(token_matches(&token, &token));
        assert!(!token_matches(&token, "short"));
        assert!(!token_matches(&token, &format!("{token}x")));
        // Flip one character deterministically: a random token may not
        // contain the letter being replaced, which would make this vacuous.
        let mut wrong = token.clone();
        let position = token.len() - 1;
        wrong.replace_range(
            position..position + 1,
            if token.ends_with('a') { "b" } else { "a" },
        );
        assert!(!token_matches(&token, &wrong));
        assert_ne!(token, wrong);
    }

    #[test]
    fn the_fingerprint_does_not_reveal_the_token() {
        let token = generate_token().unwrap();
        let print = fingerprint(&token);
        assert_eq!(print.len(), 16);
        assert!(!token.contains(&print));
        assert_eq!(print, fingerprint(&token));
        assert_ne!(print, fingerprint(&generate_token().unwrap()));
    }
}
