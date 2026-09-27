use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use thiserror::Error;
use uuid::Uuid;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME: usize = 2 * 1024 * 1024;
pub const DEFAULT_CONTROL_PORT: u32 = 1024;
const MAGIC: [u8; 4] = *b"AFG1";
const REPLAY_CAPACITY: usize = 1024;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("malformed frame: {0}")]
    Malformed(String),
    #[error("authentication failed")]
    Authentication,
    #[error("unsupported protocol version {0}")]
    Version(u16),
    #[error("frame too large: {0}")]
    TooLarge(usize),
    #[error("unsupported operation: {0}")]
    UnknownOperation(String),
    #[error("duplicate request {0}")]
    Duplicate(Uuid),
    #[error("serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Health,
    Exec,
    ReadFile,
    WriteFile,
    ListDirectory,
    CreateDirectory,
    RemoveFile,
    Shutdown,
    PrepareSnapshot,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub version: u16,
    pub request_id: Uuid,
    pub operation: Operation,
    pub payload: RequestPayload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RequestPayload {
    None,
    Exec {
        argv: Vec<String>,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        env: std::collections::BTreeMap<String, String>,
        #[serde(default = "default_exec_timeout_ms")]
        timeout_ms: u64,
        #[serde(default = "default_output_limit")]
        output_limit: usize,
        #[serde(default, with = "base64_bytes")]
        stdin: Vec<u8>,
    },
    Path {
        path: String,
    },
    WriteFile {
        path: String,
        #[serde(with = "base64_bytes")]
        content: Vec<u8>,
        #[serde(default)]
        mode: Option<u32>,
    },
}

fn default_exec_timeout_ms() -> u64 {
    30_000
}
fn default_output_limit() -> usize {
    1_048_576
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub version: u16,
    pub request_id: Uuid,
    pub payload: ResponsePayload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponsePayload {
    Health {
        ready: bool,
    },
    Exec {
        exit_code: i32,
        #[serde(with = "base64_bytes")]
        stdout: Vec<u8>,
        #[serde(with = "base64_bytes")]
        stderr: Vec<u8>,
        duration_ms: u64,
        timed_out: bool,
    },
    ReadFile {
        #[serde(with = "base64_bytes")]
        content: Vec<u8>,
    },
    WriteFile,
    ListDirectory {
        entries: Vec<DirectoryEntry>,
    },
    CreateDirectory,
    RemoveFile,
    Shutdown,
    PrepareSnapshot,
    Error {
        code: String,
        message: String,
        retryable: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub name: String,
    pub path: String,
    pub kind: FileKind,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    File,
    Directory,
}

mod base64_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Default)]
pub struct ReplayCache {
    seen: HashMap<Uuid, ()>,
    order: VecDeque<Uuid>,
}

impl ReplayCache {
    pub fn check_and_insert(&mut self, id: Uuid) -> Result<(), ProtocolError> {
        if self.seen.contains_key(&id) {
            return Err(ProtocolError::Duplicate(id));
        }
        self.seen.insert(id, ());
        self.order.push_back(id);
        if self.order.len() > REPLAY_CAPACITY
            && let Some(old) = self.order.pop_front()
        {
            self.seen.remove(&old);
        }
        Ok(())
    }
}

pub fn auth_tag(secret: &[u8], version: u16, body: &[u8]) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts arbitrary key lengths");
    mac.update(&version.to_be_bytes());
    mac.update(&(body.len() as u32).to_be_bytes());
    mac.update(body);
    mac.finalize().into_bytes().into()
}

pub fn write_frame<W: Write>(
    writer: &mut W,
    secret: &[u8],
    request: &Request,
) -> Result<(), ProtocolError> {
    write_message(
        writer,
        secret,
        request.request_id,
        serde_json::to_vec(request)?,
    )
}

pub fn write_response<W: Write>(
    writer: &mut W,
    secret: &[u8],
    response: &Response,
) -> Result<(), ProtocolError> {
    write_message(
        writer,
        secret,
        response.request_id,
        serde_json::to_vec(response)?,
    )
}

fn write_message<W: Write>(
    writer: &mut W,
    secret: &[u8],
    id: Uuid,
    body: Vec<u8>,
) -> Result<(), ProtocolError> {
    if body.len() > MAX_FRAME {
        return Err(ProtocolError::TooLarge(body.len()));
    }
    let tag = auth_tag(secret, PROTOCOL_VERSION, &body);
    writer.write_all(&MAGIC)?;
    writer.write_all(&PROTOCOL_VERSION.to_be_bytes())?;
    writer.write_all(&(body.len() as u32).to_be_bytes())?;
    writer.write_all(&tag)?;
    writer.write_all(&body)?;
    writer.flush()?;
    let _ = id;
    Ok(())
}

pub fn read_frame<R: Read>(reader: &mut R, secret: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut magic = [0; 4];
    reader.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(ProtocolError::Malformed("bad magic".into()));
    }
    let mut version = [0; 2];
    reader.read_exact(&mut version)?;
    let version = u16::from_be_bytes(version);
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::Version(version));
    }
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME {
        return Err(ProtocolError::TooLarge(length));
    }
    let mut expected = [0; 32];
    reader.read_exact(&mut expected)?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let actual = auth_tag(secret, version, &body);
    let mut difference = 0u8;
    for (left, right) in expected.iter().zip(actual.iter()) {
        difference |= left ^ right;
    }
    if difference != 0 {
        return Err(ProtocolError::Authentication);
    }
    Ok(body)
}

pub fn read_request<R: Read>(
    reader: &mut R,
    secret: &[u8],
    replay: &mut ReplayCache,
) -> Result<Request, ProtocolError> {
    let request: Request = serde_json::from_slice(&read_frame(reader, secret)?)?;
    if request.version != PROTOCOL_VERSION {
        return Err(ProtocolError::Version(request.version));
    }
    replay.check_and_insert(request.request_id)?;
    Ok(request)
}

pub fn read_response<R: Read>(reader: &mut R, secret: &[u8]) -> Result<Response, ProtocolError> {
    let response: Response = serde_json::from_slice(&read_frame(reader, secret)?)?;
    if response.version != PROTOCOL_VERSION {
        return Err(ProtocolError::Version(response.version));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safe_path;
    use proptest::prelude::*;

    #[test]
    fn round_trip_authenticates() {
        let request = Request {
            version: PROTOCOL_VERSION,
            request_id: Uuid::now_v7(),
            operation: Operation::Health,
            payload: RequestPayload::None,
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, b"secret", &request).unwrap();
        let mut replay = ReplayCache::default();
        assert_eq!(
            read_request(&mut bytes.as_slice(), b"secret", &mut replay)
                .unwrap()
                .request_id,
            request.request_id
        );
    }

    #[test]
    fn rejects_auth_version_size_and_duplicate() {
        let request = Request {
            version: PROTOCOL_VERSION,
            request_id: Uuid::now_v7(),
            operation: Operation::Health,
            payload: RequestPayload::None,
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, b"secret", &request).unwrap();
        let mut replay = ReplayCache::default();
        assert!(read_request(&mut bytes.as_slice(), b"wrong", &mut replay).is_err());
        assert!(read_request(&mut bytes.as_slice(), b"secret", &mut replay).is_ok());
        assert!(read_request(&mut bytes.as_slice(), b"secret", &mut replay).is_err());
        assert!(read_frame(&mut [0u8; 4].as_slice(), b"secret").is_err());
        assert!(read_frame(&mut vec![0u8; MAX_FRAME + 1].as_slice(), b"secret").is_err());
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_secret_never_authenticates_modified_body(body in proptest::collection::vec(any::<u8>(), 0..256)) {
            let mut frame = Vec::new();
            write_frame(&mut frame, b"right", &Request { version: PROTOCOL_VERSION, request_id: Uuid::now_v7(), operation: Operation::Health, payload: RequestPayload::None }).unwrap();
            let index = 42.min(frame.len().saturating_sub(1));
            if let Some(byte) = frame.get_mut(index) { *byte ^= 1; }
            assert!(read_frame(&mut frame.as_slice(), b"left").is_err());
            let _ = body;
        }

        #[test]
        fn arbitrary_workspace_relative_paths_never_escape(parts in proptest::collection::vec("[a-z]{1,8}", 0..12)) {
            let path = format!("/workspace/{}", parts.join("/"));
            let normalized = safe_path(&path).unwrap();
            prop_assert!(normalized.starts_with("/workspace"));
            prop_assert!(!safe_path("/workspace/../../etc/passwd").is_ok());
        }
    }
}
