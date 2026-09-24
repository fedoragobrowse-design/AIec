use crate::StoreError;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use reqwest::{Method, Url, header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectMetadata {
    pub key: String,
    pub size_bytes: u64,
    pub checksum_sha256: String,
    pub etag: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct GetObjectOptions {
    pub if_match: Option<String>,
    pub expected_checksum_sha256: Option<String>,
}

#[async_trait]
pub trait ObjectStore: Send + Sync {
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ObjectMetadata, StoreError>;
    async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError>;
    async fn get_checked(
        &self,
        key: &str,
        options: &GetObjectOptions,
    ) -> Result<Vec<u8>, StoreError>;
    async fn delete(&self, key: &str) -> Result<(), StoreError>;
    async fn delete_if_match(&self, key: &str, etag: &str) -> Result<(), StoreError>;
}

fn validate_object_key(key: &str) -> Result<(), StoreError> {
    if key.is_empty() || key.len() > 1024 {
        return Err(StoreError::InvalidObjectKey(
            "key must contain 1 to 1024 bytes".into(),
        ));
    }
    if key.starts_with('/')
        || key.ends_with('/')
        || key.contains('\\')
        || key.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(StoreError::InvalidObjectKey(
            "key has an unsafe path component".into(),
        ));
    }
    if key
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(StoreError::InvalidObjectKey(
            "key contains traversal or an empty component".into(),
        ));
    }
    Ok(())
}

fn checksum(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_within(root: &Path, path: &Path) -> bool {
    path == root || path.starts_with(root)
}

#[derive(Clone, Default)]
pub struct FilesystemObjectStore {
    pub root: PathBuf,
}

impl FilesystemObjectStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub async fn put(&self, key: &str, bytes: &[u8]) -> Result<ObjectMetadata, StoreError> {
        <Self as ObjectStore>::put(self, key, bytes).await
    }

    pub async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        <Self as ObjectStore>::get(self, key).await
    }

    pub async fn get_checked(
        &self,
        key: &str,
        options: &GetObjectOptions,
    ) -> Result<Vec<u8>, StoreError> {
        <Self as ObjectStore>::get_checked(self, key, options).await
    }

    pub async fn delete(&self, key: &str) -> Result<(), StoreError> {
        <Self as ObjectStore>::delete(self, key).await
    }

    pub async fn delete_if_match(&self, key: &str, etag: &str) -> Result<(), StoreError> {
        <Self as ObjectStore>::delete_if_match(self, key, etag).await
    }

    async fn root(&self) -> Result<PathBuf, StoreError> {
        tokio::fs::create_dir_all(&self.root).await?;
        Ok(tokio::fs::canonicalize(&self.root).await?)
    }

    async fn safe_path(&self, key: &str, leaf_may_be_missing: bool) -> Result<PathBuf, StoreError> {
        validate_object_key(key)?;
        let root = self.root().await?;
        let mut current = root.clone();
        let components: Vec<&str> = key.split('/').collect();
        let last = components.len().saturating_sub(1);
        for (index, component) in components.iter().enumerate() {
            current.push(component);
            match tokio::fs::symlink_metadata(&current).await {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    let resolved = tokio::fs::canonicalize(&current).await?;
                    if !is_within(&root, &resolved) {
                        return Err(StoreError::InvalidObjectKey(
                            "symlink escapes object-store root".into(),
                        ));
                    }
                    if !tokio::fs::metadata(&current).await?.is_dir() {
                        return Err(StoreError::InvalidObjectKey(
                            "symlink leaf is not a directory".into(),
                        ));
                    }
                    current = resolved;
                }
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) if index < last => {
                    return Err(StoreError::InvalidObjectKey(
                        "a parent component is not a directory".into(),
                    ));
                }
                Ok(_) if !leaf_may_be_missing => {}
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if index < last {
                        tokio::fs::create_dir(&current).await?;
                    } else if !leaf_may_be_missing {
                        return Err(error.into());
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        if current.exists() {
            let resolved = tokio::fs::canonicalize(&current).await?;
            if !is_within(&root, &resolved) {
                return Err(StoreError::InvalidObjectKey(
                    "object path escapes object-store root".into(),
                ));
            }
        }
        Ok(current)
    }

    async fn delete_path(&self, key: &str) -> Result<(), StoreError> {
        let path = self.safe_path(key, false).await?;
        match tokio::fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[async_trait]
impl ObjectStore for FilesystemObjectStore {
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ObjectMetadata, StoreError> {
        let path = self.safe_path(key, true).await?;
        let parent = path
            .parent()
            .ok_or_else(|| StoreError::InvalidObjectKey("missing object parent".into()))?;
        let temporary = parent.join(format!(".{}.tmp", Uuid::new_v4()));
        let result = async {
            let mut file = tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .await?;
            tokio::io::AsyncWriteExt::write_all(&mut file, bytes).await?;
            file.sync_all().await?;
            drop(file);
            tokio::fs::rename(&temporary, &path).await?;
            Ok::<(), std::io::Error>(())
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&temporary).await;
        }
        result?;
        Ok(ObjectMetadata {
            key: key.to_owned(),
            size_bytes: bytes.len() as u64,
            checksum_sha256: checksum(bytes),
            etag: None,
        })
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        self.get_checked(key, &GetObjectOptions::default()).await
    }

    async fn get_checked(
        &self,
        key: &str,
        options: &GetObjectOptions,
    ) -> Result<Vec<u8>, StoreError> {
        if let Some(expected) = &options.expected_checksum_sha256 {
            validate_checksum(expected)?;
        }
        let path = self.safe_path(key, false).await?;
        let bytes = tokio::fs::read(path).await?;
        if let Some(expected) = &options.expected_checksum_sha256
            && !actual_checksum(&bytes, expected)?
        {
            return Err(StoreError::ObjectStore(
                "stored object checksum mismatch".into(),
            ));
        }
        Ok(bytes)
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.delete_path(key).await
    }

    async fn delete_if_match(&self, key: &str, _etag: &str) -> Result<(), StoreError> {
        self.delete_path(key).await
    }
}

fn validate_checksum(expected: &str) -> Result<(), StoreError> {
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StoreError::InvalidObjectKey(
            "expected SHA-256 must be 64 hexadecimal characters".into(),
        ));
    }
    Ok(())
}

fn actual_checksum(bytes: &[u8], expected: &str) -> Result<bool, StoreError> {
    validate_checksum(expected)?;
    Ok(checksum(bytes).eq_ignore_ascii_case(expected))
}

#[derive(Clone)]
pub struct S3Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub prefix: String,
    pub request_timeout: Duration,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:9000".into(),
            region: "us-east-1".into(),
            bucket: "agentforge".into(),
            access_key_id: String::new(),
            secret_access_key: String::new(),
            prefix: String::new(),
            request_timeout: Duration::from_secs(30),
        }
    }
}

impl S3Config {
    fn validate(&self) -> Result<(), StoreError> {
        let endpoint = Url::parse(&self.endpoint)
            .map_err(|error| StoreError::ObjectStore(error.to_string()))?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(StoreError::ObjectStore(
                "S3 endpoint must be an HTTP(S) origin without credentials, query, or fragment"
                    .into(),
            ));
        }
        if !(3..=63).contains(&self.bucket.len())
            || self.bucket.starts_with('-')
            || self.bucket.ends_with('-')
            || !self
                .bucket
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(StoreError::ObjectStore("invalid S3 bucket name".into()));
        }
        if self.region.is_empty()
            || self.access_key_id.is_empty()
            || self.secret_access_key.is_empty()
        {
            return Err(StoreError::ObjectStore(
                "S3 region and credentials are required".into(),
            ));
        }
        if !self.prefix.is_empty() {
            validate_object_key(self.prefix.trim_end_matches('/'))?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct S3ObjectStore {
    client: reqwest::Client,
    config: S3Config,
}

struct SignedRequest {
    url: Url,
    headers: header::HeaderMap,
}

impl S3ObjectStore {
    pub fn new(config: S3Config) -> Result<Self, StoreError> {
        config.validate()?;
        let client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(|error| StoreError::ObjectStore(error.to_string()))?;
        Ok(Self { client, config })
    }

    pub async fn put(&self, key: &str, bytes: &[u8]) -> Result<ObjectMetadata, StoreError> {
        <Self as ObjectStore>::put(self, key, bytes).await
    }

    pub async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        <Self as ObjectStore>::get(self, key).await
    }

    pub async fn get_checked(
        &self,
        key: &str,
        options: &GetObjectOptions,
    ) -> Result<Vec<u8>, StoreError> {
        <Self as ObjectStore>::get_checked(self, key, options).await
    }

    pub async fn delete(&self, key: &str) -> Result<(), StoreError> {
        <Self as ObjectStore>::delete(self, key).await
    }

    pub async fn delete_if_match(&self, key: &str, etag: &str) -> Result<(), StoreError> {
        <Self as ObjectStore>::delete_if_match(self, key, etag).await
    }

    fn full_key(&self, key: &str) -> Result<String, StoreError> {
        validate_object_key(key)?;
        if self.config.prefix.is_empty() {
            return Ok(key.to_owned());
        }
        Ok(format!(
            "{}/{}",
            self.config.prefix.trim_end_matches('/'),
            key
        ))
    }

    fn object_url(&self, key: &str) -> Result<Url, StoreError> {
        let endpoint = self.config.endpoint.trim_end_matches('/');
        let encoded_key = key.split('/').map(uri_encode).collect::<Vec<_>>().join("/");
        Url::parse(&format!(
            "{endpoint}/{}/{}",
            self.config.bucket, encoded_key
        ))
        .map_err(|error| StoreError::ObjectStore(error.to_string()))
    }

    fn sign(
        &self,
        method: &Method,
        key: &str,
        body_hash: &str,
        extra_headers: &[(&str, String)],
        now: DateTime<Utc>,
    ) -> Result<SignedRequest, StoreError> {
        let url = self.object_url(key)?;
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let host = host_header(&url)?;
        let mut headers: Vec<(String, String)> = vec![
            ("host".into(), host),
            ("x-amz-content-sha256".into(), body_hash.into()),
            ("x-amz-date".into(), amz_date.clone()),
        ];
        headers.extend(
            extra_headers
                .iter()
                .map(|(name, value)| ((*name).to_ascii_lowercase(), value.clone())),
        );
        headers.sort_by(|left, right| left.0.cmp(&right.0));
        let canonical_headers = headers
            .iter()
            .map(|(name, value)| format!("{name}:{}\n", value.trim()))
            .collect::<String>();
        let signed_headers = headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            url.path(),
            canonical_query(&url),
            canonical_headers,
            signed_headers,
            body_hash
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.config.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );
        let date_key = hmac(
            format!("AWS4{}", self.config.secret_access_key).as_bytes(),
            date.as_bytes(),
        );
        let region_key = hmac(&date_key, self.config.region.as_bytes());
        let service_key = hmac(&region_key, b"s3");
        let signing_key = hmac(&service_key, b"aws4_request");
        let signature = hex::encode(hmac(&signing_key, string_to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.config.access_key_id
        );

        let mut request_headers = header::HeaderMap::new();
        for (name, value) in headers {
            request_headers.insert(
                header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|error| StoreError::ObjectStore(error.to_string()))?,
                header::HeaderValue::from_str(&value)
                    .map_err(|error| StoreError::ObjectStore(error.to_string()))?,
            );
        }
        request_headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&authorization)
                .map_err(|error| StoreError::ObjectStore(error.to_string()))?,
        );
        Ok(SignedRequest {
            url,
            headers: request_headers,
        })
    }

    fn signed(
        &self,
        method: Method,
        key: &str,
        body_hash: &str,
        extra_headers: &[(&str, String)],
    ) -> Result<SignedRequest, StoreError> {
        self.sign(&method, key, body_hash, extra_headers, Utc::now())
    }
}

#[async_trait]
impl ObjectStore for S3ObjectStore {
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ObjectMetadata, StoreError> {
        let full_key = self.full_key(key)?;
        let digest = Sha256::digest(bytes);
        let body_hash = hex::encode(digest);
        let checksum = BASE64.encode(digest);
        let signed = self.signed(
            Method::PUT,
            &full_key,
            &body_hash,
            &[
                ("content-type", "application/octet-stream".into()),
                ("if-none-match", "*".into()),
                ("x-amz-checksum-sha256", checksum.clone()),
            ],
        )?;
        let response = self
            .client
            .request(Method::PUT, signed.url)
            .headers(signed.headers)
            .body(Bytes::copy_from_slice(bytes))
            .send()
            .await
            .map_err(|error| StoreError::ObjectStore(error.to_string()))?;
        let response = require_success(response).await?;
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        Ok(ObjectMetadata {
            key: key.to_owned(),
            size_bytes: bytes.len() as u64,
            checksum_sha256: body_hash,
            etag,
        })
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        self.get_checked(key, &GetObjectOptions::default()).await
    }

    async fn get_checked(
        &self,
        key: &str,
        options: &GetObjectOptions,
    ) -> Result<Vec<u8>, StoreError> {
        let key = self.full_key(key)?;
        if let Some(expected) = &options.expected_checksum_sha256 {
            validate_checksum(expected)?;
        }
        let mut signed_headers = Vec::new();
        if let Some(etag) = &options.if_match {
            signed_headers.push(("if-match", etag.clone()));
        }
        let signed = self.signed(Method::GET, &key, EMPTY_SHA256, &signed_headers)?;
        let response = self
            .client
            .request(Method::GET, signed.url)
            .headers(signed.headers)
            .send()
            .await
            .map_err(|error| StoreError::ObjectStore(error.to_string()))?;
        let remote_checksum = response
            .headers()
            .get("x-amz-checksum-sha256")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = require_success(response)
            .await?
            .bytes()
            .await
            .map_err(|error| StoreError::ObjectStore(error.to_string()))?;
        let actual = checksum(&bytes);
        if let Some(remote) = remote_checksum {
            let remote = remote.trim_matches('"');
            let digest = BASE64.decode(remote).map_err(|error| {
                StoreError::ObjectStore(format!("invalid S3 response checksum: {error}"))
            })?;
            if hex::encode(digest) != actual {
                return Err(StoreError::ObjectStore(
                    "S3 response checksum mismatch".into(),
                ));
            }
        }
        if let Some(expected) = &options.expected_checksum_sha256
            && !actual_checksum(&bytes, expected)?
        {
            return Err(StoreError::ObjectStore(
                "S3 object checksum mismatch".into(),
            ));
        }
        if options.if_match.is_some()
            && etag.as_deref().map(|value| value.trim_matches('"'))
                != options
                    .if_match
                    .as_deref()
                    .map(|value| value.trim_matches('"'))
        {
            return Err(StoreError::ObjectStore(
                "S3 ETag precondition failed".into(),
            ));
        }
        Ok(bytes.to_vec())
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        let key = self.full_key(key)?;
        let signed = self.signed(Method::DELETE, &key, EMPTY_SHA256, &[])?;
        let response = self
            .client
            .request(Method::DELETE, signed.url)
            .headers(signed.headers)
            .send()
            .await
            .map_err(|error| StoreError::ObjectStore(error.to_string()))?;
        require_success(response).await?;
        Ok(())
    }

    async fn delete_if_match(&self, key: &str, etag: &str) -> Result<(), StoreError> {
        let key = self.full_key(key)?;
        let signed = self.signed(
            Method::DELETE,
            &key,
            EMPTY_SHA256,
            &[("if-match", etag.into())],
        )?;
        let response = self
            .client
            .request(Method::DELETE, signed.url)
            .headers(signed.headers)
            .send()
            .await
            .map_err(|error| StoreError::ObjectStore(error.to_string()))?;
        require_success(response).await?;
        Ok(())
    }
}

fn hmac(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    mac.update(value);
    mac.finalize().into_bytes().to_vec()
}

fn uri_encode(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn canonical_query(url: &Url) -> String {
    let mut pairs = url
        .query_pairs()
        .map(|(name, value)| (uri_encode(&name), uri_encode(&value)))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn host_header(url: &Url) -> Result<String, StoreError> {
    let host = url
        .host_str()
        .ok_or_else(|| StoreError::ObjectStore("S3 endpoint has no host".into()))?;
    let host = match url.port() {
        None | Some(443) if url.scheme() == "https" => host.to_owned(),
        Some(80) if url.scheme() == "http" => host.to_owned(),
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    Ok(host)
}

async fn require_success(response: reqwest::Response) -> Result<reqwest::Response, StoreError> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| StoreError::ObjectStore(error.to_string()))?;
    let body: String = body.chars().take(1024).collect();
    Err(StoreError::ObjectStore(format!(
        "S3 request returned {status}: {body}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> S3ObjectStore {
        S3ObjectStore::new(S3Config {
            endpoint: "https://s3.example.test".into(),
            region: "us-east-1".into(),
            bucket: "agentforge-test".into(),
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            prefix: "tenant-a".into(),
            request_timeout: Duration::from_secs(5),
        })
        .expect("test configuration")
    }

    #[test]
    fn rejects_unsafe_keys() {
        for key in [
            "",
            "/absolute",
            "../escape",
            "safe/../escape",
            "a//b",
            "a\\b",
        ] {
            assert!(validate_object_key(key).is_err(), "accepted {key:?}");
        }
        assert!(validate_object_key("tenant/sandbox-123/manifest.json").is_ok());
    }

    #[test]
    fn filesystem_store_rejects_symlink_escape() {
        let root = std::env::temp_dir().join(format!("agentforge-store-{}", Uuid::new_v4()));
        let outside = std::env::temp_dir().join(format!("agentforge-outside-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        let store = FilesystemObjectStore::new(&root);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        assert!(runtime.block_on(store.delete("escape/file")).is_err());
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(outside);
    }

    #[test]
    fn signs_the_aws_v4_canonical_request() {
        let signed = store()
            .sign(
                &Method::PUT,
                "tenant-a/sandbox/manifest.json",
                &Sha256::digest(b"payload")
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                &[
                    ("content-type", "application/octet-stream".into()),
                    ("if-none-match", "*".into()),
                    (
                        "x-amz-checksum-sha256",
                        BASE64.encode(Sha256::digest(b"payload")),
                    ),
                ],
                DateTime::parse_from_rfc3339("2015-08-30T12:36:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            )
            .unwrap();
        assert_eq!(
            signed.url.as_str(),
            "https://s3.example.test/agentforge-test/tenant-a/sandbox/manifest.json"
        );
        let authorization = signed
            .headers
            .get(header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, \
             SignedHeaders=content-type;host;if-none-match;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date, \
             Signature=079b20c367323ea3d6d860bfcc83daf2794808d24bb2a1b11c082828c9cc4308"
        );
    }
}
