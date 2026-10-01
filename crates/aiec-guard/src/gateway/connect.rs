use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) async fn connect(
    mut request: Request<Body>,
    state: Arc<Runtime>,
    permit: OwnedSemaphorePermit,
) -> Response<Body> {
    let Some(authority) = request.uri().authority() else {
        return deny(&state, "CONNECT authority missing", StatusCode::BAD_REQUEST).await;
    };
    let host = authority.host().to_owned();
    let Some(port) = authority.port_u16() else {
        return deny(
            &state,
            "CONNECT requires explicit port",
            StatusCode::BAD_REQUEST,
        )
        .await;
    };
    if request.uri().scheme().is_some()
        || authority.as_str().contains('@')
        || request.headers().get("host").and_then(|v| v.to_str().ok()) != Some(authority.as_str())
        || request.headers().contains_key("authorization")
        || request.headers().contains_key("x-api-key")
        || request.headers().contains_key("content-length")
        || request.headers().contains_key("transfer-encoding")
        || request
            .headers()
            .iter()
            .any(|(_, v)| v.as_bytes().windows(14).any(|w| w == b"placeholder://"))
    {
        return deny(
            &state,
            "CONNECT identity or credentials denied",
            StatusCode::FORBIDDEN,
        )
        .await;
    }
    if state
        .config
        .compiled
        .policy()
        .model
        .as_ref()
        .is_some_and(|m| m.host == host)
    {
        return deny(
            &state,
            "model destination requires broker",
            StatusCode::FORBIDDEN,
        )
        .await;
    }
    let Some(rule) = state.config.compiled.endpoint(&host, port) else {
        return deny(&state, "CONNECT destination denied", StatusCode::FORBIDDEN).await;
    };
    if !rule.allowed_methods.is_empty() || !rule.allowed_paths.is_empty() {
        return deny(
            &state,
            "opaque TLS cannot enforce HTTP methods or paths",
            StatusCode::FORBIDDEN,
        )
        .await;
    }
    let addresses = match state.resolve(&host, port).await {
        Ok(a) => a,
        Err(_) => {
            return deny(
                &state,
                "CONNECT destination resolution denied",
                StatusCode::FORBIDDEN,
            )
            .await;
        }
    };
    let upgrade = hyper::upgrade::on(&mut request);
    // Registered managed tasks preserve concurrency permits and cancel at cut/shutdown.
    let task_state = state.clone();
    let mut cancel = state.stop.subscribe();
    let task = tokio::spawn(async move {
        let _permit = permit;
        let audit = Arc::new(AuditMutex::new(Audit {
            state: task_state.clone(),
            category: Category::Network,
            destination: format!("{host}:{port}"),
            start: Instant::now(),
            out: 0,
            incoming: 0,
            allowed: false,
            reason: "TLS tunnel denied or cancelled",
            status: 200,
        }));
        let tunnel = async {
            let upgraded = tokio::time::timeout(IDLE, upgrade)
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            let mut guest = TokioIo::new(upgraded);
            let (hello, sni) = tokio::time::timeout(IDLE, read_client_hello(&mut guest))
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            if sni != host {
                return Err(());
            }
            task_state.debit(true, hello.len() as u64).map_err(|_| ())?;
            audit.lock().out = hello.len() as u64;
            if hello.len() as u64 > task_state.config.compiled.policy().limits.max_request_bytes {
                return Err(());
            }
            task_state
                .record(task_state.measured_event(
                    Category::Network,
                    Decision::Allow,
                    "CONNECT authority and visible SNI agree; opaque HTTP uninspected",
                    Some(format!("{host}:{port}")),
                    hello.len() as u64,
                    0,
                    Duration::ZERO,
                ))
                .await
                .map_err(|_| ())?;
            // Dial only pinned addresses after the visible TLS identity agrees. No trust in client DNS.
            let mut upstream = tokio::time::timeout(
                Duration::from_secs(5),
                TcpStream::connect(addresses.as_slice()),
            )
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
            tokio::time::timeout(IDLE, upstream.write_all(&hello))
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
            let (guest_read, guest_write) = tokio::io::split(guest);
            let (up_read, up_write) = upstream.split();
            tokio::try_join!(
                pump(
                    guest_read,
                    up_write,
                    task_state.clone(),
                    audit.clone(),
                    true,
                    hello.len() as u64
                ),
                pump(
                    up_read,
                    guest_write,
                    task_state.clone(),
                    audit.clone(),
                    false,
                    0
                )
            )?;
            let mut a = audit.lock();
            a.allowed = true;
            a.reason = "TLS tunnel complete";
            Ok::<(), ()>(())
        };
        tokio::select! { _ = cancel.changed() => {}, _ = tokio::time::sleep(LIFETIME) => {}, _ = tunnel => {} }
    });
    match state.tunnels.lock() {
        Ok(mut tunnels) => {
            tunnels.retain(|task| !task.is_finished());
            tunnels.push(task);
        }
        Err(_) => {
            task.abort();
            return response(
                StatusCode::SERVICE_UNAVAILABLE,
                "tunnel manager unavailable",
            );
        }
    }
    response(StatusCode::OK, "")
}

async fn pump<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    state: Arc<Runtime>,
    audit: Arc<AuditMutex<Audit>>,
    outgoing: bool,
    mut count: u64,
) -> std::result::Result<(), ()> {
    let mut buffer = [0; CHUNK];
    loop {
        let size = tokio::time::timeout(IDLE, reader.read(&mut buffer))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
        if size == 0 {
            writer.shutdown().await.map_err(|_| ())?;
            return Ok(());
        }
        count = count.saturating_add(size as u64);
        {
            let mut a = audit.lock();
            if outgoing {
                a.out = count;
            } else {
                a.incoming = count;
            }
        }
        state.debit(outgoing, size as u64).map_err(|_| ())?;
        let cap = if outgoing {
            state.config.compiled.policy().limits.max_request_bytes
        } else {
            state.config.compiled.policy().limits.max_response_bytes
        };
        if count > cap || !state.active() {
            return Err(());
        }
        tokio::time::timeout(IDLE, writer.write_all(&buffer[..size]))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
    }
}

async fn read_client_hello<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<(Vec<u8>, String)> {
    let mut wire = Vec::with_capacity(4096);
    let mut handshake = Vec::with_capacity(4096);
    loop {
        let mut header = [0; 5];
        reader.read_exact(&mut header).await?;
        let size = u16::from_be_bytes([header[3], header[4]]) as usize;
        if header[0] != 22
            || header[1] != 3
            || !(1..=3).contains(&header[2])
            || size == 0
            || size > 16384
            || wire.len() + size + 5 > 32768
        {
            return Err(std::io::Error::other("invalid TLS hello"));
        }
        wire.extend_from_slice(&header);
        let start = handshake.len();
        handshake.resize(start + size, 0);
        reader.read_exact(&mut handshake[start..]).await?;
        wire.extend_from_slice(&handshake[start..]);
        if handshake.len() < 4 {
            continue;
        }
        let length = ((handshake[1] as usize) << 16)
            | ((handshake[2] as usize) << 8)
            | handshake[3] as usize;
        if handshake[0] != 1 || length > 16384 {
            return Err(std::io::Error::other("invalid TLS hello"));
        }
        if handshake.len() < length + 4 {
            continue;
        }
        // No early data, a second handshake, or opaque bytes smuggled in the identity record.
        if handshake.len() != length + 4 {
            return Err(std::io::Error::other("ambiguous TLS hello"));
        }
        let sni = parse_sni(&handshake[4..])
            .ok_or_else(|| std::io::Error::other("missing or invalid visible TLS identity"))?;
        return Ok((wire, sni));
    }
}
fn take<'a>(input: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    if input.len() < len {
        return None;
    }
    let (a, b) = input.split_at(len);
    *input = b;
    Some(a)
}
fn number(input: &mut &[u8]) -> Option<usize> {
    let b = take(input, 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]) as usize)
}
fn parse_sni(mut hello: &[u8]) -> Option<String> {
    let version = take(&mut hello, 2)?;
    if version != [3, 3] && version != [3, 1] {
        return None;
    }
    take(&mut hello, 32)?;
    let sid = *take(&mut hello, 1)?.first()? as usize;
    if sid > 32 {
        return None;
    }
    take(&mut hello, sid)?;
    let ciphers = number(&mut hello)?;
    if ciphers < 2 || ciphers % 2 != 0 {
        return None;
    }
    take(&mut hello, ciphers)?;
    let compression = *take(&mut hello, 1)?.first()? as usize;
    if compression != 1 || take(&mut hello, compression)? != [0] {
        return None;
    }
    let extensions = number(&mut hello)?;
    if extensions != hello.len() {
        return None;
    }
    let mut seen = std::collections::HashSet::new();
    let mut sni = None;
    while !hello.is_empty() {
        let kind = number(&mut hello)?;
        let size = number(&mut hello)?;
        let mut data = take(&mut hello, size)?;
        if !seen.insert(kind) || kind == 0xfe0d || kind == 42 {
            return None;
        } // ECH / early_data obscure routing or replay semantics.
        if kind == 0 {
            let total = number(&mut data)?;
            if total != data.len() {
                return None;
            }
            if *take(&mut data, 1)?.first()? != 0 {
                return None;
            }
            let len = number(&mut data)?;
            let name = std::str::from_utf8(take(&mut data, len)?).ok()?;
            if !data.is_empty()
                || name.is_empty()
                || name.len() > 253
                || name != name.to_ascii_lowercase()
                || name.split('.').any(|l| {
                    l.is_empty()
                        || l.len() > 63
                        || l.starts_with('-')
                        || l.ends_with('-')
                        || !l
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                })
            {
                return None;
            }
            sni = Some(name.to_owned());
        }
    }
    sni
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hello(name: &str) -> Vec<u8> {
        let mut h = vec![3, 3];
        h.extend([0; 32]);
        h.push(0);
        h.extend([0, 2, 0x13, 1, 1, 0]);
        let mut names = vec![0];
        names.extend((name.len() as u16).to_be_bytes());
        names.extend(name.as_bytes());
        let mut extension = Vec::new();
        extension.extend((names.len() as u16).to_be_bytes());
        extension.extend(names);
        h.extend(((extension.len() + 4) as u16).to_be_bytes());
        h.extend([0, 0]);
        h.extend((extension.len() as u16).to_be_bytes());
        h.extend(extension);
        h
    }
    #[test]
    fn visible_sni_is_unambiguous_and_dns_shaped() {
        assert_eq!(
            parse_sni(&hello("allowed.example")),
            Some("allowed.example".into())
        );
        assert!(parse_sni(&hello("ALLOWED.example")).is_none());
        assert!(parse_sni(&hello("a..example")).is_none());
        let mut h = hello("allowed.example");
        h.push(0);
        assert!(parse_sni(&h).is_none());
        for size in 0..hello("allowed.example").len() {
            assert!(parse_sni(&hello("allowed.example")[..size]).is_none());
        }
    }
}
