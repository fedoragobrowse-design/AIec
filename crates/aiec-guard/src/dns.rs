//! DNS is authoritative for policy names; denied names never reach a resolver.
use crate::{
    Result,
    events::{Category, Decision},
    gateway::Runtime,
};
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{
        DNSClass, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    task::JoinSet,
};
const DNS_FRAME: usize = 4096;

pub(crate) async fn serve_udp(socket: UdpSocket, state: Arc<Runtime>) -> Result<()> {
    let mut stop = state.stop.subscribe();
    let mut bytes = [0; DNS_FRAME + 1];
    // Serial UDP processing bounds work and memory; DNS resolver and sink have finite deadlines.
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => { if *stop.borrow() == u64::MAX { break; } }
            packet = socket.recv_from(&mut bytes) => {
                let (size, peer) = packet?;
                if peer.ip() != IpAddr::V4(state.config.guest_ip) {
                    state.record(state.measured_event(Category::Dns, Decision::Deny, "DNS guest source mismatch", None, size as u64, 0, Duration::ZERO)).await?;
                    continue;
                }
                let reply = answer(&bytes[..size], &state, false).await?;
                if let Some(reply) = reply { socket.send_to(&reply, peer).await?; }
            }
        }
    }
    Ok(())
}

pub(crate) async fn serve_tcp(listener: TcpListener, state: Arc<Runtime>) -> Result<()> {
    let mut stop = state.stop.subscribe();
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => { if *stop.borrow() == u64::MAX { break; } }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => {
                let (mut socket, peer) = accepted?;
                if peer.ip() != IpAddr::V4(state.config.guest_ip) {
                    state.record(state.measured_event(Category::Dns, Decision::Deny, "DNS guest source mismatch", None, 0, 0, Duration::ZERO)).await?; continue;
                }
                let Ok(permit) = state.connections.clone().try_acquire_owned() else { continue; };
                let state = state.clone();
                tasks.spawn(async move {
                    let _permit = permit; let mut stop = state.stop.subscribe();
                    let process = async {
                        // One bounded frame per connection. Clients can reopen for another question.
                        let size = socket.read_u16().await? as usize;
                        if size == 0 || size > DNS_FRAME {
                            let _ = state.rate(true);
                            let _ = state.debit(true, 2);
                            state.record(state.measured_event(Category::Dns, Decision::Deny, "DNS TCP frame too large or empty", None, 2, 0, Duration::ZERO)).await?;
                            return Ok::<(), crate::GuardError>(());
                        }
                        let mut bytes = vec![0; size]; socket.read_exact(&mut bytes).await?;
                        if let Some(reply) = answer(&bytes, &state, true).await? {
                            socket.write_u16(reply.len() as u16).await?; socket.write_all(&reply).await?;
                        }
                        socket.shutdown().await?; Ok(())
                    };
                    tokio::select! { _ = stop.changed() => {}, _ = tokio::time::sleep(Duration::from_secs(15)) => {}, _ = process => {} }
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn answer(bytes: &[u8], state: &Runtime, tcp: bool) -> Result<Option<Vec<u8>>> {
    let start = Instant::now();
    let id = if bytes.len() >= 2 {
        u16::from_be_bytes([bytes[0], bytes[1]])
    } else {
        0
    };
    let mut reply = Message::new();
    reply
        .set_id(id)
        .set_message_type(MessageType::Response)
        .set_authoritative(true)
        .set_recursion_available(false);
    let mut decision = Decision::Deny;
    let mut reason = "malformed DNS query";
    let mut destination = None;
    if state.debit(true, bytes.len() as u64).is_err() {
        state
            .record(state.measured_event(
                Category::Dns,
                Decision::Deny,
                "DNS outbound byte budget exhausted",
                None,
                bytes.len() as u64,
                0,
                start.elapsed(),
            ))
            .await?;
        return Ok(None);
    }
    if !state.active() {
        reply.set_response_code(ResponseCode::Refused);
        reason = "gateway cut";
    } else if state.rate(true).is_err() {
        reply.set_response_code(ResponseCode::Refused);
        reason = "DNS rate exhausted";
    } else if bytes.len() > DNS_FRAME || bytes.len() < 12 || !raw_question_valid(bytes) {
        reply.set_response_code(ResponseCode::FormErr);
    } else if let Ok(query) = Message::from_vec(bytes) {
        // Prevent parser differential attacks: parse/reencode alone is not sufficient; reject
        // question compression (unnecessary for one question), trailing wire data and all additions.
        let shape_valid = query.message_type() == MessageType::Query
            && query.op_code() == OpCode::Query
            && query.queries().len() == 1
            && query.answers().is_empty()
            && query.name_servers().is_empty()
            && query.additionals().is_empty()
            && raw_question_valid(bytes);
        if !shape_valid {
            reply.set_response_code(ResponseCode::FormErr);
        } else {
            let q = &query.queries()[0];
            let name = q
                .name()
                .to_ascii()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            let kind = q.query_type();
            let valid_name = name.len() <= 253
                && !name.is_empty()
                && name.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                });
            reply.add_query(q.clone());
            let port = state
                .config
                .compiled
                .policy()
                .network
                .egress
                .iter()
                .find(|rule| rule.host == name)
                .map(|rule| rule.port);
            if valid_name {
                destination = Some(name.clone());
            }
            if !valid_name || q.query_class() != DNSClass::IN {
                reply.set_response_code(ResponseCode::FormErr);
            } else if !matches!(kind, RecordType::A | RecordType::AAAA)
                || !state
                    .config
                    .compiled
                    .policy()
                    .network
                    .dns
                    .allowed_record_types
                    .iter()
                    .any(|t| t == &kind.to_string())
                || port.is_none()
                || !state.config.compiled.allows_dns(&name, u16::from(kind))
            {
                reply.set_response_code(ResponseCode::Refused);
                reason = "DNS name or record type denied";
            } else {
                let model = state
                    .config
                    .compiled
                    .policy()
                    .model
                    .as_ref()
                    .filter(|m| m.host == name);
                let addresses = if model.is_some() {
                    Ok(vec![SocketAddr::new(IpAddr::V4(state.config.bind_ip), 0)])
                } else {
                    state.resolve(&name, port.expect("approved DNS port")).await
                };
                match addresses {
                    Ok(addresses) => {
                        let mut seen = std::collections::HashSet::new();
                        for address in addresses {
                            if !seen.insert(address.ip()) {
                                continue;
                            }
                            let data = match (kind, address.ip()) {
                                (RecordType::A, IpAddr::V4(ip)) => Some(RData::A(A(ip))),
                                (RecordType::AAAA, IpAddr::V6(ip)) => Some(RData::AAAA(AAAA(ip))),
                                _ => None,
                            };
                            if let Some(data) = data {
                                reply.add_answer(Record::from_rdata(q.name().clone(), 30, data));
                            }
                        }
                        reply.set_response_code(ResponseCode::NoError);
                        decision = Decision::Allow;
                        reason = if model.is_some() {
                            "DNS model points to gateway"
                        } else {
                            "DNS validated destination"
                        };
                    }
                    Err(_) => {
                        reply.set_response_code(ResponseCode::Refused);
                        reason = "DNS resolved destination denied";
                    }
                }
            }
        }
    } else {
        reply.set_response_code(ResponseCode::FormErr);
    }
    let mut wire = reply
        .to_vec()
        .map_err(|_| crate::GuardError::Unavailable("DNS encoding failed".into()))?;
    if !tcp && wire.len() > 512 {
        reply.take_answers();
        reply.set_truncated(true);
        wire = reply
            .to_vec()
            .map_err(|_| crate::GuardError::Unavailable("DNS encoding failed".into()))?;
    }
    if state.debit(false, wire.len() as u64).is_err() {
        state
            .record(state.measured_event(
                Category::Dns,
                Decision::Deny,
                "DNS inbound byte budget exhausted",
                destination,
                bytes.len() as u64,
                0,
                start.elapsed(),
            ))
            .await?;
        return Ok(None);
    }
    state
        .record(state.measured_event(
            Category::Dns,
            decision,
            reason,
            destination,
            bytes.len() as u64,
            wire.len() as u64,
            start.elapsed(),
        ))
        .await?;
    Ok(Some(wire))
}

// Exactly one uncompressed question and no extra bytes. RFC name pointers, loops,
// forward references and compressed labels all fail before any external resolution.
fn raw_question_valid(bytes: &[u8]) -> bool {
    if bytes.len() < 17
        || bytes[4..6] != [0, 1]
        || bytes[6..10] != [0; 4]
        || !matches!(bytes[10..12], [0, 0] | [0, 1])
    {
        return false;
    }
    let mut index = 12;
    let mut length = 0;
    loop {
        let Some(&size) = bytes.get(index) else {
            return false;
        };
        index += 1;
        if size == 0 {
            if length > 253 || index + 4 > bytes.len() {
                return false;
            }
            let end = index + 4;
            if bytes[11] == 0 {
                return end == bytes.len();
            }
            // Accept one option-free EDNS0 OPT, bounded by DNS_FRAME. Replies remain <=512
            // and set TC when necessary, so TCP remains the size escape hatch.
            let opt = &bytes[end..];
            return opt.len() == 11
                && opt[0..3] == [0, 0, 41]
                && opt[5..9] == [0, 0, 0, 0]
                && opt[9..11] == [0, 0];
        }
        if size > 63 || index + size as usize > bytes.len() {
            return false;
        }
        length += size as usize + usize::from(length > 0);
        index += size as usize;
        if length > 253 {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn question_rejects_compression_trailing_data_and_oversized_labels() {
        let bytes = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
        assert!(raw_question_valid(&bytes));
        let mut bad = bytes.to_vec();
        bad[12] = 0xc0;
        assert!(!raw_question_valid(&bad));
        let mut bad = bytes.to_vec();
        bad.push(0);
        assert!(!raw_question_valid(&bad));
        let mut bad = bytes.to_vec();
        bad[12] = 64;
        assert!(!raw_question_valid(&bad));
    }
}
