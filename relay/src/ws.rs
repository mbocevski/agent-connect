//! WebSocket endpoint `/v0/ws` (SPEC §8.2).

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;

use crate::auth::{random_bytes, verify_ws_auth};
use crate::proto::{ClientFrame, ErrorCode, ServerFrame, b64_encode, log_tag, parse_client_frame};
use crate::relay::{Relay, RelayError};
use crate::store::Store;

/// How long a client has to answer the challenge.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// Messages sent to a connection per storage round trip.
const BATCH: u32 = 256;
/// Transport-level cap. The protocol limit (`Limits::frame_max`) is enforced
/// per frame with a `too_large` error; this only stops absurd allocations.
const HARD_MAX_MESSAGE: usize = 4 << 20;

/// Upgrade handler.
pub async fn ws_handler<S: Store>(
    State(relay): State<Arc<Relay<S>>>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.max_message_size(HARD_MAX_MESSAGE)
        .max_frame_size(HARD_MAX_MESSAGE)
        .on_upgrade(move |socket| session(relay, socket))
}

async fn send_frame(socket: &mut WebSocket, frame: &ServerFrame) -> bool {
    socket.send(Message::text(frame.to_json())).await.is_ok()
}

async fn close(socket: &mut WebSocket, reason: &str) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: 1008,
            reason: reason.into(),
        })))
        .await;
}

/// Run the challenge/response handshake; returns the authenticated mailbox.
async fn authenticate<S: Store>(relay: &Relay<S>, socket: &mut WebSocket) -> Option<String> {
    let nonce = random_bytes::<32>();
    let challenge = ServerFrame::Challenge {
        nonce: b64_encode(&nonce),
    };
    if !send_frame(socket, &challenge).await {
        return None;
    }
    let first = tokio::time::timeout(AUTH_TIMEOUT, socket.recv()).await;
    let mailbox = match first {
        Ok(Some(Ok(Message::Text(text)))) => {
            match parse_client_frame(text.as_str(), relay.limits().frame_max) {
                Ok(ClientFrame::Auth { sig_key, sig }) => {
                    verify_ws_auth(&nonce, relay.host(), &sig_key, &sig)
                }
                _ => None,
            }
        }
        _ => None,
    };
    if mailbox.is_none() {
        relay.metrics().auth_failure();
        let e = relay.error_frame(
            None,
            RelayError::new(ErrorCode::AuthFailed, "authentication failed"),
        );
        let _ = send_frame(socket, &e).await;
        close(socket, "auth_failed").await;
    }
    mailbox
}

/// Send every queued message after `last_seq`, oldest first.
async fn flush<S: Store>(
    relay: &Relay<S>,
    socket: &mut WebSocket,
    mailbox: &str,
    last_seq: &mut i64,
) -> bool {
    loop {
        let batch = match relay.pending(mailbox, *last_seq, BATCH).await {
            Ok(b) => b,
            Err(e) => {
                let f = relay.error_frame(None, e);
                let _ = send_frame(socket, &f).await;
                return false;
            }
        };
        let full = batch.len() == BATCH as usize;
        for m in batch {
            // The stored envelope JSON is forwarded verbatim; it is never
            // inspected or logged.
            let text = format!(r#"{{"t":"deliver","env":{}}}"#, m.json);
            if socket.send(Message::text(text)).await.is_err() {
                return false;
            }
            *last_seq = m.seq;
        }
        if !full {
            return true;
        }
    }
}

async fn session<S: Store>(relay: Arc<Relay<S>>, mut socket: WebSocket) {
    relay.metrics().connection();
    let Some(mailbox) = authenticate(&relay, &mut socket).await else {
        return;
    };
    let tag = log_tag(&mailbox);
    tracing::debug!(mailbox = %tag, "connected");
    let ready = ServerFrame::Ready {
        mailbox_id: mailbox.clone(),
    };
    if !send_frame(&mut socket, &ready).await {
        return;
    }
    // Register before the first flush so nothing queued in between is missed.
    let registration = relay.register(&mailbox);
    let mut last_seq = 0_i64;
    if !flush(&relay, &mut socket, &mailbox, &mut last_seq).await {
        return;
    }
    loop {
        tokio::select! {
            () = registration.notify.notified() => {
                if !flush(&relay, &mut socket, &mailbox, &mut last_seq).await {
                    break;
                }
            }
            incoming = socket.recv() => {
                let reply = match incoming {
                    Some(Ok(Message::Text(text))) => {
                        match parse_client_frame(text.as_str(), relay.limits().frame_max) {
                            Ok(frame) => relay.handle(&mailbox, frame).await,
                            Err((code, detail)) => {
                                Some(relay.error_frame(None, RelayError::new(code, detail)))
                            }
                        }
                    }
                    Some(Ok(Message::Binary(_))) => Some(relay.error_frame(
                        None,
                        RelayError::new(ErrorCode::BadRequest, "text frames only"),
                    )),
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => None,
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                };
                if let Some(frame) = reply
                    && !send_frame(&mut socket, &frame).await
                {
                    break;
                }
            }
        }
    }
    tracing::debug!(mailbox = %tag, "disconnected");
}
