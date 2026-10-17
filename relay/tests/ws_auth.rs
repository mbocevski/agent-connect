//! WebSocket authentication (SPEC §8.2) and frame hygiene.

mod common;

use agentconnect_relay::Limits;
use common::{
    Client, HOST, Harness, auth_frame, fresh_id, mailbox_of, raw_connect, raw_recv, raw_send,
    signing_key,
};
use serde_json::{Value, json};

async fn challenge(ws: &mut common::Ws) -> String {
    let c = raw_recv(ws).await.unwrap();
    assert_eq!(c["t"], "challenge");
    c["nonce"].as_str().unwrap().to_owned()
}

async fn expect_auth_failed(ws: &mut common::Ws) {
    let e = raw_recv(ws).await.unwrap();
    assert_eq!(e["t"], "error", "{e}");
    assert_eq!(e["code"], "auth_failed");
    assert!(raw_recv(ws).await.is_none(), "connection must be closed");
}

#[tokio::test]
async fn valid_auth_yields_the_derived_mailbox_id() {
    let h = Harness::start().await;
    let c = Client::connect(h.addr, signing_key(1)).await;
    assert_eq!(c.mailbox, mailbox_of(&signing_key(1)));
    assert_eq!(c.mailbox.len(), 22);
}

#[tokio::test]
async fn challenge_nonces_are_fresh_32_byte_values() {
    let h = Harness::start().await;
    let mut a = raw_connect(h.addr).await;
    let mut b = raw_connect(h.addr).await;
    let (na, nb) = (challenge(&mut a).await, challenge(&mut b).await);
    assert_ne!(na, nb);
    assert_eq!(
        agentconnect_relay::proto::b64_decode(&na).unwrap().len(),
        32
    );
}

#[tokio::test]
async fn bad_signature_is_rejected() {
    let h = Harness::start().await;
    let mut ws = raw_connect(h.addr).await;
    let nonce = challenge(&mut ws).await;
    let mut frame = auth_frame(&signing_key(1), &nonce, HOST);
    // Sign with a different key but claim key 1.
    frame["sig"] = auth_frame(&signing_key(2), &nonce, HOST)["sig"].clone();
    raw_send(&mut ws, &frame).await;
    expect_auth_failed(&mut ws).await;
}

#[tokio::test]
async fn replayed_auth_from_an_earlier_connection_is_rejected() {
    let h = Harness::start().await;
    let key = signing_key(1);

    let mut first = raw_connect(h.addr).await;
    let nonce1 = challenge(&mut first).await;
    let captured = auth_frame(&key, &nonce1, HOST);
    raw_send(&mut first, &captured).await;
    assert_eq!(raw_recv(&mut first).await.unwrap()["t"], "ready");

    let mut second = raw_connect(h.addr).await;
    let _fresh_nonce = challenge(&mut second).await;
    raw_send(&mut second, &captured).await;
    expect_auth_failed(&mut second).await;
}

#[tokio::test]
async fn signature_for_another_relay_host_is_rejected() {
    let h = Harness::start().await;
    let mut ws = raw_connect(h.addr).await;
    let nonce = challenge(&mut ws).await;
    raw_send(
        &mut ws,
        &auth_frame(&signing_key(1), &nonce, "evil.example"),
    )
    .await;
    expect_auth_failed(&mut ws).await;
}

#[tokio::test]
async fn first_frame_must_be_auth() {
    let h = Harness::start().await;
    for first in [
        json!({"t": "ack", "msg_id": fresh_id()}),
        json!({"t": "auth", "sig_key": "x", "sig": "y"}),
        json!({"nonsense": true}),
    ] {
        let mut ws = raw_connect(h.addr).await;
        challenge(&mut ws).await;
        raw_send(&mut ws, &first).await;
        expect_auth_failed(&mut ws).await;
    }
    let mut ws = raw_connect(h.addr).await;
    challenge(&mut ws).await;
    common::raw_send(&mut ws, &Value::String("not an object".into())).await;
    expect_auth_failed(&mut ws).await;
}

#[tokio::test]
async fn auth_after_ready_is_a_bad_request_and_the_session_survives() {
    let h = Harness::start().await;
    let mut c = h.client(1).await;
    let r = c
        .request(&json!({"t": "auth", "sig_key": "x", "sig": "y"}))
        .await;
    assert_eq!(r["code"], "bad_request");
    let r = c.group_create(&fresh_id()).await;
    assert_eq!(r["t"], "accepted");
}

#[tokio::test]
async fn malformed_frames_get_bad_request_and_keep_the_connection() {
    let h = Harness::start().await;
    let mut c = h.client(1).await;
    for bad in [
        json!({"t": "frobnicate"}),
        json!({"t": "ack", "msg_id": "short"}),
        json!({"t": "send", "env": {"v": 0}}),
        json!({"t": "group.create", "group_id": "nope", "epoch": 0}),
        json!({"t": "group.create", "group_id": fresh_id(), "epoch": 3}),
    ] {
        let r = c.request(&bad).await;
        assert_eq!(r["t"], "error", "{bad}");
        assert_eq!(r["code"], "bad_request", "{bad}");
    }
    c.send_raw(&Value::String("[1,2".into())).await;
    assert_eq!(c.reply().await["code"], "bad_request");
    // Binary frames are rejected too.
    use futures_util::SinkExt;
    c.ws.send(tokio_tungstenite::tungstenite::Message::Binary(
        vec![1, 2, 3].into(),
    ))
    .await
    .unwrap();
    assert_eq!(c.reply().await["code"], "bad_request");
    assert_eq!(c.group_create(&fresh_id()).await["t"], "accepted");
}

#[tokio::test]
async fn oversized_frames_get_too_large() {
    let h = Harness::start().await;
    let mut c = h.client(1).await;
    let gid = fresh_id();
    let mut env = c.envelope("application", &gid, 0);
    env["ct"] = json!("A".repeat(Limits::default().frame_max + 1));
    let r = c.send(&env).await;
    assert_eq!(r["code"], "too_large");
    // A frame just under the limit is judged on its merits (unknown group).
    let mut env = c.envelope("application", &gid, 0);
    env["ct"] = json!("A".repeat(Limits::default().frame_max - 1024));
    let r = c.send(&env).await;
    assert_eq!(r["code"], "unknown_group");
}

#[tokio::test]
async fn sender_must_match_the_authenticated_mailbox() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let b = h.client(2).await;
    let gid = common::make_group(&mut a, &[&b]).await;
    let mut forged = a.envelope("application", &gid, 1);
    forged["sender"] = json!(b.mailbox);
    assert_eq!(a.send(&forged).await["code"], "bad_request");
}
