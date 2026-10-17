//! Property tests for the frame parser. Seeded through `AC_TEST_SEED`
//! (TESTING.md) when set.

use agentconnect_relay::proto::{
    ClientFrame, ErrorCode, b64_encode, mailbox_id_from_key, parse_client_frame,
};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, RngSeed};

const MAX: usize = 1 << 20;

fn config() -> Config {
    let mut cfg = Config {
        cases: 512,
        failure_persistence: None,
        ..Config::default()
    };
    if let Some(seed) = std::env::var("AC_TEST_SEED")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        cfg.rng_algorithm = RngAlgorithm::ChaCha;
        cfg.rng_seed = RngSeed::Fixed(seed);
    }
    cfg
}

fn valid_envelope_json() -> impl Strategy<Value = String> {
    (
        prop::sample::select(vec!["commit", "proposal", "application"]),
        any::<[u8; 16]>(),
        any::<[u8; 16]>(),
        any::<[u8; 32]>(),
        any::<u64>(),
        prop::collection::vec(any::<u8>(), 0..256),
    )
        .prop_map(|(kind, gid, mid, key, epoch, ct)| {
            format!(
                r#"{{"v":0,"kind":"{kind}","group_id":"{}","epoch":{epoch},"msg_id":"{}","sender":"{}","ct":"{}"}}"#,
                b64_encode(&gid),
                b64_encode(&mid),
                mailbox_id_from_key(&key),
                b64_encode(&ct),
            )
        })
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn arbitrary_text_never_panics(s in ".*") {
        let _ = parse_client_frame(&s, MAX);
    }

    #[test]
    fn arbitrary_bytes_as_lossy_text_never_panics(b in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = parse_client_frame(&String::from_utf8_lossy(&b), MAX);
    }

    #[test]
    fn json_shaped_noise_never_panics(
        t in prop::sample::select(vec!["auth", "send", "ack", "group.create", "invite.consume", "join", "x"]),
        a in ".{0,40}",
        n in any::<i128>(),
    ) {
        let a = a.replace(['\\', '"'], "");
        for f in [
            format!(r#"{{"t":"{t}","msg_id":"{a}","env":{n},"epoch":{n}}}"#),
            format!(r#"{{"t":"{t}","env":{{"v":{n},"kind":"{a}"}}}}"#),
            format!(r#"{{"t":"{t}","invite_id":"{a}","group_id":"{a}","epoch":"{a}"}}"#),
        ] {
            let _ = parse_client_frame(&f, MAX);
        }
    }

    #[test]
    fn valid_envelopes_parse_and_roundtrip(env in valid_envelope_json()) {
        let frame = format!(r#"{{"t":"send","env":{env}}}"#);
        let parsed = parse_client_frame(&frame, MAX).expect("valid frame");
        let ClientFrame::Send { env: e } = parsed else { panic!("not a send") };
        let again = serde_json::to_string(&e).unwrap();
        let reparsed = parse_client_frame(&format!(r#"{{"t":"send","env":{again}}}"#), MAX).unwrap();
        prop_assert_eq!(reparsed, ClientFrame::Send { env: e });
    }

    #[test]
    fn single_byte_corruption_never_panics(
        env in valid_envelope_json(),
        at in any::<prop::sample::Index>(),
        byte in any::<u8>(),
    ) {
        let mut frame = format!(r#"{{"t":"send","env":{env}}}"#).into_bytes();
        let i = at.index(frame.len());
        frame[i] = byte;
        let _ = parse_client_frame(&String::from_utf8_lossy(&frame), MAX);
    }

    #[test]
    fn oversized_input_is_always_too_large(extra in 1_usize..64) {
        let s = " ".repeat(100 + extra);
        let err = parse_client_frame(&s, 100).unwrap_err();
        prop_assert_eq!(err.0, ErrorCode::TooLarge);
    }
}
