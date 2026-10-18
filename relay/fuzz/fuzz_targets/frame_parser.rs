//! Fuzz target: the relay frame parser.
#![no_main]

use agentconnect_relay::proto::{parse_client_frame, ClientFrame};
use libfuzzer_sys::fuzz_target;

// The relay parses untrusted text frames before authentication completes and
// after it. The parser must never panic and must always honour the size limit.
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let limit = 1 << 20;
    match parse_client_frame(&text, limit) {
        Ok(
            ClientFrame::Send { env }
            | ClientFrame::Join { env, .. }
            | ClientFrame::Knock { env, .. },
        ) => {
            // Accepted envelopes always re-validate and re-serialise.
            assert!(env.validate().is_ok());
            let _ = serde_json::to_string(&env).unwrap();
        }
        Ok(_) => {}
        Err((code, _)) => {
            if text.len() > limit {
                assert_eq!(code, agentconnect_relay::proto::ErrorCode::TooLarge);
            }
        }
    }
});
