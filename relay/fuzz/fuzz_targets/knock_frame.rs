//! Fuzz target: the `knock` frame (ADR-006).
#![no_main]

use agentconnect_relay::proto::{
    knock_ct_fits, parse_client_frame, ClientFrame, ErrorCode, Kind, MAX_KNOCK_CT,
};
use libfuzzer_sys::fuzz_target;

// Knocks come from any mailbox, to any door. The parser must never panic,
// must never decode `ct`, and an accepted knock always has a well-formed
// envelope of kind `knock` whose `ct` fits the 16 KiB cap.
fuzz_target!(|data: &[u8]| {
    let body = String::from_utf8_lossy(data);
    // Steer the input towards knock frames as well as raw bytes.
    let framed = format!(r#"{{"t":"knock",{body}"#);
    for text in [body.as_ref(), framed.as_str()] {
        match parse_client_frame(text, 1 << 20) {
            Ok(ClientFrame::Knock { env, .. }) => {
                assert!(env.validate().is_ok());
                assert_eq!(env.kind, Kind::Knock);
                assert!(env.group_id.is_none() && env.to.is_empty());
                assert!(knock_ct_fits(&env.ct));
                assert!(env.ct.len() * 3 / 4 <= MAX_KNOCK_CT);
                let _ = serde_json::to_string(&env).unwrap();
            }
            Ok(ClientFrame::Send { env } | ClientFrame::Join { env, .. }) => {
                // A knock envelope may parse in another frame; the relay
                // refuses it there. It always has its door id.
                if env.kind == Kind::Knock {
                    assert!(env.door_id.is_some());
                } else {
                    assert!(env.door_id.is_none());
                }
            }
            Ok(_) => {}
            Err((code, _)) => {
                assert!(matches!(code, ErrorCode::TooLarge | ErrorCode::BadRequest));
            }
        }
    }
});
