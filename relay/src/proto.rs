//! Wire types and frame parsing (SPEC §7.1, §8.2, §8.4).
//!
//! The relay routes on the outer envelope only: it never decodes `ct`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Longest optional correlation `msg_id` on `group.create` / `invite.consume`.
pub const MAX_CORRELATION_ID: usize = 64;
/// Length of a base64url `mailbox_id` (SPEC §2).
pub const MAILBOX_ID_LEN: usize = 22;
/// Maximum number of recipients in a `welcome_wrapped` envelope.
pub const MAX_WELCOME_RECIPIENTS: usize = 50;
/// Maximum number of hints in a commit's `routing` object.
pub const MAX_ROUTING_HINTS: usize = 50;
/// Largest `ct` of a `knock` envelope, in decoded bytes (16 KiB).
pub const MAX_KNOCK_CT: usize = 16 * 1024;

/// Encode bytes as base64url without padding.
#[must_use]
pub fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url without padding.
#[must_use]
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// Derive `mailbox_id` = base64url(SHA-256(`SK.pub`))[0..22].
#[must_use]
pub fn mailbox_id_from_key(sig_key: &[u8]) -> String {
    let mut id = b64_encode(&Sha256::digest(sig_key));
    id.truncate(MAILBOX_ID_LEN);
    id
}

/// The key behind [`log_tag`]: random, drawn once per process and never
/// stored, so tags can't be computed by someone who holds an id and don't
/// match across restarts.
static LOG_TAG_KEY: std::sync::LazyLock<[u8; 32]> =
    std::sync::LazyLock::new(crate::auth::random_bytes);

/// A short tag for an identifier, for logs: the first 4 bytes of
/// HMAC-SHA256 under a per-process random key, in hex. Stable within one
/// process, so log lines about one group can be followed; unrelated across
/// restarts and to anyone without the key.
#[must_use]
pub fn log_tag(id: &str) -> String {
    log_tag_with(&LOG_TAG_KEY, id)
}

/// [`log_tag`] under an explicit key.
fn log_tag_with(key: &[u8; 32], id: &str) -> String {
    use hmac::{Hmac, KeyInit, Mac as _};
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("any key length works");
    mac.update(id.as_bytes());
    let digest = mac.finalize().into_bytes();
    digest[..4].iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// True if `s` is a well-formed `mailbox_id`.
#[must_use]
pub fn is_mailbox_id(s: &str) -> bool {
    // 22 base64url characters carry 132 bits; accept any that decode (the
    // last character may carry non-zero padding bits in a truncated hash).
    s.len() == MAILBOX_ID_LEN
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// True if `s` is 16 random bytes in base64url (`group_id`, `invite_id`, `msg_id`).
#[must_use]
pub fn is_id16(s: &str) -> bool {
    s.len() == 22 && b64_decode(s).is_some_and(|b| b.len() == 16)
}

/// Relay error codes (SPEC §8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Authentication failed.
    AuthFailed,
    /// The commit or proposal epoch is not current.
    EpochConflict,
    /// The sender is not a member of the group.
    NotMember,
    /// No such group.
    UnknownGroup,
    /// The invite is unknown, exhausted, expired or revoked.
    InviteNotOpen,
    /// The door is unknown, expired or closed.
    DoorNotOpen,
    /// Too many requests.
    RateLimited,
    /// The frame exceeds the size limit.
    TooLarge,
    /// A queue or group size limit was hit.
    QuotaExceeded,
    /// The frame is malformed.
    BadRequest,
    /// Server-side failure.
    Internal,
}

impl ErrorCode {
    /// Every code, in a stable order.
    pub const ALL: [ErrorCode; 11] = [
        ErrorCode::AuthFailed,
        ErrorCode::EpochConflict,
        ErrorCode::NotMember,
        ErrorCode::UnknownGroup,
        ErrorCode::InviteNotOpen,
        ErrorCode::DoorNotOpen,
        ErrorCode::RateLimited,
        ErrorCode::TooLarge,
        ErrorCode::QuotaExceeded,
        ErrorCode::BadRequest,
        ErrorCode::Internal,
    ];

    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::AuthFailed => "auth_failed",
            ErrorCode::EpochConflict => "epoch_conflict",
            ErrorCode::NotMember => "not_member",
            ErrorCode::UnknownGroup => "unknown_group",
            ErrorCode::InviteNotOpen => "invite_not_open",
            ErrorCode::DoorNotOpen => "door_not_open",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::TooLarge => "too_large",
            ErrorCode::QuotaExceeded => "quota_exceeded",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Internal => "internal",
        }
    }

    /// The HTTP status used for this code on the REST API.
    #[must_use]
    pub fn http_status(self) -> u16 {
        match self {
            ErrorCode::AuthFailed => 401,
            ErrorCode::NotMember => 403,
            ErrorCode::UnknownGroup | ErrorCode::InviteNotOpen | ErrorCode::DoorNotOpen => 404,
            ErrorCode::EpochConflict => 409,
            ErrorCode::TooLarge => 413,
            ErrorCode::RateLimited | ErrorCode::QuotaExceeded => 429,
            ErrorCode::BadRequest => 400,
            ErrorCode::Internal => 500,
        }
    }
}

/// The envelope kind (SPEC §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// An MLS commit.
    Commit,
    /// A standalone MLS proposal.
    Proposal,
    /// An MLS application message.
    Application,
    /// A Welcome wrapped under the invite's `welcome_key`.
    WelcomeWrapped,
    /// A join request addressed to an invite's inviter.
    JoinRequest,
    /// A sealed knock addressed to a door's owner (ADR-006).
    Knock,
}

/// Fan-out table hints on a commit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Routing {
    /// Mailboxes added by the commit.
    #[serde(default)]
    pub add: Vec<String>,
    /// Mailboxes removed by the commit.
    #[serde(default)]
    pub remove: Vec<String>,
}

/// The outer envelope, the only part of a message the relay reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Protocol version (0).
    pub v: u32,
    /// Message kind.
    pub kind: Kind,
    /// Group id; absent for `join_request` and `knock`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    /// The door a `knock` is for; absent for every other kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub door_id: Option<String>,
    /// Epoch for commit, proposal and application messages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    /// 16 random bytes, base64url.
    pub msg_id: String,
    /// The sender's mailbox.
    pub sender: String,
    /// Recipients for `welcome_wrapped`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<String>,
    /// Commit routing hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<Routing>,
    /// Opaque ciphertext (base64url). Never decoded, never logged.
    pub ct: String,
}

impl Envelope {
    /// Check the envelope's shape (not its authorisation).
    ///
    /// # Errors
    ///
    /// Returns a human-readable reason if the envelope is malformed.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.v != 0 {
            return Err("unsupported protocol version");
        }
        if !is_id16(&self.msg_id) {
            return Err("msg_id must be 16 random bytes, base64url");
        }
        if !is_mailbox_id(&self.sender) {
            return Err("malformed sender mailbox id");
        }
        if b64_decode(&self.ct).is_none() {
            return Err("ct must be base64url without padding");
        }
        if let Some(g) = &self.group_id
            && !is_id16(g)
        {
            return Err("malformed group_id");
        }
        match self.kind {
            Kind::Commit | Kind::Proposal | Kind::Application => {
                if self.group_id.is_none() {
                    return Err("group_id is required");
                }
                if self.epoch.is_none() {
                    return Err("epoch is required");
                }
            }
            Kind::WelcomeWrapped => {
                if self.group_id.is_none() {
                    return Err("group_id is required");
                }
                if self.to.is_empty() || self.to.len() > MAX_WELCOME_RECIPIENTS {
                    return Err("welcome_wrapped needs 1..=50 recipients");
                }
                if !self.to.iter().all(|m| is_mailbox_id(m)) {
                    return Err("malformed recipient mailbox id");
                }
            }
            Kind::JoinRequest => {}
            Kind::Knock => {
                if self.group_id.is_some() || self.epoch.is_some() || !self.to.is_empty() {
                    return Err("a knock has no group_id, epoch or recipients");
                }
                if !self.door_id.as_deref().is_some_and(is_id16) {
                    return Err("a knock needs a door_id of 16 random bytes, base64url");
                }
            }
        }
        if self.kind != Kind::Knock && self.door_id.is_some() {
            return Err("door_id is only valid on knocks");
        }
        if let Some(r) = &self.routing {
            if self.kind != Kind::Commit {
                return Err("routing is only valid on commits");
            }
            if r.add.len() > MAX_ROUTING_HINTS || r.remove.len() > MAX_ROUTING_HINTS {
                return Err("too many routing hints");
            }
            if !r.add.iter().chain(&r.remove).all(|m| is_mailbox_id(m)) {
                return Err("malformed routing mailbox id");
            }
        }
        Ok(())
    }
}

/// Frames sent by clients (SPEC §8.2).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "t")]
pub enum ClientFrame {
    /// Authentication reply to the challenge.
    #[serde(rename = "auth")]
    Auth {
        /// `SK.pub`, base64url.
        sig_key: String,
        /// Ed25519 signature, base64url.
        sig: String,
    },
    /// Send an envelope.
    #[serde(rename = "send")]
    Send {
        /// The envelope.
        env: Envelope,
    },
    /// Acknowledge delivery of a message.
    #[serde(rename = "ack")]
    Ack {
        /// The acknowledged `msg_id`.
        msg_id: String,
    },
    /// Register a group.
    #[serde(rename = "group.create")]
    GroupCreate {
        /// The new group's id.
        group_id: String,
        /// Must be 0.
        epoch: u64,
        /// Optional correlation id echoed in the reply.
        #[serde(default)]
        msg_id: Option<String>,
    },
    /// Consume one use of an invite.
    #[serde(rename = "invite.consume")]
    InviteConsume {
        /// The invite.
        invite_id: String,
        /// Optional correlation id echoed in the reply.
        #[serde(default)]
        msg_id: Option<String>,
    },
    /// Forward a join request to the invite's inviter.
    #[serde(rename = "join")]
    Join {
        /// The invite.
        invite_id: String,
        /// A `join_request` envelope.
        env: Envelope,
    },
    /// Forward a sealed knock to a door's owner (ADR-006).
    #[serde(rename = "knock")]
    Knock {
        /// The door; must equal the envelope's `door_id`.
        door_id: String,
        /// A `knock` envelope.
        env: Envelope,
    },
}

impl ClientFrame {
    /// The `msg_id` the reply to this frame carries (SPEC §8.2): the
    /// envelope's, or for `group.create` and `invite.consume` the optional
    /// `msg_id` and else the group or invite id. `None` for `auth` and
    /// `ack`, which get no reply.
    #[must_use]
    pub fn correlation(&self) -> Option<String> {
        match self {
            ClientFrame::Auth { .. } | ClientFrame::Ack { .. } => None,
            ClientFrame::Send { env }
            | ClientFrame::Join { env, .. }
            | ClientFrame::Knock { env, .. } => Some(env.msg_id.clone()),
            ClientFrame::GroupCreate {
                group_id, msg_id, ..
            } => Some(msg_id.clone().unwrap_or_else(|| group_id.clone())),
            ClientFrame::InviteConsume { invite_id, msg_id } => {
                Some(msg_id.clone().unwrap_or_else(|| invite_id.clone()))
            }
        }
    }
}

/// Frames sent by the relay (SPEC §8.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum ServerFrame {
    /// Authentication challenge.
    #[serde(rename = "challenge")]
    Challenge {
        /// 32 random bytes, base64url.
        nonce: String,
    },
    /// Authentication succeeded.
    #[serde(rename = "ready")]
    Ready {
        /// The authenticated mailbox.
        mailbox_id: String,
    },
    /// A queued envelope.
    #[serde(rename = "deliver")]
    Deliver {
        /// The envelope.
        env: Box<Envelope>,
    },
    /// This mailbox's queue was full and messages for a group were dropped.
    /// Sent once per overflow episode; the member must re-sync or be removed.
    #[serde(rename = "queue_overflow")]
    QueueOverflow {
        /// The group whose traffic was dropped.
        group_id: String,
        /// The first dropped message.
        msg_id: String,
        /// That message's epoch (absent for a Welcome).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        epoch: Option<u64>,
    },
    /// Every message that was queued for the mailbox when it authenticated
    /// has been sent (SPEC §8.2): the end of the reconnect drain.
    #[serde(rename = "drained")]
    Drained,
    /// A send was accepted.
    #[serde(rename = "accepted")]
    Accepted {
        /// The accepted message (or invite/group id for the control frames).
        msg_id: String,
    },
    /// A request failed.
    #[serde(rename = "error")]
    Error {
        /// The failing message, when known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        msg_id: Option<String>,
        /// The error code.
        code: ErrorCode,
        /// A human-readable detail. Never contains message content.
        detail: String,
        /// For `epoch_conflict`: the group's current epoch.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        current_epoch: Option<u64>,
    },
}

impl ServerFrame {
    /// An error frame.
    #[must_use]
    pub fn error(msg_id: Option<String>, code: ErrorCode, detail: impl Into<String>) -> Self {
        ServerFrame::Error {
            msg_id,
            code,
            detail: detail.into(),
            current_epoch: None,
        }
    }

    /// Serialise to a JSON text frame.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"t":"error","code":"internal","detail":"serialisation failed"}"#.to_owned()
        })
    }
}

/// True if base64url `ct` decodes to at most [`MAX_KNOCK_CT`] bytes. Only the
/// length is looked at: the relay never decodes a knock.
#[must_use]
pub fn knock_ct_fits(ct: &str) -> bool {
    // Unpadded base64url carries 6 bits per character.
    ct.len().saturating_mul(3) / 4 <= MAX_KNOCK_CT
}

/// Parse a client text frame, enforcing the size limit first.
///
/// # Errors
///
/// `too_large` if `text` exceeds `max_len`; `bad_request` for malformed JSON,
/// an unknown frame type or a malformed envelope.
pub fn parse_client_frame(text: &str, max_len: usize) -> Result<ClientFrame, (ErrorCode, String)> {
    if text.len() > max_len {
        return Err((ErrorCode::TooLarge, "frame exceeds the size limit".into()));
    }
    let frame: ClientFrame = serde_json::from_str(text)
        .map_err(|_| (ErrorCode::BadRequest, "malformed frame".to_owned()))?;
    match &frame {
        ClientFrame::Knock { env, .. } if !knock_ct_fits(&env.ct) => {
            return Err((ErrorCode::TooLarge, "knock ct exceeds 16 KiB".into()));
        }
        ClientFrame::Send { env }
        | ClientFrame::Join { env, .. }
        | ClientFrame::Knock { env, .. } => env
            .validate()
            .map_err(|e| (ErrorCode::BadRequest, e.to_owned()))?,
        ClientFrame::Ack { msg_id } if !is_id16(msg_id) => {
            return Err((ErrorCode::BadRequest, "malformed msg_id".into()));
        }
        ClientFrame::GroupCreate {
            msg_id: Some(m), ..
        }
        | ClientFrame::InviteConsume {
            msg_id: Some(m), ..
        } if m.chars().count() > MAX_CORRELATION_ID => {
            return Err((ErrorCode::BadRequest, "msg_id is too long".into()));
        }
        _ => {}
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id16(n: u8) -> String {
        b64_encode(&[n; 16])
    }

    fn env(kind: Kind) -> Envelope {
        Envelope {
            v: 0,
            kind,
            group_id: Some(id16(1)),
            door_id: None,
            epoch: Some(0),
            msg_id: id16(2),
            sender: mailbox_id_from_key(b"k"),
            to: vec![],
            routing: None,
            ct: b64_encode(b"ciphertext"),
        }
    }

    #[test]
    fn log_tags_are_keyed_per_process() {
        let id = mailbox_id_from_key(&crate::auth::random_bytes::<32>());
        let tag = log_tag(&id);
        assert_eq!(tag.len(), 8);
        assert!(tag.bytes().all(|b| b.is_ascii_hexdigit()));
        // Stable within the process, so one group's lines can be followed.
        assert_eq!(log_tag(&id), tag);
        assert_ne!(log_tag(&format!("{id}x")), tag);
        // Not the unkeyed hash prefix anyone holding the id could compute.
        let unkeyed =
            Sha256::digest(id.as_bytes())[..4]
                .iter()
                .fold(String::new(), |mut out, b| {
                    use std::fmt::Write as _;
                    let _ = write!(out, "{b:02x}");
                    out
                });
        assert_ne!(tag, unkeyed);
        // Another key (another process) gives an unrelated tag.
        let a = crate::auth::random_bytes::<32>();
        let b = crate::auth::random_bytes::<32>();
        assert_eq!(log_tag_with(&a, &id), log_tag_with(&a, &id));
        assert_ne!(log_tag_with(&a, &id), log_tag_with(&b, &id));
    }

    #[test]
    fn correlation_follows_the_reply_rules() {
        let e = env(Kind::Application);
        let send = ClientFrame::Send { env: e.clone() };
        assert_eq!(send.correlation(), Some(e.msg_id.clone()));
        let knock = ClientFrame::Knock {
            door_id: id16(3),
            env: e.clone(),
        };
        assert_eq!(knock.correlation(), Some(e.msg_id.clone()));
        let join = ClientFrame::Join {
            invite_id: id16(4),
            env: e.clone(),
        };
        assert_eq!(join.correlation(), Some(e.msg_id));
        let create = |msg_id| ClientFrame::GroupCreate {
            group_id: id16(5),
            epoch: 0,
            msg_id,
        };
        assert_eq!(create(None).correlation(), Some(id16(5)));
        assert_eq!(create(Some("c".into())).correlation(), Some("c".into()));
        let consume = |msg_id| ClientFrame::InviteConsume {
            invite_id: id16(6),
            msg_id,
        };
        assert_eq!(consume(None).correlation(), Some(id16(6)));
        assert_eq!(consume(Some("i".into())).correlation(), Some("i".into()));
        let ack = ClientFrame::Ack { msg_id: id16(7) };
        assert_eq!(ack.correlation(), None);
        let auth = ClientFrame::Auth {
            sig_key: String::new(),
            sig: String::new(),
        };
        assert_eq!(auth.correlation(), None);
    }

    #[test]
    fn mailbox_id_is_22_chars_of_the_key_hash() {
        let key = crate::auth::random_bytes::<32>();
        let id = mailbox_id_from_key(&key);
        assert_eq!(id.len(), 22);
        assert!(is_mailbox_id(&id));
        assert!(b64_encode(&Sha256::digest(key)).starts_with(&id));
    }

    #[test]
    fn id_predicates() {
        assert!(is_id16(&id16(9)));
        assert!(!is_id16("short"));
        assert!(!is_id16(&"!".repeat(22)));
        assert!(!is_mailbox_id("short"));
        assert!(!is_mailbox_id(&"+".repeat(22)));
        assert_eq!(log_tag("abc").len(), 8);
        assert_ne!(log_tag("abc"), log_tag("xyz"));
    }

    #[test]
    fn error_codes_have_distinct_names_and_statuses() {
        let names: std::collections::HashSet<_> =
            ErrorCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(names.len(), ErrorCode::ALL.len());
        for code in ErrorCode::ALL {
            assert!((400..=500).contains(&code.http_status()));
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
        }
    }

    #[test]
    fn valid_envelopes_pass() {
        for kind in [Kind::Commit, Kind::Proposal, Kind::Application] {
            assert_eq!(env(kind).validate(), Ok(()));
        }
        let mut welcome = env(Kind::WelcomeWrapped);
        welcome.to = vec![mailbox_id_from_key(b"x")];
        assert_eq!(welcome.validate(), Ok(()));
        let mut join = env(Kind::JoinRequest);
        join.group_id = None;
        join.epoch = None;
        assert_eq!(join.validate(), Ok(()));
    }

    #[test]
    fn malformed_envelopes_fail() {
        let mut e = env(Kind::Commit);
        e.v = 1;
        assert!(e.validate().is_err());
        let mut e = env(Kind::Commit);
        e.msg_id = "x".into();
        assert!(e.validate().is_err());
        let mut e = env(Kind::Commit);
        e.sender = "x".into();
        assert!(e.validate().is_err());
        let mut e = env(Kind::Commit);
        e.ct = "***".into();
        assert!(e.validate().is_err());
        let mut e = env(Kind::Commit);
        e.group_id = Some("bad".into());
        assert!(e.validate().is_err());
        let mut e = env(Kind::Commit);
        e.group_id = None;
        assert!(e.validate().is_err());
        let mut e = env(Kind::Application);
        e.epoch = None;
        assert!(e.validate().is_err());
        let mut e = env(Kind::WelcomeWrapped);
        assert!(e.validate().is_err(), "no recipients");
        e.to = vec!["bad".into()];
        assert!(e.validate().is_err(), "bad recipient");
        e.group_id = None;
        e.to = vec![mailbox_id_from_key(b"x")];
        assert!(e.validate().is_err(), "welcome needs a group");
        let mut e = env(Kind::Application);
        e.routing = Some(Routing::default());
        assert!(e.validate().is_err(), "routing only on commits");
        let mut e = env(Kind::Commit);
        e.routing = Some(Routing {
            add: vec!["bad".into()],
            remove: vec![],
        });
        assert!(e.validate().is_err());
        e.routing = Some(Routing {
            add: vec![mailbox_id_from_key(b"x"); MAX_ROUTING_HINTS + 1],
            remove: vec![],
        });
        assert!(e.validate().is_err());
    }

    fn knock() -> Envelope {
        Envelope {
            group_id: None,
            epoch: None,
            door_id: Some(id16(7)),
            ..env(Kind::Knock)
        }
    }

    #[test]
    fn knock_envelopes_carry_a_door_and_nothing_group_bound() {
        assert_eq!(knock().validate(), Ok(()));
        let json = serde_json::to_value(knock()).unwrap();
        assert_eq!(json["kind"], "knock");
        assert_eq!(json["door_id"], id16(7));
        assert!(json.get("group_id").is_none() && json.get("to").is_none());
        let bad = [
            Envelope {
                door_id: None,
                ..knock()
            },
            Envelope {
                door_id: Some("short".into()),
                ..knock()
            },
            Envelope {
                group_id: Some(id16(1)),
                ..knock()
            },
            Envelope {
                epoch: Some(0),
                ..knock()
            },
            Envelope {
                to: vec![mailbox_id_from_key(b"x")],
                ..knock()
            },
            Envelope {
                routing: Some(Routing::default()),
                ..knock()
            },
            Envelope {
                door_id: Some(id16(7)),
                ..env(Kind::Application)
            },
        ];
        for e in bad {
            assert!(e.validate().is_err(), "{e:?}");
        }
    }

    #[test]
    fn knock_frames_parse_and_their_ct_is_capped() {
        let frame = |ct: &[u8]| {
            let e = Envelope {
                ct: b64_encode(ct),
                ..knock()
            };
            format!(
                r#"{{"t":"knock","door_id":"{}","env":{}}}"#,
                id16(7),
                serde_json::to_string(&e).unwrap()
            )
        };
        let max = crate::store::DEFAULT_FRAME_MAX;
        assert!(matches!(
            parse_client_frame(&frame(&vec![1; MAX_KNOCK_CT]), max),
            Ok(ClientFrame::Knock { .. })
        ));
        let err = parse_client_frame(&frame(&vec![1; MAX_KNOCK_CT + 1]), max).unwrap_err();
        assert_eq!(err.0, ErrorCode::TooLarge);
        assert!(knock_ct_fits(""));
        let no_door = format!(
            r#"{{"t":"knock","door_id":"{}","env":{}}}"#,
            id16(7),
            serde_json::to_string(&Envelope {
                door_id: None,
                ..knock()
            })
            .unwrap()
        );
        assert_eq!(
            parse_client_frame(&no_door, max).unwrap_err().0,
            ErrorCode::BadRequest
        );
    }

    #[test]
    fn parses_every_client_frame() {
        let e = serde_json::to_string(&env(Kind::Application)).unwrap();
        let frames = [
            r#"{"t":"auth","sig_key":"a","sig":"b"}"#.to_owned(),
            format!(r#"{{"t":"send","env":{e}}}"#),
            format!(r#"{{"t":"ack","msg_id":"{}"}}"#, id16(3)),
            format!(
                r#"{{"t":"group.create","group_id":"{}","epoch":0}}"#,
                id16(4)
            ),
            format!(
                r#"{{"t":"invite.consume","invite_id":"{}","msg_id":"m"}}"#,
                id16(5)
            ),
        ];
        for f in &frames {
            assert!(
                parse_client_frame(f, crate::store::DEFAULT_FRAME_MAX).is_ok(),
                "{f}"
            );
        }
        let mut join = env(Kind::JoinRequest);
        join.group_id = None;
        let j = format!(
            r#"{{"t":"join","invite_id":"{}","env":{}}}"#,
            id16(5),
            serde_json::to_string(&join).unwrap()
        );
        assert!(matches!(
            parse_client_frame(&j, crate::store::DEFAULT_FRAME_MAX),
            Ok(ClientFrame::Join { .. })
        ));
    }

    #[test]
    fn rejects_bad_frames_with_the_right_code() {
        let code = |s: &str, max| parse_client_frame(s, max).unwrap_err().0;
        assert_eq!(code("not json", 100), ErrorCode::BadRequest);
        assert_eq!(code(r#"{"t":"nope"}"#, 100), ErrorCode::BadRequest);
        assert_eq!(
            code(r#"{"t":"ack","msg_id":"x"}"#, 100),
            ErrorCode::BadRequest
        );
        assert_eq!(code(r#"{"t":"ack","msg_id":"x"}"#, 5), ErrorCode::TooLarge);
        let long = format!(
            r#"{{"t":"invite.consume","invite_id":"{}","msg_id":"{}"}}"#,
            id16(1),
            "m".repeat(65)
        );
        assert_eq!(code(&long, 1000), ErrorCode::BadRequest);
        assert_eq!(
            code(r#"{"t":"send","env":{"v":0,"kind":"commit"}}"#, 1000),
            ErrorCode::BadRequest
        );
        let mut e = env(Kind::Commit);
        e.v = 9;
        let f = format!(
            r#"{{"t":"send","env":{}}}"#,
            serde_json::to_string(&e).unwrap()
        );
        assert_eq!(
            code(&f, crate::store::DEFAULT_FRAME_MAX),
            ErrorCode::BadRequest
        );
    }

    #[test]
    fn server_frames_serialise_as_specified() {
        let f = ServerFrame::Ready {
            mailbox_id: "m".into(),
        };
        assert_eq!(f.to_json(), r#"{"t":"ready","mailbox_id":"m"}"#);
        assert_eq!(ServerFrame::Drained.to_json(), r#"{"t":"drained"}"#);
        let f = ServerFrame::error(None, ErrorCode::NotMember, "no");
        assert_eq!(
            f.to_json(),
            r#"{"t":"error","code":"not_member","detail":"no"}"#
        );
        let f = ServerFrame::QueueOverflow {
            group_id: "g".into(),
            msg_id: "m".into(),
            epoch: None,
        };
        assert_eq!(
            f.to_json(),
            r#"{"t":"queue_overflow","group_id":"g","msg_id":"m"}"#
        );
        let f = ServerFrame::Deliver {
            env: Box::new(env(Kind::Application)),
        };
        let back: ServerFrame = serde_json::from_str(&f.to_json()).unwrap();
        assert_eq!(back, f);
    }
}
