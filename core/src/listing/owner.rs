//! Owner verification: the `/.well-known/agentconnect.json` file and the
//! owner states (SPEC §13.2.4). Format and state only: fetching it (HTTPS,
//! no redirects, public addresses only) is the caller's job.

use serde_json::{Map, Value};

use super::{is_canonical_host, is_listing_name, is_owner_domain};
use crate::encoding::{MAX_SAFE_INTEGER, parse_json_unique_keys};
use crate::error::{Error, Result};
use crate::identity::{fingerprint, parse_identity};

/// The well-known path on the owner domain (RFC 8615).
pub const OWNER_FILE_PATH: &str = "/.well-known/agentconnect.json";
/// The largest owner file (SPEC §13.2.4).
pub const MAX_OWNER_FILE_BYTES: usize = 64 * 1024;
/// A fetch that vouched keeps the owner `verified` this long: 24 h.
pub const VERIFIED_FOR_SECS: u64 = 24 * 3600;
/// After this long without a vouching fetch the owner is `failed`: 7 days.
pub const STALE_AFTER_SECS: u64 = 7 * 24 * 3600;

const fn bad(what: &'static str) -> Error {
    Error::InvalidOwnerFile(what)
}

/// The URL of the owner file for `domain`.
///
/// # Errors
///
/// [`Error::InvalidOwnerFile`] if `domain` isn't a valid owner domain
/// (SPEC §13.1.1).
pub fn owner_file_url(domain: &str) -> Result<String> {
    if is_owner_domain(domain) {
        Ok(format!("https://{domain}{OWNER_FILE_PATH}"))
    } else {
        Err(bad("owner domain"))
    }
}

/// A valid `identities` entry: the domain vouches for this key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerIdentity {
    /// `ac:v0:…`.
    pub identity: String,
    /// `None`: every listing of the key. Otherwise only these
    /// `<directory>/a/<name>` listings.
    pub listings: Option<Vec<String>>,
}

/// Why a key was revoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationReason {
    /// Replaced by a new key (rotation).
    Superseded,
    /// The key leaked.
    Compromised,
}

/// A `revoked` entry. It counts once its `identity` is valid, whatever
/// the other fields say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerRevocation {
    /// `ac:v0:…`.
    pub identity: String,
    /// Unix seconds, if given as a valid integer.
    pub revoked_at: Option<u64>,
    /// The reason, if it is one of the two defined.
    pub reason: Option<RevocationReason>,
}

/// A parsed owner file (SPEC §13.2.4). Invalid entries are dropped; they
/// vouch for nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerFile {
    identities: Vec<OwnerIdentity>,
    revoked: Vec<OwnerRevocation>,
}

/// What one fetched file says about one listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vouch {
    /// The file lists the identity (and the listing, if the entry limits
    /// it) and doesn't revoke it.
    Vouches,
    /// The file doesn't vouch for this identity in this listing.
    DoesNotVouch,
    /// The file lists the identity in `revoked`, with what its entry says.
    Revoked {
        /// The entry's `revoked_at`, if it is a valid integer.
        revoked_at: Option<u64>,
        /// The entry's `reason`, if it is one of the two defined.
        reason: Option<RevocationReason>,
    },
}

impl Vouch {
    /// `"vouches"`, `"does_not_vouch"` or `"revoked"`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vouches => "vouches",
            Self::DoesNotVouch => "does_not_vouch",
            Self::Revoked { .. } => "revoked",
        }
    }
}

fn listing_ref_ok(s: &str) -> bool {
    s.split_once("/a/")
        .is_some_and(|(dir, name)| is_canonical_host(dir) && is_listing_name(name))
}

fn parse_identity_entry(entry: &Value) -> Option<OwnerIdentity> {
    let entry = entry.as_object()?;
    let identity = entry.get("identity")?.as_str()?;
    let key = parse_identity(identity).ok()?;
    if let Some(fp) = entry.get("fingerprint")
        && fp.as_str() != Some(fingerprint(&key).as_str())
    {
        return None;
    }
    let listings = match entry.get("listings") {
        None => None,
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .map(|i| i.as_str().filter(|s| listing_ref_ok(s)).map(str::to_owned))
                .collect::<Option<Vec<_>>>()?,
        ),
        Some(_) => return None,
    };
    Some(OwnerIdentity {
        identity: identity.to_owned(),
        listings,
    })
}

fn parse_revocation_entry(entry: &Value) -> Option<OwnerRevocation> {
    let entry = entry.as_object()?;
    let identity = entry.get("identity")?.as_str()?;
    parse_identity(identity).ok()?;
    Some(OwnerRevocation {
        identity: identity.to_owned(),
        revoked_at: entry
            .get("revoked_at")
            .and_then(Value::as_u64)
            .filter(|t| *t <= MAX_SAFE_INTEGER),
        reason: match entry.get("reason").and_then(Value::as_str) {
            Some("superseded") => Some(RevocationReason::Superseded),
            Some("compromised") => Some(RevocationReason::Compromised),
            _ => None,
        },
    })
}

fn array<'a>(top: &'a Map<String, Value>, key: &str, what: &'static str) -> Result<&'a [Value]> {
    match top.get(key) {
        None => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(_) => Err(bad(what)),
    }
}

impl OwnerFile {
    /// Parses an owner file: I-JSON of at most 64 KiB with no duplicate
    /// keys, an object with `"v": 0`, and optional `identities` and
    /// `revoked` arrays. Unknown fields are ignored at every level. Entries
    /// that break their rules are dropped (SPEC §13.2.4).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidOwnerFile`] when the file as a whole is invalid; such
    /// a file vouches for nothing.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_OWNER_FILE_BYTES {
            return Err(bad("too large"));
        }
        let value = parse_json_unique_keys(bytes, "owner file").map_err(|_| bad("not I-JSON"))?;
        let top = value.as_object().ok_or(bad("not an object"))?;
        if top.get("v").and_then(Value::as_u64) != Some(0) {
            return Err(bad("v must be 0"));
        }
        let identities = array(top, "identities", "identities is not an array")?
            .iter()
            .filter_map(parse_identity_entry)
            .collect();
        let revoked = array(top, "revoked", "revoked is not an array")?
            .iter()
            .filter_map(parse_revocation_entry)
            .collect();
        Ok(Self {
            identities,
            revoked,
        })
    }

    /// The valid `identities` entries.
    #[must_use]
    pub fn identities(&self) -> &[OwnerIdentity] {
        &self.identities
    }

    /// The `revoked` entries with a valid identity.
    #[must_use]
    pub fn revoked(&self) -> &[OwnerRevocation] {
        &self.revoked
    }

    /// What this file says about `identity` listed as `name` on
    /// `directory`.
    #[must_use]
    pub fn vouch(&self, identity: &str, directory: &str, name: &str) -> Vouch {
        if let Some(r) = self.revoked.iter().find(|r| r.identity == identity) {
            return Vouch::Revoked {
                revoked_at: r.revoked_at,
                reason: r.reason,
            };
        }
        let listing = format!("{directory}/a/{name}");
        let listed = self.identities.iter().any(|e| {
            e.identity == identity && e.listings.as_ref().is_none_or(|ls| ls.contains(&listing))
        });
        if listed {
            Vouch::Vouches
        } else {
            Vouch::DoesNotVouch
        }
    }

    /// [`OwnerFile::vouch`] on raw fetched bytes: a file that doesn't parse
    /// vouches for nothing. For the owner state, use
    /// [`OwnerFile::fetch_result`], which counts such a file as a failed
    /// fetch.
    #[must_use]
    pub fn vouch_bytes(bytes: &[u8], identity: &str, directory: &str, name: &str) -> Vouch {
        Self::parse(bytes).map_or(Vouch::DoesNotVouch, |f| f.vouch(identity, directory, name))
    }

    /// The [`FetchResult`] of fetched bytes, for [`OwnerChecks::record`]: a
    /// file that doesn't parse as a whole counts as a **failed fetch**, not
    /// as "doesn't vouch" (SPEC §13.2.4). A broken edit therefore can't
    /// clear an earlier revocation or turn a verified owner into `failed`
    /// at once; it ages like an unreachable server.
    #[must_use]
    pub fn fetch_result(bytes: &[u8], identity: &str, directory: &str, name: &str) -> FetchResult {
        Self::parse(bytes).map_or(FetchResult::Failed, |f| {
            FetchResult::Fetched(f.vouch(identity, directory, name))
        })
    }
}

/// The result of one fetch of the owner file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchResult {
    /// A file was fetched; this is what it says.
    Fetched(Vouch),
    /// No file was fetched (network, TLS, status, redirect, content type,
    /// size or address rule).
    Failed,
}

/// The latest completed fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LatestFetch {
    /// Unix seconds.
    pub at: u64,
    /// Its result.
    pub result: FetchResult,
}

/// The fetch history [`owner_state`] needs. Keep it per listing and
/// update it with [`OwnerChecks::record`] after every fetch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnerChecks {
    /// When a fetch last vouched (Unix seconds), if ever.
    pub last_vouched_at: Option<u64>,
    /// The latest fetch that got a file which doesn't vouch or revokes the
    /// identity, with its time. A negative result is sticky: only a later
    /// fetch that vouches clears it.
    pub last_negative: Option<(u64, Vouch)>,
    /// The latest completed fetch, if any.
    pub latest: Option<LatestFetch>,
    /// The human chose not to fetch (a daemon's `--no-domain-check`).
    pub skipped: bool,
}

impl OwnerChecks {
    /// Folds one fetch at `at` into the history.
    pub fn record(&mut self, at: u64, result: FetchResult) {
        match result {
            FetchResult::Fetched(Vouch::Vouches) => {
                self.last_vouched_at = Some(self.last_vouched_at.map_or(at, |t| t.max(at)));
            }
            FetchResult::Fetched(v) => {
                if self.last_negative.is_none_or(|(t, _)| at >= t) {
                    self.last_negative = Some((at, v));
                }
            }
            FetchResult::Failed => {}
        }
        if self.latest.is_none_or(|l| at >= l.at) {
            self.latest = Some(LatestFetch { at, result });
        }
    }
}

/// The owner state of a listing (SPEC §13.2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerState {
    /// The domain vouched within 24 h.
    Verified,
    /// No `owner_domain`.
    Unclaimed,
    /// It vouched between 24 h and 7 days ago; later fetches failed.
    Stale,
    /// The latest file doesn't vouch, or nothing vouched for 7 days.
    Failed,
    /// A fetch revoked the identity, and none has vouched since.
    Revoked,
    /// No fetch has completed yet (a directory shows "checking").
    Checking,
    /// The human skipped the fetch, so nothing is known (a daemon records
    /// this for a knock made with `--no-domain-check`).
    Unchecked,
}

impl OwnerState {
    /// The state's name as written in SPEC §13.2.4.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unclaimed => "unclaimed",
            Self::Stale => "stale",
            Self::Failed => "failed",
            Self::Revoked => "revoked",
            Self::Checking => "checking",
            Self::Unchecked => "unchecked",
        }
    }
}

/// The owner state at `now` of a listing that claims `owner_domain`, from
/// its fetch history (SPEC §13.2.4).
///
/// A negative result is sticky. After a fetch that doesn't vouch or that
/// revokes, the state stays `failed` or `revoked` through any number of
/// failed fetches, and only a later fetch that vouches clears it. Only
/// fetches that vouched count towards `verified` and `stale`.
#[must_use]
pub fn owner_state(owner_domain: Option<&str>, checks: &OwnerChecks, now: u64) -> OwnerState {
    if owner_domain.is_none() {
        return OwnerState::Unclaimed;
    }
    if checks.skipped {
        return OwnerState::Unchecked;
    }
    // Fold `latest` in too, so a caller that only set `latest` is safe.
    let mut h = OwnerChecks {
        latest: None,
        ..*checks
    };
    match checks.latest {
        Some(l) => h.record(l.at, l.result),
        None if h.last_vouched_at.is_none() && h.last_negative.is_none() => {
            return OwnerState::Checking;
        }
        None => {}
    }
    if let Some((neg_at, neg)) = h.last_negative
        && h.last_vouched_at.is_none_or(|v| v <= neg_at)
    {
        return match neg {
            Vouch::Revoked { .. } => OwnerState::Revoked,
            _ => OwnerState::Failed,
        };
    }
    match h.last_vouched_at.map(|t| now.saturating_sub(t)) {
        Some(age) if age <= VERIFIED_FOR_SECS => OwnerState::Verified,
        Some(age) if age <= STALE_AFTER_SECS => OwnerState::Stale,
        _ => OwnerState::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::rng::Rng;
    use serde_json::json;

    const DIR: &str = "agents.example";
    const REV: Vouch = Vouch::Revoked {
        revoked_at: None,
        reason: None,
    };

    fn ids() -> (Identity, Identity) {
        let rng = Rng::for_test("owner-file");
        (
            Identity::generate(&rng).unwrap(),
            Identity::generate(&rng).unwrap(),
        )
    }

    fn parse(v: &Value) -> Result<OwnerFile> {
        OwnerFile::parse(&serde_json::to_vec_pretty(v).unwrap())
    }

    #[test]
    fn a_file_vouches_for_listed_identities() {
        let (a, b) = ids();
        let f = parse(&json!({
            "v": 0,
            "note": "maintained by the platform team",
            "identities": [
                {"identity": a.id(), "fingerprint": a.fingerprint(), "x": 1},
                {"identity": b.id(), "listings": [format!("{DIR}/a/release-planner")]},
            ],
        }))
        .unwrap();
        assert_eq!(f.identities().len(), 2);
        assert_eq!(f.vouch(&a.id(), DIR, "anything"), Vouch::Vouches);
        assert_eq!(f.vouch(&b.id(), DIR, "release-planner"), Vouch::Vouches);
        assert_eq!(f.vouch(&b.id(), DIR, "other-name"), Vouch::DoesNotVouch);
        assert_eq!(
            f.vouch(&b.id(), "other.example", "release-planner"),
            Vouch::DoesNotVouch
        );
        let stranger = Identity::generate(&Rng::for_test("owner-stranger")).unwrap();
        assert_eq!(
            f.vouch(&stranger.id(), DIR, "release-planner"),
            Vouch::DoesNotVouch
        );
        assert_eq!(f.revoked(), []);
    }

    #[test]
    fn invalid_entries_vouch_for_nothing() {
        let (a, b) = ids();
        let f = parse(&json!({
            "v": 0,
            "identities": [
                {"identity": a.id(), "fingerprint": b.fingerprint()},
                {"identity": b.id(), "listings": ["not a listing"]},
                {"identity": "ac:v0:nope"},
                {"fingerprint": a.fingerprint()},
                {"identity": b.id(), "listings": "agents.example/a/x"},
                "just a string",
            ],
        }))
        .unwrap();
        assert_eq!(f.identities(), []);
        assert_eq!(
            f.vouch(&a.id(), DIR, "release-planner"),
            Vouch::DoesNotVouch
        );
    }

    #[test]
    fn revocation_wins_and_is_lenient_about_its_other_fields() {
        let (a, b) = ids();
        let f = parse(&json!({
            "v": 0,
            "identities": [{"identity": a.id()}, {"identity": b.id()}],
            "revoked": [
                {"identity": a.id(), "revoked_at": 1_792_000_000, "reason": "superseded"},
                {"identity": b.id(), "revoked_at": "yesterday", "reason": "lost"},
                {"identity": "ac:v0:nope", "reason": "compromised"},
            ],
        }))
        .unwrap();
        assert_eq!(
            f.vouch(&a.id(), DIR, "release-planner"),
            Vouch::Revoked {
                revoked_at: Some(1_792_000_000),
                reason: Some(RevocationReason::Superseded)
            }
        );
        assert_eq!(f.vouch(&b.id(), DIR, "release-planner"), REV);
        assert_eq!(f.revoked().len(), 2);
        assert_eq!(f.revoked()[0].reason, Some(RevocationReason::Superseded));
        assert_eq!(f.revoked()[0].revoked_at, Some(1_792_000_000));
        assert_eq!(f.revoked()[1].reason, None);
        assert_eq!(f.revoked()[1].revoked_at, None);
        let c = parse(&json!({"v": 0, "revoked": [{"identity": a.id(), "reason": "compromised"}]}))
            .unwrap();
        assert_eq!(c.revoked()[0].reason, Some(RevocationReason::Compromised));
    }

    #[test]
    fn invalid_files_are_rejected() {
        let (a, _) = ids();
        let entry = format!("{{\"identity\":\"{}\"}}", a.id());
        for (bytes, err) in [
            (
                format!("{{\"v\":0,\"v\":0,\"identities\":[{entry}]}}"),
                bad("not I-JSON"),
            ),
            (
                "{\"v\":0,\"identities\":[{\"identity\":\"x\",\"identity\":\"y\"}]}".to_owned(),
                bad("not I-JSON"),
            ),
            ("[]".to_owned(), bad("not an object")),
            ("{\"v\":1}".to_owned(), bad("v must be 0")),
            ("{\"identities\":[]}".to_owned(), bad("v must be 0")),
            (
                "{\"v\":0,\"identities\":{}}".to_owned(),
                bad("identities is not an array"),
            ),
            (
                "{\"v\":0,\"revoked\":1}".to_owned(),
                bad("revoked is not an array"),
            ),
            ("{\"v\":0} trailing".to_owned(), bad("not I-JSON")),
            ("{\"v\":0,\"x\":\"\\ud800\"}".to_owned(), bad("not I-JSON")),
        ] {
            assert_eq!(OwnerFile::parse(bytes.as_bytes()), Err(err), "{bytes}");
            assert_eq!(
                OwnerFile::vouch_bytes(bytes.as_bytes(), &a.id(), DIR, "release-planner"),
                Vouch::DoesNotVouch
            );
        }
        let big = format!(
            "{{\"v\":0,\"pad\":\"{}\"}}",
            "x".repeat(MAX_OWNER_FILE_BYTES)
        );
        assert_eq!(OwnerFile::parse(big.as_bytes()), Err(bad("too large")));
        let ok = format!("{{\"v\":0,\"identities\":[{entry}],\"n\":1.5}}");
        assert_eq!(
            OwnerFile::vouch_bytes(ok.as_bytes(), &a.id(), DIR, "release-planner"),
            Vouch::Vouches
        );
        assert_eq!(
            OwnerFile::parse(b"{\"v\":0}").unwrap().identities().len(),
            0
        );
    }

    /// Review M1: a failed fetch after a negative one used to bring back
    /// `verified` (within 24 h of the last vouch) or `stale`.
    #[test]
    fn negative_results_are_sticky() {
        const H: u64 = 3600;
        let d = Some("example.com");
        let history = |steps: &[(u64, FetchResult)]| {
            let mut c = OwnerChecks::default();
            for (at, r) in steps {
                c.record(*at, *r);
            }
            c
        };
        let ok = FetchResult::Fetched(Vouch::Vouches);
        let no = FetchResult::Fetched(Vouch::DoesNotVouch);
        let rev = FetchResult::Fetched(REV);
        let fail = FetchResult::Failed;
        let t = 100 * 24 * H;
        for (steps, now, expected) in [
            (
                vec![(t - 2 * H, ok), (t - H, no), (t, fail)],
                t,
                OwnerState::Failed,
            ),
            (
                vec![(t - 2 * H, ok), (t - H, rev), (t, fail)],
                t,
                OwnerState::Revoked,
            ),
            // Days of failures don't wear a revocation down to `stale`.
            (
                vec![(t - 2 * H, ok), (t - H, rev), (t + 3 * 24 * H, fail)],
                t + 3 * 24 * H,
                OwnerState::Revoked,
            ),
            // Only a later vouching fetch clears it.
            (
                vec![(t - 2 * H, ok), (t - H, no), (t, ok)],
                t,
                OwnerState::Verified,
            ),
            (
                vec![(t - 2 * H, ok), (t - H, rev), (t, ok), (t + H, fail)],
                t + H,
                OwnerState::Verified,
            ),
            (vec![(t - H, rev), (t - H, ok)], t, OwnerState::Revoked),
            (vec![(t - 2 * H, ok), (t, fail)], t, OwnerState::Verified),
            (vec![(t - 2 * 24 * H, ok), (t, fail)], t, OwnerState::Stale),
            (vec![(t, fail)], t, OwnerState::Failed),
            (vec![], t, OwnerState::Checking),
        ] {
            let c = history(&steps);
            assert_eq!(owner_state(d, &c, now), expected, "{steps:?}");
        }
        // Out-of-order records keep the newest of each.
        let c = history(&[(t, no), (t - H, ok), (t - 2 * H, rev)]);
        assert_eq!(c.last_negative, Some((t, Vouch::DoesNotVouch)));
        assert_eq!(c.latest.map(|l| l.at), Some(t));
        assert_eq!(owner_state(d, &c, t), OwnerState::Failed);
        // A human who skipped the fetch.
        let skipped = OwnerChecks {
            skipped: true,
            ..OwnerChecks::default()
        };
        assert_eq!(owner_state(d, &skipped, t), OwnerState::Unchecked);
        assert_eq!(owner_state(None, &skipped, t), OwnerState::Unclaimed);
    }

    /// Review L2: a file broken as a whole is a failed fetch, so it can't
    /// clear an earlier revocation.
    #[test]
    fn a_broken_file_is_a_failed_fetch() {
        let (a, _) = ids();
        let broken = format!(
            "{{\"v\":0,\"v\":0,\"identities\":[{{\"identity\":\"{}\"}}]}}",
            a.id()
        );
        assert_eq!(
            OwnerFile::fetch_result(broken.as_bytes(), &a.id(), DIR, "release-planner"),
            FetchResult::Failed
        );
        let revoking = format!(
            "{{\"v\":0,\"revoked\":[{{\"identity\":\"{}\",\"reason\":\"compromised\"}}]}}",
            a.id()
        );
        let r = OwnerFile::fetch_result(revoking.as_bytes(), &a.id(), DIR, "release-planner");
        assert_eq!(
            r,
            FetchResult::Fetched(Vouch::Revoked {
                revoked_at: None,
                reason: Some(RevocationReason::Compromised)
            })
        );
        let mut c = OwnerChecks::default();
        c.record(10, r);
        c.record(20, FetchResult::Failed);
        assert_eq!(
            owner_state(Some("example.com"), &c, 20),
            OwnerState::Revoked
        );
        assert_eq!(Vouch::Vouches.as_str(), "vouches");
        assert_eq!(REV.as_str(), "revoked");
        assert_eq!(Vouch::DoesNotVouch.as_str(), "does_not_vouch");
    }

    #[test]
    fn owner_file_urls() {
        assert_eq!(
            owner_file_url("example.com").unwrap(),
            "https://example.com/.well-known/agentconnect.json"
        );
        assert_eq!(owner_file_url("127.0.0.1"), Err(bad("owner domain")));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn owner_states_follow_the_fetch_history() {
        const H: u64 = 3600;
        let now = 100 * 24 * H;
        let at = |result, t| OwnerChecks {
            last_vouched_at: None,
            latest: Some(LatestFetch { at: t, result }),
            ..OwnerChecks::default()
        };
        let vouched = |last: u64, latest: FetchResult| OwnerChecks {
            last_vouched_at: Some(last),
            latest: Some(LatestFetch {
                at: now,
                result: latest,
            }),
            ..OwnerChecks::default()
        };
        let d = Some("example.com");
        let cases = [
            (None, OwnerChecks::default(), OwnerState::Unclaimed),
            (
                None,
                at(FetchResult::Fetched(Vouch::Vouches), now),
                OwnerState::Unclaimed,
            ),
            (d, OwnerChecks::default(), OwnerState::Checking),
            (
                d,
                at(FetchResult::Fetched(Vouch::Vouches), now),
                OwnerState::Verified,
            ),
            (
                d,
                at(FetchResult::Fetched(Vouch::Vouches), now - 24 * H),
                OwnerState::Verified,
            ),
            (
                d,
                at(FetchResult::Fetched(Vouch::Vouches), now - 24 * H - 1),
                OwnerState::Stale,
            ),
            (
                d,
                at(FetchResult::Fetched(Vouch::DoesNotVouch), now),
                OwnerState::Failed,
            ),
            (d, at(FetchResult::Fetched(REV), now), OwnerState::Revoked),
            (d, at(FetchResult::Failed, now), OwnerState::Failed),
            (
                d,
                vouched(now - H, FetchResult::Failed),
                OwnerState::Verified,
            ),
            (
                d,
                vouched(now - 2 * 24 * H, FetchResult::Failed),
                OwnerState::Stale,
            ),
            (
                d,
                vouched(now - 7 * 24 * H, FetchResult::Failed),
                OwnerState::Stale,
            ),
            (
                d,
                vouched(now - 7 * 24 * H - 1, FetchResult::Failed),
                OwnerState::Failed,
            ),
            // A file that stopped vouching fails at once, whatever came before.
            (
                d,
                vouched(now - H, FetchResult::Fetched(Vouch::DoesNotVouch)),
                OwnerState::Failed,
            ),
            (
                d,
                vouched(now - H, FetchResult::Fetched(REV)),
                OwnerState::Revoked,
            ),
            (
                d,
                vouched(now - 30 * 24 * H, FetchResult::Fetched(Vouch::Vouches)),
                OwnerState::Verified,
            ),
        ];
        for (domain, checks, expected) in cases {
            assert_eq!(owner_state(domain, &checks, now), expected, "{checks:?}");
        }
        let names: Vec<&str> = [
            OwnerState::Verified,
            OwnerState::Unclaimed,
            OwnerState::Stale,
            OwnerState::Failed,
            OwnerState::Revoked,
            OwnerState::Checking,
            OwnerState::Unchecked,
        ]
        .iter()
        .map(|s| s.as_str())
        .collect();
        assert_eq!(
            names,
            [
                "verified",
                "unclaimed",
                "stale",
                "failed",
                "revoked",
                "checking",
                "unchecked"
            ]
        );
    }
}
