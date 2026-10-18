//! Bindings for discovery (SPEC §6.6, §13): listings, listing tokens,
//! withdrawals, owner files, doors and knocks. The checks themselves are
//! all in `agentconnect_core::listing` and `agentconnect_core::knock`.

use agentconnect_core as core;
use agentconnect_core::knock;
use agentconnect_core::listing::{self, FetchResult, LatestFetch, OwnerChecks, Vouch};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use zeroize::Zeroizing;

use crate::{Identity, array, bad_arg, err, guarded, secret32};

fn trusted(directory: &str, keys: &[Vec<u8>]) -> PyResult<listing::TrustedDirectory> {
    let keys = keys
        .iter()
        .map(|k| array::<32>(k, "directory key"))
        .collect::<PyResult<Vec<_>>>()?;
    listing::TrustedDirectory::new(directory, &keys).map_err(err)
}

fn revoked_set(revoked: &[Vec<u8>]) -> PyResult<Vec<[u8; 16]>> {
    revoked.iter().map(|r| array::<16>(r, "token id")).collect()
}

/// A listing that passed every check of SPEC §13.1, including its JWS.
#[pyclass(frozen, module = "agentconnect_core._native")]
pub(crate) struct Listing(listing::SignedListing);

#[pymethods]
impl Listing {
    /// The published bytes (canonical JCS, signature included).
    #[getter]
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.bytes())
    }

    /// The signed payload: JCS of the card without `signatures`.
    #[getter]
    fn unsigned_card<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        guarded(|| {
            Ok(PyBytes::new(
                py,
                &self.0.card().to_unsigned_json().map_err(err)?,
            ))
        })
    }

    #[getter]
    fn identity(&self) -> String {
        self.0.params().identity.clone()
    }

    #[getter]
    fn fingerprint(&self) -> String {
        self.0.fingerprint()
    }

    #[getter]
    fn name(&self) -> String {
        self.0.params().name.clone()
    }

    /// The card's display name (untrusted text).
    #[getter]
    fn display_name(&self) -> String {
        self.0.card().name.clone()
    }

    /// The card's description (untrusted text).
    #[getter]
    fn description(&self) -> String {
        self.0.card().description.clone()
    }

    #[getter]
    fn directory(&self) -> String {
        self.0.params().directory.clone()
    }

    #[getter]
    fn relay(&self) -> String {
        self.0.params().relay.clone()
    }

    #[getter]
    fn seq(&self) -> u64 {
        self.0.params().seq
    }

    #[getter]
    fn issued_at(&self) -> u64 {
        self.0.params().issued_at
    }

    #[getter]
    fn owner_domain(&self) -> Option<String> {
        self.0.params().owner_domain.clone()
    }

    /// The canonical URL, `https://<directory>/a/<name>.json`.
    #[getter]
    fn url(&self) -> String {
        self.0.url()
    }

    /// SHA-256 of the published bytes.
    #[getter]
    fn sha256<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.sha256())
    }

    #[getter]
    fn token_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.token().token_id)
    }

    #[getter]
    fn token_expires_at(&self) -> u64 {
        self.0.token().grant.expires_at
    }

    /// `{"id": bytes, "key": bytes, "expires_at": int}`, or `None` when the
    /// door is closed.
    #[getter]
    fn door<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyDict>>> {
        self.0
            .params()
            .door
            .as_ref()
            .map(|d| {
                let out = PyDict::new(py);
                out.set_item("id", PyBytes::new(py, &d.id))?;
                out.set_item("key", PyBytes::new(py, &d.key))?;
                out.set_item("expires_at", d.expires_at)?;
                Ok(out)
            })
            .transpose()
    }

    /// Whether a door is advertised and hasn't expired at `now`.
    fn door_open(&self, now: u64) -> bool {
        self.0.door_open(now)
    }

    /// The token checks (SPEC §13.2.1) against the pinned keys of
    /// `directory`, at `now`, with the revoked token ids `revoked`.
    #[pyo3(signature = (directory, directory_keys, now, revoked=Vec::new()))]
    fn check_token(
        &self,
        directory: &str,
        directory_keys: Vec<Vec<u8>>,
        now: u64,
        revoked: Vec<Vec<u8>>,
    ) -> PyResult<()> {
        guarded(|| {
            let t = trusted(directory, &directory_keys)?;
            let revoked = revoked_set(&revoked)?;
            self.0
                .check_token(&t, now, |id| revoked.contains(id))
                .map_err(err)
        })
    }

    /// Whether this listing may replace `stored` for the same directory and
    /// name (SPEC §13.2.2): the same identity needs a higher `seq`, another
    /// identity a later token.
    fn replaces(&self, stored: &Listing) -> bool {
        self.0.replaces(&stored.0)
    }

    /// Whether the tombstone `(identity, seq)` blocks this listing.
    fn tombstoned_by(&self, identity: &str, seq: u64) -> bool {
        self.0.tombstoned_by(identity, seq)
    }

    /// The publish time checks (SPEC §13.2.2).
    fn check_publish(&self, now: u64) -> PyResult<()> {
        guarded(|| self.0.check_publish(now).map_err(err))
    }

    fn __repr__(&self) -> String {
        format!(
            "Listing({}, seq {})",
            self.0.params().name,
            self.0.params().seq
        )
    }
}

/// Parses and verifies published listing bytes (SPEC §13.1).
#[pyfunction]
pub(crate) fn verify_listing(data: &[u8]) -> PyResult<Listing> {
    guarded(|| {
        listing::SignedListing::from_bytes(data)
            .map(Listing)
            .map_err(err)
    })
}

/// Signs a card (JSON without `signatures`, any formatting) with `identity`,
/// which must be its `params.identity`. Publishing is a human decision.
#[pyfunction]
pub(crate) fn sign_listing(card_json: &[u8], identity: &Identity) -> PyResult<Listing> {
    guarded(|| {
        let card = listing::ListingCard::from_unsigned_json(card_json).map_err(err)?;
        card.sign(&identity.0).map(Listing).map_err(err)
    })
}

/// Validates a card to sign and returns its canonical unsigned form (what
/// the human is shown).
#[pyfunction]
pub(crate) fn canonical_card<'py>(
    py: Python<'py>,
    card_json: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    guarded(|| {
        let card = listing::ListingCard::from_unsigned_json(card_json).map_err(err)?;
        Ok(PyBytes::new(py, &card.to_unsigned_json().map_err(err)?))
    })
}

fn token_dict<'py>(py: Python<'py>, t: &listing::ListingToken) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("token_id", PyBytes::new(py, &t.token_id))?;
    d.set_item("directory", &t.grant.directory)?;
    d.set_item("name", &t.grant.name)?;
    d.set_item("identity", &t.grant.identity)?;
    d.set_item("owner_domain", &t.grant.owner_domain)?;
    d.set_item("issued_at", t.grant.issued_at)?;
    d.set_item("expires_at", t.grant.expires_at)?;
    d.set_item("key_id", PyBytes::new(py, &t.key_id))?;
    Ok(d)
}

/// Parses a token and runs its own checks (SPEC §13.2.1) against the pinned
/// keys of `directory` at `now`. Returns its fields.
#[pyfunction]
pub(crate) fn verify_listing_token<'py>(
    py: Python<'py>,
    token_json: &[u8],
    directory: &str,
    directory_keys: Vec<Vec<u8>>,
    now: u64,
) -> PyResult<Bound<'py, PyDict>> {
    guarded(|| {
        let t = listing::ListingToken::from_json(token_json).map_err(err)?;
        t.verify(&trusted(directory, &directory_keys)?, now)
            .map_err(err)?;
        token_dict(py, &t)
    })
}

/// Whether a token binds a listing of `name` by `identity` on `directory`
/// (and `owner_domain`, if the token pins one).
#[pyfunction]
#[pyo3(signature = (token_json, directory, name, identity, owner_domain=None))]
pub(crate) fn check_token_binding(
    token_json: &[u8],
    directory: &str,
    name: &str,
    identity: &str,
    owner_domain: Option<&str>,
) -> PyResult<()> {
    guarded(|| {
        listing::ListingToken::from_json(token_json)
            .and_then(|t| t.check_binding(directory, name, identity, owner_domain))
            .map_err(err)
    })
}

/// Parses and verifies a `TokenRevocation` under the pinned keys of
/// `directory`: `{"token_id", "revoked_at", "reason"}`.
#[pyfunction]
pub(crate) fn verify_token_revocation<'py>(
    py: Python<'py>,
    revocation_json: &[u8],
    directory: &str,
    directory_keys: Vec<Vec<u8>>,
) -> PyResult<Bound<'py, PyDict>> {
    guarded(|| {
        let r = listing::TokenRevocation::from_json(revocation_json).map_err(err)?;
        r.verify(&trusted(directory, &directory_keys)?)
            .map_err(err)?;
        let d = PyDict::new(py);
        d.set_item("token_id", PyBytes::new(py, &r.token_id))?;
        d.set_item("revoked_at", r.revoked_at)?;
        d.set_item("reason", &r.reason)?;
        Ok(d)
    })
}

/// The directory operator's token key `DK` (for the operator's offline
/// tool; a directory server never holds it).
#[pyclass(frozen, module = "agentconnect_core._native")]
pub(crate) struct DirectoryKey(listing::DirectoryKey);

#[pymethods]
impl DirectoryKey {
    #[staticmethod]
    fn generate() -> PyResult<Self> {
        guarded(|| {
            let rng = core::Rng::os().map_err(err)?;
            Ok(Self(listing::DirectoryKey::generate(&rng).map_err(err)?))
        })
    }

    /// **Tests only**: a key from a 64-bit seed (guessable).
    #[staticmethod]
    fn _generate_for_testing(seed: u64) -> PyResult<Self> {
        guarded(|| {
            Ok(Self(
                listing::DirectoryKey::generate(&core::Rng::from_u64(seed)).map_err(err)?,
            ))
        })
    }

    #[staticmethod]
    fn from_secret_bytes(secret: &[u8]) -> PyResult<Self> {
        guarded(|| {
            Ok(Self(listing::DirectoryKey::from_secret_bytes(&*secret32(
                secret,
            )?)))
        })
    }

    fn secret_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.secret_bytes().as_slice())
    }

    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.public_key())
    }

    #[getter]
    fn key_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.key_id())
    }

    /// Issues a token (JCS bytes) with a fresh random `token_id`.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (directory, name, identity, issued_at, expires_at, owner_domain=None))]
    fn issue_token<'py>(
        &self,
        py: Python<'py>,
        directory: &str,
        name: &str,
        identity: &str,
        issued_at: u64,
        expires_at: u64,
        owner_domain: Option<String>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        guarded(|| {
            let rng = core::Rng::os().map_err(err)?;
            let grant = listing::TokenGrant {
                directory: directory.to_owned(),
                name: name.to_owned(),
                identity: identity.to_owned(),
                owner_domain,
                issued_at,
                expires_at,
            };
            let t = self.0.issue_token(&rng, &grant).map_err(err)?;
            Ok(PyBytes::new(py, &t.to_json().map_err(err)?))
        })
    }

    /// Revokes a token: a `TokenRevocation` (JCS bytes).
    fn revoke_token<'py>(
        &self,
        py: Python<'py>,
        token_id: &[u8],
        revoked_at: u64,
        reason: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        guarded(|| {
            let r = self
                .0
                .revoke_token(&array(token_id, "token id")?, revoked_at, reason)
                .map_err(err)?;
            Ok(PyBytes::new(py, &r.to_json().map_err(err)?))
        })
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.0)
    }
}

/// The state a directory or mirror keeps per (directory, name), forever:
/// the newest token `issued_at` accepted for the name and its identity,
/// and per identity the highest tombstoned `seq` (SPEC §13.2.2). Persist
/// the properties and rebuild it with the constructor.
#[pyclass(module = "agentconnect_core._native")]
pub(crate) struct NameRecord(listing::NameRecord);

#[pymethods]
impl NameRecord {
    #[new]
    #[pyo3(signature = (*, high_water=None, tombstones=Vec::new()))]
    fn new(high_water: Option<(u64, String)>, tombstones: Vec<(String, u64)>) -> Self {
        Self(listing::NameRecord {
            high_water,
            tombstones,
        })
    }

    /// `(token_issued_at, identity)` of the newest token accepted, or None.
    #[getter]
    fn high_water(&self) -> Option<(u64, String)> {
        self.0.high_water.clone()
    }

    /// `[(identity, seq)]`: each identity's highest tombstoned `seq`.
    #[getter]
    fn tombstones(&self) -> Vec<(String, u64)> {
        self.0.tombstones.clone()
    }

    /// Raises `AgentConnectError` (kind `superseded`) unless `listing` may
    /// be published, given the listing `stored` for the name now.
    #[pyo3(signature = (listing, stored=None))]
    fn admits(&self, listing: &Listing, stored: Option<&Listing>) -> PyResult<()> {
        guarded(|| self.0.admits(&listing.0, stored.map(|s| &s.0)).map_err(err))
    }

    /// Records an accepted listing (raises the high-water mark).
    fn accept(&mut self, listing: &Listing) {
        self.0.accept(&listing.0);
    }

    /// Records a withdrawal of the name (verified first).
    fn tombstone(&mut self, withdrawal: &[u8]) -> PyResult<()> {
        let w = listing::Withdrawal::from_json(withdrawal).map_err(err)?;
        self.0.tombstone(&w);
        Ok(())
    }
}

/// Signs a withdrawal of `name` on `directory` up to `seq` (JCS bytes).
#[pyfunction]
pub(crate) fn sign_withdrawal<'py>(
    py: Python<'py>,
    identity: &Identity,
    directory: &str,
    name: &str,
    seq: u64,
    ts: u64,
) -> PyResult<Bound<'py, PyBytes>> {
    guarded(|| {
        let w = listing::Withdrawal::sign(&identity.0, directory, name, seq, ts).map_err(err)?;
        Ok(PyBytes::new(py, &w.to_json().map_err(err)?))
    })
}

/// Parses a withdrawal and verifies its signature:
/// `{"directory", "name", "identity", "seq", "ts"}`.
#[pyfunction]
pub(crate) fn verify_withdrawal<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyDict>> {
    guarded(|| {
        let w = listing::Withdrawal::from_json(data).map_err(err)?;
        let d = PyDict::new(py);
        d.set_item("directory", &w.directory)?;
        d.set_item("name", &w.name)?;
        d.set_item("identity", &w.identity)?;
        d.set_item("seq", w.seq)?;
        d.set_item("ts", w.ts)?;
        Ok(d)
    })
}

/// The directory's freshness check on `POST /v0/withdrawals`.
#[pyfunction]
pub(crate) fn check_withdrawal_fresh(data: &[u8], directory: &str, now: u64) -> PyResult<()> {
    guarded(|| {
        listing::Withdrawal::from_json(data)
            .and_then(|w| w.check_fresh(directory, now))
            .map_err(err)
    })
}

/// Whether a (verified) withdrawal removes `listing`.
#[pyfunction]
pub(crate) fn withdrawal_applies(data: &[u8], listing: &Listing) -> PyResult<bool> {
    guarded(|| {
        listing::Withdrawal::from_json(data)
            .map(|w| w.applies_to(&listing.0))
            .map_err(err)
    })
}

/// Parses an owner file (SPEC §13.2.4):
/// `{"identities": [{"identity", "listings"}], "revoked": [{"identity",
/// "revoked_at", "reason"}]}` with invalid entries dropped.
#[pyfunction]
pub(crate) fn parse_owner_file<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyDict>> {
    guarded(|| {
        let f = listing::OwnerFile::parse(data).map_err(err)?;
        let ids = PyList::empty(py);
        for e in f.identities() {
            let d = PyDict::new(py);
            d.set_item("identity", &e.identity)?;
            d.set_item("listings", &e.listings)?;
            ids.append(d)?;
        }
        let revoked = PyList::empty(py);
        for r in f.revoked() {
            let d = PyDict::new(py);
            d.set_item("identity", &r.identity)?;
            d.set_item("revoked_at", r.revoked_at)?;
            d.set_item(
                "reason",
                r.reason.map(|x| match x {
                    listing::RevocationReason::Superseded => "superseded",
                    listing::RevocationReason::Compromised => "compromised",
                }),
            )?;
            revoked.append(d)?;
        }
        let out = PyDict::new(py);
        out.set_item("identities", ids)?;
        out.set_item("revoked", revoked)?;
        Ok(out)
    })
}

/// What fetched owner-file bytes say about a listing: `"vouches"`,
/// `"does_not_vouch"` (also for a file that doesn't parse) or `"revoked"`.
#[pyfunction]
pub(crate) fn owner_vouch(
    data: &[u8],
    identity: &str,
    directory: &str,
    name: &str,
) -> &'static str {
    listing::OwnerFile::vouch_bytes(data, identity, directory, name).as_str()
}

fn reason_str(r: listing::RevocationReason) -> &'static str {
    match r {
        listing::RevocationReason::Superseded => "superseded",
        listing::RevocationReason::Compromised => "compromised",
    }
}

/// What one fetch of the owner file counts as for the owner state
/// (SPEC §13.2.4): `{"result": "vouches" | "does_not_vouch" | "revoked" |
/// "failed", "revoked_at": int | None, "reason": str | None}`. A file that
/// doesn't parse as a whole is `"failed"`, like an unreachable server.
#[pyfunction]
pub(crate) fn owner_fetch_result<'py>(
    py: Python<'py>,
    data: &[u8],
    identity: &str,
    directory: &str,
    name: &str,
) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    match listing::OwnerFile::fetch_result(data, identity, directory, name) {
        FetchResult::Failed => d.set_item("result", "failed")?,
        FetchResult::Fetched(v) => {
            d.set_item("result", v.as_str())?;
            if let Vouch::Revoked { revoked_at, reason } = v {
                d.set_item("revoked_at", revoked_at)?;
                d.set_item("reason", reason.map(reason_str))?;
            }
        }
    }
    if !d.contains("revoked_at")? {
        d.set_item("revoked_at", py.None())?;
        d.set_item("reason", py.None())?;
    }
    Ok(d)
}

fn fetch_result(name: &str) -> PyResult<FetchResult> {
    match name {
        "vouches" => Ok(FetchResult::Fetched(Vouch::Vouches)),
        "does_not_vouch" => Ok(FetchResult::Fetched(Vouch::DoesNotVouch)),
        "revoked" => Ok(FetchResult::Fetched(Vouch::Revoked {
            revoked_at: None,
            reason: None,
        })),
        "failed" => Ok(FetchResult::Failed),
        _ => Err(bad_arg("unknown fetch result")),
    }
}

fn negative_result(name: &str) -> PyResult<Vouch> {
    match fetch_result(name)? {
        FetchResult::Fetched(v @ (Vouch::DoesNotVouch | Vouch::Revoked { .. })) => Ok(v),
        _ => Err(bad_arg("a negative result is does_not_vouch or revoked")),
    }
}

/// The owner state (SPEC §13.2.4) from a summary of the fetch history:
/// the latest fetch (`latest_result`: `"vouches"`, `"does_not_vouch"`,
/// `"revoked"` or `"failed"`, at `latest_at`), the time a fetch last
/// vouched, the last negative result (`"does_not_vouch"` or `"revoked"`,
/// at `last_negative_at`), and whether the human skipped the fetch. A
/// negative result is sticky until a later fetch vouches. `OwnerChecks`
/// keeps this summary for you.
#[pyfunction]
#[pyo3(signature = (
    owner_domain,
    now,
    latest_result=None,
    latest_at=None,
    last_vouched_at=None,
    last_negative_result=None,
    last_negative_at=None,
    skipped=false,
))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn owner_state(
    owner_domain: Option<&str>,
    now: u64,
    latest_result: Option<&str>,
    latest_at: Option<u64>,
    last_vouched_at: Option<u64>,
    last_negative_result: Option<&str>,
    last_negative_at: Option<u64>,
    skipped: bool,
) -> PyResult<&'static str> {
    let latest = match (latest_result, latest_at) {
        (Some(r), Some(at)) => Some(LatestFetch {
            at,
            result: fetch_result(r)?,
        }),
        (None, None) => None,
        _ => return Err(bad_arg("latest_result and latest_at go together")),
    };
    let last_negative = match (last_negative_result, last_negative_at) {
        (Some(r), Some(at)) => Some((at, negative_result(r)?)),
        (None, None) => None,
        _ => {
            return Err(bad_arg(
                "last_negative_result and last_negative_at go together",
            ));
        }
    };
    let checks = OwnerChecks {
        last_vouched_at,
        last_negative,
        latest,
        skipped,
    };
    Ok(listing::owner_state(owner_domain, &checks, now).as_str())
}

/// The fetch history of one listing's owner file. Record every fetch with
/// `record(at, result)`, persist the summary properties, and ask `state`.
#[pyclass(module = "agentconnect_core._native")]
pub(crate) struct OwnerHistory(OwnerChecks);

#[pymethods]
impl OwnerHistory {
    #[new]
    #[pyo3(signature = (skipped=false))]
    fn new(skipped: bool) -> Self {
        Self(OwnerChecks {
            skipped,
            ..OwnerChecks::default()
        })
    }

    /// Folds one fetch (`result` as from `owner_fetch_result`) into the
    /// history.
    fn record(&mut self, at: u64, result: &str) -> PyResult<()> {
        self.0.record(at, fetch_result(result)?);
        Ok(())
    }

    /// The owner state at `now` for a listing claiming `owner_domain`.
    fn state(&self, owner_domain: Option<&str>, now: u64) -> &'static str {
        listing::owner_state(owner_domain, &self.0, now).as_str()
    }

    #[getter]
    fn last_vouched_at(&self) -> Option<u64> {
        self.0.last_vouched_at
    }

    /// `(at, "does_not_vouch" | "revoked")` or `None`.
    #[getter]
    fn last_negative(&self) -> Option<(u64, &'static str)> {
        self.0.last_negative.map(|(at, v)| (at, v.as_str()))
    }

    /// `(at, result)` of the latest fetch, or `None`.
    #[getter]
    fn latest(&self) -> Option<(u64, &'static str)> {
        self.0.latest.map(|l| {
            (
                l.at,
                match l.result {
                    FetchResult::Fetched(v) => v.as_str(),
                    FetchResult::Failed => "failed",
                },
            )
        })
    }

    #[getter]
    fn skipped(&self) -> bool {
        self.0.skipped
    }
}

/// `https://<domain>/.well-known/agentconnect.json`.
#[pyfunction]
pub(crate) fn owner_file_url(domain: &str) -> PyResult<String> {
    guarded(|| listing::owner_file_url(domain).map_err(err))
}

/// The owner's door (SPEC §6.6.1). Holds the private key.
#[pyclass(frozen, module = "agentconnect_core._native")]
pub(crate) struct Door(knock::Door);

#[pymethods]
impl Door {
    /// A fresh door that expires at `expires_at` (Unix seconds).
    #[staticmethod]
    fn generate(expires_at: u64) -> PyResult<Self> {
        guarded(|| {
            let rng = core::Rng::os().map_err(err)?;
            Ok(Self(knock::Door::generate(&rng, expires_at).map_err(err)?))
        })
    }

    /// **Tests only**: the door whose key pair is derived from `ikm`.
    #[staticmethod]
    fn _derive_for_testing(door_id: &[u8], ikm: &[u8], expires_at: u64) -> PyResult<Self> {
        guarded(|| {
            Ok(Self(
                knock::Door::derive(array(door_id, "door id")?, &*secret32(ikm)?, expires_at)
                    .map_err(err)?,
            ))
        })
    }

    /// Restores a door from `to_secret_bytes`.
    #[staticmethod]
    fn from_secret_bytes(data: &[u8]) -> PyResult<Self> {
        guarded(|| Ok(Self(knock::Door::from_secret_bytes(data).map_err(err)?)))
    }

    /// **Contains the private key**: store it encrypted.
    fn to_secret_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.to_secret_bytes())
    }

    #[getter]
    fn id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.id())
    }

    #[getter]
    fn expires_at(&self) -> u64 {
        self.0.expires_at()
    }

    /// The 1216-byte public key for the listing.
    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.public_key())
    }

    /// Whether the private key may be deleted (1 h after expiry).
    fn key_deletable(&self, now: u64) -> bool {
        self.0.key_deletable(now)
    }

    /// The owner's checks 1–3 (SPEC §6.6.3) on a sealed knock from an
    /// envelope for `envelope_door_id`. Every failure drops the knock
    /// silently.
    fn open_knock(
        &self,
        envelope_door_id: &[u8],
        sealed: &[u8],
        now: u64,
    ) -> PyResult<OpenedKnock> {
        guarded(|| {
            self.0
                .open_knock(&array(envelope_door_id, "door id")?, sealed, now)
                .map(OpenedKnock)
                .map_err(err)
        })
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.0)
    }
}

/// A knock that passed checks 1–3; `Client.verify_knock` runs 4–5.
#[pyclass(frozen, module = "agentconnect_core._native")]
pub(crate) struct OpenedKnock(pub(crate) knock::OpenedKnock);

#[pymethods]
impl OpenedKnock {
    #[getter]
    fn door_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.knock().door_id)
    }

    #[getter]
    fn knock_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.knock().knock_id)
    }

    #[getter]
    fn ts(&self) -> u64 {
        self.0.knock().ts
    }

    /// Untrusted text.
    #[getter]
    fn display_name(&self) -> String {
        self.0.knock().display_name.clone()
    }

    /// Untrusted text.
    #[getter]
    fn note(&self) -> Option<String> {
        self.0.knock().note.clone()
    }

    #[getter]
    fn mailbox_id(&self) -> String {
        self.0.knock().mailbox_id.clone()
    }

    #[getter]
    fn key_package<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.knock().key_package)
    }

    #[getter]
    fn sig<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.knock().sig)
    }

    /// `"agentconnect/v0/knock" ‖ JCS(knock without "sig")`. It contains
    /// the `welcome_secret`; don't log it.
    #[getter]
    fn signing_input<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.knock().signing_input())
    }
}

/// A knock this instance sent, kept (encrypted) until it joins or lapses.
#[pyclass(frozen, module = "agentconnect_core._native")]
pub(crate) struct PendingKnock(pub(crate) knock::Knock);

#[pymethods]
impl PendingKnock {
    /// Restores a pending knock from `to_secret_bytes`.
    #[staticmethod]
    fn from_secret_bytes(data: &[u8]) -> PyResult<Self> {
        guarded(|| Ok(Self(knock::Knock::from_json(data).map_err(err)?)))
    }

    /// The knock's JCS form. **Contains the `welcome_secret`**: store it
    /// encrypted, delete it after joining or at `gives_up_at`.
    fn to_secret_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let json: Zeroizing<Vec<u8>> = self.0.to_json();
        PyBytes::new(py, &json)
    }

    #[getter]
    fn door_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.door_id)
    }

    #[getter]
    fn knock_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.knock_id)
    }

    #[getter]
    fn ts(&self) -> u64 {
        self.0.ts
    }

    #[getter]
    fn lapses_at(&self) -> u64 {
        self.0.lapses_at()
    }

    /// When to report "no answer" (`ts + 3600 + 300`).
    #[getter]
    fn gives_up_at(&self) -> u64 {
        self.0.gives_up_at()
    }

    /// Opens a knock-wrapped Welcome (SPEC §6.6.4).
    fn unwrap_welcome<'py>(
        &self,
        py: Python<'py>,
        wrapped: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        guarded(|| {
            Ok(PyBytes::new(
                py,
                &self.0.secret().unwrap_welcome(wrapped).map_err(err)?,
            ))
        })
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.0)
    }
}

/// A knock that passed the owner's checks 1–5. Approving it is human-only.
#[pyclass(frozen, module = "agentconnect_core._native")]
pub(crate) struct VerifiedKnock(pub(crate) knock::VerifiedKnock);

#[pymethods]
impl VerifiedKnock {
    #[getter]
    fn identity(&self) -> String {
        self.0.identity().to_owned()
    }

    #[getter]
    fn instance_id(&self) -> u64 {
        self.0.instance_id()
    }

    #[getter]
    fn fingerprint(&self) -> String {
        self.0.fingerprint()
    }

    /// Untrusted text.
    #[getter]
    fn display_name(&self) -> String {
        self.0.knock().display_name.clone()
    }

    /// Untrusted text.
    #[getter]
    fn note(&self) -> Option<String> {
        self.0.knock().note.clone()
    }

    #[getter]
    fn mailbox_id(&self) -> String {
        self.0.knock().mailbox_id.clone()
    }

    #[getter]
    fn door_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.knock().door_id)
    }

    #[getter]
    fn knock_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.knock().knock_id)
    }

    #[getter]
    fn ts(&self) -> u64 {
        self.0.knock().ts
    }

    /// When the approval lapses (`ts + 3600`).
    #[getter]
    fn lapses_at(&self) -> u64 {
        self.0.knock().lapses_at()
    }

    #[getter]
    fn key_package_ref<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.key_package_ref())
    }

    /// Until when the owner must remember this knock (`ts + 3900`).
    #[getter]
    fn forget_after(&self) -> u64 {
        self.0.forget_after()
    }

    /// SPEC §6.6.3 step 6: raises `AgentConnectError` with kind `replay`
    /// if `ledger` has seen this knock's id or KeyPackage, else records
    /// them. Call it for every verified knock before anything else.
    fn remember_in(&self, ledger: &mut KnockLedger) -> PyResult<()> {
        guarded(|| self.0.remember_in(&mut ledger.0).map_err(err))
    }

    /// Wraps a Welcome for this knock (SPEC §6.6.4 step 4).
    fn wrap_welcome<'py>(&self, py: Python<'py>, welcome: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        guarded(|| {
            let rng = core::Rng::os().map_err(err)?;
            Ok(PyBytes::new(
                py,
                &self.0.secret().wrap_welcome(&rng, welcome).map_err(err)?,
            ))
        })
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.0)
    }
}

/// An in-memory record of the knocks an owner has seen (SPEC §6.6.3 step
/// 6). A daemon that must survive restarts stores `knock_id`,
/// `key_package_ref` and `forget_after` of each `VerifiedKnock` itself.
#[pyclass(module = "agentconnect_core._native")]
pub(crate) struct KnockLedger(knock::MemoryKnockLedger);

#[pymethods]
impl KnockLedger {
    #[new]
    fn new() -> Self {
        Self(knock::MemoryKnockLedger::default())
    }

    /// Forgets entries whose knocks can no longer pass check 3 at `now`.
    fn purge(&mut self, now: u64) {
        self.0.purge(now);
    }

    fn __len__(&self) -> usize {
        self.0.len()
    }
}

/// Opens a knock-wrapped Welcome from raw parts (vectors, tests).
#[pyfunction]
pub(crate) fn unwrap_knock_welcome<'py>(
    py: Python<'py>,
    knock_id: &[u8],
    welcome_secret: &[u8],
    wrapped: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    guarded(|| {
        let s = knock::KnockSecret::from_parts(
            array(knock_id, "knock id")?,
            &*secret32(welcome_secret)?,
        );
        Ok(PyBytes::new(py, &s.unwrap_welcome(wrapped).map_err(err)?))
    })
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("E2E_EXTENSION_URI", listing::E2E_EXTENSION_URI)?;
    m.add_class::<Listing>()?;
    m.add_class::<DirectoryKey>()?;
    m.add_class::<Door>()?;
    m.add_class::<OpenedKnock>()?;
    m.add_class::<PendingKnock>()?;
    m.add_class::<VerifiedKnock>()?;
    m.add_class::<OwnerHistory>()?;
    m.add_class::<KnockLedger>()?;
    m.add_class::<NameRecord>()?;
    for f in [
        wrap_pyfunction!(verify_listing, m)?,
        wrap_pyfunction!(sign_listing, m)?,
        wrap_pyfunction!(canonical_card, m)?,
        wrap_pyfunction!(verify_listing_token, m)?,
        wrap_pyfunction!(check_token_binding, m)?,
        wrap_pyfunction!(verify_token_revocation, m)?,
        wrap_pyfunction!(sign_withdrawal, m)?,
        wrap_pyfunction!(verify_withdrawal, m)?,
        wrap_pyfunction!(check_withdrawal_fresh, m)?,
        wrap_pyfunction!(withdrawal_applies, m)?,
        wrap_pyfunction!(parse_owner_file, m)?,
        wrap_pyfunction!(owner_vouch, m)?,
        wrap_pyfunction!(owner_fetch_result, m)?,
        wrap_pyfunction!(owner_state, m)?,
        wrap_pyfunction!(owner_file_url, m)?,
        wrap_pyfunction!(unwrap_knock_welcome, m)?,
    ] {
        m.add_function(f)?;
    }
    Ok(())
}
