//! Python bindings for `agentconnect-core`, exposed as `agentconnect_core._native`.
//!
//! Synchronous, bytes in and bytes out. MLS work runs with the GIL
//! released. Errors from the core are raised as `AgentConnectError`.
//!
//! No panic crosses into Python: every binding runs under `catch_unwind`
//! and a panic is raised as `CoreError` (an `Exception`, unlike PyO3's
//! `PanicException`). A `Client` whose operation panicked drops its cached
//! groups, which are reloaded from storage on next use, so the client stays
//! usable; a group whose stored state the panic left inconsistent then
//! fails on its own and must be re-synced.
//!
//! Test-only entry points are named `_..._for_testing`: seeded randomness
//! (keys from a 64-bit seed are guessable) and a settable clock. Production
//! code never needs them.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentconnect_core as core;
use agentconnect_core::clock::Clock;
use agentconnect_core::db::SqlValue;
use agentconnect_core::group::{CommitOut, CommitSummary, Event, MemberInfo};
use agentconnect_core::{DbKey, EncryptedDb, Group, MemoryStore, SqliteStore};
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use zeroize::Zeroizing;

create_exception!(
    _native,
    AgentConnectError,
    PyValueError,
    "An error from the AgentConnect core."
);

create_exception!(
    _native,
    CoreError,
    PyException,
    "An internal failure (a panic) inside the AgentConnect core. The operation \
     did not complete. A Client drops its cached group state and reloads it \
     from storage on next use."
);

fn err(e: core::Error) -> PyErr {
    AgentConnectError::new_err(e.to_string())
}

fn panicked() -> PyErr {
    // The panic payload is not included: it could carry data we must not
    // surface (AGENTS.md: no secrets or bodies in errors).
    CoreError::new_err("the core panicked; the operation did not complete")
}

/// Runs a binding body, turning a panic into `CoreError`.
fn guarded<T>(f: impl FnOnce() -> PyResult<T>) -> PyResult<T> {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| Err(panicked()))
}

type CoreResult<T> = core::Result<T>;

fn panic_for_testing() -> CoreResult<()> {
    panic!("panic requested by a test")
}

fn array<const N: usize>(b: &[u8], what: &'static str) -> PyResult<[u8; N]> {
    b.try_into()
        .map_err(|_| AgentConnectError::new_err(format!("{what} must be {N} bytes")))
}

/// A 32-byte secret copied straight into a zeroizing buffer.
fn secret32(b: &[u8]) -> PyResult<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    if b.len() != 32 {
        return Err(AgentConnectError::new_err("secret must be 32 bytes"));
    }
    out.copy_from_slice(b);
    Ok(out)
}

/// The latest time the test clock accepts: 9999-12-31T23:59:59Z.
const MAX_TEST_TIME: u64 = 253_402_300_799;

fn test_time(now: u64) -> PyResult<u64> {
    if now == 0 || now > MAX_TEST_TIME {
        return Err(AgentConnectError::new_err(
            "time must be between 1 and 253402300799 (Unix seconds)",
        ));
    }
    Ok(now)
}

/// System time, or a fixed time set from Python (tests).
#[derive(Debug, Default)]
struct SettableClock {
    fixed_secs: AtomicU64,
}

impl Clock for SettableClock {
    fn now(&self) -> SystemTime {
        match self.fixed_secs.load(Ordering::SeqCst) {
            0 => SystemTime::now(),
            s => UNIX_EPOCH
                .checked_add(Duration::from_secs(s))
                .unwrap_or_else(SystemTime::now),
        }
    }
}

/// A long-lived identity key `IK`.
#[pyclass(frozen, module = "agentconnect_core._native")]
struct Identity(core::Identity);

#[pymethods]
impl Identity {
    /// A fresh identity from OS randomness.
    #[staticmethod]
    fn generate() -> PyResult<Self> {
        guarded(|| {
            let rng = core::Rng::os().map_err(err)?;
            Ok(Self(core::Identity::generate(&rng).map_err(err)?))
        })
    }

    /// **Tests only**: an identity from a 64-bit seed (guessable keys).
    #[staticmethod]
    fn _generate_for_testing(seed: u64) -> PyResult<Self> {
        guarded(|| {
            Ok(Self(
                core::Identity::generate(&core::Rng::from_u64(seed)).map_err(err)?,
            ))
        })
    }

    /// Restores an identity from its 32-byte secret.
    #[staticmethod]
    fn from_secret_bytes(secret: &[u8]) -> PyResult<Self> {
        guarded(|| Ok(Self(core::Identity::from_secret_bytes(&*secret32(secret)?))))
    }

    /// The 32-byte secret (store it encrypted).
    fn secret_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        guarded(|| Ok(PyBytes::new(py, self.0.secret_bytes().as_slice())))
    }

    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        guarded(|| Ok(PyBytes::new(py, &self.0.public_key())))
    }

    #[getter]
    fn id(&self) -> PyResult<String> {
        guarded(|| Ok(self.0.id()))
    }

    #[getter]
    fn fingerprint(&self) -> PyResult<String> {
        guarded(|| Ok(self.0.fingerprint()))
    }

    /// A new instance (signing key + certificate) from OS randomness.
    fn create_instance(&self) -> PyResult<Instance> {
        guarded(|| {
            let rng = core::Rng::os().map_err(err)?;
            let inst = self
                .0
                .create_instance(&rng, &core::clock::SystemClock)
                .map_err(err)?;
            Ok(Instance(inst))
        })
    }

    /// **Tests only**: an instance from a 64-bit seed and/or created at a
    /// fixed time `now` (Unix seconds).
    #[pyo3(signature = (seed=None, now=None))]
    fn _create_instance_for_testing(
        &self,
        seed: Option<u64>,
        now: Option<u64>,
    ) -> PyResult<Instance> {
        guarded(|| {
            let clock = SettableClock::default();
            if let Some(n) = now {
                clock.fixed_secs.store(test_time(n)?, Ordering::SeqCst);
            }
            let rng = match seed {
                Some(s) => core::Rng::from_u64(s),
                None => core::Rng::os().map_err(err)?,
            };
            Ok(Instance(self.0.create_instance(&rng, &clock).map_err(err)?))
        })
    }

    fn __repr__(&self) -> PyResult<String> {
        guarded(|| Ok(format!("Identity({})", self.0.id())))
    }
}

/// One instance of an identity: signing key `SK` and its certificate.
#[pyclass(frozen, module = "agentconnect_core._native")]
struct Instance(core::Instance);

#[pymethods]
impl Instance {
    #[staticmethod]
    fn from_secret_bytes(data: &[u8]) -> PyResult<Self> {
        guarded(|| Ok(Self(core::Instance::from_secret_bytes(data).map_err(err)?)))
    }

    /// Secret key and certificate (store it encrypted).
    fn to_secret_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        guarded(|| Ok(PyBytes::new(py, &self.0.to_secret_bytes().map_err(err)?)))
    }

    #[getter]
    fn identity(&self) -> PyResult<String> {
        guarded(|| Ok(self.0.identity().to_owned()))
    }

    #[getter]
    fn instance_id(&self) -> PyResult<u64> {
        guarded(|| Ok(self.0.instance_id()))
    }

    #[getter]
    fn instance_id_hex(&self) -> PyResult<String> {
        guarded(|| Ok(self.0.cert().instance_id_hex()))
    }

    #[getter]
    fn mailbox_id(&self) -> PyResult<String> {
        guarded(|| Ok(self.0.mailbox_id()))
    }

    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        guarded(|| Ok(PyBytes::new(py, &self.0.public_key())))
    }

    #[getter]
    fn cert_json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        guarded(|| Ok(PyBytes::new(py, &self.0.cert().to_json().map_err(err)?)))
    }

    /// Answers the relay's WebSocket challenge (SPEC §8.2). Signing happens in
    /// the core, and only domain-separated relay messages are signed. (The
    /// key itself still reaches Python through `to_secret_bytes`, which the
    /// daemon uses to persist the instance.)
    fn sign_relay_challenge<'py>(
        &self,
        py: Python<'py>,
        nonce: &[u8],
        relay_host: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let sig = guarded(|| self.0.sign_relay_challenge(nonce, relay_host).map_err(err))?;
        Ok(PyBytes::new(py, &sig))
    }

    /// Signs a relay REST request (SPEC §8.1.1). Use a fresh `ts` per request.
    fn sign_relay_request<'py>(
        &self,
        py: Python<'py>,
        method: &str,
        path: &str,
        ts: u64,
        body: &[u8],
        relay_host: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let sig = guarded(|| {
            Ok(self
                .0
                .sign_relay_request(method, path, ts, body, relay_host))
        })?;
        Ok(PyBytes::new(py, &sig))
    }

    fn __repr__(&self) -> PyResult<String> {
        guarded(|| Ok(format!("{:?}", self.0)))
    }
}

/// An invite held by the instance that created it.
#[pyclass(frozen, module = "agentconnect_core._native")]
struct Invite(core::Invite);

#[pymethods]
impl Invite {
    /// Restores an invite the daemon stored.
    #[staticmethod]
    fn from_parts(
        relay_host: String,
        invite_id: &[u8],
        secret: &[u8],
        expires_at: u64,
    ) -> PyResult<Self> {
        guarded(|| {
            let s =
                core::InviteSecret::from_parts(array(invite_id, "invite_id")?, &*secret32(secret)?);
            Ok(Self(core::Invite::from_parts(relay_host, s, expires_at)))
        })
    }

    #[getter]
    fn url(&self) -> PyResult<String> {
        guarded(|| Ok(self.0.url()))
    }

    #[getter]
    fn relay_host(&self) -> PyResult<String> {
        guarded(|| Ok(self.0.relay_host().to_owned()))
    }

    #[getter]
    fn invite_id<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        guarded(|| Ok(PyBytes::new(py, self.0.secret().id())))
    }

    #[getter]
    fn invite_id_b64(&self) -> PyResult<String> {
        guarded(|| Ok(self.0.secret().id_b64()))
    }

    #[getter]
    fn expires_at(&self) -> PyResult<u64> {
        guarded(|| Ok(self.0.expires_at()))
    }

    /// The invite secret (store it encrypted; it belongs only in the URL fragment).
    fn secret_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        guarded(|| Ok(PyBytes::new(py, self.0.secret().secret())))
    }

    fn __repr__(&self) -> PyResult<String> {
        guarded(|| Ok(format!("Invite({})", self.0.secret().id_b64())))
    }
}

/// A parsed invite URL (joiner side).
#[pyclass(frozen, module = "agentconnect_core._native")]
struct InviteLink(core::InviteLink);

#[pymethods]
impl InviteLink {
    #[getter]
    fn url(&self) -> PyResult<String> {
        guarded(|| Ok(self.0.url()))
    }

    #[getter]
    fn relay_host(&self) -> PyResult<String> {
        guarded(|| Ok(self.0.relay_host().to_owned()))
    }

    #[getter]
    fn invite_id<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        guarded(|| Ok(PyBytes::new(py, self.0.secret().id())))
    }

    #[getter]
    fn invite_id_b64(&self) -> PyResult<String> {
        guarded(|| Ok(self.0.secret().id_b64()))
    }

    fn secret_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        guarded(|| Ok(PyBytes::new(py, self.0.secret().secret())))
    }

    fn __repr__(&self) -> PyResult<String> {
        guarded(|| Ok(format!("InviteLink({})", self.0.secret().id_b64())))
    }
}

/// A short authentication string.
#[pyclass(frozen, module = "agentconnect_core._native")]
struct Sas(core::Sas);

#[pymethods]
impl Sas {
    #[getter]
    fn bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        guarded(|| Ok(PyBytes::new(py, &self.0.bytes())))
    }

    #[getter]
    fn emoji_indices(&self) -> PyResult<Vec<u32>> {
        // Vec<u8> would become `bytes`; indices are a list of ints.
        guarded(|| {
            Ok(self
                .0
                .emoji_indices()
                .iter()
                .map(|i| u32::from(*i))
                .collect())
        })
    }

    #[getter]
    fn decimal(&self) -> PyResult<String> {
        guarded(|| Ok(self.0.decimal()))
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    fn __hash__(&self) -> PyResult<u64> {
        guarded(|| {
            let mut b = [0u8; 8];
            b[..6].copy_from_slice(&self.0.bytes());
            Ok(u64::from_be_bytes(b))
        })
    }

    fn __repr__(&self) -> PyResult<String> {
        guarded(|| Ok(format!("Sas({})", self.0.decimal())))
    }
}

/// A JoinRequest that passed verification, for `Client.add_member` (which
/// may be retried with it, e.g. after an `epoch_conflict`).
#[pyclass(frozen, module = "agentconnect_core._native")]
struct VerifiedJoinRequest {
    inner: core::VerifiedJoinRequest,
    identity: String,
    instance_id: u64,
    display_name: String,
    mailbox_id: String,
    key_package_ref: Vec<u8>,
}

#[pymethods]
impl VerifiedJoinRequest {
    /// The KeyPackageRef (RFC 9420 §5.2): identical for a replayed request.
    #[getter]
    fn key_package_ref<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.key_package_ref)
    }

    #[getter]
    fn identity(&self) -> String {
        self.identity.clone()
    }

    #[getter]
    fn instance_id(&self) -> u64 {
        self.instance_id
    }

    #[getter]
    fn display_name(&self) -> String {
        self.display_name.clone()
    }

    #[getter]
    fn mailbox_id(&self) -> String {
        self.mailbox_id.clone()
    }
}

enum Inner {
    Memory(core::Client<MemoryStore>),
    Sqlite(core::Client<SqliteStore>),
}

struct State {
    inner: Inner,
    groups: HashMap<Vec<u8>, Group>,
}

/// One instance's MLS state over an encrypted SQLite file (or memory,
/// `path=None`).
#[pyclass(frozen, module = "agentconnect_core._native")]
struct Client {
    state: Mutex<State>,
    clock: Arc<SettableClock>,
}

/// Runs `$body` with the client's core client and group cache, under the
/// state lock and `catch_unwind`. A panic drops the cached groups (they are
/// reloaded from storage) and is raised as `CoreError`.
macro_rules! with_client {
    ($self:ident, |$c:ident, $groups:ident| $body:expr) => {{
        let mut guard = $self.lock();
        let result = catch_unwind(AssertUnwindSafe(|| -> CoreResult<_> {
            let State {
                inner,
                groups: $groups,
            } = &mut *guard;
            match inner {
                Inner::Memory($c) => $body,
                Inner::Sqlite($c) => $body,
            }
        }));
        match result {
            Ok(r) => r.map_err(err),
            Err(_) => {
                guard.groups.clear();
                Err(panicked())
            }
        }
    }};
}

fn group<'a, S: core::Store>(
    client: &core::Client<S>,
    groups: &'a mut HashMap<Vec<u8>, Group>,
    id: &[u8],
) -> CoreResult<&'a mut Group> {
    if !groups.contains_key(id) {
        let g = client
            .load_group(id)?
            .ok_or(core::Error::Malformed("unknown group id"))?;
        groups.insert(id.to_vec(), g);
    }
    groups
        .get_mut(id)
        .ok_or(core::Error::Internal("group cache"))
}

fn member<'py>(py: Python<'py>, m: &MemberInfo) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("leaf_index", m.leaf_index)?;
    d.set_item("identity", &m.identity)?;
    d.set_item("instance_id", m.instance_id)?;
    d.set_item("instance_id_hex", m.instance_id_hex())?;
    d.set_item("mailbox_id", &m.mailbox_id)?;
    Ok(d)
}

fn members<'py>(py: Python<'py>, ms: &[MemberInfo]) -> PyResult<Bound<'py, PyList>> {
    PyList::new(
        py,
        ms.iter()
            .map(|m| member(py, m))
            .collect::<PyResult<Vec<_>>>()?,
    )
}

fn routing<'py>(py: Python<'py>, r: &core::Routing) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("add", r.add.clone())?;
    d.set_item("remove", r.remove.clone())?;
    Ok(d)
}

fn summary<'py>(py: Python<'py>, s: &CommitSummary) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("epoch", s.epoch)?;
    d.set_item("committer", member(py, &s.committer)?)?;
    d.set_item("added", members(py, &s.added)?)?;
    d.set_item("removed", members(py, &s.removed)?)?;
    d.set_item("policy_changed", s.policy_changed)?;
    d.set_item("discarded_own_pending", s.discarded_own_pending)?;
    d.set_item("routing", routing(py, &s.routing())?)?;
    Ok(d)
}

fn commit_out<'py>(py: Python<'py>, c: &CommitOut) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("commit", PyBytes::new(py, &c.commit))?;
    d.set_item("msg_id", &c.msg_id)?;
    d.set_item("epoch", c.epoch)?;
    d.set_item("routing", routing(py, &c.routing)?)?;
    d.set_item("welcome", c.welcome.as_ref().map(|w| PyBytes::new(py, w)))?;
    Ok(d)
}

fn application<'py>(py: Python<'py>, m: &core::ApplicationMessage) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("type", "application")?;
    d.set_item("sender", member(py, &m.sender)?)?;
    d.set_item("epoch", m.epoch)?;
    d.set_item("plaintext", PyBytes::new(py, &m.plaintext))?;
    Ok(d)
}

fn event<'py>(py: Python<'py>, e: &Event) -> PyResult<Bound<'py, PyDict>> {
    let with_summary = |kind: &str, s: &CommitSummary| -> PyResult<Bound<'py, PyDict>> {
        let d = summary(py, s)?;
        d.set_item("type", kind)?;
        Ok(d)
    };
    match e {
        Event::Application(m) => application(py, m),
        Event::Commit(s) => with_summary("commit", s),
        Event::OwnCommitConfirmed(s) => with_summary("own_commit_confirmed", s),
        Event::Removed(s) => with_summary("removed", s),
        Event::LeaveProposed(m) => {
            let d = PyDict::new(py);
            d.set_item("type", "leave_proposed")?;
            d.set_item("member", member(py, m)?)?;
            Ok(d)
        }
        _ => {
            let d = PyDict::new(py);
            d.set_item("type", "own_echo")?;
            Ok(d)
        }
    }
}

impl Client {
    /// The state lock. Bodies run under `catch_unwind`, so the lock is not
    /// poisoned by core panics; if it ever is, the cache is dropped and the
    /// state reused.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| {
            let mut g = poisoned.into_inner();
            g.groups.clear();
            self.state.clear_poison();
            g
        })
    }

    fn with_rng(
        path: Option<String>,
        instance: &[u8],
        db_key: Option<&[u8]>,
        rng: core::Rng,
    ) -> PyResult<Self> {
        let clock = Arc::new(SettableClock::default());
        let c = clock.clone();
        let inner = (|| -> CoreResult<Inner> {
            let inst = core::Instance::from_secret_bytes(instance)?;
            Ok(match (path, db_key) {
                (Some(p), Some(k)) => Inner::Sqlite(core::Client::new(
                    SqliteStore::open(std::path::Path::new(&p), &DbKey::from_bytes(k)?)?,
                    rng,
                    inst,
                    c,
                )?),
                (Some(_), None) => {
                    return Err(core::Error::Malformed(
                        "database key (required for an on-disk store)",
                    ));
                }
                (None, Some(_)) => {
                    return Err(core::Error::Malformed(
                        "database key (an in-memory store takes none)",
                    ));
                }
                (None, None) => Inner::Memory(core::Client::new(MemoryStore::new(), rng, inst, c)?),
            })
        })()
        .map_err(err)?;
        Ok(Self {
            state: Mutex::new(State {
                inner,
                groups: HashMap::new(),
            }),
            clock,
        })
    }
}

#[pymethods]
impl Client {
    /// State in an encrypted SQLite file at `path` under the 32-byte
    /// `db_key` (required), or in memory with `path=None` and no key (tests).
    #[new]
    #[pyo3(signature = (path, instance, db_key=None))]
    fn new(
        py: Python<'_>,
        path: Option<String>,
        instance: &[u8],
        db_key: Option<&[u8]>,
    ) -> PyResult<Self> {
        py.detach(|| {
            guarded(|| {
                let rng = core::Rng::os().map_err(err)?;
                Self::with_rng(path, instance, db_key, rng)
            })
        })
    }

    /// **Tests only**: a client whose randomness comes from a 64-bit seed.
    #[staticmethod]
    #[pyo3(signature = (path, instance, seed, db_key=None))]
    fn _for_testing(
        py: Python<'_>,
        path: Option<String>,
        instance: &[u8],
        seed: u64,
        db_key: Option<&[u8]>,
    ) -> PyResult<Self> {
        py.detach(|| guarded(|| Self::with_rng(path, instance, db_key, core::Rng::from_u64(seed))))
    }

    /// **Tests only**: fix the client's clock at `now` (Unix seconds), or
    /// `None` for system time.
    #[pyo3(signature = (now))]
    fn _set_time_for_testing(&self, now: Option<u64>) -> PyResult<()> {
        guarded(|| {
            let secs = now.map(test_time).transpose()?.unwrap_or(0);
            self.clock.fixed_secs.store(secs, Ordering::SeqCst);
            Ok(())
        })
    }

    /// **Tests only**: panics inside the core while holding the client's
    /// state, to exercise panic recovery.
    fn _panic_for_testing(&self) -> PyResult<()> {
        with_client!(self, |_c, _g| panic_for_testing())
    }

    #[getter]
    fn identity(&self) -> PyResult<String> {
        with_client!(self, |c, _g| Ok(c.instance().identity().to_owned()))
    }

    #[getter]
    fn mailbox_id(&self) -> PyResult<String> {
        with_client!(self, |c, _g| Ok(c.instance().mailbox_id()))
    }

    #[getter]
    fn instance_id_hex(&self) -> PyResult<String> {
        with_client!(self, |c, _g| Ok(c.instance().cert().instance_id_hex()))
    }

    /// Creates a group with this instance as owner; returns the group id.
    fn create_group<'py>(
        &self,
        py: Python<'py>,
        name: &str,
        purpose: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let id = py.detach(|| {
            with_client!(self, |c, groups| {
                let g = c.create_group(name, purpose)?;
                let id = g.group_id().to_vec();
                groups.insert(id.clone(), g);
                Ok(id)
            })
        })?;
        Ok(PyBytes::new(py, &id))
    }

    /// Creates an invite for `relay_host` valid for `ttl_secs`.
    #[pyo3(signature = (relay_host, ttl_secs=86_400))]
    fn create_invite(&self, relay_host: &str, ttl_secs: u64) -> PyResult<Invite> {
        with_client!(self, |c, _g| core::Invite::create(
            c.rng(),
            c.clock(),
            relay_host,
            Duration::from_secs(ttl_secs)
        ))
        .map(Invite)
    }

    /// Creates a JoinRequest (JSON bytes) for a parsed invite link.
    fn create_join_request<'py>(
        &self,
        py: Python<'py>,
        link: &InviteLink,
        display_name: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let json = py.detach(|| {
            with_client!(self, |c, _g| c
                .create_join_request(link.0.secret(), display_name)?
                .to_json())
        })?;
        Ok(PyBytes::new(py, &json))
    }

    /// Verifies a JoinRequest (JSON bytes) against one of our invites.
    fn verify_join_request(
        &self,
        py: Python<'_>,
        request: &[u8],
        invite: &Invite,
    ) -> PyResult<VerifiedJoinRequest> {
        let v = py.detach(|| {
            with_client!(self, |c, _g| {
                let req = core::JoinRequest::from_json(request)?;
                c.verify_join_request(&req, &invite.0)
            })
        })?;
        Ok(VerifiedJoinRequest {
            identity: v.identity().to_owned(),
            instance_id: v.instance_id(),
            display_name: v.display_name().to_owned(),
            mailbox_id: v.mailbox_id().to_owned(),
            key_package_ref: v.key_package_ref().to_vec(),
            inner: v,
        })
    }

    /// Commits the Add (pending until confirmed) and wraps the Welcome.
    #[pyo3(signature = (group_id, request, invite, switch_floor=true))]
    fn add_member<'py>(
        &self,
        py: Python<'py>,
        group_id: &[u8],
        request: &VerifiedJoinRequest,
        invite: &Invite,
        switch_floor: bool,
    ) -> PyResult<Bound<'py, PyDict>> {
        let out = py.detach(|| {
            with_client!(self, |c, groups| group(c, groups, group_id)?.add_member(
                c,
                &request.inner,
                &invite.0,
                switch_floor
            ))
        })?;
        commit_out(py, &out)
    }

    /// Joins from a wrapped Welcome, checking it against the InviteMeta
    /// (relay JSON) shown to the human. Returns the group id.
    fn join<'py>(
        &self,
        py: Python<'py>,
        link: &InviteLink,
        invite_meta: &[u8],
        wrapped_welcome: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let id = py.detach(|| {
            with_client!(self, |c, groups| {
                let meta = core::InviteMeta::from_json(invite_meta)?;
                let g = c.join_from_wrapped_welcome(link.0.secret(), &meta, wrapped_welcome)?;
                let id = g.group_id().to_vec();
                groups.insert(id.clone(), g);
                Ok(id)
            })
        })?;
        Ok(PyBytes::new(py, &id))
    }

    /// Processes one MLS message; returns an event dict.
    fn process<'py>(
        &self,
        py: Python<'py>,
        group_id: &[u8],
        message: &[u8],
    ) -> PyResult<Bound<'py, PyDict>> {
        let e = py.detach(|| {
            with_client!(self, |c, groups| group(c, groups, group_id)?
                .process(c, message))
        })?;
        event(py, &e)
    }

    /// Encrypts an inner message (JSON bytes).
    fn seal<'py>(
        &self,
        py: Python<'py>,
        group_id: &[u8],
        inner: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let ct = py.detach(|| {
            with_client!(self, |c, groups| group(c, groups, group_id)?.seal(c, inner))
        })?;
        Ok(PyBytes::new(py, &ct))
    }

    /// Decrypts an application message.
    fn open<'py>(
        &self,
        py: Python<'py>,
        group_id: &[u8],
        ciphertext: &[u8],
    ) -> PyResult<Bound<'py, PyDict>> {
        let m = py.detach(|| {
            with_client!(self, |c, groups| group(c, groups, group_id)?
                .open(c, ciphertext))
        })?;
        application(py, &m)
    }

    fn sas(&self, group_id: &[u8]) -> PyResult<Sas> {
        with_client!(self, |c, groups| group(c, groups, group_id)
            .map(|g| g.sas()))
        .map(Sas)
    }

    fn epoch(&self, group_id: &[u8]) -> PyResult<u64> {
        with_client!(self, |c, groups| group(c, groups, group_id)
            .map(|g| g.epoch()))
    }

    fn members<'py>(&self, py: Python<'py>, group_id: &[u8]) -> PyResult<Bound<'py, PyList>> {
        let ms = with_client!(self, |c, groups| group(c, groups, group_id)?.members())?;
        members(py, &ms)
    }

    /// `ac_group_policy` as JCS JSON bytes.
    fn policy<'py>(&self, py: Python<'py>, group_id: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let p = with_client!(self, |c, groups| group(c, groups, group_id)?
            .policy()?
            .to_json())?;
        Ok(PyBytes::new(py, &p))
    }

    /// `ac_group_meta` as JCS JSON bytes.
    fn meta<'py>(&self, py: Python<'py>, group_id: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let m = with_client!(self, |c, groups| group(c, groups, group_id)?
            .meta()?
            .to_json())?;
        Ok(PyBytes::new(py, &m))
    }

    fn has_pending_commit(&self, group_id: &[u8]) -> PyResult<bool> {
        with_client!(self, |c, groups| group(c, groups, group_id)
            .map(|g| g.has_pending_commit()))
    }

    fn remove<'py>(
        &self,
        py: Python<'py>,
        group_id: &[u8],
        identity: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let out = py.detach(|| {
            with_client!(self, |c, groups| group(c, groups, group_id)?
                .remove(c, identity))
        })?;
        commit_out(py, &out)
    }

    fn update<'py>(&self, py: Python<'py>, group_id: &[u8]) -> PyResult<Bound<'py, PyDict>> {
        let out =
            py.detach(|| with_client!(self, |c, groups| group(c, groups, group_id)?.update(c)))?;
        commit_out(py, &out)
    }

    /// Commits a new policy (canonical JSON bytes).
    fn set_policy<'py>(
        &self,
        py: Python<'py>,
        group_id: &[u8],
        policy: &[u8],
    ) -> PyResult<Bound<'py, PyDict>> {
        let out = py.detach(|| {
            with_client!(self, |c, groups| {
                let p = core::GroupPolicy::from_json(policy)?;
                group(c, groups, group_id)?.set_policy(c, &p)
            })
        })?;
        commit_out(py, &out)
    }

    fn commit_pending_proposals<'py>(
        &self,
        py: Python<'py>,
        group_id: &[u8],
    ) -> PyResult<Bound<'py, PyDict>> {
        let out = py.detach(|| {
            with_client!(self, |c, groups| group(c, groups, group_id)?
                .commit_pending_proposals(c))
        })?;
        commit_out(py, &out)
    }

    /// Our own Remove proposal (`kind: proposal`).
    fn propose_leave<'py>(
        &self,
        py: Python<'py>,
        group_id: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let p = py.detach(|| {
            with_client!(self, |c, groups| group(c, groups, group_id)?
                .propose_leave(c))
        })?;
        Ok(PyBytes::new(py, &p))
    }

    /// Merges the pending commit on the relay's `accepted{msg_id}`.
    fn confirm_pending_commit<'py>(
        &self,
        py: Python<'py>,
        group_id: &[u8],
        msg_id: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let s = py.detach(|| {
            with_client!(self, |c, groups| group(c, groups, group_id)?
                .confirm_pending_commit(c, msg_id))
        })?;
        summary(py, &s)
    }

    fn discard_pending_commit(&self, group_id: &[u8]) -> PyResult<()> {
        with_client!(self, |c, groups| group(c, groups, group_id)?
            .discard_pending_commit(c))
    }

    /// Deletes the group's local state.
    fn delete_group(&self, group_id: &[u8]) -> PyResult<()> {
        with_client!(self, |c, groups| {
            group(c, groups, group_id)?;
            match groups.remove(group_id) {
                Some(g) => g.delete(c),
                None => Ok(()),
            }
        })
    }
}

/// Parses an invite URL (SPEC §4.1).
#[pyfunction]
fn parse_invite_url(url: &str) -> PyResult<InviteLink> {
    guarded(|| core::InviteLink::parse(url).map(InviteLink).map_err(err))
}

/// The JoinRequest MAC (SPEC §6.1) under the invite's `join_key`, which is
/// derived and dropped inside the core.
#[pyfunction]
fn join_request_mac<'py>(
    py: Python<'py>,
    invite_id: &[u8],
    secret: &[u8],
    key_package: &[u8],
    mailbox_id: &str,
    display_name: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    guarded(|| {
        let invite =
            core::InviteSecret::from_parts(array(invite_id, "invite_id")?, &*secret32(secret)?);
        let mac = core::join::join_request_mac(
            &invite.join_key(),
            &core::join::MacInput {
                invite_id: invite.id(),
                key_package,
                mailbox_id,
                display_name,
            },
        );
        Ok(PyBytes::new(py, &mac))
    })
}

/// Opens a WrappedWelcome (SPEC §6.4) under the invite's `welcome_key`.
#[pyfunction]
fn unwrap_welcome<'py>(
    py: Python<'py>,
    invite_id: &[u8],
    secret: &[u8],
    wrapped: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    guarded(|| {
        let s = core::InviteSecret::from_parts(array(invite_id, "invite_id")?, &*secret32(secret)?);
        Ok(PyBytes::new(py, &s.unwrap_welcome(wrapped).map_err(err)?))
    })
}

/// The SAS for given epoch authenticator, group id and epoch (SPEC §3.5).
#[pyfunction]
fn derive_sas(epoch_authenticator: &[u8], group_id: &[u8], epoch: u64) -> PyResult<Sas> {
    guarded(|| Ok(Sas(core::Sas::derive(epoch_authenticator, group_id, epoch))))
}

fn sql_value(v: &Bound<'_, PyAny>) -> PyResult<SqlValue> {
    if v.is_none() {
        return Ok(SqlValue::Null);
    }
    if let Ok(b) = v.cast::<PyBytes>() {
        return Ok(SqlValue::Blob(b.as_bytes().to_vec()));
    }
    if let Ok(s) = v.cast::<PyString>() {
        return Ok(SqlValue::Text(s.to_str()?.to_owned()));
    }
    if v.cast::<PyFloat>().is_ok() {
        return Ok(SqlValue::Real(v.extract::<f64>()?));
    }
    if v.cast::<PyInt>().is_ok() {
        return Ok(SqlValue::Integer(v.extract::<i64>()?));
    }
    Err(PyTypeError::new_err(
        "SQL parameters must be None, int, float, str or bytes",
    ))
}

fn py_value<'py>(py: Python<'py>, v: &SqlValue) -> PyResult<Bound<'py, PyAny>> {
    Ok(match v {
        SqlValue::Null => py.None().into_bound(py),
        SqlValue::Integer(i) => i.into_pyobject(py)?.into_any(),
        SqlValue::Real(f) => f.into_pyobject(py)?.into_any(),
        SqlValue::Text(s) => PyString::new(py, s).into_any(),
        SqlValue::Blob(b) => PyBytes::new(py, b).into_any(),
    })
}

fn sql_params(params: &[Bound<'_, PyAny>]) -> PyResult<Vec<SqlValue>> {
    params.iter().map(sql_value).collect()
}

/// The daemon's own database (ADR-003): SQLCipher, keyed with a key the core
/// derives from the 32-byte `db_key` (the MLS store's key) under
/// `"agentconnect/v0/daemon-db-key"`, so the derived key never reaches
/// Python. There is no unencrypted mode: a wrong key, or a cleartext file,
/// raises `AgentConnectError`.
#[pyclass(frozen, module = "agentconnect_core._native")]
struct Database(EncryptedDb);

#[pymethods]
impl Database {
    #[new]
    fn new(py: Python<'_>, path: &str, db_key: &[u8]) -> PyResult<Self> {
        py.detach(|| {
            guarded(|| {
                let root = DbKey::from_bytes(db_key).map_err(err)?;
                let key = root.derive(core::db::DAEMON_DB_INFO);
                Ok(Self(
                    EncryptedDb::open(std::path::Path::new(path), &key).map_err(err)?,
                ))
            })
        })
    }

    /// Runs one statement and returns its rows as tuples.
    #[pyo3(signature = (sql, params=Vec::new()))]
    fn query<'py>(
        &self,
        py: Python<'py>,
        sql: &str,
        params: Vec<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyList>> {
        guarded(|| {
            let rows = self.0.query(sql, &sql_params(&params)?).map_err(err)?;
            let out = PyList::empty(py);
            for row in &rows {
                let values = row
                    .iter()
                    .map(|v| py_value(py, v))
                    .collect::<PyResult<Vec<_>>>()?;
                out.append(PyTuple::new(py, values)?)?;
            }
            Ok(out)
        })
    }

    /// Runs one statement for its effect: `(changes, last_insert_rowid)`.
    #[pyo3(signature = (sql, params=Vec::new()))]
    fn execute(&self, sql: &str, params: Vec<Bound<'_, PyAny>>) -> PyResult<(u64, i64)> {
        guarded(|| {
            let done = self.0.execute(sql, &sql_params(&params)?).map_err(err)?;
            Ok((done.changes, done.last_insert_rowid))
        })
    }

    /// Runs `;`-separated statements without parameters.
    fn execute_script(&self, sql: &str) -> PyResult<()> {
        guarded(|| self.0.execute_batch(sql).map_err(err))
    }

    /// Closes the database; later calls raise `AgentConnectError`.
    fn close(&self) -> PyResult<()> {
        guarded(|| self.0.close().map_err(err))
    }

    fn __repr__(&self) -> &'static str {
        "Database(...)"
    }
}

/// Re-encrypts the store at `path` from `old_key` to `new_key` (32 bytes
/// each). No `Client` may have the store open while this runs.
#[pyfunction]
fn rekey_store(py: Python<'_>, path: &str, old_key: &[u8], new_key: &[u8]) -> PyResult<()> {
    py.detach(|| {
        guarded(|| {
            let old = DbKey::from_bytes(old_key).map_err(err)?;
            let new = DbKey::from_bytes(new_key).map_err(err)?;
            SqliteStore::rekey(std::path::Path::new(path), &old, &new).map_err(err)
        })
    })
}

/// The padding bucket for an application plaintext length, or None.
#[pyfunction]
fn padding_bucket(plaintext_len: usize) -> PyResult<Option<usize>> {
    guarded(|| Ok(core::padding::bucket_for(plaintext_len)))
}

/// Verifies an instance certificate (signature only) and returns its fields.
#[pyfunction]
fn verify_instance_cert<'py>(py: Python<'py>, cert_json: &[u8]) -> PyResult<Bound<'py, PyDict>> {
    guarded(|| {
        let cert = core::InstanceCert::from_json(cert_json).map_err(err)?;
        cert.verify().map_err(err)?;
        let d = PyDict::new(py);
        d.set_item("identity", &cert.identity)?;
        d.set_item("instance_id", cert.instance_id_hex())?;
        d.set_item("sig_key", PyBytes::new(py, &cert.sig_key))?;
        d.set_item("created_at", cert.created_at)?;
        d.set_item(
            "signing_input",
            PyBytes::new(py, &cert.signing_input().map_err(err)?),
        )?;
        Ok(d)
    })
}

/// `ac:v0:<b64url IK.pub>`.
#[pyfunction]
fn identity_id(ik_pub: &[u8]) -> PyResult<String> {
    guarded(|| Ok(core::identity::identity_id(&array(ik_pub, "ik_pub")?)))
}

/// The identity fingerprint (SPEC §2).
#[pyfunction]
fn fingerprint(ik_pub: &[u8]) -> PyResult<String> {
    guarded(|| Ok(core::identity::fingerprint(&array(ik_pub, "ik_pub")?)))
}

/// The mailbox id of an instance key (SPEC §2).
#[pyfunction]
fn mailbox_id(sig_key: &[u8]) -> PyResult<String> {
    guarded(|| Ok(core::identity::mailbox_id(sig_key)))
}

/// Return True if `v` is a protocol version this build can speak.
#[pyfunction]
fn supports_protocol(v: u32) -> bool {
    core::supports_protocol(v)
}

#[pymodule]
#[pyo3(name = "_native")]
fn native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("PROTOCOL_VERSION", core::PROTOCOL_VERSION)?;
    m.add("CIPHERSUITE_V0", core::CIPHERSUITE_V0)?;
    m.add("PADDING_BUCKETS", core::padding::BUCKETS.to_vec())?;
    m.add("DB_KEY_LEN", core::provider::DB_KEY_LEN)?;
    m.add("AgentConnectError", m.py().get_type::<AgentConnectError>())?;
    m.add("CoreError", m.py().get_type::<CoreError>())?;
    m.add_class::<Identity>()?;
    m.add_class::<Instance>()?;
    m.add_class::<Invite>()?;
    m.add_class::<InviteLink>()?;
    m.add_class::<Sas>()?;
    m.add_class::<VerifiedJoinRequest>()?;
    m.add_class::<Client>()?;
    m.add_class::<Database>()?;
    for f in [
        wrap_pyfunction!(supports_protocol, m)?,
        wrap_pyfunction!(parse_invite_url, m)?,
        wrap_pyfunction!(join_request_mac, m)?,
        wrap_pyfunction!(unwrap_welcome, m)?,
        wrap_pyfunction!(derive_sas, m)?,
        wrap_pyfunction!(padding_bucket, m)?,
        wrap_pyfunction!(rekey_store, m)?,
        wrap_pyfunction!(verify_instance_cert, m)?,
        wrap_pyfunction!(identity_id, m)?,
        wrap_pyfunction!(fingerprint, m)?,
        wrap_pyfunction!(mailbox_id, m)?,
    ] {
        m.add_function(f)?;
    }
    Ok(())
}
