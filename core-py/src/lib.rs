//! Python bindings for `agentconnect-core`, exposed as `agentconnect_core._native`.
//!
//! Synchronous, bytes in and bytes out. MLS work runs with the GIL
//! released. Every error is raised as `AgentConnectError`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentconnect_core as core;
use agentconnect_core::clock::Clock;
use agentconnect_core::group::{CommitOut, CommitSummary, Event, MemberInfo};
use agentconnect_core::{Group, MemoryStore, SqliteStore};
use pyo3::create_exception;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use zeroize::Zeroizing;

create_exception!(
    _native,
    AgentConnectError,
    PyValueError,
    "An error from the AgentConnect core."
);

fn err(e: core::Error) -> PyErr {
    AgentConnectError::new_err(e.to_string())
}

type CoreResult<T> = core::Result<T>;

fn rng(seed: Option<u64>) -> CoreResult<core::Rng> {
    Ok(match seed {
        Some(s) => core::Rng::from_u64(s),
        None => core::Rng::os()?,
    })
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

/// System time, or a fixed time set from Python (tests).
#[derive(Debug, Default)]
struct SettableClock {
    fixed_secs: AtomicU64,
}

impl Clock for SettableClock {
    fn now(&self) -> SystemTime {
        match self.fixed_secs.load(Ordering::SeqCst) {
            0 => SystemTime::now(),
            s => UNIX_EPOCH + Duration::from_secs(s),
        }
    }
}

/// A long-lived identity key `IK`.
#[pyclass(frozen, module = "agentconnect_core._native")]
struct Identity(core::Identity);

#[pymethods]
impl Identity {
    /// A fresh identity. `seed` is for tests only.
    #[staticmethod]
    #[pyo3(signature = (seed=None))]
    fn generate(seed: Option<u64>) -> PyResult<Self> {
        Ok(Self(
            core::Identity::generate(&rng(seed).map_err(err)?).map_err(err)?,
        ))
    }

    /// Restores an identity from its 32-byte secret.
    #[staticmethod]
    fn from_secret_bytes(secret: &[u8]) -> PyResult<Self> {
        Ok(Self(core::Identity::from_secret_bytes(&*secret32(secret)?)))
    }

    /// The 32-byte secret (store it encrypted).
    fn secret_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.secret_bytes().as_slice())
    }

    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.public_key())
    }

    #[getter]
    fn id(&self) -> String {
        self.0.id()
    }

    #[getter]
    fn fingerprint(&self) -> String {
        self.0.fingerprint()
    }

    /// A new instance (signing key + certificate). `seed` and `now` (Unix
    /// seconds) are for tests only.
    #[pyo3(signature = (seed=None, now=None))]
    fn create_instance(&self, seed: Option<u64>, now: Option<u64>) -> PyResult<Instance> {
        let clock = SettableClock::default();
        if let Some(n) = now {
            clock.fixed_secs.store(n, Ordering::SeqCst);
        }
        let inst = self
            .0
            .create_instance(&rng(seed).map_err(err)?, &clock)
            .map_err(err)?;
        Ok(Instance(inst))
    }

    fn __repr__(&self) -> String {
        format!("Identity({})", self.0.id())
    }
}

/// One instance of an identity: signing key `SK` and its certificate.
#[pyclass(frozen, module = "agentconnect_core._native")]
struct Instance(core::Instance);

#[pymethods]
impl Instance {
    #[staticmethod]
    fn from_secret_bytes(data: &[u8]) -> PyResult<Self> {
        Ok(Self(core::Instance::from_secret_bytes(data).map_err(err)?))
    }

    /// Secret key and certificate (store it encrypted).
    fn to_secret_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.0.to_secret_bytes().map_err(err)?))
    }

    #[getter]
    fn identity(&self) -> String {
        self.0.identity().to_owned()
    }

    #[getter]
    fn instance_id(&self) -> u64 {
        self.0.instance_id()
    }

    #[getter]
    fn instance_id_hex(&self) -> String {
        self.0.cert().instance_id_hex()
    }

    #[getter]
    fn mailbox_id(&self) -> String {
        self.0.mailbox_id()
    }

    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.public_key())
    }

    #[getter]
    fn cert_json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.0.cert().to_json().map_err(err)?))
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.0)
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
        let s = core::InviteSecret::from_parts(array(invite_id, "invite_id")?, &*secret32(secret)?);
        Ok(Self(core::Invite::from_parts(relay_host, s, expires_at)))
    }

    #[getter]
    fn url(&self) -> String {
        self.0.url()
    }

    #[getter]
    fn relay_host(&self) -> String {
        self.0.relay_host().to_owned()
    }

    #[getter]
    fn invite_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.secret().id())
    }

    #[getter]
    fn invite_id_b64(&self) -> String {
        self.0.secret().id_b64()
    }

    #[getter]
    fn expires_at(&self) -> u64 {
        self.0.expires_at()
    }

    /// The invite secret (store it encrypted; it belongs only in the URL fragment).
    fn secret_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.secret().secret())
    }

    fn __repr__(&self) -> String {
        format!("Invite({})", self.0.secret().id_b64())
    }
}

/// A parsed invite URL (joiner side).
#[pyclass(frozen, module = "agentconnect_core._native")]
struct InviteLink(core::InviteLink);

#[pymethods]
impl InviteLink {
    #[getter]
    fn url(&self) -> String {
        self.0.url()
    }

    #[getter]
    fn relay_host(&self) -> String {
        self.0.relay_host().to_owned()
    }

    #[getter]
    fn invite_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.secret().id())
    }

    #[getter]
    fn invite_id_b64(&self) -> String {
        self.0.secret().id_b64()
    }

    fn secret_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.secret().secret())
    }

    fn __repr__(&self) -> String {
        format!("InviteLink({})", self.0.secret().id_b64())
    }
}

/// A short authentication string.
#[pyclass(frozen, module = "agentconnect_core._native")]
struct Sas(core::Sas);

#[pymethods]
impl Sas {
    #[getter]
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.bytes())
    }

    #[getter]
    fn emoji_indices(&self) -> Vec<u32> {
        // Vec<u8> would become `bytes`; indices are a list of ints.
        self.0
            .emoji_indices()
            .iter()
            .map(|i| u32::from(*i))
            .collect()
    }

    #[getter]
    fn decimal(&self) -> String {
        self.0.decimal()
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    fn __hash__(&self) -> u64 {
        let mut b = [0u8; 8];
        b[..6].copy_from_slice(&self.0.bytes());
        u64::from_be_bytes(b)
    }

    fn __repr__(&self) -> String {
        format!("Sas({})", self.0.decimal())
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
}

#[pymethods]
impl VerifiedJoinRequest {
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

/// One instance's MLS state over a SQLite file (or memory, `path=None`).
#[pyclass(frozen, module = "agentconnect_core._native")]
struct Client {
    state: Mutex<State>,
    clock: Arc<SettableClock>,
}

macro_rules! with_client {
    ($self:ident, |$c:ident, $groups:ident| $body:expr) => {
        (|| -> CoreResult<_> {
            let mut guard = $self.lock()?;
            let State {
                inner,
                groups: $groups,
            } = &mut *guard;
            match inner {
                Inner::Memory($c) => $body,
                Inner::Sqlite($c) => $body,
            }
        })()
    };
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
    fn lock(&self) -> CoreResult<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| core::Error::Internal("client lock poisoned"))
    }
}

#[pymethods]
impl Client {
    /// `path=None` keeps state in memory (tests). `seed` is for tests only.
    #[new]
    #[pyo3(signature = (path, instance, seed=None))]
    fn new(
        py: Python<'_>,
        path: Option<String>,
        instance: &[u8],
        seed: Option<u64>,
    ) -> PyResult<Self> {
        let clock = Arc::new(SettableClock::default());
        let c = clock.clone();
        let inner = py
            .detach(move || -> CoreResult<Inner> {
                let inst = core::Instance::from_secret_bytes(instance)?;
                let r = rng(seed)?;
                Ok(match path {
                    Some(p) => Inner::Sqlite(core::Client::new(
                        SqliteStore::open(std::path::Path::new(&p))?,
                        r,
                        inst,
                        c,
                    )?),
                    None => Inner::Memory(core::Client::new(MemoryStore::new(), r, inst, c)?),
                })
            })
            .map_err(err)?;
        Ok(Self {
            state: Mutex::new(State {
                inner,
                groups: HashMap::new(),
            }),
            clock,
        })
    }

    /// Fix the client's clock at `now` (Unix seconds), or `None` for system
    /// time. Tests only.
    #[pyo3(signature = (now))]
    fn set_time(&self, now: Option<u64>) {
        self.clock
            .fixed_secs
            .store(now.unwrap_or(0), Ordering::SeqCst);
    }

    #[getter]
    fn identity(&self) -> PyResult<String> {
        with_client!(self, |c, _g| Ok(c.instance().identity().to_owned())).map_err(err)
    }

    #[getter]
    fn mailbox_id(&self) -> PyResult<String> {
        with_client!(self, |c, _g| Ok(c.instance().mailbox_id())).map_err(err)
    }

    #[getter]
    fn instance_id_hex(&self) -> PyResult<String> {
        with_client!(self, |c, _g| Ok(c.instance().cert().instance_id_hex())).map_err(err)
    }

    /// Creates a group with this instance as owner; returns the group id.
    fn create_group<'py>(
        &self,
        py: Python<'py>,
        name: &str,
        purpose: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let id = py
            .detach(|| {
                with_client!(self, |c, groups| {
                    let g = c.create_group(name, purpose)?;
                    let id = g.group_id().to_vec();
                    groups.insert(id.clone(), g);
                    Ok(id)
                })
            })
            .map_err(err)?;
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
        .map_err(err)
    }

    /// Creates a JoinRequest (JSON bytes) for a parsed invite link.
    fn create_join_request<'py>(
        &self,
        py: Python<'py>,
        link: &InviteLink,
        display_name: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let json = py
            .detach(|| {
                with_client!(self, |c, _g| c
                    .create_join_request(link.0.secret(), display_name)?
                    .to_json())
            })
            .map_err(err)?;
        Ok(PyBytes::new(py, &json))
    }

    /// Verifies a JoinRequest (JSON bytes) against one of our invites.
    fn verify_join_request(
        &self,
        py: Python<'_>,
        request: &[u8],
        invite: &Invite,
    ) -> PyResult<VerifiedJoinRequest> {
        let v = py
            .detach(|| {
                let req = core::JoinRequest::from_json(request)?;
                with_client!(self, |c, _g| c.verify_join_request(&req, &invite.0))
            })
            .map_err(err)?;
        Ok(VerifiedJoinRequest {
            identity: v.identity().to_owned(),
            instance_id: v.instance_id(),
            display_name: v.display_name().to_owned(),
            mailbox_id: v.mailbox_id().to_owned(),
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
        let out = py
            .detach(|| {
                with_client!(self, |c, groups| group(c, groups, group_id)?.add_member(
                    c,
                    &request.inner,
                    &invite.0,
                    switch_floor
                ))
            })
            .map_err(err)?;
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
        let id = py
            .detach(|| {
                let meta = core::InviteMeta::from_json(invite_meta)?;
                with_client!(self, |c, groups| {
                    let g = c.join_from_wrapped_welcome(link.0.secret(), &meta, wrapped_welcome)?;
                    let id = g.group_id().to_vec();
                    groups.insert(id.clone(), g);
                    Ok(id)
                })
            })
            .map_err(err)?;
        Ok(PyBytes::new(py, &id))
    }

    /// Processes one MLS message; returns an event dict.
    fn process<'py>(
        &self,
        py: Python<'py>,
        group_id: &[u8],
        message: &[u8],
    ) -> PyResult<Bound<'py, PyDict>> {
        let e = py
            .detach(|| {
                with_client!(self, |c, groups| group(c, groups, group_id)?
                    .process(c, message))
            })
            .map_err(err)?;
        event(py, &e)
    }

    /// Encrypts an inner message (JSON bytes).
    fn seal<'py>(
        &self,
        py: Python<'py>,
        group_id: &[u8],
        inner: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let ct = py
            .detach(|| with_client!(self, |c, groups| group(c, groups, group_id)?.seal(c, inner)))
            .map_err(err)?;
        Ok(PyBytes::new(py, &ct))
    }

    /// Decrypts an application message.
    fn open<'py>(
        &self,
        py: Python<'py>,
        group_id: &[u8],
        ciphertext: &[u8],
    ) -> PyResult<Bound<'py, PyDict>> {
        let m = py
            .detach(|| {
                with_client!(self, |c, groups| group(c, groups, group_id)?
                    .open(c, ciphertext))
            })
            .map_err(err)?;
        application(py, &m)
    }

    fn sas(&self, group_id: &[u8]) -> PyResult<Sas> {
        with_client!(self, |c, groups| group(c, groups, group_id)
            .map(|g| g.sas()))
        .map(Sas)
        .map_err(err)
    }

    fn epoch(&self, group_id: &[u8]) -> PyResult<u64> {
        with_client!(self, |c, groups| group(c, groups, group_id)
            .map(|g| g.epoch()))
        .map_err(err)
    }

    fn members<'py>(&self, py: Python<'py>, group_id: &[u8]) -> PyResult<Bound<'py, PyList>> {
        let ms =
            with_client!(self, |c, groups| group(c, groups, group_id)?.members()).map_err(err)?;
        members(py, &ms)
    }

    /// `ac_group_policy` as JCS JSON bytes.
    fn policy<'py>(&self, py: Python<'py>, group_id: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let p = with_client!(self, |c, groups| group(c, groups, group_id)?
            .policy()?
            .to_json())
        .map_err(err)?;
        Ok(PyBytes::new(py, &p))
    }

    /// `ac_group_meta` as JCS JSON bytes.
    fn meta<'py>(&self, py: Python<'py>, group_id: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let m = with_client!(self, |c, groups| group(c, groups, group_id)?
            .meta()?
            .to_json())
        .map_err(err)?;
        Ok(PyBytes::new(py, &m))
    }

    fn has_pending_commit(&self, group_id: &[u8]) -> PyResult<bool> {
        with_client!(self, |c, groups| group(c, groups, group_id)
            .map(|g| g.has_pending_commit()))
        .map_err(err)
    }

    fn remove<'py>(
        &self,
        py: Python<'py>,
        group_id: &[u8],
        identity: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let out = py
            .detach(|| {
                with_client!(self, |c, groups| group(c, groups, group_id)?
                    .remove(c, identity))
            })
            .map_err(err)?;
        commit_out(py, &out)
    }

    fn update<'py>(&self, py: Python<'py>, group_id: &[u8]) -> PyResult<Bound<'py, PyDict>> {
        let out = py
            .detach(|| with_client!(self, |c, groups| group(c, groups, group_id)?.update(c)))
            .map_err(err)?;
        commit_out(py, &out)
    }

    /// Commits a new policy (canonical JSON bytes).
    fn set_policy<'py>(
        &self,
        py: Python<'py>,
        group_id: &[u8],
        policy: &[u8],
    ) -> PyResult<Bound<'py, PyDict>> {
        let out = py
            .detach(|| {
                let p = core::GroupPolicy::from_json(policy)?;
                with_client!(self, |c, groups| group(c, groups, group_id)?
                    .set_policy(c, &p))
            })
            .map_err(err)?;
        commit_out(py, &out)
    }

    fn commit_pending_proposals<'py>(
        &self,
        py: Python<'py>,
        group_id: &[u8],
    ) -> PyResult<Bound<'py, PyDict>> {
        let out = py
            .detach(|| {
                with_client!(self, |c, groups| group(c, groups, group_id)?
                    .commit_pending_proposals(c))
            })
            .map_err(err)?;
        commit_out(py, &out)
    }

    /// Our own Remove proposal (`kind: proposal`).
    fn propose_leave<'py>(
        &self,
        py: Python<'py>,
        group_id: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let p = py
            .detach(|| {
                with_client!(self, |c, groups| group(c, groups, group_id)?
                    .propose_leave(c))
            })
            .map_err(err)?;
        Ok(PyBytes::new(py, &p))
    }

    /// Merges the pending commit on the relay's `accepted{msg_id}`.
    fn confirm_pending_commit<'py>(
        &self,
        py: Python<'py>,
        group_id: &[u8],
        msg_id: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let s = py
            .detach(|| {
                with_client!(self, |c, groups| group(c, groups, group_id)?
                    .confirm_pending_commit(c, msg_id))
            })
            .map_err(err)?;
        summary(py, &s)
    }

    fn discard_pending_commit(&self, group_id: &[u8]) -> PyResult<()> {
        with_client!(self, |c, groups| group(c, groups, group_id)?
            .discard_pending_commit(c))
        .map_err(err)
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
        .map_err(err)
    }
}

/// Parses an invite URL (SPEC §4.1).
#[pyfunction]
fn parse_invite_url(url: &str) -> PyResult<InviteLink> {
    core::InviteLink::parse(url).map(InviteLink).map_err(err)
}

/// `join_key` (SPEC §3.5).
#[pyfunction]
fn derive_join_key<'py>(
    py: Python<'py>,
    invite_id: &[u8],
    secret: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let k =
        core::invite::derive_join_key(&array(invite_id, "invite_id")?, &array(secret, "secret")?);
    Ok(PyBytes::new(py, k.as_slice()))
}

/// `welcome_key` (SPEC §3.5).
#[pyfunction]
fn derive_welcome_key<'py>(
    py: Python<'py>,
    invite_id: &[u8],
    secret: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let k = core::invite::derive_welcome_key(
        &array(invite_id, "invite_id")?,
        &array(secret, "secret")?,
    );
    Ok(PyBytes::new(py, k.as_slice()))
}

/// The JoinRequest MAC (SPEC §6.1).
#[pyfunction]
fn join_request_mac<'py>(
    py: Python<'py>,
    join_key: &[u8],
    invite_id: &[u8],
    key_package: &[u8],
    mailbox_id: &str,
    display_name: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let mac = core::join::join_request_mac(
        &array(join_key, "join_key")?,
        &core::join::MacInput {
            invite_id: &array(invite_id, "invite_id")?,
            key_package,
            mailbox_id,
            display_name,
        },
    );
    Ok(PyBytes::new(py, &mac))
}

/// Opens a WrappedWelcome (SPEC §6.4).
#[pyfunction]
fn unwrap_welcome<'py>(
    py: Python<'py>,
    invite_id: &[u8],
    secret: &[u8],
    wrapped: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let s = core::InviteSecret::from_parts(array(invite_id, "invite_id")?, &*secret32(secret)?);
    Ok(PyBytes::new(py, &s.unwrap_welcome(wrapped).map_err(err)?))
}

/// The SAS for given epoch authenticator, group id and epoch (SPEC §3.5).
#[pyfunction]
fn derive_sas(epoch_authenticator: &[u8], group_id: &[u8], epoch: u64) -> Sas {
    Sas(core::Sas::derive(epoch_authenticator, group_id, epoch))
}

/// The padding bucket for an application plaintext length, or None.
#[pyfunction]
fn padding_bucket(plaintext_len: usize) -> Option<usize> {
    core::padding::bucket_for(plaintext_len)
}

/// Verifies an instance certificate (signature only) and returns its fields.
#[pyfunction]
fn verify_instance_cert<'py>(py: Python<'py>, cert_json: &[u8]) -> PyResult<Bound<'py, PyDict>> {
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
}

/// `ac:v0:<b64url IK.pub>`.
#[pyfunction]
fn identity_id(ik_pub: &[u8]) -> PyResult<String> {
    Ok(core::identity::identity_id(&array(ik_pub, "ik_pub")?))
}

/// The identity fingerprint (SPEC §2).
#[pyfunction]
fn fingerprint(ik_pub: &[u8]) -> PyResult<String> {
    Ok(core::identity::fingerprint(&array(ik_pub, "ik_pub")?))
}

/// The mailbox id of an instance key (SPEC §2).
#[pyfunction]
fn mailbox_id(sig_key: &[u8]) -> String {
    core::identity::mailbox_id(sig_key)
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
    m.add("AgentConnectError", m.py().get_type::<AgentConnectError>())?;
    m.add_class::<Identity>()?;
    m.add_class::<Instance>()?;
    m.add_class::<Invite>()?;
    m.add_class::<InviteLink>()?;
    m.add_class::<Sas>()?;
    m.add_class::<VerifiedJoinRequest>()?;
    m.add_class::<Client>()?;
    for f in [
        wrap_pyfunction!(supports_protocol, m)?,
        wrap_pyfunction!(parse_invite_url, m)?,
        wrap_pyfunction!(derive_join_key, m)?,
        wrap_pyfunction!(derive_welcome_key, m)?,
        wrap_pyfunction!(join_request_mac, m)?,
        wrap_pyfunction!(unwrap_welcome, m)?,
        wrap_pyfunction!(derive_sas, m)?,
        wrap_pyfunction!(padding_bucket, m)?,
        wrap_pyfunction!(verify_instance_cert, m)?,
        wrap_pyfunction!(identity_id, m)?,
        wrap_pyfunction!(fingerprint, m)?,
        wrap_pyfunction!(mailbox_id, m)?,
    ] {
        m.add_function(f)?;
    }
    Ok(())
}
