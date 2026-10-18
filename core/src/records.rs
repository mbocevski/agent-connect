//! `core`'s own records, kept next to the MLS state in the [`Store`]:
//! what a pending commit looks like on the wire (SPEC §8.3), which
//! KeyPackages were already used in an Add (SPEC §6.2), and who was a
//! member in the previous epoch (the §8.3 grace window).

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::encoding::hex;
use crate::error::{Error, Result};
use crate::group::MemberInfo;
use crate::provider::Store;

fn group_key(kind: &str, group_id: &[u8]) -> Vec<u8> {
    [
        b"agentconnect/v0/".as_slice(),
        kind.as_bytes(),
        b"/",
        group_id,
    ]
    .concat()
}

fn load<S: Store, T: DeserializeOwned>(store: &S, key: &[u8]) -> Result<Option<T>> {
    store
        .get_record(key)?
        .map(|raw| {
            serde_json::from_slice(&raw).map_err(|_| Error::Storage("corrupt record".into()))
        })
        .transpose()
}

fn save<S: Store, T: Serialize>(store: &S, key: &[u8], value: &T) -> Result<()> {
    let raw = serde_json::to_vec(value).map_err(|_| Error::Internal("record encoding"))?;
    store.put_record(key, Some(&raw))
}

/// SHA-256 of a serialised MLS message, as lowercase hex.
pub(crate) fn wire_hash(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// The own commit waiting for relay confirmation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingRecord {
    /// The envelope `msg_id` the commit is sent under.
    pub msg_id: String,
    /// [`wire_hash`] of the commit as sent.
    pub hash: String,
}

/// Own commits built in one epoch.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OwnCommits {
    /// The epoch the commits were built in.
    pub epoch: u64,
    /// The current pending commit, if any.
    pub pending: Option<PendingRecord>,
    /// Hashes of commits built in this epoch and then discarded.
    pub discarded: Vec<String>,
    /// Hash of this instance's own commit that started this epoch, so its
    /// fan-out copy is recognised after an `accepted` already merged it.
    #[serde(default)]
    pub confirmed: Option<String>,
}

impl OwnCommits {
    /// The record for `epoch`; a record for another epoch is stale.
    pub fn load<S: Store>(store: &S, group_id: &[u8], epoch: u64) -> Result<Self> {
        let rec: Option<Self> = load(store, &group_key("own-commits", group_id))?;
        Ok(rec.filter(|r| r.epoch == epoch).unwrap_or(Self {
            epoch,
            ..Self::default()
        }))
    }

    pub fn save<S: Store>(&self, store: &S, group_id: &[u8]) -> Result<()> {
        save(store, &group_key("own-commits", group_id), self)
    }

    /// Moves the pending commit to the discarded list.
    pub fn discard_pending(&mut self) {
        if let Some(p) = self.pending.take() {
            self.discarded.push(p.hash);
        }
    }
}

/// The members of the epoch before the current one: application messages
/// from that epoch (the SPEC §8.3 grace window) are attributed against it,
/// not against the current tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PreviousMembers {
    pub epoch: u64,
    pub members: Vec<MemberInfo>,
}

impl PreviousMembers {
    pub fn load<S: Store>(store: &S, group_id: &[u8]) -> Result<Option<Self>> {
        load(store, &group_key("previous-members", group_id))
    }

    pub fn save<S: Store>(&self, store: &S, group_id: &[u8]) -> Result<()> {
        save(store, &group_key("previous-members", group_id), self)
    }
}

/// Whether a KeyPackage (by `KeyPackageRef`) was already used in an Add
/// this client merged, in any group: a KeyPackage is single-use (SPEC §6.2,
/// RFC 9420 §16.8), so a replayed JoinRequest must not re-add a member.
pub(crate) fn key_package_used<S: Store>(store: &S, kp_ref: &[u8]) -> Result<bool> {
    Ok(store
        .get_record(&group_key("key-package-used", kp_ref))?
        .is_some())
}

/// Which pending own commit reserved a KeyPackage for its Add: the group
/// and the commit's [`wire_hash`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Reservation {
    pub group_id: Vec<u8>,
    pub hash: String,
}

/// The reservation of a KeyPackage (by `KeyPackageRef`), if any. It counts
/// only while its commit is still the group's pending one; the caller
/// checks that against the MLS state.
pub(crate) fn key_package_reservation<S: Store>(
    store: &S,
    kp_ref: &[u8],
) -> Result<Option<Reservation>> {
    load(store, &group_key("key-package-reserved", kp_ref))
}

/// Reserves the KeyPackages a pending own commit Adds, so that no other
/// group's commit Adds them before it merges or is dropped (SPEC §6.2,
/// "KeyPackage reuse").
pub(crate) fn reserve_key_packages<S: Store>(
    store: &S,
    kp_refs: &[Vec<u8>],
    reservation: &Reservation,
) -> Result<()> {
    for r in kp_refs {
        save(store, &group_key("key-package-reserved", r), reservation)?;
    }
    Ok(())
}

/// Records KeyPackages used by a merged Add.
pub(crate) fn mark_key_packages_used<S: Store>(store: &S, kp_refs: &[Vec<u8>]) -> Result<()> {
    for r in kp_refs {
        store.put_record(&group_key("key-package-used", r), Some(b"1"))?;
        store.put_record(&group_key("key-package-reserved", r), None)?;
    }
    Ok(())
}

/// Deletes a group's records (with the group).
pub(crate) fn delete_group<S: Store>(store: &S, group_id: &[u8]) -> Result<()> {
    store.put_record(&group_key("own-commits", group_id), None)?;
    store.put_record(&group_key("previous-members", group_id), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{MemoryStore, SqliteStore};

    fn round_trip<S: Store>(store: &S) {
        let gid = b"group-id-16bytes";
        let fresh = OwnCommits::load(store, gid, 3).unwrap();
        assert_eq!(fresh.epoch, 3);
        assert!(fresh.pending.is_none());
        let mut rec = fresh;
        rec.pending = Some(PendingRecord {
            msg_id: "m".into(),
            hash: wire_hash(b"x"),
        });
        rec.save(store, gid).unwrap();
        assert_eq!(OwnCommits::load(store, gid, 3).unwrap(), rec);
        // A record for another epoch is stale.
        assert!(OwnCommits::load(store, gid, 4).unwrap().pending.is_none());
        rec.discard_pending();
        assert_eq!(rec.discarded, vec![wire_hash(b"x")]);
        let prev = PreviousMembers {
            epoch: 2,
            members: Vec::new(),
        };
        prev.save(store, gid).unwrap();
        assert_eq!(PreviousMembers::load(store, gid).unwrap(), Some(prev));
        delete_group(store, gid).unwrap();
        assert!(OwnCommits::load(store, gid, 3).unwrap().pending.is_none());
        assert_eq!(PreviousMembers::load(store, gid).unwrap(), None);

        assert!(!key_package_used(store, b"ref").unwrap());
        let reservation = Reservation {
            group_id: gid.to_vec(),
            hash: wire_hash(b"x"),
        };
        reserve_key_packages(store, &[b"ref".to_vec()], &reservation).unwrap();
        assert_eq!(
            key_package_reservation(store, b"ref").unwrap(),
            Some(reservation)
        );
        mark_key_packages_used(store, &[b"ref".to_vec()]).unwrap();
        assert!(key_package_used(store, b"ref").unwrap());
        assert_eq!(key_package_reservation(store, b"ref").unwrap(), None);

        store.put_record(b"junk", Some(b"not json")).unwrap();
        assert_eq!(
            load::<S, OwnCommits>(store, b"junk"),
            Err(Error::Storage("corrupt record".into()))
        );
    }

    #[test]
    fn records_round_trip_in_both_stores() {
        round_trip(&MemoryStore::new());
        round_trip(&SqliteStore::open_in_memory().unwrap());
    }
}
