//! Group metadata, group policy and commit authorisation (SPEC §3.4, §9).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::encoding::{from_jcs, jcs};
use crate::error::{Error, Result};
use crate::identity::parse_identity;

/// Maximum group size (relay default, SPEC §8.3).
pub const MAX_GROUP_SIZE: u32 = 50;
/// Maximum `GroupMeta.name` length in characters (SPEC §3.4).
pub const MAX_NAME_CHARS: usize = 80;
/// Maximum `GroupMeta.purpose` length in characters (SPEC §3.4).
pub const MAX_PURPOSE_CHARS: usize = 500;

/// `ac_group_meta` (SPEC §3.4). Immutable for the life of the group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupMeta {
    /// Always 0.
    pub v: u32,
    /// Display name, at most 80 characters.
    pub name: String,
    /// Scope statement, at most 500 characters.
    pub purpose: String,
    /// Creation time, Unix seconds.
    pub created_at: u64,
    /// Identity of the creator.
    pub created_by: String,
}

impl GroupMeta {
    /// Checks the field constraints.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedVersion`] or [`Error::InvalidGroupContext`].
    pub fn validate(&self) -> Result<()> {
        if self.v != 0 {
            return Err(Error::UnsupportedVersion);
        }
        if self.name.chars().count() > MAX_NAME_CHARS {
            return Err(Error::InvalidGroupContext("group name too long"));
        }
        if self.purpose.chars().count() > MAX_PURPOSE_CHARS {
            return Err(Error::InvalidGroupContext("purpose too long"));
        }
        parse_identity(&self.created_by).map_err(|_| Error::InvalidGroupContext("created_by"))?;
        Ok(())
    }

    /// JCS encoding.
    ///
    /// # Errors
    ///
    /// Only if serialisation fails.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        jcs(self)
    }

    /// Parses and validates canonical JSON.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], [`Error::UnsupportedVersion`] or
    /// [`Error::InvalidGroupContext`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let meta: Self = from_jcs(bytes, "group meta")?;
        meta.validate()?;
        Ok(meta)
    }
}

/// Who may commit Adds via invites (SPEC §9.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvitePermission {
    /// Only the owner.
    Owner,
    /// The owner and admins.
    Admins,
    /// Every member.
    Members,
}

/// Who may remove other members (SPEC §9.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemovePermission {
    /// Only the owner.
    Owner,
    /// The owner and admins.
    Admins,
}

/// Floor mode (SPEC §9.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Floor {
    /// Everyone is triggered.
    Free,
    /// Only addressed members are triggered.
    Mention,
    /// Only the floor holder and moderator are triggered.
    Moderated,
}

/// Loop guard settings (SPEC §10.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoopGuard {
    /// Maximum agent turns before pausing.
    pub max_agent_turns: u32,
}

/// `ac_group_policy` (SPEC §9.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupPolicy {
    /// Always 0.
    pub v: u32,
    /// The owner identity.
    pub owner: String,
    /// Admin identities.
    pub admins: Vec<String>,
    /// Who may invite.
    pub invite: InvitePermission,
    /// Who may remove others.
    pub remove: RemovePermission,
    /// Maximum number of instances (leaves).
    pub max_members: u32,
    /// Hold deliveries until the human verified the epoch (SPEC §10.4).
    pub require_verified: bool,
    /// Floor mode.
    pub floor: Floor,
    /// Floor moderator.
    pub floor_moderator: Option<String>,
    /// Loop guard.
    pub loop_guard: LoopGuard,
}

/// A member's role (SPEC §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Plain member.
    Member,
    /// Admin.
    Admin,
    /// Owner.
    Owner,
}

impl GroupPolicy {
    /// The SPEC §9.1 defaults for a new group owned by `owner`.
    #[must_use]
    pub fn default_for(owner: &str) -> Self {
        Self {
            v: 0,
            owner: owner.to_owned(),
            admins: Vec::new(),
            invite: InvitePermission::Owner,
            remove: RemovePermission::Owner,
            max_members: MAX_GROUP_SIZE,
            require_verified: false,
            floor: Floor::Free,
            floor_moderator: None,
            loop_guard: LoopGuard {
                max_agent_turns: 20,
            },
        }
    }

    /// Checks the field constraints.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedVersion`] or [`Error::InvalidGroupContext`].
    pub fn validate(&self) -> Result<()> {
        if self.v != 0 {
            return Err(Error::UnsupportedVersion);
        }
        let bad_id = |id: &String| parse_identity(id).is_err();
        if bad_id(&self.owner) {
            return Err(Error::InvalidGroupContext("policy owner"));
        }
        if self.admins.iter().any(bad_id)
            || self.admins.iter().collect::<BTreeSet<_>>().len() != self.admins.len()
        {
            return Err(Error::InvalidGroupContext("policy admins"));
        }
        if self.floor_moderator.as_ref().is_some_and(bad_id) {
            return Err(Error::InvalidGroupContext("policy floor_moderator"));
        }
        if self.max_members == 0 || self.max_members > MAX_GROUP_SIZE {
            return Err(Error::InvalidGroupContext("policy max_members"));
        }
        Ok(())
    }

    /// JCS encoding.
    ///
    /// # Errors
    ///
    /// Only if serialisation fails.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        jcs(self)
    }

    /// Parses and validates canonical JSON.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], [`Error::UnsupportedVersion`] or
    /// [`Error::InvalidGroupContext`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let policy: Self = from_jcs(bytes, "group policy")?;
        policy.validate()?;
        Ok(policy)
    }

    /// The role of `identity`.
    #[must_use]
    pub fn role_of(&self, identity: &str) -> Role {
        if identity == self.owner {
            Role::Owner
        } else if self.admins.iter().any(|a| a == identity) {
            Role::Admin
        } else {
            Role::Member
        }
    }

    /// Whether `identity` may commit Adds via invites.
    #[must_use]
    pub fn may_invite(&self, identity: &str) -> bool {
        let role = self.role_of(identity);
        match self.invite {
            InvitePermission::Owner => role == Role::Owner,
            InvitePermission::Admins => role >= Role::Admin,
            InvitePermission::Members => true,
        }
    }

    /// Whether `identity` may remove other members.
    #[must_use]
    pub fn may_remove(&self, identity: &str) -> bool {
        let role = self.role_of(identity);
        match self.remove {
            RemovePermission::Owner => role == Role::Owner,
            RemovePermission::Admins => role >= Role::Admin,
        }
    }
}

/// One removal in a commit.
#[derive(Clone, Debug)]
pub(crate) struct Removal {
    pub identity: String,
    /// The proposal came from the removed leaf itself (a leave).
    pub self_proposed: bool,
}

/// What a commit does, as needed for authorisation.
#[derive(Clone, Debug)]
pub(crate) struct CommitFacts {
    pub committer: String,
    pub adds: Vec<String>,
    pub removes: Vec<Removal>,
    pub new_policy: Option<GroupPolicy>,
    pub members_before: usize,
    pub members_after: usize,
    /// Identities present after the commit.
    pub identities_after: BTreeSet<String>,
}

/// Checks a commit against the policy in force at its epoch (SPEC §9.2).
///
/// The rules of SPEC §9.1–§9.2:
/// - An Add is allowed if the committer's identity satisfies `invite`, or
///   if the added identity is the committer's own (another replica).
/// - Removing the owner's instances needs the owner, unless it's a leave.
/// - The floor switch (`free` → `mention` in the commit that grows the
///   group past two instances) is accepted from any committer allowed to
///   make that Add.
pub(crate) fn authorize(policy: &GroupPolicy, facts: &CommitFacts) -> Result<()> {
    let committer = facts.committer.as_str();
    for added in &facts.adds {
        if added != committer && !policy.may_invite(committer) {
            return Err(Error::Unauthorized("committer may not invite"));
        }
    }
    for r in &facts.removes {
        if r.self_proposed || r.identity == committer {
            continue;
        }
        if !policy.may_remove(committer) {
            return Err(Error::Unauthorized("committer may not remove members"));
        }
        if r.identity == policy.owner && policy.role_of(committer) != Role::Owner {
            return Err(Error::Unauthorized("only the owner may remove the owner"));
        }
    }
    if let Some(new) = &facts.new_policy {
        authorize_policy_change(policy, new, facts)?;
    }
    let max = facts
        .new_policy
        .as_ref()
        .map_or(policy.max_members, |p| p.max_members);
    if facts.members_after > usize::try_from(max).unwrap_or(usize::MAX) {
        return Err(Error::Unauthorized("group would exceed max_members"));
    }
    Ok(())
}

fn authorize_policy_change(
    old: &GroupPolicy,
    new: &GroupPolicy,
    facts: &CommitFacts,
) -> Result<()> {
    if new == old {
        return Ok(());
    }
    if !facts.identities_after.contains(&new.owner) {
        return Err(Error::Unauthorized("new owner is not a member"));
    }
    let committer = facts.committer.as_str();
    match old.role_of(committer) {
        Role::Owner => Ok(()),
        role => {
            let floor_only = GroupPolicy {
                floor: old.floor,
                floor_moderator: old.floor_moderator.clone(),
                ..new.clone()
            } == *old;
            if role == Role::Admin && floor_only {
                return Ok(());
            }
            let floor_switch = GroupPolicy {
                floor: Floor::Mention,
                ..old.clone()
            } == *new
                && old.floor == Floor::Free
                && !facts.adds.is_empty()
                && facts.members_before <= 2
                && facts.members_after > 2;
            if floor_switch {
                return Ok(());
            }
            Err(Error::Unauthorized("committer may not change this policy"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::rng::Rng;

    fn ids(n: u64) -> Vec<String> {
        (0..n)
            .map(|i| {
                Identity::generate(&Rng::for_test(&format!("seed-{}", 100 + i)))
                    .unwrap()
                    .id()
            })
            .collect()
    }

    fn facts(committer: &str) -> CommitFacts {
        CommitFacts {
            committer: committer.into(),
            adds: vec![],
            removes: vec![],
            new_policy: None,
            members_before: 2,
            members_after: 2,
            identities_after: BTreeSet::new(),
        }
    }

    #[test]
    fn policy_round_trips_and_validates() {
        let id = ids(1);
        let p = GroupPolicy::default_for(&id[0]);
        let json = p.to_json().unwrap();
        assert_eq!(GroupPolicy::from_json(&json).unwrap(), p);
        let mut bad = p.clone();
        bad.v = 1;
        assert_eq!(bad.validate(), Err(Error::UnsupportedVersion));
        let mut bad = p.clone();
        bad.owner = "x".into();
        assert!(bad.validate().is_err());
        let mut bad = p.clone();
        bad.admins = vec![id[0].clone(), id[0].clone()];
        assert!(bad.validate().is_err());
        let mut bad = p.clone();
        bad.floor_moderator = Some("x".into());
        assert!(bad.validate().is_err());
        let mut bad = p.clone();
        bad.max_members = 51;
        assert!(bad.validate().is_err());
        let s = String::from_utf8(json)
            .unwrap()
            .replace("\"v\":0", "\"v\":0,\"z\":1");
        assert!(GroupPolicy::from_json(s.as_bytes()).is_err());
    }

    #[test]
    fn meta_validates_lengths() {
        let id = ids(1);
        let meta = GroupMeta {
            v: 0,
            name: "n".repeat(80),
            purpose: "\u{e9}".repeat(500),
            created_at: 1,
            created_by: id[0].clone(),
        };
        assert_eq!(
            GroupMeta::from_json(&meta.to_json().unwrap()).unwrap(),
            meta
        );
        let long = GroupMeta {
            name: "n".repeat(81),
            ..meta.clone()
        };
        assert!(long.validate().is_err());
        let long = GroupMeta {
            purpose: "p".repeat(501),
            ..meta.clone()
        };
        assert!(long.validate().is_err());
        let v1 = GroupMeta {
            v: 1,
            ..meta.clone()
        };
        assert_eq!(v1.validate(), Err(Error::UnsupportedVersion));
        let by = GroupMeta {
            created_by: "x".into(),
            ..meta
        };
        assert!(by.validate().is_err());
    }

    #[test]
    fn roles_and_permissions() {
        let id = ids(3);
        let mut p = GroupPolicy::default_for(&id[0]);
        p.admins = vec![id[1].clone()];
        assert_eq!(p.role_of(&id[0]), Role::Owner);
        assert_eq!(p.role_of(&id[1]), Role::Admin);
        assert_eq!(p.role_of(&id[2]), Role::Member);
        assert!(p.may_invite(&id[0]) && !p.may_invite(&id[1]));
        p.invite = InvitePermission::Admins;
        p.remove = RemovePermission::Admins;
        assert!(p.may_invite(&id[1]) && !p.may_invite(&id[2]));
        assert!(p.may_remove(&id[1]) && !p.may_remove(&id[2]));
        p.invite = InvitePermission::Members;
        assert!(p.may_invite(&id[2]));
    }

    #[test]
    fn adds_and_removes_follow_policy() {
        let id = ids(3);
        let p = GroupPolicy::default_for(&id[0]);
        let mut f = facts(&id[1]);
        f.adds = vec![id[2].clone()];
        assert_eq!(
            authorize(&p, &f),
            Err(Error::Unauthorized("committer may not invite"))
        );
        // Another replica of the committer's own identity is fine.
        f.adds = vec![id[1].clone()];
        authorize(&p, &f).unwrap();

        let mut f = facts(&id[1]);
        f.removes = vec![Removal {
            identity: id[2].clone(),
            self_proposed: false,
        }];
        assert_eq!(
            authorize(&p, &f),
            Err(Error::Unauthorized("committer may not remove members"))
        );
        f.removes[0].self_proposed = true;
        authorize(&p, &f).unwrap();

        let mut p2 = p.clone();
        p2.remove = RemovePermission::Admins;
        p2.admins = vec![id[1].clone()];
        let mut f = facts(&id[1]);
        f.removes = vec![Removal {
            identity: id[0].clone(),
            self_proposed: false,
        }];
        assert_eq!(
            authorize(&p2, &f),
            Err(Error::Unauthorized("only the owner may remove the owner"))
        );

        let mut f = facts(&id[0]);
        f.members_after = 51;
        assert_eq!(
            authorize(&p, &f),
            Err(Error::Unauthorized("group would exceed max_members"))
        );
    }

    #[test]
    fn policy_changes_follow_roles() {
        let id = ids(3);
        let mut old = GroupPolicy::default_for(&id[0]);
        old.admins = vec![id[1].clone()];
        let members: BTreeSet<String> = id.iter().cloned().collect();

        let mut new = old.clone();
        new.require_verified = true;
        let mut f = facts(&id[0]);
        f.identities_after = members.clone();
        f.new_policy = Some(new.clone());
        authorize(&old, &f).unwrap();
        f.committer = id[1].clone();
        assert!(authorize(&old, &f).is_err());

        // Admins may change the floor only.
        let mut floor = old.clone();
        floor.floor = Floor::Moderated;
        floor.floor_moderator = Some(id[1].clone());
        f.new_policy = Some(floor);
        authorize(&old, &f).unwrap();
        f.committer = id[2].clone();
        assert!(authorize(&old, &f).is_err());

        // Unchanged policy is a no-op.
        f.new_policy = Some(old.clone());
        authorize(&old, &f).unwrap();

        // Owner transfer needs a current member.
        let mut transfer = old.clone();
        transfer.owner = ids(5)[4].clone();
        let mut f = facts(&id[0]);
        f.identities_after = members.clone();
        f.new_policy = Some(transfer);
        assert_eq!(
            authorize(&old, &f),
            Err(Error::Unauthorized("new owner is not a member"))
        );
    }

    #[test]
    fn floor_switch_on_third_member_is_allowed_for_the_inviter() {
        let id = ids(3);
        let mut old = GroupPolicy::default_for(&id[0]);
        old.invite = InvitePermission::Members;
        let switched = GroupPolicy {
            floor: Floor::Mention,
            ..old.clone()
        };
        let mut f = facts(&id[1]);
        f.adds = vec![id[2].clone()];
        f.members_after = 3;
        f.identities_after = id.iter().cloned().collect();
        f.new_policy = Some(switched.clone());
        authorize(&old, &f).unwrap();
        // Not when the group already had three members.
        f.members_before = 3;
        f.members_after = 4;
        assert!(authorize(&old, &f).is_err());
        // Not combined with other changes.
        f.members_before = 2;
        f.members_after = 3;
        f.new_policy = Some(GroupPolicy {
            require_verified: true,
            ..switched
        });
        assert!(authorize(&old, &f).is_err());
    }
}
