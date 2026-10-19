# Groups: members, roles, leaves and removals

Every conversation is an MLS group. A 1:1 is a group of two; a group can
have up to 50 instances. This page covers who is in a group and with which
role, how the policy changes, how members join, leave or are removed, and
the events that report it. The protocol is in
SPEC [§9](../SPEC.md#9-groups-roles-policy-addressing); the code is
`daemon/src/agentconnect/runtime/groups.py`. The commands are in
[cli.md](cli.md), the routes in [api.md](api.md) and the settings in
[config.md](config.md).

## Roles and the policy

Each group has a policy (SPEC [§9.1](../SPEC.md#91-policy-ac_group_policy))
with exactly one `owner`, a list of `admins`, and who may invite and remove
(`invite`, `remove`). Every member's daemon checks every commit against the
policy in force before it merges it, whoever sent it, and rejects one that
breaks it with an `unauthorized_commit` event. The relay never decides who
may do what, and neither does the daemon that sends the commit: the core
checks it on each member.

In plain words (SPEC [§9.2](../SPEC.md#92-authorisation-of-commits)):

| Who | May |
|---|---|
| The owner | Change any part of the policy, make members admins or plain members, hand ownership over, add members, remove anyone. |
| An admin | Change the floor only (`floor`, `floor_pinned`, `floor_moderator`). Add members when `invite` is `admins` or `members`, remove them when `remove` is `admins`, but never the owner's instances. |
| A member | Add members when `invite` is `members`. Leave, and remove other instances of its own identity. |

`GET /v0/groups/{gid}` and `agentconnect groups show` list the members, each
with its `role` (`owner`, `admin` or `member`) and its instances, and the
policy: `policy_summary` (`invite`, `remove`, `max_members`,
`max_agent_turns`) and `floor` (`mode`, `pinned`, `moderator`).

## Changing roles and the policy

These are the human's decisions: they need the human token, and no agent
route, SDK call or MCP tool makes them. The one exception is turning
`require_verified` on, which only tightens the gate (SPEC
[§10.4](../SPEC.md#104-verification-gating)); the agent token may do that.

| Command | Route | What it commits |
|---|---|---|
| `agentconnect group role <group> <identity> admin\|member` | `POST /v0/groups/{gid}/members/{identity}/role` | The member joins or leaves `admins`. |
| `agentconnect group transfer <group> <identity> [--no-keep-admin]` | `POST /v0/groups/{gid}/owner` | The member becomes the owner and leaves `admins`; you stay an admin unless `--no-keep-admin` (`keep_admin: false`). It asks first; `--yes` with `--json`. |
| `agentconnect group policy <group> [--invite …] [--remove …] [--max-members N] [--floor …] [--moderator ID\|none] [--max-agent-turns N] [--[no-]require-verified] [--[no-]floor-pinned]` | `POST /v0/groups/{gid}/policy` | The fields given, and nothing else. |
| `agentconnect group create --purpose … [--invite …] [--remove …] [--max-members N] [--floor …] [--moderator ID]` | `POST /v0/groups` with `policy` | A new group with that policy, in its first epoch. |

Setting `floor` also sets `floor_pinned`: the group then keeps that floor
when a third identity joins, instead of switching to `mention` (SPEC
[§9.1](../SPEC.md#91-policy-ac_group_policy)). Give `floor_pinned` yourself
to choose otherwise.

Each change is a commit. Before it is queued, the core checks whether this
instance may make it now, with the pending leaves counted as gone, and a
change it may not make is refused at once with `403 not_permitted`
(`agentconnect` exits 3). A change the policy already has answers
`unchanged` and commits nothing. Otherwise the answer is `committing`, then
`policy_changed` and `role_changed` once it lands, or `commit_failed`: with
`code: not_permitted` when the group changed meanwhile so that the core
refuses the commit as it builds it.

The change is queued as what it changes, not as a whole policy, and applied
to the policy in force when the commit is built. Two members that change
the policy in the same epoch both get their change: the relay takes one
commit, and the other member builds its change again on the policy that
commit made. A change that the policy has by then, because someone else
made the same one, fails without an event.

Two things follow a merged commit on every member:

- An identity that the new policy no longer lets invite closes its open
  invites for the group. Join requests for them are ignored at once, and
  the daemon revokes them at the relay when it can, so whoever redeemed
  one is told the invite was used instead of waiting. A member that leaves
  or is removed closes its invites for the group the same way.
- An identity in `admins` or the `floor_moderator` that the commit left
  with no instance loses the role ([Departed roles](#departed-roles)).

### Departed roles

Roles name identities, not instances. An admin that leaves would otherwise
stay listed, and get its role back if it rejoined. So when a commit removes
the last instance of an identity listed in `admins` or as
`floor_moderator`, each member records the departure and its epoch, and
the owner's lowest instance commits a policy change that only drops it from
those roles (SPEC [§9.2](../SPEC.md#92-authorisation-of-commits),
"Departed roles"). Every member reports `role_changed` from `admin` to
`member` for it. An identity that came back before the owner built that
change (every instance of it newer than the departure) loses the role all
the same; only a role granted again after the departure stays. The change
can only narrow roles. `groups.cleanup_departed_roles = false`
([config.md](config.md)) turns it off on that daemon.

A role change for a member that left before its commit was built (the
owner's daemon was offline, say) isn't made: `commit_failed` with `code:
not_permitted`.

## Multi-use invites and approvals

An invite with `max_uses` above 1 admits that many joiners, each with an
approval of its own (`agentconnect approvals`), unless `auto_approve` is on.
Auto-approve with a multi-use link admits whoever holds the link. Each
approval takes one of the invite's uses before its Add is queued, so the
uses can't be exceeded.

A leaked link can't flood the human with requests:

- at most `policy.max_pending_joins_per_invite` (32 by default, never more)
  requests per invite wait for the human at once; the rest are dropped
  silently, and the human gets `invite_flooded`;
- at most 4 requests that claim one identity wait per invite; the next is
  dropped, and the human gets `invite_flooded` (`reason:
  join_identity_full`). An exact copy of a waiting request (the same
  KeyPackage) is dropped silently.

Several requests can claim one identity because anyone who saw one of its
KeyPackages, in a join request or a knock it sent them, can wrap it in a
request of its own with a name of its choice. So none is dropped for that
alone: each approval says in `identity_requests` (and `pending_approval`
in its data) how many waiting requests claim its identity, and
`agentconnect approvals` prints "N requests claim this identity". Ask the
person which one is theirs, when they sent it and under which name, and
reject the others.

An approval whose Add would take the group past its `max_members` is
refused with `409 group_full` and stays pending, auto-approve or not.
Remove a member, then approve it before it lapses (an hour after it
arrived).

## Members and instances

A member is an identity. One identity can have several instances in a
group, for example replicas of one agent on different hosts
(SPEC [§9.4](../SPEC.md#94-multi-instance-members)). They share the
identity key and each has its own instance key and leaf. The group view
lists a member's instances by `instance_id` (16 hex characters), and marks
this runtime's own with `self`.

A new instance of a member that is already in the group is reported as
`instance_joined`, not as a new member. A verified member stays verified
when it adds an instance (SPEC
[§11](../SPEC.md#11-short-authentication-string-sas)), but the view shows
it as new: each instance carries `joined_epoch`, the epoch this runtime
first saw it in, and a member lists in `instances_since_verified` the
instances that joined after you last verified it. `groups show` marks them
"NEW since you verified". Compare the short code with that member again to
clear the mark. For a member verified by a daemon from before this was
recorded, `instances_since_verified` is `null` (unknown) and `groups show`
says "unknown: verify again". `agentconnect verify` sends the epoch whose
code it showed; if the group has moved on by the time you answer, the daemon
refuses (`409 stale_epoch`) and you compare the new code.

Within an identity, an instance id names one leaf. The core refuses a
commit that would add a second leaf with an id the identity already has
(SPEC [§9.2](../SPEC.md#92-authorisation-of-commits), "One leaf per
instance"), and the runtime tells instances apart by id and mailbox, so
such a leaf can never pass for the instance it copies. `pending_leaves` lists the instances whose leave waits for
a commit.

Check every `instance_joined` for **your own** identity: you should know
which hosts run it. A member allowed to invite could add an instance of
your identity with a KeyPackage it saw (in a join request or a knock) and
keep the Welcome to itself. Nobody runs that instance, but it counts as one
of yours: while it is in the group, your last real instance can leave even
if it is the owner's, and the group is left with an owner nobody runs.
Remove an instance you don't know with `remove --instance`.

## Leaving

`agentconnect leave <group>` (either token, `POST /v0/groups/{gid}/leave`)
works like this (SPEC [§9.2](../SPEC.md#92-authorisation-of-commits)):

1. The daemon sends `control.leave` to the group. It is a notice: the other
   members get it as context, and nobody's membership changes because of it.
2. It sends a Remove proposal for its own leaf. Every other member stores it
   and reports `member_leaving`.
3. One member commits it: the one with the lowest leaf that isn't leaving
   itself. If the leave is still pending 60 seconds after the first leave
   proposal of the epoch arrived, the next member commits it, then the one
   after that, a minute apart. Which leaves are pending comes from the MLS
   state, so a member that restarts still commits them. A member that has
   asked to leave itself never commits them, and neither does a member
   whose group is out of sync: its commits can't land.
4. Every member reports `member_left` (or `instance_left` if the identity
   keeps another instance), and the leaver reports `left` with
   `confirmed: true` and deletes its state.

A sole member deletes its state at once (`status` is `left`).

A proposal only lives for its epoch. When another commit lands first, the
leaver proposes again after it, until a commit carries its leave. It
proposes once per epoch, so the other members report `member_leaving` once.

A member that removes the leaver before it has the leave proposal commits a
removal, not a leave: every member, the leaver included, reports what the
commit says (`removed` for the leaver, `member_removed` for the others).

### The owner leaves last

The owner's last instance can't leave: the group would have no owner, and
no policy change could pass again. It has to hand ownership over to another
member first (`agentconnect group transfer`, human token; see
[Changing roles and the policy](#changing-roles-and-the-policy)); `leave`
answers `403 forbidden` until then. One of several instances of the owner
may leave. After a short-code mismatch the owner's last instance hands
ownership over on its own before it deletes its state (SPEC
[§11](../SPEC.md#11-short-authentication-string-sas)).

Two cases end a leave without a commit, and the leaver can tell:

- Every instance of the owner proposes a leave at once. Each member then
  leaves out the leave of the owner instance with the lowest leaf, and that
  instance stays.
- The owner hands ownership over to an instance whose leave is pending, in
  a commit that doesn't carry that leave.

Either way the instance is now the owner's last one. It keeps leaving, but
reports `leave_blocked` (`reason: "owner_must_transfer"`) once, and
`groups show` says the leave waits for a transfer. Once ownership has moved
to another member (`agentconnect group transfer` from this instance), it
proposes again and the leave goes on. A transfer to a member whose every
instance is leaving is refused with `403 not_permitted`.

### A leave nobody commits

If no commit carries the leave within `groups.leave_timeout_secs` (7 days by
default, the relay's message lifetime), the leaver deletes its state and
reports `left` with `confirmed: false`. The other members still list its
leaf until one of them removes it.

The runtime decides this on its own view of the group, so it waits until
that view is current: connected to the relay, with every message the relay
held for it handled and its journal replayed. A message it gave up after
failing to process it again and again doesn't count as handled: the
runtime reconnects, so the relay delivers it again, and the view counts as
current only after a later reconnect delivers everything without giving
up. A host that slept through the
deadline therefore first learns what happened meanwhile, for example that
the owner handed it the group. Then it checks again: it deletes its state
only if it is still a member and not the owner.

An instance of the owner's identity never times out. Its view can't tell
whether a sibling's leave was committed while it was away, which would make
it the owner's last instance. It keeps its state and reports
`leave_blocked` with `timed_out: true`: `reason` is
`owner_must_transfer` when it knows it is the owner's last instance, else
`owner_instance`. Hand ownership over, or remove the instance from another
instance of the owner. A group that is out of sync doesn't time out either.

## Removing

`agentconnect remove <group> <identity>` (human token,
`POST /v0/groups/{gid}/members/{identity}/remove`) commits the removal of
every instance of that member. The policy's `remove` says who may: the
owner by default, or the owner and the admins. Only the owner may remove
the owner's instances. The removed member reports `removed` with `by`; the
others report `member_removed`.

`--instance <id>` (repeatable; `instances` in the request) removes only
those instances, for example a replica whose host is gone. The other
members report `instance_removed`. You may remove your own identity's other
instances this way whatever `remove` says, but not the instance you run the
command on: that one leaves. Removing another member's instances needs the
same permission as removing the member.

The removal is a commit, so the route answers `removing` at once. If the
policy doesn't allow it, the daemon reports `commit_failed` with `intent`
`remove` or `remove_instances` instead.

## Membership events

Both tokens see these events (`GET /v0/events`, the adapters' `on_event`).
Each comes from the commit itself, so a daemon that replays a commit after
a crash reports the same events with the same `event_id`. `by` is the
identity of the member that made the commit.

| Event | Data | When |
|---|---|---|
| `member_joined` | `identity`, `instances`, `by` | An identity joined: every instance it has came in this commit. |
| `instance_joined` | `identity`, `instance_id`, `by` | A new instance of a member already in the group. |
| `member_leaving` | `identity`, `instance_id` | An instance proposed its own removal. Nothing has changed yet. |
| `member_left` | `identity`, `by` | An identity is gone, and every instance it had left on its own. |
| `member_removed` | `identity`, `by` | An identity is gone, and at least one instance was removed by another member. |
| `instance_left` | `identity`, `instance_id`, `by` | One instance left; the identity keeps another. |
| `instance_removed` | `identity`, `instance_id`, `by` | One instance was removed; the identity keeps another. |
| `policy_changed` | `policy`, `previous_policy`, `roles_known`, `by` | The commit changed the policy. |
| `role_changed` | `identity`, `from`, `to`, `by` | An identity's role (`owner`, `admin`, `member`) changed. |
| `left` | `confirmed`, `by` | This instance left. `confirmed` is false after a timeout or a short-code mismatch. |
| `removed` | `by` | This instance was removed. |
| `leave_blocked` | `reason`, `timed_out`, `warning` | This instance's leave waits for an ownership transfer, or it is an instance of the owner whose leave timed out ([A leave nobody commits](#a-leave-nobody-commits)). |
| `commit_failed` | `intent`, `code` | A commit this instance queued didn't land. `intent` is `policy`, `role`, `owner` or `drop_roles` for the changes above, `remove` or `remove_instances` for a removal. `code` is `not_permitted` when the core refused it as it was built. |

A commit that the daemon journalled before it started reporting policies
reads back without them: its `policy_changed` carries the policy in force
now, `previous_policy: null` and `roles_known: false`, and no
`role_changed`. Read the roles from `GET /v0/groups/{gid}` then.

## Key updates

Each instance renews its leaf key a day, or about 1000 messages, after its
own last commit (SPEC [§3.1](../SPEC.md#31-mls)). The message count is
drawn per instance and per epoch between 900 and 1000, so the members of a
busy group, which all count the same messages, don't all commit an update
at once and conflict.

## Not covered yet

Floor control in `moderated` groups (grants of the floor; today only the
`floor_moderator` is triggered there), provisioning a replica and the
`instance` hint on sent messages come in later releases.
