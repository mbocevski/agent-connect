# Groups: members, leaves and removals

Every conversation is an MLS group. A 1:1 is a group of two; a group can
have up to 50 instances. This page covers who is in a group, how members
leave or are removed, and the events that report it. The protocol is in
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

`GET /v0/groups/{gid}` and `agentconnect groups show` list the members, each
with its `role` (`owner`, `admin` or `member`) and its instances.

## Members and instances

A member is an identity. One identity can have several instances in a
group, for example replicas of one agent on different hosts
(SPEC [§9.4](../SPEC.md#94-multi-instance-members)). They share the
identity key and each has its own instance key and leaf. The group view
lists a member's instances by `instance_id` (16 hex characters), and marks
this runtime's own with `self`.

A new instance of a member that is already in the group is reported as
`instance_joined`, not as a new member. A verified member stays verified
when it adds an instance.

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
   state, so a member that restarts still commits them.
4. Every member reports `member_left` (or `instance_left` if the identity
   keeps another instance), and the leaver reports `left` with
   `confirmed: true` and deletes its state.

A sole member deletes its state at once (`status` is `left`).

A proposal only lives for its epoch. When another commit lands first, the
leaver proposes again after it, until a commit carries its leave.

### The owner leaves last

The owner's last instance can't leave: the group would have no owner, and
no policy change could pass again. It has to hand ownership over to another
member first; `leave` answers `403 forbidden` until then. One of several
instances of the owner may leave. (Today the only hand-over is the one after
a short-code mismatch, SPEC [§11](../SPEC.md#11-short-authentication-string-sas);
a command to hand ownership over comes in a later release.)

Two cases end a leave without a commit, and the leaver can tell:

- Every instance of the owner proposes a leave at once. Each member then
  leaves out the leave of the owner instance with the lowest leaf, and that
  instance stays.
- The owner hands ownership over to an instance whose leave is pending, in
  a commit that doesn't carry that leave.

Either way the instance is now the owner's last one. It keeps leaving, but
reports `leave_blocked` (`reason: "owner_must_transfer"`) once, and
`groups show` says the leave waits for a transfer. Once ownership has moved
to another member, it proposes again and the leave goes on.

### A leave nobody commits

If no commit carries the leave within `groups.leave_timeout_secs` (7 days by
default, the relay's message lifetime), the leaver deletes its state and
reports `left` with `confirmed: false`. The other members still list its
leaf until one of them removes it. The owner's last instance never times
out this way: it keeps its state and reports `leave_blocked` again with
`timed_out: true`.

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
| `leave_blocked` | `reason`, `timed_out`, `warning` | This instance's leave waits for an ownership transfer. |

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

Changing roles and the policy through the API and the CLI, handing over
ownership on request, floor control in `moderated` groups, provisioning a
replica and the `instance` hint on sent messages come in later releases.
