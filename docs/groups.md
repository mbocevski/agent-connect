# Groups: members, roles, leaves, removals and the floor

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
`max_agent_turns`) and `floor` (`mode`, `pinned`, `moderator`, and the
`effective_moderator` and `holder` of [floor control](#floor-control)).
They also show where this runtime delivers the group's messages and
events: `adapters`, the list the human pinned with `agentconnect group
adapters` (or `null`: the config's `daemon.adapters`), and `delivers_to`,
the adapters that receive them now ([config.md](config.md#several-adapters)).

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
  one is told the invite was used instead of waiting. Their secrets are
  deleted, or, if the keystore can't delete them yet (a locked OS keyring,
  a failing disk), on a later housekeeping pass. A member that
  leaves or is removed closes its invites for the group the same way.
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
the same; only a role granted again after the departure stays. Granting
admin to such an identity before the cleanup landed (`group role … admin`)
commits two changes, the drop and the grant, so the grant is one every
member sees and the role stays. The change
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
  join_identity_full`, with that `identity`, once per identity), whose
  warning says the requests may be replayed and the identity's own may be
  one of those dropped. An exact copy of a waiting request (the same
  KeyPackage) is dropped silently;
- when `policy.max_failed_joins_per_invite` (16 by default, never more)
  requests for an invite fail within 10 minutes (a wrong MAC, or sent from
  a mailbox other than the one they name), the human gets `invite_flooded`
  (`reason: join_failures`; while they go on, each notice waits twice as
  long as the last, from 10 minutes up to a day).
  Failed requests are dropped; requests that pass the checks still reach
  the human.

A request is accepted only from the mailbox it names (SPEC §6.2 step 3):
anyone with the link can wrap a KeyPackage they saw, in a join request or a
knock sent to them, in a request of their own, so one from another mailbox
is dropped before it takes a ledger entry or reaches the human, like a
failed MAC. Several requests can still claim one identity: each of its
instances can send one, and a relay that lies about the sender can deliver
a wrapped KeyPackage under the KeyPackage's own mailbox. So none is dropped for that
alone: each approval in `GET /v0/approvals` says in `identity_requests` how
many waiting requests claim its identity now, and `agentconnect approvals`
prints "N requests claim this identity". Each approval, and its
`pending_approval` event, also carries the joiner's `instance_id` and
`mailbox_id`, which tell two requests of one identity apart
(`instance_id` is null for a request stored by an older daemon).
`pending_approval` carries the count when that request arrived; an earlier request's event isn't sent
again when another arrives, so the approvals view is the one to go by. Ask
the person which one is theirs, when they sent it and under which name,
and reject the others. Rejecting one makes room for the identity's next
request.

An approval whose Add would take the group past its `max_members` is
refused with `409 group_full` and stays pending, auto-approve or not.
Remove a member, then approve it before it lapses (an hour after it
arrived).

A group made by approving a knock is the agent's only once the knocker is
in ([discovery.md](discovery.md)). Until then the agent token can't tell it
exists: its status doesn't count it, and every route that takes a group
answers it as it answers one that doesn't exist (`404 not_found`, "no such
active group").

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
clear the mark ([Comparing short codes](#comparing-short-codes)). For a
member verified by a daemon from before this was recorded,
`instances_since_verified` is `null` (unknown) and `groups show` says
"unknown: verify again".

## Comparing short codes

The short code comes from a SAS run between two daemons (SPEC
[§11](../SPEC.md#11-short-authentication-string-sas)). Both humans run
`agentconnect verify <group> <member>` at the same time, on a call or in
person, each naming the other. The two daemons each commit to a random
nonce inside the group, reveal it once they hold the other's commitment,
and derive the code from the epoch and both nonces. There is no group-wide
code: in a group of N members, each human compares codes with each of the
N − 1 others.

- `verify` shows the code with two instance labels, yours and theirs; the
  other human reads the same two the other way round. It asks about the
  code and about the labels, always. A code that differs is the
  mismatch, whatever the labels: an attacker in the middle can copy the
  real instance ids. With the same code, labels that don't mirror count as
  a warning, and `verify` asks for the two labels the other human reads. If
  both name instances in your view (theirs one of the member's, and their
  "yours" one of your own identity's), two runs of replicas paired
  crosswise: start again, naming the instance with `--instance`. Anything
  else is treated as codes that differ: an attacker in the middle uses
  instance ids of its own.
- Answering that the codes differ leaves the group, whatever happened
  since the code appeared (`sas_mismatch`). Answering that they match marks
  the member verified, within 600 s of the code appearing, also when the
  epoch moved on meanwhile.
- After 60 s without the other side, `verify` says that your daemons may
  not see the same group, and offers to treat it as different codes: a fork
  shows either as codes that differ or as runs that never pair.
- A run that ends after your daemon revealed its nonce is a warning, and
  names the member whose commit ended it. After two warnings with one
  member, `verify` stops and offers the mismatch action; the daemon never
  leaves on its own, because a relay that drops messages causes the same.
- One run per pair of identities at a time: a second one, also from
  another instance of your identity, answers `409 conflict`.
- `Ctrl-C` while `verify` waits gives the run up: before your daemon
  revealed its nonce, the other daemon is told (`control.sas_cancel`) and
  nothing is counted. A restart does the same for the commitments it left.
- While a run is under way or its code waits for your answer, the daemon
  defers its update cadence, for at most 600 s in total. Another member's
  leave can't wait (no message goes out while a proposal is pending); a run
  it ends is a warning that names the member who left.
- While a leave is pending, runs wait for its commit and then go on. A run
  whose reveal couldn't go out because of it ends (`proposal_pending`) with
  nothing counted, and starts again after the commit.
- The codes and the run events (`sas_requested`, `sas_paired`, `sas_code`,
  `sas_aborted`, `sas_unpaired`, `sas_stopped`, `verifications_reset`) are
  the human's. The agent never sees them, and no event it sees carries a
  code.
- The first start of this version resets every verified flag once and says
  why (`verifications_reset`): those flags rested on a group-wide code that
  an attacker in the middle could choose.

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

## Replicas

A replica is an instance of your identity on another host. Making one takes
two steps, both for the human:

1. **Provision it.** `agentconnect identity export` on a stopped runtime
   writes the identity key into a file encrypted under a one-time code, and
   `agentconnect identity import` on the new host puts it into a new, empty
   data directory with a fresh instance: its own signing key, `instance_id`
   and mailbox. Only the CLI does this, with no API route, SDK call or MCP
   tool (ADR-005), and the import refuses a data directory that already
   holds an instance, so a copy of one can't pass as a replica
   ([cli.md](cli.md#provisioning-a-replica)).
2. **Add it to each group.** On a running instance of the identity,
   `agentconnect invite create --group <group> --replica --instance <id>`
   (human token; `replica: true` and `instance` on `POST
   /v0/groups/{gid}/invites`) creates a replica invite pinned to the
   instance id the import printed, and the new host accepts it. You may
   create one whatever the group's `invite` says (SPEC
   [§9.2](../SPEC.md#92-authorisation-of-commits): any instance may add
   another instance of its own identity). It admits only your identity, and
   only the pinned instance: any other request is dropped before it uses
   any of the invite's share of the join ledger, without reaching you,
   with an audit row with reason `join_not_replica`. A replica invite stays
   open when the policy stops letting you invite; it closes, like every
   other, when you leave or are removed.

   Pin it. Anyone who holds the link and saw a KeyPackage of another of
   your instances (in a request it sent to their invite, say) can send a
   request that claims your identity too. Pinned, such a request is
   dropped. Unpinned, every request of your identity waits for you, even
   with `auto_approve` on, and you approve only the one whose `instance_id`
   is the one `identity import` printed. A wrong pick uses the invite up
   and adds a leaf that nobody runs.

The members see `instance_joined` for the new instance. Every host that
holds the key can add instances that every member accepts, so check each
`instance_joined` for your own identity ([Members and
instances](#members-and-instances)), and remove a replica you no longer run
with `remove --instance`.

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
| `role_changed` | `identity`, `from`, `to`, `moderator_from`, `moderator_to`, `by` | An identity's role (`owner`, `admin`, `member`) changed, or it became or stopped being the `floor_moderator` (`moderator_from`, `moderator_to`; `from` equals `to` when only that changed). |
| `floor_changed` | `mode`, `moderator`, `effective_moderator`, `holder`, `by`, `reason` | The floor holder, the moderator or the floor mode changed ([Floor control](#floor-control)). |
| `left` | `confirmed`, `by` | This instance left. `confirmed` is false after a timeout or a short-code mismatch. |
| `removed` | `by` | This instance was removed. |
| `leave_blocked` | `reason`, `timed_out`, `warning` | This instance's leave waits for an ownership transfer, or it is an instance of the owner whose leave timed out ([A leave nobody commits](#a-leave-nobody-commits)). |
| `commit_failed` | `intent`, `code` | A commit this instance queued didn't land. `intent` is `policy`, `role`, `owner` or `drop_roles` for the changes above, `remove` or `remove_instances` for a removal. `code` is `not_permitted` when the core refused it as it was built. |

### A group the relay deleted

A relay deletes a group nobody has used for its idle period (30 days by
default) while none of its members is connected (SPEC
[§8.3](../SPEC.md#83-delivery-service-rules), "Idle groups"). A member
that comes back gets `unknown_group` for its next message, commit or
leave proposal. The daemon then puts the group out of sync (an
`out_of_sync` event with `reason: "unknown_group"`; `out_of_sync_reason`
in `GET /v0/groups/{gid}` and `agentconnect groups show <group>`), and the send
fails with `send_failed` (`code: "unknown_group"`). It doesn't re-create
the group or rejoin it: the group can't be resumed at the relay, so start
a new one and invite the others again. An out-of-sync group takes no new
invites (`out_of_sync`).

A member learns this only when it sends: one that only listens isn't told
that the group is gone. Once the group is deleted, anyone who knows its id
can register it again at the relay. A member then gets `not_member`
instead, and the daemon reports `relay_misbehaviour` (`reason:
"not_member"`), once per epoch, and leaves the group as it is: a relay
that misbehaves, or a commit removing this instance that hasn't arrived
yet, look the same.

A relay also refuses to register a new group past its limits (SPEC
[§8.3](../SPEC.md#83-delivery-service-rules), `group.create`), most often
with `quota_exceeded`. The group then exists only on this daemon: it goes
out of sync with `reason: "not_created"` and the refusal's `code`, it
takes no invites, and an approved knock waiting on it fails
(`knock_approval_failed`, `code: "not_created"`). Create the group again
later. A refusal that means "not now" (`rate_limited`, `internal`) is
tried again after a backoff instead, and so is a `group.create` whose
answer was lost: the relay answers its creator's repeat `accepted`.

A commit that the daemon journalled before it started reporting policies
reads back without them: its `policy_changed` carries the policy in force
now, `previous_policy: null` and `roles_known: false`, and no
`role_changed`. Read the roles from `GET /v0/groups/{gid}` then.

## Floor control

The policy's `floor` says whose agents a message triggers (SPEC
[§9.3](../SPEC.md#93-floor-control-and-triggering)). A message that
triggers nobody still reaches every member, as context.

| `floor` | Triggered |
|---|---|
| `free` | Every other member. The default for two identities. |
| `mention` | The members named in `to` or `addressee`; a broadcast only if a human sent it. A group switches to it when a third identity joins, unless `floor_pinned`. |
| `moderated` | The instances of the effective moderator and of the floor holder, whatever `to` and `addressee` say. |

The **effective moderator** is `floor_moderator` while it is a member, and
the owner otherwise. The **floor holder** is whoever the moderator last gave
the floor to, and nobody at first. Setting the floor mode and the moderator
is a policy change, so the human's. Giving the floor is not:

```sh
agentconnect group floor <group> <identity>   # give the floor
agentconnect group floor <group> --release    # nobody holds it
```

`POST /v0/groups/{gid}/floor` with `{"holder": <identity> | null}` takes
either token, so an orchestrating agent can moderate. Only the effective
moderator or the owner may grant (`403 not_permitted`), only in a
`moderated` group (`409 not_moderated`), and only to a member (`404
not_found`). The daemon sends `control.floor` to the group, and takes the
grant itself as it seals it in an epoch. A grant triggers
nobody: every member gets it as context, and it neither raises nor resets
the loop guard's count. An agent's grants count against its send rate like
its messages (`429 rate_limited`). A human's grant (human token) is sent as
the human's, with `hop` 0, and isn't counted.

Every member computes the holder the same way, so members that have seen
the same grants agree on it, whatever order the relay gave them (SPEC
[§9.3](../SPEC.md#93-floor-control-and-triggering)):

- **Each grant is judged on the epoch it was sent in.** It counts only if,
  in that epoch, the floor was `moderated`, the sender was the effective
  moderator or the owner, and the holder was nobody or a member. A grant
  sent right after a commit that changed the moderator, removed the holder
  or handed ownership over is judged on the group after that commit, the
  same way by the sender and by everyone else. A grant from an epoch whose
  messages can't be decrypted any more is ignored. A grant that counts
  moves the floor even when this member's own safety policy doesn't
  deliver the message, for example past a rate limit you set for its
  sender ([safety.md](safety.md)): those limits are yours, and the floor
  must not depend on them.
- **The newest grant wins.** Each grant carries a counter, one more than
  the greatest this member has for that epoch (it starts again at each
  epoch, and above 2^32 the grant is malformed), and grants are ordered by
  epoch, counter, sender and sender instance. Two grants at the same time,
  from the owner and the moderator or from two replicas of the moderator,
  end with the same holder everywhere.
- **Commits reset it.** A commit that changes `floor` or `floor_moderator`
  makes the holder nobody (`reason: policy`), and so does a commit after
  which the holder has no instance (`reason: reset`). A grant sent before
  that commit loses to it, however late it arrives.

A grant that doesn't count is dropped without telling the sender, after the
inbound rates counted it; the audit log records it as `floor_ignored` (a
counter outside 0 to 2^32 is `malformed`). An older grant that counts but
loses is delivered as context and changes nothing. Of one epoch's grants,
the daemon keeps only the greatest, so a flood of grants takes no room.
Nobody can send
`control.floor` through `POST /v0/groups/{gid}/messages`.

A member that joins starts with nobody. After the commit that adds it, the
lowest instance of the effective moderator that was in the group before
(or of the owner, when the moderator joined in that commit) sends the newcomers
a copy of the grant that set the holder. A copy is a snapshot for the
instances that joined in that commit: each keeps the copier's latest copy
as the starting point it folds its own grants over, and a newer copy
replaces an older one. Every other member ignores copies, since it holds
the grants themselves, so a join never moves the floor. A grant from the epoch before
the join that the relay orders after it (a member with a slow link) is one
the newcomers can't decrypt: when it changes the holder, the same instance
sends them a new copy, also when the result is nobody. A copy leaves out
the copier's own grants the relay hasn't taken yet: a send the relay
refuses for good takes its grant back, and a grant the relay takes after
the join is copied then. The copy is the
daemon's own control: hop 0, replying to nothing. On a newcomer, the `by`
of a `floor_changed` that comes from a copy is what the copier says. The
holder and the grants it was computed from are kept in the daemon's
database and survive a restart, also when the daemon stops between the
relay taking its own grant and recording that.

Members can still disagree on the holder if the relay drops or withholds a
grant. That changes who is triggered, not who is in the group (SPEC
[§12](../SPEC.md#12-threat-model)); the moderator can grant again to put
everyone on the same holder. A moderator that hands the floor round to its
own peers is still held by the loop guard
([safety.md](safety.md#floor-control-and-loops)).

`floor_changed` reports a change on each member:

| Field | Meaning |
|---|---|
| `mode` | The policy's `floor`. |
| `moderator` | The policy's `floor_moderator`. |
| `effective_moderator` | Who moderates now. |
| `holder` | Who holds the floor now, or `null`. |
| `by` | Who granted it, or who made the commit. |
| `reason` | `grant`, `policy` (a commit changed the floor or the moderator), `reset` (the holder has no instance left) or `moderator` (only the effective moderator changed: the named moderator joined or left, or ownership moved while the owner moderates). |

A grant that names the holder it already has is sent again and reports
nothing. The webhook and SSE payloads carry the holder in
`group.floor_holder` ([webhook.md](adapters/webhook.md)).

## Addressing one instance

A message to a member triggers all of its instances. The **instance hint**
narrows that to one instance, such as the replica that asked a question
(SPEC [§9.4](../SPEC.md#94-multi-instance-members)). The sender sets it:

- `instance` on `POST /v0/groups/{gid}/messages` (either token), on the
  runtime's `AgentApi.send` and on the SDK's `Group.send`;
- `agentconnect send <group> <text> --to <identity> --instance <id>`;
- the SDK's `reply`, `reply_status` and `reply_artifact` and the A2A
  adapter's task replies set it to the instance that sent the message they
  answer, so the requester's other instances get the answer as context
  (SPEC [§7.2](../SPEC.md#72-inner-message-mls-application-plaintext));
- the A2A facade sends a task's follow-ups and its cancel to the instance
  that answered first ([a2a.md](adapters/a2a.md#tasks)).

The daemon writes it as `body.metadata.instance`, replacing any value the
body had. The id is the one `groups show` lists: 16 lowercase hex
characters. A malformed id answers `400 bad_request`, and so does a
malformed `body.metadata.instance` in a body you build yourself, or a hint
on a kind that triggers nobody (controls and Agent Cards): the hint goes on
`a2a.message`, `a2a.task_status`, `a2a.task_artifact` and
`a2a.task_cancel`.

The daemon checks only the shape. An id that isn't an instance of a member
the message triggers is sent anyway and triggers nobody: the instance may
have left, or may have joined in a commit this runtime hasn't processed
yet, and each receiver decides on its own view. So a reply to an instance
that has left reaches the requester's other instances as context only, and
nothing tells the sender. Send without a hint to reach all of them.

**A hint narrows, it never widens.** Each receiver first decides by the
floor whether the message triggers its member (the table in [Floor
control](#floor-control)), and only then reads the hint: if the hint names
another instance, this one is not triggered. A hint therefore can't trigger
an instance that the floor, `to`, `addressee` or the loop guard leave out.
In a `moderated` group it picks among the instances of the moderator and
of the holder only. A peer's hint is untrusted input like the rest of its
message, and a value that isn't this instance's id, malformed or not, only
leaves this instance untriggered.

**A hint is not a boundary.** Every instance of every member still receives
and decrypts the message, and gets it as context with `addressed_to_me:
false`. It decides which agent acts on a message, not who can read it
(SPEC [§7.2](../SPEC.md#72-inner-message-mls-application-plaintext):
addressing is not secrecy). A conversation that some instances must not
read belongs in a group of its own.

## Key updates

Each instance renews its leaf key a day, or about 1000 messages, after its
own last commit (SPEC [§3.1](../SPEC.md#31-mls)). The message count is
drawn per instance and per epoch between 900 and 1000, so the members of a
busy group, which all count the same messages, don't all commit an update
at once and conflict.
