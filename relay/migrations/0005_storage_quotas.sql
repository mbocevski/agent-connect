-- Storage hardening (SPEC §8.3, "Storage" and "Limits").
--
-- Each payload is stored once and every recipient's queue row points at
-- it. Queue rows carry the part of the queue they are charged to (bucket):
-- 0 for group traffic of a group the recipient has sent in, 1 for
-- everything from non-members (Welcomes, join requests, knocks, and the
-- traffic of a group the recipient hasn't sent in yet), and the group they
-- belong to ('' for join requests and knocks). Byte counters per mailbox
-- part, per (mailbox, part, group), per sender and per (sender, group) are
-- kept in the same transactions as the rows they count.
--
-- The migration copies every queued envelope once (payloads, then the new
-- queue) before it drops the old table, in one transaction: it needs about
-- the size of the queued messages in free space, and the relay serves
-- nothing until it is done.

CREATE TABLE payloads (
    id INTEGER PRIMARY KEY,
    sender TEXT NOT NULL,               -- the charged sender; '' is uncharged
    group_id TEXT NOT NULL,             -- '' for join requests and knocks
    env TEXT NOT NULL,
    size INTEGER NOT NULL
) STRICT;

-- The old rows keep their seq, and each becomes its own payload. Knocks and
-- markers are charged to nobody, as new ones are.
INSERT INTO payloads (id, sender, group_id, env, size)
SELECT
    seq,
    CASE
        WHEN marker = 0 AND COALESCE(json_extract(env, '$.kind'), '') != 'knock'
            THEN COALESCE(json_extract(env, '$.sender'), '')
        ELSE ''
    END,
    COALESCE(json_extract(env, '$.group_id'), ''),
    env,
    size
FROM messages;

CREATE TABLE queue (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox TEXT NOT NULL,
    msg_id TEXT NOT NULL,
    payload INTEGER NOT NULL REFERENCES payloads (id),
    group_id TEXT NOT NULL,
    size INTEGER NOT NULL,
    bucket INTEGER NOT NULL,
    marker INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL         -- unix milliseconds
) STRICT;

INSERT INTO queue (seq, mailbox, msg_id, payload, group_id, size, bucket, marker, expires_at)
SELECT
    seq,
    mailbox,
    msg_id,
    seq,
    COALESCE(json_extract(env, '$.group_id'), ''),
    size,
    CASE
        WHEN marker = 0
            AND json_extract(env, '$.kind') IN ('welcome_wrapped', 'join_request', 'knock')
            THEN 1
        ELSE 0
    END,
    marker,
    expires_at
FROM messages;

-- Go on handing out higher seq numbers than the old table did.
DELETE FROM sqlite_sequence WHERE name = 'queue';
INSERT INTO sqlite_sequence (name, seq)
SELECT 'queue', seq FROM sqlite_sequence WHERE name = 'messages';

-- Overflow episodes are per (mailbox, part, group), so every group that
-- loses messages gets its own marker. An old episode carries on for the
-- group its marker names.
CREATE TABLE overflow_groups (
    mailbox TEXT NOT NULL,
    bucket INTEGER NOT NULL,
    group_id TEXT NOT NULL,
    PRIMARY KEY (mailbox, bucket, group_id)
) STRICT, WITHOUT ROWID;
INSERT OR IGNORE INTO overflow_groups (mailbox, bucket, group_id)
SELECT mailbox, 0, COALESCE(json_extract(env, '$.group_id'), '')
FROM messages
WHERE marker = 1 AND mailbox IN (SELECT mailbox FROM overflow);
DROP TABLE overflow;
ALTER TABLE overflow_groups RENAME TO overflow;

DROP TABLE messages;
ALTER TABLE queue RENAME TO messages;
CREATE INDEX messages_mailbox ON messages (mailbox, seq);
CREATE INDEX messages_ack ON messages (mailbox, msg_id);
CREATE INDEX messages_expiry ON messages (expires_at);
CREATE INDEX messages_payload ON messages (payload);
CREATE INDEX messages_group ON messages (group_id, mailbox);

CREATE TABLE mailbox_usage (
    mailbox TEXT NOT NULL,
    bucket INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    PRIMARY KEY (mailbox, bucket)
) STRICT, WITHOUT ROWID;

INSERT INTO mailbox_usage (mailbox, bucket, bytes)
SELECT mailbox, bucket, SUM(size) FROM messages GROUP BY mailbox, bucket;

CREATE TABLE group_usage (
    mailbox TEXT NOT NULL,
    bucket INTEGER NOT NULL,
    group_id TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    PRIMARY KEY (mailbox, bucket, group_id)
) STRICT, WITHOUT ROWID;

INSERT INTO group_usage (mailbox, bucket, group_id, bytes)
SELECT mailbox, bucket, group_id, SUM(size) FROM messages GROUP BY mailbox, bucket, group_id;

CREATE TABLE sender_usage (
    sender TEXT PRIMARY KEY NOT NULL,
    bytes INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

INSERT INTO sender_usage (sender, bytes)
SELECT sender, SUM(size) FROM payloads WHERE sender != '' GROUP BY sender;

CREATE TABLE sender_group_usage (
    sender TEXT NOT NULL,
    group_id TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    PRIMARY KEY (sender, group_id)
) STRICT, WITHOUT ROWID;

INSERT INTO sender_group_usage (sender, group_id, bytes)
SELECT sender, group_id, SUM(size) FROM payloads WHERE sender != '' GROUP BY sender, group_id;

-- A member counts as one once it has sent in the group. Existing members
-- are treated as confirmed: there is no record of what they sent.
ALTER TABLE group_members ADD COLUMN confirmed INTEGER NOT NULL DEFAULT 0;
UPDATE group_members SET confirmed = 1;

-- Mailboxes a commit added that are still waiting for their Welcome, and
-- the member whose commit added them: only that member may send it, once.
CREATE TABLE welcome_due (
    group_id TEXT NOT NULL REFERENCES groups (group_id) ON DELETE CASCADE,
    mailbox TEXT NOT NULL,
    added_by TEXT NOT NULL,
    expires_at INTEGER NOT NULL,        -- unix milliseconds
    PRIMARY KEY (group_id, mailbox)
) STRICT, WITHOUT ROWID;
CREATE INDEX welcome_due_expiry ON welcome_due (expires_at);
