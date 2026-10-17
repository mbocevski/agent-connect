-- AgentConnect relay schema v1. Public metadata and ciphertext only.
CREATE TABLE invites (
    invite_id TEXT PRIMARY KEY NOT NULL,
    group_name TEXT NOT NULL,
    inviter_name TEXT NOT NULL,
    purpose TEXT NOT NULL,
    expires_at INTEGER NOT NULL,        -- unix seconds
    max_uses INTEGER NOT NULL,
    uses_left INTEGER NOT NULL,
    member_count INTEGER,
    inviter_mailbox TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL         -- unix milliseconds
) STRICT;

CREATE TABLE groups (
    group_id TEXT PRIMARY KEY NOT NULL,
    epoch INTEGER NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE group_members (
    group_id TEXT NOT NULL REFERENCES groups (group_id) ON DELETE CASCADE,
    mailbox TEXT NOT NULL,
    PRIMARY KEY (group_id, mailbox)
) STRICT;

CREATE TABLE messages (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox TEXT NOT NULL,
    msg_id TEXT NOT NULL,
    env TEXT NOT NULL,
    size INTEGER NOT NULL,
    expires_at INTEGER NOT NULL         -- unix milliseconds
) STRICT;
CREATE INDEX messages_mailbox ON messages (mailbox, seq);
CREATE INDEX messages_expiry ON messages (expires_at);

-- Idempotency: a repeated (sender, msg_id) is accepted but not re-delivered.
CREATE TABLE seen (
    sender TEXT NOT NULL,
    msg_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,        -- unix milliseconds
    PRIMARY KEY (sender, msg_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX seen_expiry ON seen (expires_at);
