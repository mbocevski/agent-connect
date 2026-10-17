-- Doors (ADR-006): a public door id mapped to its owner's mailbox, and
-- nothing else. Rows go when the door expires; a closed door keeps its row
-- until then so its id can't be registered again.
CREATE TABLE doors (
    door_id TEXT PRIMARY KEY NOT NULL,
    owner_mailbox TEXT NOT NULL,
    expires_at INTEGER NOT NULL,        -- unix seconds
    closed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL         -- unix milliseconds
) STRICT;
CREATE INDEX doors_owner ON doors (owner_mailbox, expires_at);
CREATE INDEX doors_expiry ON doors (expires_at);
