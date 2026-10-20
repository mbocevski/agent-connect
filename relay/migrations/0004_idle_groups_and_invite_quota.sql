-- Idle groups (SPEC §8.3): when the group last had an accepted send, so the
-- purge can delete a group nobody has used for the idle period. 0 means
-- "not since it was created" (the sweep also checks `created_at`).
ALTER TABLE groups ADD COLUMN active_at INTEGER NOT NULL DEFAULT 0;  -- unix milliseconds
-- Earlier versions recorded no activity: count every existing group as used
-- at the upgrade, so none is deleted for idleness it may not have had.
UPDATE groups SET active_at = CAST(strftime('%s', 'now') AS INTEGER) * 1000;
CREATE INDEX groups_active ON groups (active_at);

-- Who registered a group, so a repeated `group.create` from the same
-- mailbox (its reply was lost) is answered `accepted`. NULL for groups from
-- before this column.
ALTER TABLE groups ADD COLUMN created_by TEXT;

-- The per-mailbox quota on open invites counts by inviter.
CREATE INDEX invites_inviter ON invites (inviter_mailbox, expires_at);
