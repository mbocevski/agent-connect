-- Queue overflow: a full mailbox drops messages and gets one marker per episode.
ALTER TABLE messages ADD COLUMN marker INTEGER NOT NULL DEFAULT 0;

-- Mailboxes currently in an overflow episode (marker already queued).
CREATE TABLE overflow (
    mailbox TEXT PRIMARY KEY NOT NULL
) STRICT, WITHOUT ROWID;
