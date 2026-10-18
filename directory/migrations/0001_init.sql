-- Directory schema (ADR-006 Decision 4). Nothing about readers.

CREATE TABLE listings (
    name TEXT PRIMARY KEY,
    identity TEXT NOT NULL,
    seq BIGINT NOT NULL,
    token_id TEXT NOT NULL,
    owner_domain TEXT,
    -- The owner-check history the core's owner_state reads: the latest
    -- fetch, the last vouching fetch and the latest negative result.
    owner_latest TEXT,
    owner_checked_at BIGINT,
    owner_verified_at BIGINT,
    owner_negative TEXT,
    owner_negative_at BIGINT,
    door_expires_at BIGINT,
    token_expires_at BIGINT NOT NULL,
    published_at BIGINT NOT NULL,
    key_changed_at BIGINT,
    bytes BYTEA NOT NULL,
    sha256 TEXT NOT NULL,
    search_title TEXT NOT NULL,
    search_skills TEXT NOT NULL,
    search_description TEXT NOT NULL,
    skill_keys TEXT [] NOT NULL,
    search_vec TSVECTOR GENERATED ALWAYS AS (
        setweight(to_tsvector('english'::regconfig, search_title), 'A')
        || setweight(to_tsvector('english'::regconfig, search_skills), 'B')
        || setweight(to_tsvector('english'::regconfig, search_description), 'C')
    ) STORED
);

CREATE INDEX listings_search_vec ON listings USING gin (search_vec);
CREATE INDEX listings_skill_keys ON listings USING gin (skill_keys);
CREATE INDEX listings_identity ON listings (identity);
CREATE INDEX listings_token_id ON listings (token_id);
CREATE INDEX listings_owner_checked_at ON listings (owner_checked_at);

-- The highest withdrawn seq per (name, identity). Kept as long as the name
-- (SPEC 13.2.2): never purged.
CREATE TABLE tombstones (
    name TEXT NOT NULL,
    identity TEXT NOT NULL,
    seq BIGINT NOT NULL,
    kind TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (name, identity)
);

-- (name, identity) pairs an owner domain revoked, and when the directory saw
-- it. Such an identity lists the name again only under a later token.
CREATE TABLE owner_revocations (
    name TEXT NOT NULL,
    identity TEXT NOT NULL,
    revoked_at BIGINT NOT NULL,
    PRIMARY KEY (name, identity)
);

-- Signed withdrawals and revocations, in order, kept 30 days.
CREATE TABLE feed (
    pos BIGSERIAL PRIMARY KEY,
    kind TEXT NOT NULL,
    entry TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

-- Per name, the newest token issued_at ever accepted and its identity (the
-- core's NameRecord high-water mark). Kept for good, so a name can't go back
-- to a key it was rotated away from.
CREATE TABLE name_marks (
    name TEXT PRIMARY KEY,
    issued_at BIGINT NOT NULL,
    identity TEXT NOT NULL
);

CREATE TABLE revoked_tokens (
    token_id TEXT PRIMARY KEY,
    revoked_at BIGINT NOT NULL
);
