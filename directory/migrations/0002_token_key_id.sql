-- The embedded token's key_id (base64url), so listings under a key the
-- directory no longer pins are left out by the queries themselves (SR-24).
-- Empty for rows stored before this column; maintenance fills it in.
ALTER TABLE listings ADD COLUMN token_key_id TEXT NOT NULL DEFAULT '';
