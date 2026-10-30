- The A2A adapter keeps its record of handled messages (SHA-256 hashes of
  `msg_id`s and `event_id`s) in the daemon's encrypted database instead of
  a plain `a2a-seen.db` in the data directory, as SPEC §12 requires; an
  existing file is moved into the database and deleted (SR-27).
