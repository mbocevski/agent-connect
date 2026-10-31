- A JoinRequest now carries a signature under its KeyPackage's key, because the
  MAC proves only that the sender holds the link. An inviter drops a request
  whose signature fails, and `policy.auto_approve` no longer approves a request
  without one: it waits for you, marked "possession not proven" in
  `approvals list`. Requests from older clients take that path until they
  upgrade.
