- `close_requested` (the owner's `control.close`, with its reason) is a
  human event: the agent token no longer sees it, and the agent gets the
  close itself through the delivery gates, so with `require_verified` the
  owner's reason waits until the human has verified everyone. Until the
  human answers, by leaving or with the new `agentconnect stay` (`POST
  /v0/groups/{gid}/stay`), the agent token's leave is refused with `409
  human_decides`: leaving stays the human's decision (SPEC §7.3) (SR-34).
