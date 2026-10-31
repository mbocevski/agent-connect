- `close_requested` (the owner's `control.close`, with its reason) is a
  human event: the agent token no longer sees it. The agent gets the close
  itself through the delivery gates, so with `require_verified` the
  owner's reason waits until the human has verified everyone, and leaving
  stays the human's decision (SPEC §7.3) (SR-34).
