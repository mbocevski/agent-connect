- With the agent token, `GET /v0/status` (and the MCP status tool) no
  longer counts a group hidden from the agent, an approved knock's group
  before the knocker is in, in `groups`, `out_of_sync`, the queue sizes
  or the pending joins, and an event stream for such a group is `404
  not_found` as for one that doesn't exist (SR-32).
