- With the agent token, `GET /v0/status` (and the MCP status tool) no
  longer counts a group hidden from the agent, an approved knock's group
  before the knocker is in, in `groups`, `out_of_sync`, the queue sizes
  or the pending joins, and every route that takes a group, event streams
  included, answers such a group exactly as one that doesn't exist
  (`404 not_found`, "no such active group") (SR-32).
