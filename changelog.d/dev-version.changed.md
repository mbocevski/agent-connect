- A build from a checkout carries the next pre-release's development version
  (`0.1.0a5.dev0`) between releases, so a locally built wheel never shares a
  version with a published one and an installer can't mix them: the exact pin
  between the packages finds no match instead of pulling a published
  `agentconnect-core`. The relay's and the directory's `build_info` metric
  reports it as `0.1.0a5.dev0`. The release workflow refuses a development
  version, and `just set-version` and `just next-dev` move the version
  (CONTRIBUTING.md, "Releases").
