- Changelog entries are fragments: a pull request adds one file,
  `changelog.d/<slug>.<section>.md`, instead of editing `[Unreleased]` in
  `CHANGELOG.md`, so pull requests no longer conflict over the changelog.
  `just changelog-cut` assembles the fragments after the entries already
  under `[Unreleased]` and deletes them, and `just changelog-preview` prints
  the result. The `changelog` check and the README rule of the docs check
  read fragments. See `changelog.d/README.md`.
