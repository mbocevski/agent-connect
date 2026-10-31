# Changelog fragments

Each pull request with a user-visible change adds one file here, so two PRs
never edit the same lines of `CHANGELOG.md` and never conflict over it.
`just changelog-cut X.Y.Z` moves every fragment into the new release section
of `CHANGELOG.md` and deletes it. `just changelog-preview` prints the
`[Unreleased]` section as the cut would assemble it.

## Naming

`<slug>.<section>.md`

- `<slug>` is lowercase letters, digits and hyphens: a short name for the
  change, such as `facade-socket` or `directory-timeouts`. Fragments sort by
  slug within a section, so the slug is the order of the entries in the
  release.
- `<section>` is one of `added`, `changed`, `deprecated`, `removed`, `fixed`
  or `security`, the headings of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

A security fix goes under `security`, whatever else it also is. A new
feature goes under `added`: `scripts/check_docs.py` then asks for a README
Status change when the PR touches a component.

## Content

One Markdown bullet. It may wrap; indent the lines that continue it by two
spaces. No blank lines, no headings, no second bullet at the top level.

```markdown
- The directory limits slow and many connections, with the relay's
  defaults: a request head has to arrive within
  `AC_DIRECTORY_HEADER_TIMEOUT_SECS`.
```

Write what changed for a user and what they have to do about it, in the
voice of the rest of `CHANGELOG.md`. A preview that needs a data reset or a
new relay says so at the top of its release notes, not in a fragment.

## Checks

`scripts/check-changelog.sh` (pre-push hook and the CI `changelog` job)
fails a branch with a user-facing commit and no new fragment, and fails on
any malformed file in this directory. The `skip-changelog` label skips the
first check, for a change that isn't user-facing.
