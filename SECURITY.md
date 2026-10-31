# Security policy

AgentConnect is pre-alpha security software. Please report vulnerabilities
privately.

## Reporting

Use GitHub's **private vulnerability reporting** on this repository
("Security" tab → "Report a vulnerability"). Don't open public issues for
security problems.

Please include:

- The affected component (`core`, `relay`, `daemon`, `sdk`, or the protocol
  in `SPEC.md`).
- Steps to reproduce, or a proof of concept.
- The impact as you understand it, with reference to the threat model in
  `SPEC.md` §12.

What happens next is under [What to expect](#what-to-expect).

## What to expect

These are targets for a project that one maintainer runs, not guarantees.

| Step | Target |
|---|---|
| Acknowledge the report | 3 business days |
| Confirm the finding, or say why it isn't one, and rate its severity | 7 days after the acknowledgement |
| Release a fix for a High finding | 14 days after it is confirmed |
| Release a fix for a Medium finding | 30 days after it is confirmed |
| Release a fix for a Low finding | the next preview, or 90 days after it is confirmed if that comes first |

Severity follows the scale in the
[v0 security review](docs/security-review-v0.md#method): High breaks the
canonical claim or a threat-model mitigation, Medium weakens a mitigation or
needs a local attacker, and Low is a gap in defence in depth. If a fix will miss its
target, the report thread says so and gives the reason and a new date.

Disclosure is coordinated with the reporter. The advisory goes public when
the fix is released, or 90 days after the report if a fix isn't ready by
then, whichever comes first; the reporter and the maintainer can agree on a
different date. The advisory credits the reporter unless they ask us not to.
There is no bounty.

## How fixes ship

- A fix lands through the normal pull request flow in
  [CONTRIBUTING.md](CONTRIBUTING.md), with a regression test. For an
  undisclosed finding, the work happens in the private fork that GitHub
  creates for the advisory, and the pull request opens when the fix is ready
  to release.
- A crash in the nightly fuzz run is handled as an undisclosed finding: the
  job logs only the target and the input's SHA-256, and a maintainer
  reproduces it locally.
- The fix ships in a new preview release. Its `CHANGELOG.md` entry sits under
  `### Security` and names the finding, and the release notes list it under
  "What was fixed", with the findings that remain open.
- After the release is out, we publish a GitHub security advisory for the
  repository, with the affected and fixed versions and a CVE or GHSA id when
  one is assigned.
- Older previews don't get patches. Upgrade to the fixed release, and read the
  release notes for any step an upgrade needs.

## Verifying a release

Every release file is signed with Sigstore and carries a SLSA provenance
attestation from the release workflow, and so do both container images.

- `just release-verify X.Y.Z` downloads the GitHub Release `vX.Y.Z`, runs
  `gh attestation verify` on every file and checks each file's cosign
  bundle (`<file>.sigstore.json`), then does both for the relay and
  directory images at that version. A signature counts only if the release
  workflow made it for tag `vX.Y.Z`. Pass the version without the `v`, for
  example `0.1.0a3`. It needs `gh` and `cosign`, and checks against
  `mbocevski/agent-connect` whatever your clone's default repository is
  (`AC_RELEASE_REPO` names another).
- To check one file's signature:
  `cosign verify-blob --bundle <file>.sigstore.json --certificate-identity https://github.com/mbocevski/agent-connect/.github/workflows/release.yml@refs/tags/vX.Y.Z --certificate-oidc-issuer https://token.actions.githubusercontent.com <file>`.
- To check one file: `gh attestation verify <file> --repo mbocevski/agent-connect`.
- To check an image by digest, take the digest from the release notes:
  `gh attestation verify oci://ghcr.io/mbocevski/agentconnect-relay@sha256:<digest> --repo mbocevski/agent-connect`
  (and `agentconnect-directory` for the other image).
- The Python packages reach PyPI through trusted publishing from the release
  workflow, with no stored token, and PyPI attaches its own attestations.
- Release tags are signed: `git tag -v vX.Y.Z`.

## Scope

In scope:

- Protocol design flaws.
- Cryptographic misuse.
- Relay behaviour that leaks plaintext or secrets.
- Membership or policy bypass.
- SAS weaknesses.
- Daemon local-API exposure.
- Supply-chain issues in our build and release.

Out of scope: anything `SPEC.md` §12 lists as a non-goal. That includes
metadata visible to the relay, availability, compromised endpoints, and model
providers seeing plaintext.

## Reviews

The internal v0 security review, with its findings, the threat-model
mapping and the recommended external review, is in
[docs/security-review-v0.md](docs/security-review-v0.md).

## Dependency and image scanning

- Dependabot updates Cargo, Python, GitHub Actions, pre-commit hooks, the Rust
  toolchain and the base images in the Dockerfiles.
- `cargo deny` checks advisories and licences; the nightly workflow also runs
  `pip-audit`.
- [Trivy](https://trivy.dev/) scans the relay and directory container images
  (the base image's OS packages and the bundled binaries). The CI `image` job
  scans the amd64 images on every PR and the nightly `image-scan` job scans
  them again, to catch new CVEs against unchanged images. Both upload SARIF to
  code scanning (categories `image-relay` and `image-directory`) with HIGH
  and CRITICAL findings only, fixed or not, and fail on those that have a fix.
  The full all-severity report is a workflow artifact (`trivy-image-relay`,
  `trivy-image-directory`, kept 30 days). The image scan is not part of the required `ci-ok`
  check, so a vulnerability database outage or a newly published CVE doesn't
  block unrelated merges.
- Both images run on `gcr.io/distroless/base-nossl-debian12:nonroot`, pinned
  by tag and digest so Dependabot opens a PR when distroless rebuilds. The
  base has glibc and the CA bundle but no `libssl3`. The binaries need none:
  the directory uses rustls, and the relay's SQLCipher links a vendored,
  static OpenSSL. This cleared CVE-2026-84782 (`libssl3`, no Debian fix) by
  removing the package rather than ignoring it. `libgcc_s.so.1`, which the
  Rust binaries need (static libgcc doesn't remove that dependency), is
  copied from the build stage, under its multiarch directory, because the
  base lacks it. It comes from the pinned `rust:1.99.1-bookworm` builder and
  is updated with it. It isn't a dpkg package in the final image, so Trivy
  doesn't track its CVEs there.
  Don't switch back to `cc` or `base` without checking for `libssl3`.
- Accepted CVEs go in `.trivyignore.yaml` with a statement and an
  `expired_at` review date; Trivy stops ignoring an entry on that date.
- When any nightly job fails, the workflow opens (or comments on) the issue
  titled "nightly: failing jobs" and closes it on the next green run, because
  scheduled-workflow failures only email the last editor of the cron.

## Supported versions

AgentConnect is in a research preview. Only the latest preview release, and
`main`, get security fixes. Check the
[releases page](https://github.com/mbocevski/agent-connect/releases) for the
latest one. Once there is a stable release, this section will name the lines
that still get fixes.

## Handling known vulnerabilities

The rules below keep a known advisory from sitting unnoticed in the tree.

- **Fix first.** An advisory against a dependency or a base image with a fix
  available gets a small pull request that updates it, on the targets in the
  table under [What to expect](#what-to-expect). Dependabot opens many of
  them; the nightly audit finds the rest.
- **A temporary patch** is for a fix that exists upstream but isn't released.
  Patch the crate in `[patch.crates-io]` of the root `Cargo.toml`, at an exact
  full commit SHA, never a branch or tag. `scripts/check_cargo_patch.py`
  enforces the SHA and the same table in every workspace, and `deny.toml`
  allows only the upstream repository as a git source. Say in a comment what
  the patch is for and when it goes.
- **An ignore** is for an advisory that doesn't apply or has no fix. Each
  entry in `deny.toml` carries a `reason`. Each entry in `.trivyignore.yaml`
  carries a `statement` and an `expired_at` date, and Trivy stops ignoring it
  on that date, so the scan fails until someone decides again.
- **Removal.** A patch goes when the nightly `check_cargo_patch.py upstream`
  step reports a release that carries the fix, and the nightly failure issue
  says so. An ignore goes when the advisory is fixed or withdrawn, or when
  its `expired_at` date comes and the reason no longer holds.
- **Release blockers.** The nightly run, audit included, has to be green
  before a release. A confirmed finding that the release gate names, or an
  advisory with a fix available, blocks the preview until it is fixed. A
  finding that remains open when we release is listed in the release notes
  with a link to its entry in the security review.
