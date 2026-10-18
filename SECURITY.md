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

We aim to acknowledge reports within 3 business days.

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

## Dependency and image scanning

- Dependabot updates Cargo, Python, GitHub Actions, pre-commit hooks, the Rust
  toolchain and the base images in the Dockerfiles.
- `cargo deny` checks advisories and licences; the nightly workflow also runs
  `pip-audit`.
- [Trivy](https://trivy.dev/) scans the relay and directory container images
  (the base image's OS packages and the bundled binaries). The CI `image` job
  scans the amd64 images on every PR and the nightly `image-scan` job scans
  them again, to catch new CVEs against unchanged images. Both upload SARIF to
  code scanning (categories `image-relay` and `image-directory`) and fail on
  HIGH and CRITICAL vulnerabilities that have a fix. Unfixed ones are reported
  in code scanning only. The image scan is not part of the required `ci-ok`
  check, so a vulnerability database outage or a newly published CVE doesn't
  block unrelated merges.
- Accepted CVEs go in `.trivyignore.yaml` with a statement and an
  `expired_at` review date; Trivy stops ignoring an entry on that date.
- When any nightly job fails, the workflow opens (or comments on) the issue
  titled "nightly: failing jobs" and closes it on the next green run, because
  scheduled-workflow failures only email the last editor of the cron.

## Supported versions

Only the latest commit on `main` is supported until the first release.
