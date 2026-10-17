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

## Supported versions

Only the latest commit on `main` is supported until the first release.
