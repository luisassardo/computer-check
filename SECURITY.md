# Security Policy

ComputerCheck is built for high-risk users — journalists, sources, and human-rights
defenders — who use it to audit their own devices. We take vulnerabilities seriously
and welcome responsible disclosure.

## Reporting a vulnerability

Email **security@c-lab.tools** with:

- a description of the issue and its impact,
- steps to reproduce (a proof-of-concept if possible),
- the affected version / commit and platform.

Please report **privately** — do not open a public issue, pull request, or social
post for security problems. If you need to encrypt your report, ask for our PGP key
at the same address.

We aim to acknowledge reports within **72 hours** and to share a remediation timeline
after triage. There is no paid bug-bounty program; we credit reporters in the release
notes unless you prefer to stay anonymous.

## Scope

In scope: this repository's code and the artifacts it produces (the desktop app and
installers, and the scan engine). Out of scope: third-party dependencies (please
report those upstream), and social-engineering or physical attacks against maintainers.

Of particular interest: anything that breaks the read-only guarantee, exfiltrates scan
data off the device without consent, or weakens the encrypted local history / age export.

## Safe harbor

We will not pursue legal action against good-faith security research that respects user
privacy, avoids data destruction, and gives us reasonable time to fix the issue before
public disclosure.

## Languages

You can write to us in English, Spanish, or German.
