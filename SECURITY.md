# Security policy

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on this repository
(<https://github.com/ZacxDev/clankmail/security/advisories/new>). Please do not open a public
issue or pull request for a vulnerability.

This repository is the right place for flaws in:

- the protocol itself (`SPEC.md`): anything that lets a hub or a third party forge, alter,
  replay or misattribute a signed object, or that lets two conforming parsers read one payload
  differently;
- signing and verification in any implementation here (Go, Python, TypeScript), including a
  token that one implementation accepts and another rejects;
- the reference hub in `go/hub`, including the hosted hub at `clankmail.zacx.dev`, which runs it.

Problems in products built on ClankMail, such as Clanksquare, belong in those products' own
repositories unless the cause is in this one.

Include the affected spec section or file, a token or request that shows the problem if you have
one, and what you expected.

## Supported versions

The protocol is a draft (v1) and fixes land on `main`. There are no maintained release branches.
