# Contributing to ClankMail

Issues and pull requests are welcome, from people and from AI coding agents. An agent working on
the repo should read [AGENTS.md](AGENTS.md) first. Security problems go through
[SECURITY.md](SECURITY.md), not a public issue.

## Build and test

| Part | Needs | Command |
|---|---|---|
| Go reference (`go/clankmail`) | Go (version in `go.mod`) | `make conformance-go` |
| Vectors (`vectors/vectors.json`) | Go | `make vectors`, then `git diff --exit-code -- vectors/` |
| Python (`python/`) | Python 3 with `cryptography` | `make conformance-python` |
| TypeScript (`ts/`) | Node 24, no packages | `make conformance-ts`; typecheck with `npx -p typescript tsc -p ts --noEmit` |
| Hub (`go/hub`, its own module) | Go, a C toolchain for `-race` | `make hub-test` |
| Hub, as an outside module sees it | Go, network | `make hub-consumer-check` |
| End to end | Go, Node 24 | `make smoke-local` |
| Hub guard mutation battery | Go, Python 3 | `make hub-mutate` (a few minutes) |

`make conformance` runs all three implementations against the same vectors. CI
(`.github/workflows/ci.yml`) runs every row above. A new security guard in `go/hub` gets a
mutant in `go/hub/testdata/mutate.py` that its test must kill.

## Changing the protocol

`SPEC.md` is the authority and `vectors/vectors.json` is part of it (SPEC.md §12). A pull request
that changes what the spec requires must, in the same pull request:

1. change the text of `SPEC.md`;
2. add or change vectors in `go/cmd/genvectors` and regenerate them with `make vectors` (never
   edit `vectors.json` by hand);
3. update **every** implementation (Go, Python, TypeScript) so `make conformance` passes, and the
   hub when the change touches hub behaviour.

Open a spec-change proposal issue first for anything beyond a wording fix, so the design can be
agreed before the work across all three implementations.

`ts/` was written by an author that saw only `SPEC.md` and the vectors (`ts/BRIEF.md`,
`ts/NOTES.md`). When the TypeScript side fails on a spec change, treat that as a possible gap in
the spec text before patching the code.

## Pull requests

- Keep each pull request to one change, and say which spec sections it touches.
- A bug fix comes with a test that fails without the fix.
- This repo is public: no credentials, private hostnames or addresses, or personal data in code,
  tests, logs or commit messages.

By contributing you agree that your contribution is licensed under Apache-2.0 (see `LICENSE`).
