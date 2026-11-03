# Contributing to ClankMail

Issues and pull requests are welcome, from people and from AI coding agents. An agent working on
the repo should also read [AGENTS.md](AGENTS.md). Security problems go through
[SECURITY.md](SECURITY.md), not a public issue. The repo layout is in the README.

## Build and test

| Part | Needs | Command |
|---|---|---|
| Go reference (`go/clankmail`) | Go (version in `go.mod`) | `make conformance-go` |
| Vectors (`vectors/vectors.json`) | Go | `make vectors`, then `git diff --exit-code -- vectors/` |
| Python (`python/`) | Python 3 with `cryptography` | `make conformance-python` |
| TypeScript (`ts/`) | Node 24, no packages | `make conformance-ts`, and the typecheck `npx --yes -p typescript@7.0.2 tsc -p ts --noEmit` |
| Hub (`go/hub`, its own module) | Go 1.26 and a C toolchain for `-race` (one memory bound fails under `-race` on older Go: #13) | `make hub-test` |
| Hub, as an outside module sees it | Go, network | `make hub-consumer-check` |
| Hub guard mutation battery | Go, Python 3 | `make hub-mutate` (a few minutes) |
| End to end | Go, Node 24 | `make smoke-local` |
| README 30-second-start snippets | Go, Node 24, Python 3 with `cryptography`, port 8080 free | `make readme-snippets` |

`make conformance` runs all three implementations against the same vectors. CI
(`.github/workflows/ci.yml`) runs every row above. A new security guard in `go/hub` gets a
mutant in `go/hub/testdata/mutate.py` that its test must kill.

## Changing the protocol

`SPEC.md` is the authority and `vectors/vectors.json` is part of it (SPEC.md §12). **Change the
spec ⇒ update the vectors ⇒ update every implementation, in the same pull request:**

1. change the text of `SPEC.md`;
2. add or change vectors in `go/cmd/genvectors` and regenerate them with `make vectors`. Never
   edit `vectors.json` by hand, and never change a vector to match an implementation; `make
   vectors` must leave the file byte-identical unless the spec changed;
3. update **every** implementation (Go, Python, TypeScript) so `make conformance` passes, and the
   hub when the change touches hub behaviour.

Open a spec-change proposal issue first for anything beyond a wording fix, so the design can be
agreed before the work across all three implementations.

`ts/` was written by an author that saw only `SPEC.md` and the vectors (`ts/BRIEF.md`,
`ts/NOTES.md`). When the TypeScript side disagrees with the others, check whether the spec text
is ambiguous before patching it to match Go: finding that is what the independent implementation
is for.

## Pull requests

- Keep each pull request to one change, and say which spec sections it touches.
- A bug fix comes with a test that fails without the fix.
- This repo is public. Do not commit credentials, keys other than the fixed test seeds, private
  hostnames, IP addresses, internal registry or cluster names, local paths, or anything about
  other projects or clients, in code, comments, tests, logs or commit messages.

By contributing you agree that your contribution is licensed under Apache-2.0 (see `LICENSE`).
