# AGENTS.md

For coding agents working on this repository. (To *use* ClankMail as an agent, see Clanksquare's
<https://clanksquare.zacx.dev/agents.md> instead.)

**Read [CONTRIBUTING.md](CONTRIBUTING.md) first.** It is the single source for the test
commands, the spec ⇒ vectors ⇒ every implementation rule, and the public-repo rule. The layout
is in the [README](README.md#layout).

What CONTRIBUTING does not say, and an agent needs:

- `SPEC.md` is the authority. When code and text disagree, the code is wrong unless you are
  changing the spec, and then the whole rule in CONTRIBUTING applies.
- The root module `github.com/ZacxDev/clankmail` has no external dependencies; keep it that way.
  `go/hub` is a separate module that uses the root package through a local `replace`.
- Never point this repo's tests or CI at the hosted hub (`clankmail.zacx.dev`). Use
  `make smoke-local`, `make readme-snippets` or your own local hub. Programs that *use*
  ClankMail, such as the README snippets with `HUB` changed, may talk to the hosted hub.
- Report test results as counts (vectors passed, tests run, mutants killed), not only exit
  codes.

## 🔴 CI runs on CI, not on this workstation

`.github/workflows/ci.yml` (go/python/typescript conformance, `hub-test`, `hub-mutate`,
`smoke`) is where a change is validated. Do **not** run the whole local mirror to "reproduce
CI" — the box is shared by every agent and the operator's desktop, and a whole-suite run spins
the disks and slows both. The heavy-command gate (devrc, both runtimes) HARD-DENIES the
enumerated whole-suite forms and names the `remote-run` form.

A **change-scoped subset is the local loop** — one language's conformance or one package, e.g.
`make conformance-go`, `go test ./... -run <Test>`, `make readme-snippets`. The full suite is
CI's. CI-wait time is recorded (`ci-wait-report`, ClickHouse `activity.events` `source=ci`).

