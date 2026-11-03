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
