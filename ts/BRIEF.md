# Task: an independent TypeScript implementation of ClankMail v1

You are writing a clean-room implementation of a signed-messaging protocol. Your ONLY inputs are
the two files in this directory:

- `SPEC.md` — the normative specification. It is the authority.
- `vectors/vectors.json` — the published conformance vectors (SPEC.md §12 describes them).

## Independence rules (the whole point of this task — do not break them)
- Read ONLY `SPEC.md` and `vectors/vectors.json`. Do not read, search for, or fetch any other
  implementation of this protocol: no web search, no web fetch, no GitHub, no package registry
  lookups, nothing outside this directory. Other implementations exist; the value of this one is
  that it was derived from the text alone. If the spec is ambiguous, decide from the text, and
  record the ambiguity (see deliverables) — never resolve it by looking elsewhere.
- Do not edit `SPEC.md` or `vectors/vectors.json`.
- Write only inside the `ts/` directory (and the completion marker named at the end).

## What to build
1. `ts/clankmail.ts` — a library implementing the parts of the spec the vectors exercise:
   the encodings (§2), the signed token wire form, payload and object id (§3), the ordered,
   fail-closed verification pipeline with its exact error codes (§4), the identity/message/channel
   object schemas as far as §4 validates them (§6, §7), derived ids (e.g. a channel id from its
   genesis object), and a signer that produces a token from a seed and payload bytes.
2. `ts/conformance.ts` — a runner: `node ts/conformance.ts <path-to-vectors.json>`. For EVERY
   vector it checks what SPEC.md §12 says a conforming implementation must do:
   - each `valid` vector: the pipeline returns the expected `id`, `t` and `from`;
   - each `valid` vector: the signer reproduces the token byte-for-byte from the named key's seed
     and `payload_b64` (the authoritative bytes — never re-encode `payload`);
   - each `derived` value is reproduced;
   - each `invalid` vector: the pipeline returns exactly the expected error code.
   It prints one line per failure (vector name, expected, got) and a final summary line exactly of
   the form `ts: <N> passed` when everything passes (N = number of vectors checked across
   valid+invalid), and exits 0 only if every check passed; any failure exits 1. A vector file it
   cannot parse, or a category it finds empty, must also exit non-zero — never report success
   over zero checks.

## Constraints
- Runtime: Node 24, run directly as `.ts` via Node's built-in type stripping. So use only
  erasable TypeScript syntax: no `enum`, no `namespace`, no constructor parameter properties,
  and use `import ... from "./clankmail.ts"` with the explicit `.ts` extension.
- Zero npm dependencies. Use `node:crypto` (Ed25519 via `crypto.createPrivateKey` from a raw
  seed wrapped in its PKCS#8 DER prefix, `crypto.sign(null, ...)`, `crypto.verify(null, ...)`,
  SHA-256 via `createHash`), `node:fs`, `Buffer`. No package.json needed.
- Pay close attention to the spec's rules on exact bytes, step ORDER in §4 (signature checked
  before parsing, etc.), duplicate JSON keys including escaped duplicates, invalid points and
  small-order/torsion components — if `node:crypto` verification semantics differ from what the
  spec requires (e.g. cofactored vs cofactorless verification, rejecting non-canonical encodings),
  you must implement the required checks yourself rather than trust the library default. Several
  vectors exist specifically to catch that.
- Also add `ts/tsconfig.json` such that `tsc -p ts --noEmit` typechecks cleanly (strict mode,
  `allowImportingTsExtensions`, `noEmit`, module/target suitable for Node 24, types for node may
  be unavailable — if so, declare the minimal ambient types you need in a `ts/node-shim.d.ts`
  rather than installing anything). If typechecking cannot be made to work without installing
  packages, say so in NOTES.md and skip it; the runner passing under `node` is the hard
  requirement.

## Acceptance (run these yourself, iterate until green)
```bash
node ts/conformance.ts vectors/vectors.json
```
Must end with `ts: 144 passed` and exit 0. Then prove the runner can fail: temporarily copy the
vectors file to `ts/neg-control.json`, change ONE expected error code in an `invalid` vector and
ONE expected `id` in a `valid` vector, run the runner on that copy, confirm it exits 1 naming both
vectors, then delete `ts/neg-control.json`.

## Deliverables
- `ts/clankmail.ts`, `ts/conformance.ts`, `ts/tsconfig.json` (+ shim if needed).
- `ts/NOTES.md`: how to run it; every place the spec was ambiguous or silent and what you chose;
  any vector you could only pass by a choice the text does not clearly mandate (name it); and an
  explicit statement of which files you read while writing this.
- Do not stop to ask questions — nobody can answer them. Work through to green.

## Completion marker — LAST step, after everything above is done and verified
Write `.opencode-dispatch/ts-impl.complete.md` containing the final output of
`node ts/conformance.ts vectors/vectors.json` and the negative-control result. Write nothing after it.
