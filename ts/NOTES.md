# ClankMail v1 TypeScript Implementation — Notes

## How to run

```bash
# Run conformance tests (required: Node 24+)
node ts/conformance.ts vectors/vectors.json   # or: make conformance-ts

# TypeCheck (requires tsc on PATH)
tsc -p ts --noEmit
```

Expected output: `ts: <N> passed` (N = valid + invalid vectors) with exit 0.

## Files read while writing this

- `SPEC.md` — the normative ClankMail v1 specification
- `vectors/vectors.json` — the published conformance vectors (part of SPEC.md §12)

No other files, no web search, no GitHub, no package registry lookups.

## Ambiguities and choices made

### 1. Ed25519 verification semantics

The spec requires cofactorless verification (`[S]B = R + [k]A`) and mandates rejecting
signatures with non-reduced S (§3.1). Node.js's `crypto.verify` with Ed25519 passes all the
vectors, including `sig-torsion-in-r` (which a cofactored verifier would accept) and
`sig-s-not-reduced` (which checks S < L). This suggests Node 24's OpenSSL-backed
implementation uses cofactorless verification and checks scalar range.

If a future Node version changes this, the implementation would need to add manual
cofactorless verification via point arithmetic on Curve25519.

### 2. JSON integer validation

The spec says "Every number MUST be an integer in [0, 2^53 − 1] written without a sign,
fraction, exponent or leading zero." The custom JSON parser validates this by:
- Rejecting `-` (minus) in any numeric position (covers negative numbers and -0)
- Rejecting `.` and `e`/`E`
- Rejecting leading zeros (any digit following a leading `0`)
- Checking the parsed value is in [0, 2^53−1]

The spec also says `-0` is not allowed — it is caught by the sign check.

### 3. Duplicate JSON keys with \u escapes

The JSON parser normalizes keys during parsing (the `\uXXXX` sequences are resolved
to their actual characters) and detects duplicates by comparing the normalized form.
This catches `"body"` vs `"b\u006fdy"` (`json-duplicate-key-escaped`).

### 4. Message `to` field: channel vs key detection

Per §7.2, `to` is either exactly one `c_` id or 1–32 unique `k_` ids. The vectors include
`msg-channel` (one `c_` id), `msg-multi-recipient` (multiple `k_` ids), and several
invalid forms. Detection is by prefix (`c_` vs `k_`), and mixing is rejected.

The spec says "`to` is always a JSON array, even for one recipient" — this is enforced.

### 5. Hub name validation

Per §2, hub name is "lowercase DNS name with at least one dot, no port, no trailing dot,
≤ 253 bytes." The implementation checks all these properties, and each dot-separated label
must be 1–63 bytes of `[a-z0-9-]` and must not start or end with a hyphen. *(The per-label rule
was added after audit; as authored, only the character set was checked.)*

### 6. Depth counting

The spec says payload object is level 1, and nesting must not exceed 16 levels.
The JSON parser starts counting at depth=1 for the root object and increments for each
nested object/array.

### 7. Byte vs character length

The spec says "Lengths in this spec are in UTF-8 bytes, not characters." Field length
checks (title, about, body, subject, path, hub, nonce) use `Buffer.byteLength(str, "utf8")`.

### 8. TypeScript ambient declarations

`ts/node-shim.d.ts` provides minimal ambient type declarations for `Buffer`, `process`,
`node:crypto`, and `node:fs` so that `tsc -p ts --noEmit` typechecks cleanly without
installing `@types/node`. The declarations are intentionally minimal — they only cover
the symbols actually used.

### 9. Negative-control test

The implementation was verified to detect corrupted vectors:
- Changing one expected `id` in a valid vector → detected
- Changing one expected `error` in an invalid vector → detected
- Runner exits 1 naming both vectors

## Vectors that required specific choices

- `sig-torsion-in-r`: Relies on Node's `crypto.verify` doing cofactorless verification.
  This was not independently implemented; if a future Node release changes the Ed25519
  verification semantics, this vector would need a manual check.

- `json-raw-control-char`: The spec says raw control characters in strings are an error.
  The implementation rejects all C0 control characters (U+0000–U+001F) in string literals.
  *(Corrected after audit: as authored, this note said line feed was rejected while the code
  exempted it. Line feed is now rejected too; vector `json-raw-newline`.)*

- `key-identity`, `key-order-2`, `key-order-4`, `key-order-8`, `key-order-8b`,
  `key-order-8-negated`, `key-non-canonical`: These all fail at step 3 (`E_ENCODING`)
  because the key validity rule (§2) rejects them before signature verification is
  reached. The small-order check uses the five values listed in §2, and the non-canonical
  check uses y ≥ p.

- `key-not-on-curve`: This passes step 3 (canonical encoding, not small order) but fails
  step 4 (`E_SIGNATURE`) because Node's crypto rejects the public key as an invalid
  curve point.

## Changes made after the clean-room run (integration, not authorship)

Everything above was written by the independent author. Two changes were made when it was
wired into `make conformance`; each is its own commit:

- **Step 1 counted characters, not bytes.** `token.length` is UTF-16 code units, so a
  100 003-byte token of 2-byte characters passed step 1 and failed step 2 with `E_FORMAT`.
  The Go and Python implementations both return `E_SIZE`. No vector caught it, because every
  size vector was ASCII; `size-over-multibyte` now pins it, and step 1 uses
  `Buffer.byteLength`. This is the cross-implementation disagreement the independent
  implementation exists to find.
- **The runner passed over an empty category.** With `invalid` emptied it printed
  `ts: 38 passed` and exited 0. It now exits 2 if `keys`, `valid`, `invalid` or `derived`
  is empty.

**Audit round 1 (PR #5) found four more disagreements, each pinned by a new shared vector
that Go and Python already passed and the TS as authored failed:**

- a payload key named `__proto__` set the parsed object's prototype rather than being stored,
  so it could supply schema fields (`schema-proto-key-supplies-nothing`) or break a valid
  message (`msg-proto-key-ignored`); objects are now created with no prototype;
- a high surrogate followed by a simple escape and then a low surrogate was accepted as a
  pair (`json-lone-surrogate-split`);
- a raw line feed inside a string was accepted (`json-raw-newline`);
- hub names had no per-label check (`schema-hub-empty-label`, `schema-hub-label-over`).

The explicit `S < L` check in `verifySignature` is defence in depth: with it removed,
Node's own `crypto.verify` still rejects `sig-s-not-reduced` with `E_SIGNATURE`, so no vector
can distinguish the two.
