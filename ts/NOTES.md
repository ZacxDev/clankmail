# ClankMail v1 TypeScript Implementation — Notes

## How to run

```bash
# Run conformance tests (required: Node 24+)
node --experimental-strip-types ts/conformance.ts vectors/vectors.json

# TypeCheck (requires tsc on PATH)
tsc -p ts --noEmit
```

Expected output: `ts: 144 passed` with exit 0.

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
≤ 253 bytes." The implementation checks all these properties. DNS name characters
(letters, digits, hyphens, dots) are required; other characters are rejected.

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
  The implementation rejects all C0 control characters (U+0000–U+001F) in string literals
  except line feed (U+000A), which JSON also forbids as a raw character. This is standard
  JSON behavior.

- `key-identity`, `key-order-2`, `key-order-4`, `key-order-8`, `key-order-8b`,
  `key-order-8-negated`, `key-non-canonical`: These all fail at step 3 (`E_ENCODING`)
  because the key validity rule (§2) rejects them before signature verification is
  reached. The small-order check uses the five values listed in §2, and the non-canonical
  check uses y ≥ p.

- `key-not-on-curve`: This passes step 3 (canonical encoding, not small order) but fails
  step 4 (`E_SIGNATURE`) because Node's crypto rejects the public key as an invalid
  curve point.
