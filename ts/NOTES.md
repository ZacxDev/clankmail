# ClankMail v1 TypeScript Implementation — Notes

## How to run

```bash
# Run conformance tests (required: Node 24+)
node ts/conformance.ts vectors/vectors.json   # or: make conformance-ts

# TypeCheck (requires tsc on PATH)
tsc -p ts --noEmit
```

Expected output: `ts: 165 passed` (42 valid + 117 invalid + 6 digest) with exit 0.

## Files read

### First implementation (clean-room)

- `SPEC.md` — the normative ClankMail v1 specification
- `vectors/vectors.json` — the published conformance vectors (part of SPEC.md §12)

No other files, no web search, no GitHub, no package registry lookups.

### This update (§7.4, §8.1, §12)

- `SPEC.md` — full text; focus on §7.4 (sub object), §8.1 (digest), §12 (conformance)
- `vectors/vectors.json` — full file; focus on the `digest` section and the new `sub` vectors

No other files, no web search, no GitHub, no package registry lookups.

## Changes in this update (§7.4, §8.1, §12)

### `sub` object type (§7.4)
- Added `"sub"` to `KNOWN_TYPES` so the §4 pipeline accepts sub objects.
- Added `validateSub`: requires a `channel` field that is a valid `c_` id.
- The `sub` and `sub-by-principal` valid vectors now pass; `schema-sub-missing-channel`,
  `schema-sub-channel-slug`, `schema-sub-channel-is-key`, `schema-sub-channel-array`,
  and `signer-mismatch-sub` fail with the expected codes.
- §6.3 already allowed revoking a `sub` (`revoke.target` is any `m_` id), so `revoke-sub`
  (which targets a `sub`'s id) already passed — the existing `revoke` schema validation
  accepts any valid `m_` id as `target`.

### Digest function (§8.1)
- Added `computeDigest(posts, limit, perChannel)` — a pure, deterministic function.
- Counts: for each window post, count `replies` and distinct `repliers` from ALL posts
  (window + non-window) in the same channel, with `re` matching, `from` differing (no
  self-replies), and not hidden. Banned authors' replies count (spec says bans do not
  change counts).
- Ranking: repliers desc → replies desc → ts desc → id asc as byte string.
- Caps: walk ranked window, skip if `per_channel` reached for that channel, stop at
  `limit`. `omitted` = window posts not selected.

### Conformance runner
- Added digest section parsing and checking.
- An empty `digest` section exits 2, like any other empty category.
- The final summary counts valid + invalid + digest = 165 vectors.

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

### 10. Digest id comparison as byte strings

The spec says "id ascending, compared as a byte string" for tiebreaking. The implementation
uses JavaScript's `<`/`>` on the id strings, which compares UTF-16 code units. All
conformance vector ids are ASCII alphanumeric characters (`m_` + base32), so UTF-16
comparison is equivalent to byte-string comparison for these values. If future vectors
include non-ASCII characters in ids this would need to change to a Buffer comparison.

### 11. `revoke-sub` vector

The `revoke-sub` vector (a `revoke` targeting a `sub`'s id) already passed without changes
because the existing `revoke` schema accepts any valid `m_` id as `target`. No new schema
rule was needed.

### 12. No other digest input validation

The spec says `limit` is 1–50 and `per_channel` is 1–50 (§8.1). The `computeDigest`
function does not validate these; it is a pure function of its inputs. The conformance
vectors use values within these ranges.

### 13. `window` semantics

A post with `window: true` is in the window and may appear in items. A post with `window:
false` (or absent) is not a window post; it only contributes to reply counts. Window
posts are never hidden or banned (§12).

## Vectors that required specific choices

### First implementation

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

### This update

- `rank-order`: The tiebreak on `ts` then id byte-string comparison was taken directly
  from the spec text. The implementation matches all six items in order.

- `remove-and-ban`: The banned author's reply (scout, `m_vi7sd3c...`) still counts as a
  reply and a distinct replier, per §8.1 "Bans do not change counts." The hidden reply
  (`m_qhvi5ca...` by bob) does not count, and the hidden reply by carol (`m_ohwdsa7...`)
  also doesn't count; once ALL of a replier's replies are removed, that replier is gone
  from the count. This is confirmed by the expected results: post `m_g4gzuph...` has 2
  repliers (bob has one visible reply `m_uq5xa2b...`; scout's banned reply still counts)
  and 2 replies.

- `caps`: The `per_channel=2` cap skips the third `c_qkyg` post (`m_usxjmon...`) which
  is ranked 3rd, and `limit=3` stops before the 5th ranked post (`m_fqhig7lg...`),
  yielding `omitted: 2`. This confirms the interaction between ranking and caps as
  specified.

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

## Negative controls

### First implementation

The conformance vectors, when corrupted, are detected: changing one expected `id` in a
valid vector or changing one expected `error` in an invalid vector causes the runner
to exit 1 naming both vectors.

### This update

- Copied `vectors/vectors.json` to `ts/neg-control.json`.
- Swapped items[0] and items[1] in the `rank-order` case.
- Changed `replies` from 2 to 99 in `remove-and-ban` items[0].
- The runner exited 1 and named both `rank-order` and `remove-and-ban`.
- Deleted the copy.