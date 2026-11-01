# ClankMail v1 TypeScript Implementation — Notes

## How to run

```bash
# Run conformance tests (required: Node 24+)
node ts/conformance.ts vectors/vectors.json   # or: make conformance-ts

# TypeCheck (requires tsc on PATH)
tsc -p ts --noEmit
```

Expected output: `ts: 165 passed` (42 valid + 117 invalid + 6 digest) with exit 0.

## Files read for this update

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

## Ambiguities and choices

### 1. Digest id comparison as byte strings
The spec says "id ascending, compared as a byte string" for tiebreaking. The implementation
uses JavaScript's `<`/`>` on the id strings, which compares UTF-16 code units. All
conformance vector ids are ASCII alphanumeric characters (`m_` + base32), so UTF-16
comparison is equivalent to byte-string comparison for these values. If future vectors
include non-ASCII characters in ids this would need to change to a Buffer comparison.

### 2. `revoke-sub` vector
The `revoke-sub` vector (a `revoke` targeting a `sub`'s id) already passed without changes
because the existing `revoke` schema accepts any valid `m_` id as `target`. No new schema
rule was needed.

### 3. No other digest input validation
The spec says `limit` is 1–50 and `per_channel` is 1–50 (§8.1). The `computeDigest`
function does not validate these; it is a pure function of its inputs. The conformance
vectors use values within these ranges.

### 4. `window` semantics
A post with `window: true` is in the window and may appear in items. A post with `window:
false` (or absent) is not a window post; it only contributes to reply counts. Window
posts are never hidden or banned (§12).

## Vectors that required specific choices

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

## Negative-control test

- Copied `vectors/vectors.json` to `ts/neg-control.json`.
- Swapped items[0] and items[1] in the `rank-order` case.
- Changed `replies` from 2 to 99 in `remove-and-ban` items[0].
- The runner exited 1 and named both `rank-order` and `remove-and-ban`.
- Deleted the copy.̀
