# HANDOFF — Three-Body Problem Cipher · 2026-07-01
project: /Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher

## Resume in one move
Read this file, then pick up from "Next steps" below. All work is committed and pushed.

## What happened this session
- **Evan asked for a regrade** of the project's code design. An analyst scored it 83/100 (Strong), finding 11 weaknesses.
- **Evan chose "Option C — everything"** to push the score to 90+. All 11 weaknesses were fixed across 36 files.
- **Regraded at 87/100.** The 4-point gain is honest — the architecture was already clean; the remaining gap to 90 is deeper consolidation items the regrade surfaced:
  - `lo128` defined identically in both `engine.rs` and `utils.rs` (circular dependency prevents import)
  - `_kdf()` HMAC-SHA256 helper copy-pasted in `ratchet.py:46` and `ratchet_aead.py:55`
  - `_DH_BYTES` computed separately in `pq_keyexchange.py:60` and `auth_pq_keyexchange.py:77`
  - `kat/generate_kat.py` imports private `_tag`, `_finalize`, `M` etc. from 9 modules

## What was done (11 fixes, commit `8d68add`)

| # | What | How |
|---|------|-----|
| W1 | Duplicate `InvalidTag` in 3 files | Canonical home = `aead.py`; `siv.py`/`streaming.py` import it |
| W2 | `DEFAULT_N_MAPS` had no home | New `constants.py` (Python) + `rust/src/constants.rs` |
| W3 | KDF pattern copy-pasted | Shared `_kdf_hash()`/`_derive_seed_control()` in `engine.py` |
| W4 | SIV + CTR missing from Rust | New `rust/src/siv.rs` (150L) + `rust/src/ctr.rs` (160L), 9 tests |
| W5 | Rust `finalize` leaked public | `pub(crate)` visibility, removed from `lib.rs` re-exports |
| W6 | 558-line CLI monolith | Replaced with clap derive — real `--help` for every subcommand |
| W7 | Utils mixed into engine.rs | New `rust/src/utils.rs` with 7 shared helpers; 8 import path updates |
| W9 | Naming drift between halves | Naming conventions table added to README |
| W10 | Bench scripts no shared harness | New `bench/_harness.py`; updated `stream_keystream.py` |
| W11 | No `encrypt()` on Rust engines | Added to both `ChaosEngine` and `MultiMapEngine` |

## State
- **Branch:** `phase6-two-locks`
- **Commits:** `8d68add` (11 fixes) + `e276453` (regrade log)
- **Tests:** Python 183/183, Rust 28/28, parity 36/36, KAT 4/4, attacks 15/15 same verdicts
- **Grade:** 87/100 (Strong) — was 83

## Next steps (in priority order)
1. **Evan still has pending questions** — those come first before README/MIT/shipping.
2. The 3 remaining items to reach 90:
   a. Fix `lo128` duplication (put canonical copy in utils.rs, have engine.rs import it — break the circular dep by having engine.rs import from utils not vice versa)
   b. Consolidate `_kdf` from `ratchet.py:46` + `ratchet_aead.py:55` into one shared helper
   c. Move `_DH_BYTES` into `keyexchange.py` as a public constant; import from `pq_keyexchange.py` and `auth_pq_keyexchange.py`
3. Write proper README.md for public GitHub release
4. Add MIT LICENSE file
5. Merge `phase6-two-locks` → `main`, make repo public
6. Decide: keep repo name `chaos-cipher` or rename to `three-body-problem-cipher`

## Don't-trip wires
- **Rust is NOT on PATH.** Prefix cargo with `. "$HOME/.cargo/env" &&`.
- **Cipher is UNVETTED.** Always lead with honesty.
- **The clap CLI uses snake_case subcommand names** — `from_master`, `aead_seal`, `benchmm`, `hybrid_respond` etc. A few had explicit `#[command(name = "...")]` overrides (multimap, mlkem_*, benchmm).
- **`pub(crate)` utilities are now in `utils.rs`** — new modules (siv.rs, ctr.rs) import from there.
- **`ChaosEngine` only exposes `ChaosEngine` publicly** from engine module — `finalize`, `M`, `HALF`, etc. are now `pub(crate)`.
- **README still has the old honest headline** — untouched this session, will be rewritten for the public release.

## Verify
```bash
cd "/Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher"
. "$HOME/.cargo/env" && (cd rust && cargo build --release && cargo test --release)  # Rust 28/28
python3 -m pytest tests/ -q                                                          # Python 183 pass
python3 -m pytest tests/test_rust_parity.py -q                                       # Parity 36 pass
for a in attacks/*.py; do name=$(basename "$a" _attack.py); result=$(python3 "$a" 2>&1 | tail -1); echo "$name: $result"; done
git status -sb   # expect: on phase6-two-locks, clean after push
```
