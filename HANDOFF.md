# HANDOFF — Three-Body Problem Cipher · 2026-07-01
project: /Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher

## Resume in one move
Ask Evan which question he wants answered first (he had "a few more questions" before continuing to the README and MIT license). Then act on the answer.

## Goal
Get the Three-Body Problem Cipher ready for public GitHub release — as a portfolio piece and research invite. Three things remain: (1) answer Evan's pending questions, (2) write a proper README.md, (3) add an MIT LICENSE file.

## State
- **Done (this session):**
  - **Split `rust/src/lib.rs` from 1,863-line god file into 9 modules** matching the Python half's structure: `engine.rs` (379 lines, chaos core + shared helpers), `multimap.rs` (63), `ratchet.rs` (87), `aead.rs` (111), `streaming.rs` (167), `ratchet_aead.rs` (188), `twolock.rs` (215), `keyexchange.rs` (269), `auth_pq.rs` (319). `lib.rs` is now 60 lines of `pub mod` declarations + `pub use` re-exports.
  - **Every module has a plain-English doc header** explaining what it does, why it exists, and which Python file it mirrors.
  - **Rust: 19/19 tests pass, zero warnings, clean build.**
  - **Python: 183/183 tests pass.**
  - **All 13 attack scripts return same verdicts as before the split.**
  - **No code changes — only file reorganization.** The public API is identical; `main.rs` compiles unchanged. KAT contract untouched.
  - **Graded the project: 78/100 (Strong).** Deep modules, honest documentation, thorough tests. The Rust god-file was the main thing holding it back — now fixed.
- **In flight:** nothing. Clean stop. Evan said he has "a few more questions" before the README/MIT step.
- **Blocked / open:**
  1. Evan's pending questions (unknown — waiting on him)
  2. README.md needs writing
  3. MIT LICENSE file needs adding
  4. Before public release: merge `phase6-two-locks` into `main`, make repo public on GitHub

## Next steps
1. Answer Evan's pending questions.
2. Write README.md — the public face of the repo. Combine the plain-English style of `scorecard.html` with the honesty of `REPORT.md`.
3. Add MIT LICENSE file.
4. Merge `phase6-two-locks` → `main`, make GitHub repo public.
5. Decide: keep repo name `chaos-cipher` or rename to `three-body-problem-cipher` (GitHub redirects old URLs).

## Key files
- `/Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher/rust/src/lib.rs` — 60 lines, re-exports only
- `/Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher/rust/src/engine.rs` — chaos core + shared helpers
- `/Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher/scorecard.html` — the client-facing demo
- `/Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher/PROGRESS.md` — living compass
- `/Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher/REPORT.md` — honest self-evaluation (speed line is STALE — reports 2.6 MB/s Python figure; Rust core is 61 MB/s)
- `/Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher/THREAT_MODEL.md` — threat table
- `/Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher/CLAUDE.md` — project rules + 3-pillar save ritual

## Don't-trip wires
- **Rust is NOT on PATH.** Prefix cargo with `. "$HOME/.cargo/env" &&`.
- **Cipher is UNVETTED.** Always lead with honesty; never present as the only lock. The "two-locks" design is the framing.
- **PROGRESS.md speed line is stale** (needs update: "2.6 MB/s / 786×" → "61 MB/s" for Rust).
- **The split did not change any logic** — only moved code into files. If tests or parity break, check that all `pub(crate)` visibility is correct on the shared helpers in `engine.rs` (they're: `u`, `kdf_hash`, `derive_seed_control`, `hmac_sha256`, `cat`, `ct_eq`, `hmac_sha256_multi`, `HmacSha256`).
- **git status:** on branch `phase6-two-locks`; `HANDOFF.md` and `lib.rs` modified; 9 new module files unstaged. Nothing committed from this session.
- **"Chaos" is now a description, not the name.** Product name = Three-Body Problem Cipher.

## Run / verify
```bash
cd "/Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher"
. "$HOME/.cargo/env" && (cd rust && cargo build --release && cargo test --release)  # Rust 19/19
python3 -m pytest tests/ -q                                                          # Python 183 pass
for a in attacks/*.py; do name=$(basename "$a" _attack.py); result=$(python3 "$a" 2>&1 | tail -1); echo "$name: $result"; done
git status -sb   # expect: on phase6-two-locks, uncommitted changes
```
