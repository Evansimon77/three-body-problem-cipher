# Chaos Cipher (Progress)

Last updated: 2026-06-06 | Branch: key-exchange | Status: v5 key-exchange built & proven (branch, pre-merge); roadmap (multi-map → CTR → key-exchange) COMPLETE

## 🎯 Goal
Build and **rigorously prove/disprove** a chaos-based stream cipher (integer PWLCM keystream)
as a research/learning project. "Prove it works" = try hard to break it and measure it against
real standards. Engine-first; any real application is deferred until the evidence justifies it
(and even then, only as a layer over a vetted primitive).

## ⏭️ NEXT
The original three-branch roadmap is **COMPLETE** (multi-map → CTR → key-exchange). Remaining is
optional polish, no new security claims:
- [ ] **Merge `key-exchange` → `main`** when ready (branch 3 proven; awaiting go-ahead).
- [ ] (Optional) Install `ent` + `dieharder` (`brew install ent dieharder`) and run the full randomness battery on ≥100 MB.
- [ ] (Optional) Wire `SeekableCTR` into `aead.py` as a selectable mode for large-file random access.
- [ ] (Optional) Add an authentication layer over DH (fingerprint/signature) to close the MITM gap shown in `attacks/dh_mitm.py`.

✅ Branch 1 (multi-map) merged. ✅ Branch 2 (seekable CTR) merged. ✅ Branch 3 (key-exchange) DONE, see below.

## What It Does
Pure-integer PWLCM (modulus `M = 2^61 - 1`) generates a deterministic, cross-machine keystream;
XOR encrypts. An AEAD shell (`aead.py`) wraps it with a fresh random nonce per message +
encrypt-then-MAC (HMAC-SHA256) so tampering/wrong-keys are rejected. Simple interface:
`seal(key, msg)` / `open_(key, blob)`.

## Stack
Python 3.14, stdlib only for the engine (no numpy). `pytest` for tests, `cryptography` for the
speed-benchmark baselines (AES-256-CTR, ChaCha20). Optional `ent`/`dieharder` via Homebrew.

## Repo / Deployment
- GitHub: **`Evansimon77/chaos-cipher`** (private). Local: `Projects/chaos-cipher/`.
- Not deployed anywhere — research artifact only.

## Architecture
- `engine.py` — chaotic core: PWLCM, weak-parameter rejection, `from_master()` hash KDF.
- `aead.py` — safe shell: `seal()`/`open_()`, random nonce, encrypt-then-MAC, AAD, constant-time verify.
- `tests/` — correctness, period (Brent), avalanche, AEAD auth.
- `attacks/` — two-time-pad break, known-plaintext state recovery (+ invertibility proof).
- `bench/` — NIST-lite randomness, `randomness.sh` (ent/dieharder), speed vs AES/ChaCha.
- `REPORT.md` — honest verdict. `README.md` — usage.

## Key Findings (see REPORT.md)
- ✅ Integer-math determinism (cross-machine sync) **works** — the one original claim that holds.
- ✅ Avalanche ≈ 0.5000; passes NIST-lite randomness screen; 18/18 tests green.
- ❌ "Unhackable / no-structure / quantum-proof" claims are **false**: map is invertible;
  two-time-pad breaks it on nonce reuse; weak-key class existed (now rejected).
- ⚠️ ~700–800× slower than AES/ChaCha. **Still UNVETTED** — not for real data.

## Recent Work

### ✅ DONE 2026-06-06: Branch 3 — key-exchange layer (`DHParty`) — built & PROVEN (roadmap complete)
> Merged Branch 2 (`ctr-mode`) to `main` first (`5dccd04`). Then built `keyexchange.py`: classic
> finite-field **Diffie-Hellman** over RFC 3526 MODP Group 14 (2048-bit safe prime, pure-integer
> `pow()`). Both parties derive the same 32-byte key from exchanged *public* values; a SHA-512 KDF
> turns the group element into a uniform key fed straight to `seal()` — **agree a key over an open
> channel with zero pre-shared secret.** Deliberate design: vetted DH math for key agreement, chaos
> only for the bulk cipher (NOT a homemade chaos key exchange — those are broken, and inventing one
> would be the overclaim this project disproves; this is the v1 "layer over a vetted primitive"
> advice made real). Kept the break-it ethos: `attacks/dh_mitm.py` shows a passive eavesdropper
> FAILS (DH holds), an active man-in-the-middle SUCCEEDS against unauthenticated DH (honest
> weakness), and a verified fingerprint catches it. Peer-value validation rejects small-subgroup
> footguns (0/1/p−1/out-of-range). 49/49 tests pass (+14 in `test_keyexchange.py`). Committed
> `d3b9cb7` on branch `key-exchange`, pushed, pre-merge. **Three-branch roadmap now COMPLETE.**

### ✅ DONE 2026-06-06: Branch 2 — seekable CTR mode (`SeekableCTR`) — built & PROVEN
> Merged Branch 1 (`multi-map`) to `main` first (fast-forward `438b7a8`). Then built `ctr.py`:
> counter mode over the 3-map keystream. The stream is cut into `BLOCK_SIZE` (64B) blocks; block
> *i* is derived independently from `(master_key, nonce, block_index=i)` via the same
> domain-separated SHA-512 KDF (counter folded in) — the AES-CTR construction with the 3-map chaos
> keystream as the PRF. **Win:** `keystream(n, offset=k)` returns global bytes `k..k+n-1` directly,
> so any position is O(1) random-access (decrypt the middle of a file / parallelize) instead of
> spooling from byte 0. **Proof:** `tests/test_ctr.py` (10 new) — windowed reads equal the
> full-stream slice across block boundaries; reading at position 1,000,000 derives **one** block,
> not a million. 35/35 tests pass. Cost: CTR ≈ 1.2× slower than streaming 3-map (~0.64 MB/s) — the
> honest price of seekability. Blocks are domain-separated (more separation than the streaming
> single-orbit map). REPORT v4 frames it as a **capability** upgrade, not a security claim — it
> inherits the chaos security unchanged. Committed `0810174` on branch `ctr-mode`, pushed, pre-merge.

### ✅ DONE 2026-06-06: Branch 1 — multi-map (3 independent PWLCMs) — weak spot fixed & PROVEN
> Implemented the "three-body" idea as **3 independent PWLCM maps XOR-combined** (`multimap.py`,
> `MultiMapEngine`); `aead.py` `seal()/open_()` now uses it by default. Maps are independent
> (uncoupled) → hides each map's invertibility footprint + avoids chaos-sync. **Proof:**
> `attacks/known_plaintext.py` Part C re-runs the exact Part-B attack vs 3 maps — at M=2²⁰ and
> M=2²⁴ it can **no longer predict future keystream** (it broke the single map at those scales);
> naive joint brute-force ~2^159. 25/25 tests pass (new `test_multimap.py`; AEAD still green).
> Cost: 3-map ≈ 3.3× slower than 1-map (~0.8 MB/s). Still UNVETTED (beats *this* attack, not a
> proof). On branch `multi-map`, pre-merge. Decided against nesting/N>3 (cost+complexity+sync,
> no real gain past brute-force wall).

### ✅ DONE 2026-06-06: Decoupled tests from the "save" command
> Clarified the workflow per user: **save = exactly three steps** (commit+push → Obsidian log →
> PROGRESS.md update). Running `pytest` is now a **separate** action, done only on request or when
> verifying work on its own — never bundled into or gating `save`. Updated project `CLAUDE.md` +
> the `chaos-cipher-save-workflow` memory.

### ✅ DONE 2026-06-06: v2 AEAD shell + GitHub + three-pillar workflow
> Added weak-parameter **rejection** (`MIN_P` band) + `from_master()` hash KDF (no weak key
> reachable; the old `key=1,ctrl=1`→period-1 collapse is gone). Added **authentication** via a
> `seal()`/`open_()` AEAD shell (`aead.py`): fresh random nonce per message (kills two-time-pad
> in practice) + encrypt-then-MAC (HMAC-SHA256), constant-time verify, AAD binding. 18/18 tests
> pass (10 new in `test_aead.py`: tamper/truncation/wrong-key/AAD all rejected). Pushed to private
> repo `Evansimon77/chaos-cipher`; folder renamed `chaos-engine`→`chaos-cipher`. Established the
> GitHub/Obsidian/PROGRESS three-pillar workflow + the "save" command.

### ✅ DONE 2026-06-06: v1 engine + adversarial harness + honest REPORT
> Built faithful pure-integer PWLCM cipher + full attack/test harness (period via Brent,
> avalanche, NIST-lite, two-time-pad, known-plaintext state recovery, speed bench). Verdict in
> `REPORT.md`: the core idea synchronizes across machines, but the strong "unhackable" claims
> don't survive contact with real attacks. Decision: engine-first, app deferred, evidence-driven.
