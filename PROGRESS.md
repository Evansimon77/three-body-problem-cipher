# Chaos Cipher (Progress)

Last updated: 2026-06-28 | Branch: branchless-core | Status: 🛠️ **MAX-SECURITY REBUILD IN PROGRESS** — no-compromise path. **🎉 PHASE 1 COMPLETE.** **Phase 2 IN PROGRESS** (4/5 items; only #7 heavy randomness left): **(D) new differential/correlation tooling done** (`attacks/differential_attack.py`) — attacks the brand-new output path (127→64 fold, fmix64 mixer, top-32 truncation); all four parts pass *at the chance noise floor* (every state bit avalanches, fold carries the top half P∈[0.470,0.528], no usable differential, truncation wall leaks nothing, 2^(w/2) preimage law confirmed). **Existing attacks re-run + honestly relabeled done** — all survive the new 4-map/2^127 design; the meet-in-the-middle in `core_cryptanalysis.py` was GENERALIZED from hardcoded-3-map to a balanced N-map split → honest cost ~2^254 time+memory (was the stale 2^122); `known_plaintext.py`/`output_filter.py` labels corrected. **New period census on 2^127 + TMTO check done** (`period_census.py`): √M law holds (per-map ~2^62, 4-map combined ~2^247), 0 traps/300 keys, 0/7 edges, tiny-cycles are a small-grid artifact (now reported as a trend); NEW Part E TMTO is honest two-sided — 2^254 worst case (2 bits under 256, so publish ~254-bit), 2^504 realistic, data starved by auto-rekey. 81/81 tests. **Only #7 heavy randomness (PractRand/dieharder) left in Phase 2.** **Phase 0 done** (branchless constant-time map). **Phase 1 #3/#4 done** (frosted-glass nonlinear output + multi-byte). **Phase 1 #1 done TODAY** (bigger grid 2^61→2^127): per-map period lifted ~2^30 → ~2^62 (√M law, measured exponent 0.489). The edge census CAUGHT a real bug #1 introduced — a degenerate all-zero key fell into a 6-step short cycle because nonce=0 collapsed the init mixing to `x=key+1` (a tiny start state that resonates with the map). FIXED by an unconditional avalanche in the init so any key→strong x0; re-verified 0/7 short cycles, 72/72 tests, all 4 filter attacks pass, bias clean. **Phase 1 #2 done TODAY** (map count 3→**4**): chose 4 after measuring — sub-maps proven independent (worst pairwise corr 0.008), combined output clean at N=3/4/5, cost ~linear (4 = 1.3× the 3-map time), work-factor at N=4 ~2^252 period / ~2^508 joint state. Stopped at 4 not 5+ because all maps share the master key, so key/KDF — not map count — is the real ceiling. New validation: `attacks/map_count_attack.py`. **Phase 1 A (auto-rekey ratchet) done TODAY** — new `ratchet.py`: one-way HMAC-SHA256 key chain re-keys every 64 KiB and burns the old key. Gives **forward secrecy** (a key leak can't decrypt past epochs — demonstrated) + **dissolves the period limit** (each epoch is a fresh ~2^252 orbit; usable length effectively unbounded). Validated `attacks/ratchet_attack.py` (forward secrecy PASS, epochs independent, no re-key seam — after fixing a too-strict seam test that cried wolf on sampling noise). 81/81 tests. **🎉 PHASE 1 COMPLETE. Next: Phase 2 — attack the whole new design HARD.** See "🗺️ MASTER ROADMAP".

---
Prior status: 🔬 **v9 PERIOD CENSUS DONE** — answered the veteran's make-or-break question (§2). Honest finding: the map is a **random function**, so period ≈ **√M ≈ 2³⁰, NOT 2⁶¹** (rho/birthday law, measured exponent 0.489). **No traps:** 1,000/1,000 production keys + 7 adversarial edges show no short cycle; fixed-point capture ~1e-9 and even then mutes only 1 of the 3 XOR'd maps. Mitigated by the 3-map combiner (lcm ~2⁹⁰) + CTR mode + a per-key data limit. REPORT **v9**; `test_period.py` upgraded to a **1,000-marble guard**. **72/72 tests pass.** (Prior: all 3 hardening suggestions done & merged to main `cdc598c`.) Resume point: 🔖 **SPEED / Rust rewrite** — architecture DECIDED (chaos outer wall + AES inner vault; make the chaos engine itself fast, don't blend AES in); user leaning **Rust** for a fast constant-time core; mid-discussion on the "expert questions" checklist (§2 period = DONE; §4 constant-time + §3 KAT set = pre-port must-dos). See "🔖 RESUME HERE" in NEXT. End-goal unchanged: deploy as **outer layer over a vetted primitive** ("Option B") for AsturAI client data — never the only lock.

> 📓 Older work-log entries trimmed for brevity — full history in git.

## 🎯 Goal
Build and **rigorously prove/disprove** a chaos-based stream cipher (integer PWLCM keystream)
as a research/learning project. "Prove it works" = try hard to break it and measure it against
real standards. Engine-first; any real application is deferred until the evidence justifies it
(and even then, only as a layer over a vetted primitive).

## 🗺️ MASTER ROADMAP — the no-compromise, max-security path (set 2026-06-28)
User's directive: ignore "what's easy for a lazy system"; top priority is the best, most secure
version we can build. Honest ceiling (always true): the chaos layer ALONE never earns trust — real
security = a fast, hardened, **externally-reviewed** outer wall over a **vetted vault** (two locks).
Ordering rule: **design it right → break it → freeze it → make it fast → wrap it → two-lock it →
let strangers attack it.** Never speed up or ship a design that isn't finalized + self-attacked.

- [x] **Phase 0 — Branchless constant-time map** (DONE 2026-06-28, branch `branchless-core`). Removed
      the secret-dependent `if/elif` (timing-leak #1) via 4-candidate mask-select. Bit-identical to old
      (fingerprint + 200k random/edge cases + 72/72 tests). Left a code note: timing-leak #2 (divide by
      secret `p`) is NOT fixed here — needs the precomputed-reciprocal trick in Rust (Phase 4).

- [ ] **Phase 1 — Finalize the CORE design** (math changes happen here, together, before freeze/port):
  - [x] **#3 Frosted-glass output** — nonlinear ARX finalizer so output can't be rolled back to state
        (kills the invertibility weakness). DONE 2026-06-28, attacked.
  - [x] **#4 More bytes per step** — stop emitting 1 byte per expensive step; safe *because* of #3.
        DONE 2026-06-28 (OUTPUT_BYTES_PER_STEP=4; speed win is Rust-only).
  - [x] **#1 Bigger grid (2^127−1)** — per-map period ~2^30 → ~2^62 (erases the headline weakness).
        DONE 2026-06-28. Also fixed an init-mixing bug it exposed (degenerate-key short cycle). Note:
        `_finalize` now XOR-folds the 127-bit state into 64 bits so all bits reach the output.
  - [x] **#2 Final map count** (3 → **4**) — picked and locked DONE 2026-06-28. Measured: maps
        independent (corr 0.008), no new bias, ~linear cost; 4 = one redundant wall + margin over
        256-bit; 5+ rejected (shared-key ceiling). Validation: `attacks/map_count_attack.py`.
  - [x] **A. Auto-rekey ratchet** — DONE 2026-06-28 (`ratchet.py`). One-way HMAC key chain, re-keys
        every 64 KiB, burns old key. Forward secrecy + unbounded length, both measured. Validation:
        `attacks/ratchet_attack.py`. (AEAD wiring is deferred to Phase 5 by design.)
  - **✅ PHASE 1 COMPLETE (2026-06-28).** Core design finalized: branchless map, frosted-glass output,
    multi-byte, 2^127 grid, 4 maps, auto-rekey. ▶ Next: **Phase 2 — attack the whole design hard.**
- [ ] **Phase 2 — Attack our own design HARD** (nothing proceeds unless it survives):
  - [x] **D. New attack tooling** — DONE 2026-06-28 (`attacks/differential_attack.py`). Differential +
        correlation battery on the NEW output path (fold + fmix64 + truncation). All 4 parts pass at the
        noise floor: avalanche (every 127 state bits reach output ~½, fold carries top half), no usable
        single-bit differential, no published→hidden/state correlation (truncation wall holds), preimage
        law ~2^(w/2) confirmed (2^32 candidates/step/map).
  - [x] Re-run every existing attack vs the new design — DONE 2026-06-28. All survive. Also fixed
        stale labels honestly: `core_cryptanalysis.py` now reports the real 4-map count AND its MITM
        was GENERALIZED to a balanced meet-in-the-middle at the shipped map count (was hardcoded 3-map)
        → honest cost ~2^254 time+memory (was the stale 2^122). `known_plaintext.py` Part C → 4 maps,
        naive joint ~2^508 / MITM ~2^254. `output_filter.py` Part 4 label → 4-map. (period_census is
        the separate item below.)
  - [x] New period census on the bigger grid + state-size/TMTO check — DONE 2026-06-28
        (`attacks/period_census.py`, relabeled 2^61→2^127 / 3-map→4-map, re-run on the real grid).
        Part A full census: tiny-cycle basins are a SMALL-GRID artifact that shrinks with the grid
        (100%@2^13 → 0.04%@2^21; now reported as a trend + ok-band vs rejected-edge split, fixing a
        misleading single-max). Part B: 0 traps / 300 production keys at 2^127. Part C: 0/7 adversarial
        edges (confirms the init-avalanche fix holds). Part D: √M law holds (exp 0.489) → per-map
        period ~2^62, 4-map combined ~2^247. NEW Part E (TMTO): honest two-sided — worst case (p known)
        508-bit state → 2^254 (2 bits under a strict 256-bit claim; publish ~254-bit, matching the
        MITM), realistic (p secret) ~1008-bit → 2^504; auto-rekey starves TMTO data by 2^238 either way.
  - [ ] **#7 heavy randomness** (PractRand/dieharder) — last Phase-2 item.
- [ ] **Phase 3 — Freeze + write the contract:**
  - [ ] **E. Threat-model + bit-security claim** (one page). [ ] **§3 KAT** frozen vectors.
        [ ] Constant-time spec (map done + reciprocal-division plan).
- [ ] **Phase 4 — Rust core (the speed blocker):** [ ] #5 Rust hot loop (~50–100×).
      [ ] **§4 precomputed reciprocal** (kills timing-leak #2 + speed). [ ] parallel maps + CTR blocks.
      [ ] differential fuzz Rust==KAT; benchmark vs AES/ChaCha.
- [ ] **Phase 5 — Harden the shell:** [ ] **#6 key-commitment.** [ ] **B. streaming/chunked AEAD**
      (big files). [ ] wire **A. auto-rekey** in. [ ] **F. post-quantum hybrid** key exchange.
- [ ] **Phase 6 — THE SECURITY GOAL: two locks** — integrate as the OUTER layer over a vetted inner
      vault (AES-256-GCM / XChaCha20-Poly1305); specify where chaos sits + order of ops ("Option B").
- [ ] **Phase 7 — External validation** — peer review / audit; only outsiders failing to break it turns
      "I think it's secure" into "it's secure." Mandatory for the stated goal.

## ⏭️ NEXT

### 🔖 PRIOR RESUME POINT (superseded by the Master Roadmap above — kept for context)
**Architecture DECIDED with user (2026-06-06):** chaos = **outer wall** (exposed, gets battle-tested by
real attacks), AES = **inner vault** (if the chaos wall ever cracks, the client is STILL fully protected).
Two real walls = "Option B". The blocker is **speed** — a slow cipher is unsellable ("clogs the client's
system; nobody buys that"). **Key decision:** do NOT blend AES into chaos (that either stays slow or turns
into "mostly AES"); instead make the **chaos engine itself fast** — the two-wall design stays, we just swap
the slow motor. Plan: (1) rewrite the hot loop in a fast language (~50–100×), (2) parallelize the 3 maps +
CTR blocks → realistic **~100–500 MB/s = "feels instant"**; honest wall = can't tie AES's AES-NI silicon.
Speed today: 0.77 MB/s (3-map) vs AES ~2,146 / ChaCha ~1,905 MB/s.

**Language: leaning Rust** (memory-safety for free + good constant-time tooling `subtle` → right for a
security product) over C. User paused here ("more questions first"; switched to max-effort reasoning).

**The veteran's "expert questions" checklist** (now drives the rewrite — from the 2026-06-06 chat):
- [x] **§2 Guaranteed minimum period** — ✅ DONE this session (v9 census: period = √M ≈ 2³⁰, no traps).
- [ ] **§4 Constant-time / branchless core** — the PWLCM `if` is secret-dependent ⇒ timing-leak risk.
      MUST write the map **branchless** when porting (a real point for Rust). **Pre-port must-do.**
- [ ] **§3 Frozen KAT set** — known-answer vectors so the Rust port is provably **bit-identical** to the
      Python reference (+ differential fuzz). Build BEFORE porting. **Pre-port must-do.**
- [ ] §1 formal threat model + bit-security claim; §3 TMTO state-size check; §5 per-key **data limit**
      (v9 gave the number: rekey well before ~1 GB single-map); §6 external review; §7 "why chaos" value
      prop (answered: sacrificial outer wall over a vetted vault).
- **▶️ NEXT ACTIONS when user returns:** answer their remaining questions, then either (a) build the KAT
  set + a branchless map and start the Rust core, or (b) keep it on paper. **Decide scope: real build vs
  curiosity.** Also still open: the PARKED AsturAI Option-B bridge (below).

**Phase (2026-06-06): strengthen the cipher's security** (DONE — all 3 below), then deploy as the *outer*
layer over a vetted primitive ("Option B" / defense-in-depth) to protect AsturAI client data — never the
only lock. Each hardening idea must be *measured/attacked*, not asserted (project ethos). Three-step plan
agreed with user (Suggestion 1 → 2 → 3):
- [x] **Suggestion 1 — clever-burglar cryptanalysis** (`attacks/core_cryptanalysis.py`, REPORT v6). DONE & merged to main.
      Bias hunt = clean (2.52 σ), independence = confirmed (1.71 σ), MITM = honest correction 2^159→~2^122.
- [x] **Suggestion 2 — nonce-misuse resistance** ("the seatbelt", `siv.py`, REPORT v7). DONE, pre-merge on `nonce-misuse-siv`.
      Deterministic SIV AEAD: IV = HMAC(K, aad‖plaintext) used as both keystream IV and auth tag. No nonce to reuse;
      different messages never share a keystream (C0⊕C1=M0⊕M1 two-time-pad equality no longer holds). 61/61 tests pass.
- [x] **Suggestion 3 — DH authentication** (`auth_keyexchange.py`, REPORT v8). DONE & merged to main.
      Triple-DH (static+ephemeral, Noise/X3DH pattern): session key mixes ee + es + se, so a MITM lacking a
      party's static private can't derive it. `attacks/auth_dh_mitm.py` shows the old MITM now FAILS. 71/71 tests pass.
- [ ] 🅿️ **PARKED (2026-06-06, user's request) — the AsturAI "Option-B" bridge.** Specify the integration
      contract: where the chaos layer sits, what vetted AEAD it wraps, the order of operations. Deliberately
      deferred — user has more questions about the cipher itself first. Pick this up when they say so.
- [ ] (Deferred) Heavyweight randomness (dieharder/PractRand) — decided against 2026-06-06 unless explicitly wanted; randomness ≠ security.

Optional capability polish (no security claim, lower priority):
- [ ] Wire `SeekableCTR` into `aead.py` as a selectable mode for large-file random access.

✅ `ent` battery (Fourmilab) on **100 MB** of the shipped 3-map keystream — PASSED (entropy 7.999998/8,
chi-square 261.62 @ 37%, mean 127.4968, serial corr 0.0001). NIST-lite subset passes too. Strong PRNG;
does NOT change UNVETTED status. See REPORT.md "Randomness battery".

✅ Branch 1 (multi-map) merged. ✅ Branch 2 (seekable CTR) merged. ✅ Branch 3 (key-exchange) DONE, see below.

## What It Does
Pure-integer PWLCM (modulus `M = 2^127 - 1`) generates a deterministic, cross-machine keystream;
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

### ✅ DONE 2026-06-28: Housekeeping — /check tooling installed + project made clean
> Branch `branchless-core`. Not a roadmap item — a health pass before resuming Phase 2.
> Installed the three `/check` tools (ruff, pytest-cov, pip-audit). Results, all addressed:
> **(1) Analyzer** — was 31 cosmetic flags (stray `f` prefixes, 3 dead variables, 10 deliberate
> compact `;` lines). Auto-fixed the f-strings, deleted the 3 dead vars (`se_bit`, `alice`, `bs` —
> none hid a bug), added `ruff.toml` ignoring E702 to document the intentional compact-line style.
> Analyzer now **PASS**. **(2) Dependencies** — bumped `cryptography` 48.0.0 → 49.0.0 (clears
> GHSA-537c-gmf6-5ccf; benchmark-only dep, never touches the cipher). Chaos-cipher's own deps now
> clean; the 10 remaining pip-audit hits belong to OTHER projects in the shared Python, not this one.
> **(3) Coverage** — still skipped (code is loose scripts, no installable package); deferred, low value.
> No cipher logic touched. 81/81 tests still pass.

### ✅ DONE 2026-06-28: Phase 2 — new period census on the 2^127 grid + TMTO/state-size check
> Branch `branchless-core`. Third Phase-2 item. Re-ran `attacks/period_census.py` on the finalized
> 2^127 / 4-map design (relabeled the stale 2^61 / 3-map prints) and added a new TMTO part.
> **Part A (full census, small scale):** found and FIXED a misleading summary — the old "worst tiny
> basin" lumped the REJECTED edge-p values in with the real accepted band. Split them; the honest
> accepted-band worst is a SMALL-GRID artifact that shrinks as the grid grows (100%@2^13 → 38% → 0.68%
> → 5% → 0.04%@2^21), now shown as a trend table, not a scary single max. **Part B (real grid):** 0
> traps among 300 production-seeded keys at 2^127 (budget 60k steps). **Part C (edges):** 0/7 adversarial
> inputs short-cycle — confirms the init-avalanche fix (that closed the degenerate-key 6-cycle #1
> introduced) still holds. **Part D (scaling law):** the √M random-function law holds, fitted exponent
> 0.489 → extrapolated per-map period ~2^62, 4-map combined (lcm) ~2^247 (flagged honestly as a ~90-bit
> extrapolation beyond the measured k≤37, a trend not a measurement). **Part E (NEW — TMTO/state-size):**
> a generic time-memory trade-off breaks a stream cipher at ~2^(state/2). Reported two-sided and
> honestly: worst case (break-point p assumed KNOWN) hidden state = 508 bits → TMTO ~2^254 — which is
> 2 bits UNDER a strict 256-bit claim, so the honest bit-security to publish is ~254 (matching the MITM),
> not a round 256; realistic case (p is secret, ~125 bits/map) → ~1008-bit secret → TMTO ~2^504, clearing
> the 512-bit rule comfortably; and auto-rekey (item A) starves the DATA a TMTO needs by ~2^238 either
> way. Noted N=5 maps would lift the worst case to 2^317 if a clean ≥256 margin is ever required.
> **81/81 tests.** Honest scope: this is a generic-bound + structural census, NOT a proof; PWLCM's
> affine structure could admit a data-cheaper attack. Still UNVETTED. **Next: #7 heavy randomness.**

### ✅ DONE 2026-06-28: Phase 2 — honest re-run of every existing attack vs the new design
> Branch `branchless-core`. Second Phase-2 item. Re-ran the whole attack suite against the finalized
> 4-map / 2^127 / frosted-glass engine — everything still survives — and fixed the attacks that ran on
> the new engine but still PRINTED the old design (a report that misdescribes what it attacked is a
> quiet lie). **The non-lazy fix, not just text:** `core_cryptanalysis.py` Part C's meet-in-the-middle
> was hardcoded to 3 maps; I GENERALIZED it to a balanced MITM at the shipped map count — split the N
> maps into two halves, table one half's forced output prefixes, match the other half — and ran it at
> small scale (M=2^8 → MITM 2^16 vs naive 2^32; M=2^10 → 2^20 vs 2^40), confirming it still predicts
> unseen keystream and that the cost law is 2^(ceil(N/2)·state). Honest real-engine number: **N=4,
> 127-bit state → MITM ~2^254 in TIME *and* MEMORY** (the 2^254 memory is itself prohibitive), naive
> joint ~2^508 — superseding the stale 3-map "2^122". `known_plaintext.py` Part C now runs the single-
> map attack against 4 maps (still FAILS to predict) and states the same 2^508 / 2^254 honest costs;
> noted the per-map "first byte" anchor is gone under XOR. `output_filter.py` Part 4 label → 4-map.
> Also re-ran two-time-pad, both DH MITM attacks (key-exchange layer, unaffected), map-count, ratchet —
> all as expected. Fixed `_finalize` import use in core (added `from engine import M`). **81/81 tests.**
> Honest scope: this is housekeeping + a sharper (correct) MITM number, not a new break. Still UNVETTED.
> **Next Phase-2: new period census on the 2^127 grid, then TMTO/state-size, then #7 PractRand.**

### ✅ DONE 2026-06-28: Phase 2 (D) — differential & correlation hunt on the NEW output path
> Branch `branchless-core`. First Phase-2 item. New `attacks/differential_attack.py` attacks the math
> Phase 1 ADDED and nothing had yet hit directly: the **fold** (127-bit state XOR-folded to 64), the
> **fmix64 mixer** (#3 frosted glass), and the **truncation** (emit only the top 32 of 64 bits). Four
> parts, every claim a measured number judged against the honest noise floor (√(2 ln n_cells), because
> a fixed "3σ" cutoff cries wolf when you test thousands of cells):
> **Part 1 — avalanche:** flip each of the 127 state bits, measure P(each of 64 output bits flips).
> Worst cell 3.79σ vs a 4.24σ chance-floor; 0 avalanche-gap cells; the high state bits (64–126, the
> folded-in half) reach the output at P∈[0.470,0.528] — proves the fold actually carries the top half
> (the bug #1 could have left). **Part 2 — differentials:** single-bit input differences give unbiased
> per-bit output diffs (4.27σ at a 4.24σ floor) and the output diff spreads to ~32 of 64 bits — no
> high-probability differential. **Part 3 — truncation wall:** drove the REAL engine, measured published
> top-32 ↔ hidden low-32 (and ↔ state, and word t↔t+1) bit correlations — all at floor (3.73σ vs 3.72),
> so the bits we publish leak nothing about the half we hide. **Part 4 — recovery cost:** censused a
> width-scaled mixer; preimage count tracks 2^(w/2) exactly → at full width 2^32 candidate finalize-
> inputs per emitted step, PER map, XOR'd over 4 — the honest reason truncation is the wall. Fixed the
> now-stale `_finalize` docstring (61-bit→127, 3-map→4-map) and pointed it at this evidence. **81/81
> tests.** Honest scope: bounds biases to ~1/√N at the tested N; absence of a found bias ≠ proof. Still
> UNVETTED. **Next Phase-2 items: honest re-run/relabel of the existing attacks (they run on the new
> engine but some still print "3-map/2^61"), new period census on 2^127, TMTO/state-size, #7 PractRand.**

### ✅ DONE 2026-06-28: Phase 1 (A) — auto-rekey ratchet (forward secrecy + unbounded length) → PHASE 1 COMPLETE
> Branch `branchless-core`. New module `ratchet.py` (`RatchetEngine`, drop-in keystream source). A
> one-way **HMAC-SHA256 key chain**: from chain key K_i derive this epoch's keystream key MK_i AND the
> next chain key K_{i+1}, then DROP K_i. Re-keys every `epoch_bytes` (default **64 KiB**); each epoch is
> a fresh independent `MultiMapEngine`. **Two payoffs, both measured** (`attacks/ratchet_attack.py`):
> (1) **FORWARD SECRECY** — captured the live key at epoch C and showed: future reproduces exactly,
> PAST does NOT leak, and capturing one epoch earlier WOULD read it (proving only the burned key
> protected the past). (2) **PERIOD DISSOLVED** — each epoch is a fresh ~2^252 combined orbit, re-keyed
> ~2^46× below any single orbit; usable length bounded only by a 2^64 epoch counter. Also: epochs are
> independent (corr 0.036) and there is **no re-key seam** — the seam correlation sits at the noise
> floor (z=1.5 vs baseline z=1.1). **Process note:** the seam test first cried "CHECK" — investigated
> and found it was MY test's fault (a raw 0.05 cutoff on only 399 boundary samples ≈ 1 std-error of
> noise); rewrote it to judge by z-score against the ordinary-correlation noise floor. Added
> `tests/test_ratchet.py` (9 tests: cross-epoch round-trip, determinism, checkpoint/resume, etc).
> **81/81 tests pass.** HONEST SCOPE: symmetric forward secrecy only — NOT future-secrecy after a live
> capture (that needs the DH/PQ ratchet, item F, later) and NOT a proof of security. Key-burning is
> best-effort in Python (immutable bytes); the Rust port will `zeroize`. Still UNVETTED. AEAD wiring
> deferred to Phase 5 by design. **🎉 Phase 1 (core design) is DONE — next is Phase 2: break it.**

### ✅ DONE 2026-06-28: Phase 1 (#2) — map count locked at 4 (was 3), chosen by measurement
> Branch `branchless-core`. Raised `DEFAULT_N_MAPS` 3 → **4** (the keystream is the XOR of N independent
> PWLCM maps). **Why 4, decided on evidence not vibes** (`attacks/map_count_attack.py`): (1) INDEPENDENCE
> — the premise behind XOR-combining — holds across all maps incl. the 4th/5th: worst pairwise byte
> correlation 0.008, bit-agreement deviation 0.001. (2) NO NEW BIAS at N=3/4/5 (chi²/serial/per-bit all
> clean). (3) COST is ~linear: N=4 = 1.31× the N=3 time, N=5 = 1.63× (a Rust-phase concern; we pick on
> security margin, not Python speed). (4) WORK-FACTOR: N=4 → combined period ~2^252, joint hidden state
> ~2^508 — vast margin over a 256-bit target. **Why not 5+:** all maps derive from the SAME master key
> (domain-separated), so key/KDF recovery — not the map count — is the true ceiling; beyond a redundant
> wall + margin, extra maps add period & redundancy, not unbounded bit-security. Change propagates via
> `DEFAULT_N_MAPS` (aead/siv/ctr all default to it); updated the two `n_maps==3` tests → 4 and the bench.
> **72/72 tests pass.** Honest scope unchanged: still UNVETTED; this validates the independence premise +
> the cost of the choice, not security. **Next: A — auto-rekey ratchet (last Phase-1 item).**

### ✅ DONE 2026-06-28: Phase 1 (#1) — bigger grid 2^61→2^127, period lifted, init bug found & fixed
> Branch `branchless-core`. Moved the grid from `M = 2^61-1` to **`M = 2^127-1` (Mersenne prime M127)**.
> **Why:** the honest per-map period is √M (random-function rho law), so a bigger grid is the only lever
> that raises it. **Measured** the law at small scales (k=21..37, exponent **b=0.489≈0.5**) and extrapolated
> to the new grid: per-map period **~2^62** (was ~2^30); 3-map XOR combiner ~2^185. Three engine changes:
> (1) `M`/`HALF`/`DEAD_STATE_FIX` scaled (DEAD is now a 128-bit pattern %M so the escape lands mid-space);
> (2) `MIN_P` made relative (`HALF>>20`) so the weak-param band scales with the grid; (3) **`_finalize`
> now XOR-folds the wide state into 64 bits FIRST** — without this the bare 64-bit mask would silently drop
> the top 63 state bits (caught while designing). **Measure-don't-assert paid off:** the edge census flagged
> a NEW bug — `key=0/ctrl=0` (and `key=1`) fell into a **6-step short cycle**. Root cause (traced): with
> nonce=0 the init mixing collapsed to `x = key+1`, a tiny start state that resonates with `p≈M/2^21`.
> **Fix (chosen by data over 4 variants):** an unconditional 2-round ARX avalanche in `__init__` so ANY
> (key,nonce) — incl. all-zero — diffuses across the full grid. A "make MIN_P ugly" variant did NOT fix it
> (proved the tiny x0, not the clean MIN_P, was the cause). **Re-verified:** edge census **0/7** short cycles,
> **72/72** tests, all **4** filter attacks pass, bias clean (0.93σ, χ²=231, serial -0.0006). Honest scope
> unchanged: still UNVETTED; this raised the period floor + closed an init footgun, not a proof of security.

### ✅ DONE 2026-06-28: Phase 0 + Phase 1 (#3, #4) — branchless map + frosted-glass output, attacked
> Branch `branchless-core`. User chose the **no-compromise, max-security path** and the 7-phase Master
> Roadmap was recorded (see top). Three pieces landed and were measured, not asserted:
> **(Phase 0) Branchless constant-time map** — replaced the secret-dependent 4-way `if/elif` in
> `_next_state` with a 4-candidate mask-select (walk all doors every step, keep the right answer), killing
> timing-leak #1. Proven **bit-identical** to the old map: same keystream fingerprint + 200k random/edge
> cases (0 mismatches) + 72/72 tests. Honest note left in code: timing-leak #2 (divide by secret `p`)
> is NOT fixed here — needs the precomputed-reciprocal trick in the Rust port (Phase 4).
> **(#3) Frosted-glass output** — `generate_byte` no longer emits a raw window of the state
> (`(x>>24)&0xFF`); it now emits bytes from a NONLINEAR finalizer `_finalize` (SplitMix64/fmix64,
> multiply+xorshift). Lives in `engine.py` so all 3 layers (engine/multimap/ctr) inherit it.
> **(#4) More bytes per step** — emit `OUTPUT_BYTES_PER_STEP=4` of 8 bytes per chaotic step (buffered).
> Honest: no Python speedup yet (branchless map = 4× arithmetic/step, Python per-byte overhead dominates)
> — the #4 win materializes only in Rust. 4 is a conservative placeholder, to be confirmed after #1.
> **Attacked (`attacks/output_filter_attack.py`, 4 parts, all PASS):** (1) output reveals no contiguous
> state slice (best window match 0.004 ≈ 1/256, was 1.000); (2) the exact known-plaintext break that
> cracks the old cipher now FAILS to predict future keystream; (3) attacker who knows the filter loses
> the free 8 bits (2^(n-8) anchored search → full 2^n, no affine shortcut); (4) no new bias (worst bit
> 1.91σ, χ²=278, serial 0.0007). Avalanche 0.4976. **Precise claim:** the filter HIDES the state from the
> output — NOT "map is now non-invertible" (it still is); protection rests on truncation + 3-map XOR.
> Still UNVETTED. 72/72 tests pass.


### ✅ DONE 2026-06-06: v9 — period census (answered §2, the chaos make-or-break question)
> On branch `period-census`. Built `attacks/period_census.py` to answer the veteran's #1 question —
> "what's the GUARANTEED period over EVERY key, not the one orbit Brent measured?" Four parts:
> (A) FULL functional-graph census at small grids (2^13–2^21) = every state mapped, not sampled;
> (B) trap hunt on the real 2^61 grid over 1,000 production-seeded keys (real SHA-512 KDF path), 200k
> budget; (C) 7 adversarial edge inputs; (D) period scaling law. **Finding:** the map is a RANDOM
> FUNCTION (tails merge), so period scales as **√M ≈ 2^30, NOT 2^61** — measured exponent 0.489 (0.50 =
> pure √N), extrapolating to ~2^29.5 ≈ 7.4e8 at k=61. Honest downward correction of the *implied* period
> by ~2^30 (same spirit as v6's 2^159→2^122). **Not a break:** B found 0 traps in 1,000 keys, C 0/7;
> fixed points ~1/map (random-function Poisson(1)) with basin ~1/√M ⇒ ~1e-9 capture, and even then only
> 1 of 3 maps goes quiet. Mitigated by the 3-map combiner (lcm ~2^90), CTR mode, and a per-key data limit
> (rekey < ~1 GB single-map). REPORT **v9** section + table + summary rows. Upgraded `tests/test_period.py`
> from 1 orbit to a **1,000-marble regression guard**. **72/72 tests pass.** Pre-merge on `period-census`.

### ✅ DONE 2026-06-06: Suggestion 3 — authenticated DH, the "secret handshake"
> Merged Suggestion 2 (`nonce-misuse-siv`) to `main` first (fast-forward `5f6f76d`). Then, on branch
> `auth-dh-handshake`, built `auth_keyexchange.py` — **authenticated Diffie-Hellman** that closes the
> active man-in-the-middle gap demonstrated in `attacks/dh_mitm.py`. Plain DH proves nobody *passive*
> can read you but NOT *who* you're talking to; the only prior defence was a human eyeballing a
> fingerprint each session. Now the identity check is baked into the key via the **triple-DH /
> static+ephemeral** pattern (the vetted Noise-framework / Signal-X3DH construction — NOT homemade).
> Each party has a long-term STATIC identity keypair (fingerprint verified out-of-band ONCE) plus a
> fresh EPHEMERAL keypair per session; the session key = SHA-512(label‖info‖ee‖sorted(es,se)) where
> ee=eph×eph (forward secrecy), es=eph×peer-STATIC, se=STATIC×peer-eph (the two identity binders).
> **Why MITM fails:** to derive Alice's key Mallory must reproduce es=DH(Alice_eph, Bob_static), which
> needs Alice's ephemeral private OR Bob's static private — she has neither, so her key can't match
> and the ciphertext won't open (no manual check needed). Added `raw_shared_secret()` to `DHParty` as
> the reusable building block (behaviour of `shared_key` unchanged). Proof: `attacks/auth_dh_mitm.py`
> runs the full middleman scenario → FAILS; `tests/test_auth_keyexchange.py` (+10) covers agreement,
> info-binding, end-to-end AEAD, MITM/impostor rejection, degenerate-key rejection. **71/71 tests
> pass.** REPORT.md **v8** section + comparison table. Honest caveat: authenticates whoever's static
> key you verified — wrong first-contact fingerprint = wrong person (same trust root as TLS/SSH);
> security rests on 2048-bit discrete log (vetted), not chaos. **All three hardening suggestions now
> DONE.** Pre-merge on `auth-dh-handshake`.

### ✅ DONE 2026-06-06: Suggestion 2 — the SIV "seatbelt" (nonce-misuse resistance)
> Merged Suggestion 1 (`core-cryptanalysis`) to `main` first (fast-forward `859792f`). Then, on branch
> `nonce-misuse-siv`, built `siv.py` — a **deterministic, nonce-misuse-resistant AEAD** in the proven
> SIV shape (Rogaway–Shrimpton / RFC 5297 AES-SIV) over the chaos keystream. The foot-gun it removes:
> `aead.py` is safe **only while every nonce is unique**; one reused nonce → same keystream → two-time-pad
> break. SIV deletes the foot-gun by having **no nonce at all** — the IV is synthesised from the message:
> `SIV = HMAC-SHA256(K_siv, len(aad)‖aad‖plaintext)`, and that 32-byte value is used as **both** the
> keystream IV **and** the auth tag (wire format `SIV(32)‖ciphertext`). On open: decrypt with the received
> SIV, recompute it from the recovered plaintext, constant-time compare → mismatch raises `InvalidTag`,
> plaintext never returned. **Guarantees:** different messages NEVER share a keystream (the classic
> `C0⊕C1 = M0⊕M1` equality no longer holds — proven in `test_two_time_pad_cancellation_does_not_leak`);
> identical messages seal identically (deterministic — leaks only equality, the unavoidable minimum), with
> an escape hatch (random salt in `aad`) tested too. `tests/test_siv.py` adds 12 tests; **61/61 pass.**
> REPORT.md **v7** section + comparison table added. Honest framing: this fixes a *usage* foot-gun with a
> vetted construction; it does NOT change the chaos core's UNVETTED status. Pre-merge on `nonce-misuse-siv`.

### ✅ DONE 2026-06-06: Suggestion 1 — "clever-burglar" cryptanalysis of the 3-map combiner
> Branch `core-cryptanalysis`. Built `attacks/core_cryptanalysis.py`: three attacks designed for a
> COMBINER (the old `known_plaintext.py` Part C only tried the naive single-map attack), each
> *measured*. **A — bias hunt:** per-bit bias, byte χ², serial corr (lags 1–8), 104-mask linear-parity
> battery on the shipped keystream → strongest 2.52 σ over ~121 tests = looks random, no exploitable
> bias. (First run reported a fake 547 σ from a self-inflicted bug — masks XOR'ing a bit with itself;
> caught + fixed, then clean.) **B — independence/sync:** sub-map↔combined & sub-map↔sub-map corr +
> sync detector → max 1.71 σ = maps truly independent, no chaos-sync. **C — meet-in-the-middle:** guess
> 2 maps, 3rd is forced + table-looked-up; succeeds at small scale (predicts unseen keystream) and
> shows real search space is 2^(2·state) **not** 2^(3·state) → honest correction of REPORT's 2^159 to
> ~**2^122** (~2^37× weaker than claimed, still astronomically safe). REPORT.md **v6** section added.
> Verdict unchanged: UNVETTED — 2/3 clever attacks found nothing, the 3rd tightened our own overclaim.
> The project got stronger by attacking itself. Pre-merge on `core-cryptanalysis`.

### ✅ DECISION 2026-06-06: Next-phase direction set — harden, then Option B for AsturAI
> Strategic decision, no code yet. The completed roadmap left the project at a "clean stop"; the user
> wants a unique, powerful, secure system for their projects — especially to protect the **AsturAI**
> engine and its **clients' private data**. Set the path: **(1) now** — genuinely strengthen the chaos
> cipher's security (target chosen next; each idea must be *measured/attacked*, not asserted); **(2)
> later** — once meaningfully stronger, deploy it as the **outer layer wrapped around a vetted AEAD**
> (ChaCha20-Poly1305 / AES-GCM / libsodium), i.e. "Option B" defense-in-depth — **never as the sole
> protection.** Reaffirmed the non-negotiable: *homemade/unique ≠ secure until publicly attacked for
> years*; the vetted primitive does the real protecting, chaos adds a unique extra wall on top. This
> makes the v1 REPORT recommendation the official roadmap and moves the project from "COMPLETE" to a
> security-hardening phase. NEXT rewritten accordingly.

### ✅ DONE 2026-06-06: 100 MB randomness battery (`ent` + NIST-lite) — PASSED
> Ran the full `ent` (Fourmilab) battery on **100 MB** of the SHIPPED 3-map keystream
> (`MultiMapEngine`), plus the NIST-lite bit subset on a slice. `bench/randomness.sh` updated to dump
> the shipped multimap (was single-map). Results: entropy 7.999998/8, chi-square 261.62 (exceeded
> 37.45% — dead center), arithmetic mean 127.4968, Monte-Carlo π error 0.00%, serial correlation
> 0.000113; bit-mode all ideal; NIST-lite monobit/runs/block-frequency all pass. **Verdict:**
> statistically indistinguishable from random — a strong PRNG result. Honest caveat (in REPORT.md):
> passing randomness ≠ secure (Mersenne Twister passes these too and is broken); status stays
> UNVETTED. Heavyweight `dieharder`/PractRand were NOT run — both removed from Homebrew, need a
> source build (left as optional). 100 MB dump at `/tmp/chaos_ks_100mb.bin`.

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

