# Chaos Cipher (Progress)

Last updated: 2026-07-02 (repo public!) | Branch: main | Status: 🚀 **LIVE** — repo public at github.com/Evansimon77/three-body-problem-cipher. Grade 90/100 Elite, README rewritten, MIT licensed. Only Phase 7 (external review) remains.

---

### ✅ DONE 2026-07-02: Consolidated last 4 copy-paste patterns — grade 87 → 90/100 (Elite)
> Branch `phase6-two-locks`, commit `dfd9545`. Fixed the 4 remaining weaknesses the handoff listed:
> (1) lo128 dedup — moved M/HALF/u to constants.rs so engine.rs can import the canonical copy from
> utils.rs instead of defining its own. (2) _kdf — single copy in ratchet.py, ratchet_aead.py imports
> it. (3) DH_BYTES — canonical in keyexchange.py, imported by pq_keyexchange and auth_pq_keyexchange.
> (4) _tag/_finalize renamed to public tag/finalize — KAT generator and attack scripts now use the
> public API, no more reaching through private doors. All 183+28+36 tests pass, ruff clean.
> ▶ Next: merge to main, make repo public, write a short launch post. Only Phase 7 remains.

### ✅ DONE 2026-07-02: README rewrite + MIT license
> Branch `phase6-two-locks`, commit `ac6f216`. Rewrote the stale v2-era README to reflect the real
> project: 4-map/2^127 grid, Rust core, two-locks, PQ KEX, 15-attack battery, honest ~254-bit claim.
> New opening leads with the three-body-problem hook — simple rules, unpredictable output — and makes
> the honest distinction between orbital chaos and PWLCM. Added standard MIT license. Discussed
> dual-licensing with Evan: MIT now doesn't block a paid commercial license for a future vetted
> version; the audited version is what people would pay for.
> ▶ Next: remaining cleanup items (lo128 dedup, _kdf consolidation, _DH_BYTES) to push the grade
> from 87→90, or merge to main and make the repo public.

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
- [x] **Phase 2 — Attack our own design HARD** ✅ COMPLETE 2026-06-28 (5/5 items; all survived):
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
  - [x] **#7 heavy randomness** — DONE 2026-06-28, on the REAL shipped path (4-map under the auto-rekey
        ratchet, via `bench/stream_keystream.py` + rewritten `bench/randomness.sh`; built PractRand 0.95
        from source). **PractRand: clean through 128 MB (199 tests); one "unusual" blip at 256 MB
        (DC6, the mildest level) that a 512 MB confirmation run made VANISH (232 tests clean) — escalation
        is the signature of a real flaw; vanishing = multiple-testing noise. Confirmed noise.** `ent` on
        64 MB: 7.999997/8 bits/byte, serial corr −0.0001, Monte-Carlo π error 0%. NIST-lite passes across
        ~30 re-key seams. (dieharder skipped — removed from Homebrew core; PractRand supersedes it.)
- [x] **Phase 3 — Freeze + write the contract:** ✅ COMPLETE 2026-06-28
  - [x] **§3 KAT** frozen vectors — `kat/vectors.json` (frozen via `kat/generate_kat.py --write`)
        covers every deterministic layer the Rust port must match bit-for-bit: finalize mixer,
        raw PWLCM engine (incl. all-zero-key edge), from_master KDF, multimap (n=1 and 4), ratchet
        across 2 re-key seams, and the deterministic SIV AEAD end-to-end. `tests/test_kat.py`
        enforces it (4 tests); PROVEN to bite — a one-char mixer drift (`>>31`→`>>30`) is caught.
  - [x] **E. Threat-model + bit-security claim** — `THREAT_MODEL.md` (attacker model, threat→answer
        table, honest **~254-bit** claim = smallest of MITM ~2^254 / worst-case TMTO ~2^254 / key
        2^256; true ceiling = key/KDF, not the chaos math; residual risks listed).
  - [x] **Constant-time spec** — `CONSTANT_TIME.md`, grounded in NEW `bench/timing_leak.py`:
        BRANCH leak CLOSED (measured 1.0% spread across regions); DIVIDE-by-secret leak OPEN
        (3.6% spread = no Python-level signal, masked by interpreter overhead — a hardware/Rust
        concern), with the precomputed-reciprocal (Barrett/Montgomery) port plan written out.
- [~] **Phase 4 — Rust core (the speed blocker):** IN PROGRESS — Stage A done 2026-06-29.
      - [x] **#5 Rust hot loop (Stage A)** — `rust/` crate ports the per-byte engine (init avalanche,
            PWLCM step, finalizer, 4-byte output buffer); **bit-identical to the frozen KAT** (3/3
            engine_raw vectors, incl. all-zero-key edge + max-ish), proven by `tests/test_rust_parity.py`
            (auto-skips if unbuilt) + 3 Rust unit tests. **Measured ~43× faster** (74.3 vs 1.74 MB/s)
            even with big-int division still in the loop. Single masked numerator/divisor select + ONE
            division per step (the shape Stage B needs).
      - [x] **§4 precomputed reciprocal (Stage B)** — DONE 2026-06-29. Replaced the Stage-A big-int
            division with a Barrett-style precomputed reciprocal: at key setup compute `V = floor(M·2^127/d)`
            once per divisor (`p`, `HALF-p`); per step `q = ((num·V)>>127) + (rem>=den)` — one branchless
            correction, no hardware divide on the secret in the hot loop. **Timing-leak #2 CLOSED**, measured
            (`chaos_core timing 128`): 0.41% spread across 128 secret keys (was 3.6% Python-masked). Verified
            against the `ruint` big-int oracle over ~4.8M random (num,den) pairs (`recip_div_matches_bigint_oracle`)
            AND bit-identical to the frozen KAT (3/3). Honest note: speed stayed ~75 MB/s (no gain — `ruint`'s
            divide ≈ a couple of its multiplies); the deliverable was constant-time, not throughput. Caught a
            stale Stage-A comment: region 3 at x==HALF gives num==den+1, not num<=den — reciprocal made exact
            across that range. Used a hand-rolled branchless `select` + `ruint` U256, not Montgomery/`subtle`.
      - [x] **port multimap + KDF (Stage C)** — DONE 2026-06-29. Rust now makes the REAL shipped
            keystream: `ChaosEngine::from_master` (seed KDF) + `MultiMapEngine` (N independent maps
            XOR-combined), real SHA-512 via the vetted `sha2` crate; the 192-bit hash output is reduced
            mod M / mod HALF exactly as the engine does. Bit-identical to the frozen KAT for from_master,
            multimap n=1 and n=4 (parity 6/6, full suite 91/91). New CLI: `from_master`, `multimap`.
      - [x] **port the auto-rekey ratchet (Stage D)** — DONE 2026-06-29. `RatchetEngine` over
            `MultiMapEngine`: one-way HMAC-SHA256 chain (vetted `hmac` crate), fresh 4-map engine per
            epoch, `nonce|ep|<idx>` epoch nonce — bit-identical to the frozen ratchet KAT across 2+
            re-key seams (parity 7/7, suite 92/92). **zeroize CLOSED**: each retired chain key wiped in
            place on re-key + live key on drop (honest residual: trusted-crate buffers + transient stack
            copies not scrubbed — documented). New CLI: `ratchet`. THREAT_MODEL/CONSTANT_TIME updated.
      - [x] **batch the 4-map combiner + benchmark vs AES/ChaCha (Stage E)** — DONE 2026-06-29.
            Restructured `MultiMapEngine` to step all maps in a batch + XOR (`next_block`), bit-identical
            (parity 7/7, suite 92/92). Modest +8% (56.9→61.4 MB/s): 8-map scales linearly with map count,
            so it's execution-port-bound on the 256-bit multiplies, NOT latency-bound — map-level overlap
            can't help much. Honest reality-check: ~37× slower than ChaCha20 (2,272 MB/s), ~149× slower
            than AES-NI (9,082 MB/s) — confirms the outer-wall-only design; still ~35× faster than Python.
            Bigger SIMD/arithmetic rewrite deliberately NOT done (disproportionate for an unvetted outer
            wall). [ ] CTR blocks (deferred — design choice, not started).
      - [x] **differential fuzz Rust==Python (Stage F)** — DONE 2026-06-29. `tests/test_rust_fuzz.py`:
            hundreds of random (mode, key, nonce, params, length) cases from a FIXED seed (reproducible,
            never flaky), Python reference computed live vs the Rust binary, byte-for-byte across all 4
            modes (ks, from_master, multimap, ratchet); edge values + small ratchet epochs (cross several
            seams); self-guards that every mode ran. Zero divergence over a 3000-case soak; suite 93/93.
            **Phase 4 feature-complete for the shipped cipher** (only the unstarted CTR feature remains).
- [x] **Phase 5 — Harden the shell:** ✅ COMPLETE 2026-06-29 (4/4; each built AND attacked/measured).
  - [x] **#6 key-commitment** — explicit CMT-4 commitment (`commit.py`) binds each blob to one key;
        wired into `aead.py` + `siv.py`. Cross-key forgery needs an HMAC-SHA256 collision (~2^128),
        measured via a birthday search (`attacks/commitment_attack.py`, fitted exponent ≈0.5). Honest:
        our HMAC tag was already a committing MAC; the explicit field makes CMT-4 provable.
  - [x] **B. streaming / chunked AEAD** — `streaming.py` (STREAM construction): per-chunk HMAC binds
        index + `final` flag, defeating reorder / drop / duplicate / truncate on top of tamper + the
        key-commitment header. Validated `attacks/streaming_attack.py` + 16 tests.
  - [x] **A. auto-rekey wired in** — `ratchet_aead.py`: forward-secret SESSION AEAD; each message keyed
        from a one-way burned HMAC chain, sealed with the committing AEAD. Capture state at msg C → read
        C onward, never 0..C-1. Validated `attacks/ratchet_aead_attack.py` + 9 tests.
  - [x] **F. post-quantum hybrid KEX** — `pq_keyexchange.py`: classical DH (RFC 3526 MODP-2048) mixed
        with **vetted ML-KEM-768** (FIPS 203, via `cryptography`/OpenSSL 3.5 — NOT hand-rolled) through a
        transcript-bound combiner; key safe if EITHER primitive holds → defeats harvest-now-decrypt-later.
        Validated `attacks/pq_hybrid_attack.py` (hybrid survival 64/64 each side, avalanche 128.6/256) +
        8 tests (auto-skip if ML-KEM absent). Unauthenticated (like plain DH) by design.
- [x] **Phase 6 — THE SECURITY GOAL: two locks** ✅ COMPLETE 2026-06-29 (branch `phase6-two-locks`,
      commit `912202c`). `twolock.py`: chaos AEAD is the OUTER wall over a vetted inner vault
      (AES-256-GCM default, ChaCha20-Poly1305 option), independent HKDF-SHA256 keys, self-describing
      blob (`alg||inner_nonce||inner_ct` encrypted+authenticated by the outer chaos layer). Order
      locked: vetted INSIDE (the lock the plaintext depends on), chaos OUTSIDE (the exposed, sacrificial
      barrier). MEASURED in `attacks/twolock_attack.py` (5/5): even granting the attacker a TOTAL chaos
      break (the outer key), peeling the wall leaves AES-256-GCM — 0/67 wrong-key opens, plaintext
      unrecoverable; the inner vault independently catches a forgery the outer alone waved through; keys
      independent (≈128/256 bit-diff). +16 tests, suite 145 pass, ruff clean, Rust contract untouched
      (parity+fuzz 8/8). THREAT_MODEL.md updated. Honest: proves the DEPLOYMENT safe, NOT the chaos math.
- [~] **Authenticated PQ handshake** (extends Phase-5 item F) — DONE 2026-06-29, commit `93b63bc`.
      `auth_pq_keyexchange.py`: confidentiality = ephemeral DH + ML-KEM-768; authentication = triple-DH
      static binding AND vetted ML-DSA-65 (FIPS 204) signatures over the transcript — hybrid on both
      axes, an impostor must break BOTH to impersonate. `attacks/auth_pq_attack.py` (6/6) grants a total
      break of each auth leg and shows the other still holds. Closes item F's "unauthenticated" caveat.
- [~] **Phase 8 — Complete the fast Rust core** (mirror every Python capability in Rust; value-order,
      speed-critical bulk path first). IN PROGRESS 2026-06-29, branch `phase6-two-locks`.
  - [x] **8.1 committing AEAD** — Rust full seal/open (HMAC tag + CMT-4 commitment + multimap XOR,
        constant-time verify); CLI `aead_seal`/`aead_open`; `aead` KAT + parity + Python↔Rust interop.
  - [x] **8.2 streaming AEAD** — STREAM construction (per-chunk index + final-flag); CLI `stream_seal`/
        `stream_open`; `stream` KAT + parity + interop; optional fixed-`salt` arg added to streaming.py.
        Both 8.1/8.2 ride existing `hmac`/`sha2` crates (no new deps). Commit `ff9ab1e`.
  - [x] **8.3 ratchet session AEAD** — DONE 2026-06-29, commit `5057d54`. `RatchetAeadSender`/`Receiver`
        port ratchet_aead.py: one-way HMAC-SHA256 chain over the Phase-8.1 committing AEAD, index sealed
        into inner aad, each burned link zeroized in place. CLI `ratchet_aead_seal`/`ratchet_aead_open`;
        deterministic `ratchet_aead` KAT (3-msg session, 2 chain seams) + parity + Python↔Rust interop.
        No new deps; ONLY the new KAT block changed (contract intact).
  - [ ] **8.4 two-locks wrapper** (port twolock.py — adds a vetted AES-256-GCM crate + HKDF).
  - [ ] **8.5 classical + PQ-hybrid key-agreement** (port keyexchange/pq_keyexchange — big-int DH + ML-KEM crate).
  - [ ] **8.6 authenticated PQ handshake** (port auth_pq_keyexchange — ML-DSA crate). Last; completeness, no speed gain.
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

### ✅ DONE 2026-06-29: Official name — "Three-Body Problem Cipher" (short handle 3BP)
> Branch `phase6-two-locks`, commit `2dc2ecf`. Renamed from the generic "Chaos Cipher" to a name with
> instant recognition (chosen via identity naming method + marketing borrowed-recognition lens): the full
> famous phrase beats a fragment because the brain recognises the whole familiar chunk. Name system =
> display **Three-Body Problem Cipher** · handle **3BP** · tagline "Encryption built on the problem no one
> can solve." `scorecard.html` retitled + tagline + all comparison labels/footer updated; "chaos" kept
> only as a description of the math. Domains free (threebodyproblemcipher.com, threebodycipher.com/.io,
> 3bpcipher.com); no trademark conflict. **Honest caveat:** the three-body-cipher concept exists in
> academic papers (IACR ePrint 2021/542) → present as an independent build of a known idea, not a first.
> Repo/folder still `chaos-cipher` (not renamed; bigger change, only if asked). No code/keystream touched.

### ✅ DONE 2026-06-29: Reworked `scorecard.html` into a non-technical client DEMO
> Branch `phase6-two-locks`, commit `0bbb67c`. Same page, retargeted at the people who'll hire Evan (mostly
> non-technical — that's WHY they hire him), so plain English leads and technical detail is secondary.
> Changes: (1) default view plain/friendly, engineer specs hidden behind a "🔧 Show technical details"
> toggle; (2) new lead section "Is it fast enough?" — a chart of real files (contract ~0.03 s, photo
> ~0.08 s) vs a "blink ≈ 0.1 s" line, so "~149× slower" can't be misread as "too slow"; raw speed-vs-AES
> kept but inside the toggle; (3) each component card gets a plain "what it means for you" line + a
> real-world analogy; (4) comparison table gains a plain-words takeaway column; (5) "UNVETTED" reworded to
> "not yet expert-reviewed" and reframed as a credibility asset (pitch = honest, careful engineering, NOT
> "I beat AES"). No engine/keystream touched → Rust contract intact. Still UNVETTED; only Phase 7 remains.

### ✅ DONE 2026-06-29: Visual scorecard + honest head-to-head vs AES-256-GCM (`scorecard.html`)
> Branch `phase6-two-locks`, commit `8a29c91`. A deliverable, not a build — a self-contained HTML page
> (no internet needed) that shows the whole project at a glance. Four parts: (1) a five-card parts list
> (chaos engine · safe shell · two-locks · key agreement · proof/tooling, each with parameters); (2) speed
> bars on a log scale; (3) a head-to-head table vs AES-256-GCM; (4) a radar chart of the trade-off shape.
> **Honest framing on purpose:** stamped UNVETTED; states plainly we did NOT beat AES (~149× slower,
> world-trusted); a callout warns the table compares AES as a *bare cipher* (in TLS 1.3 AES also gets
> forward secrecy + PQ key exchange) so our protocol-feature "wins" come from the wrapper, not the chaos
> math. Numbers = current Rust core 61 MB/s vs ChaCha20 2,272 / AES-NI 9,082 (measured today); noted
> REPORT.md's old "2.6 MB/s / 786×" is the stale Python figure. No engine/keystream touched → Rust
> contract intact. Status unchanged: UNVETTED; only Phase 7 (external review) remains.

### ✅ DONE 2026-06-29: Phase 8.3 — Rust ratchet session AEAD (forward-secret sessions in the fast core)
> Branch `phase6-two-locks`, commit `5057d54`. The Rust core could lock a single message (8.1) and a big
> streamed payload (8.2); 8.3 adds the forward-secret SESSION — a chat where each message gets its own
> throwaway key, destroyed once used, so a device captured mid-conversation reads from *now* on but never
> the earlier messages. Port of `ratchet_aead.py`.
> **What:** `RatchetAeadSender`/`RatchetAeadReceiver` advance a one-way HMAC-SHA256 key chain once per
> message and seal each with the Phase-8.1 committing AEAD (so every message inherits confidentiality +
> integrity + key-commitment). The 8-byte message index is sealed into the inner AEAD's aad, so tampering
> with the wire index makes the open fail; gaps are tolerated by fast-forwarding (and burning) skipped
> links. New CLI modes `ratchet_aead_seal`/`ratchet_aead_open`. Rides the `hmac`/`sha2` crates — NO new deps.
> **Stronger than Python in memory:** each retired chain link is wiped IN PLACE (`zeroize`) and the live
> link on drop — the forward-secrecy guarantee Python could only intend (its `del` drops a reference).
> **Small, safe Python addition:** optional `nonce=` on `aead.seal` + `inner_nonce=` on
> `SenderSession.seal`, default random → production behaviour UNCHANGED; the fixed path exists only so the
> KAT can pin the one source of nondeterminism (safe: each message already has a unique chain key, so a
> fixed inner nonce can never reuse a keystream). Mirrors how 8.2 added `salt=` to streaming.py.
> **Proof:** new deterministic `ratchet_aead` KAT — a 3-message session crossing TWO chain seams (index
> 0→1→2). Regenerated vectors.json and proved byte-for-byte that ONLY that block was added — every
> keystream/aead/stream vector byte-identical, frozen Rust contract intact. Parity: Rust reproduces all 3
> wires, opens them back, rejects a tampered ciphertext, rejects a bumped wire index, AND real interop
> (Python opens the session Rust sealed). Rust unit tests **10/10**, full Python suite **167 pass**,
> parity/kat/fuzz **25**, ruff clean, zero new clippy warnings, attack battery 6/6. Still UNVETTED.
> ▶ Next Phase 8: **8.4 two-locks wrapper** (port twolock.py) — this is where new Rust deps start
> (vetted AES-256-GCM + HKDF). Then 8.5 PQ-KEX (ML-KEM), 8.6 auth-PQ (ML-DSA), then Phase 7 (external review).

### ✅ DONE 2026-06-29: Phase 8.1 + 8.2 — Rust committing AEAD + streaming AEAD (fast core can lock real data)
> Branch `phase6-two-locks`, commit `ff9ab1e`. The Rust core made the keystream but couldn't encrypt+
> authenticate a message end to end; Phase 8 completes the fast version in value-order (speed-critical
> bulk path first, handshakes later). **8.1** ports aead.py+commit.py: full seal/open = HMAC-SHA256 tag
> + CMT-4 key-commitment + XOR over the multimap keystream, constant-time verify (CLI `aead_seal`/
> `aead_open`). **8.2** ports streaming.py: the STREAM construction — chunk-by-chunk, each chunk's HMAC
> binds its index + a final-flag so reorder/drop/duplicate/truncate are caught (CLI `stream_seal`/
> `stream_open`); added an optional fixed-`salt` arg to streaming.py for deterministic KAT use. Both ride
> the `hmac`/`sha2` crates already present — NO new dependencies.
> **Proof:** new `aead` + `stream` KAT vectors (deterministic via fixed nonce/salt); regenerated
> vectors.json and proved byte-for-byte that ONLY those two blocks changed — every keystream vector
> untouched, frozen Rust contract intact. Parity: Rust seal == frozen blob, open round-trips, tamper →
> INVALID, AND Python opens Rust-sealed blobs (real interop) — for both AEAD and streaming. Rust unit
> tests 8/8, full Python suite 162 pass, ruff clean, zero new clippy warnings. Still UNVETTED.
> ▶ Next Phase 8: 8.3 ratchet-AEAD, 8.4 two-locks (adds AES-GCM crate), 8.5 PQ-KEX (ML-KEM), 8.6 auth-PQ (ML-DSA).

### ✅ DONE 2026-06-29: Authenticated post-quantum handshake — hybrid confidentiality + hybrid authentication
> Branch `phase6-two-locks`, commit `93b63bc`. New `auth_pq_keyexchange.py` fuses the two halves we had
> separately: quantum-safe confidentiality (DH + ML-KEM-768) that couldn't prove WHO you talk to, and
> authentication (triple-DH) whose proof a quantum computer breaks. Now both, doubled-up on each axis:
> confidentiality = ephemeral DH + ML-KEM-768; authentication = triple-DH STATIC binding AND vetted
> ML-DSA-65 (FIPS 204) signatures over the full transcript. An attacker must break BOTH authentication
> mechanisms to impersonate. Three flights (SIGMA/TLS pattern); vetted primitives only.
> **Proof, MEASURED** (`attacks/auth_pq_attack.py`, 6/6): grant a TOTAL break of one auth leg, show the
> other holds. "Quantum broke DH" (give her the static private) → ML-DSA signature still rejects her.
> "ML-DSA broke" (let her sign as Bob) → static binding still locks her out (can't compute es → wrong
> key → can't read traffic). +9 tests; suite green; ruff clean; Rust contract untouched. THREAT_MODEL.md
> gained an "active MITM that also survives quantum" row. One real bug found+fixed (swapped verify args).
> Still UNVETTED.

### ✅ DONE 2026-06-29: Phase 6 — two locks ("Option B"), THE SECURITY GOAL
> Branch `phase6-two-locks` (off `phase5-aead-harden`), commit `912202c`. The deployment that makes an
> UNVETTED cipher safe to ship: wrap the data in two independent locks, one inside the other.
> **The design (`twolock.py`).** `plaintext → [INNER vault: AES-256-GCM] → [OUTER wall: chaos AEAD] →
> wire`. The inner vault is a real world-standard cipher (AES-256-GCM default, ChaCha20-Poly1305 option,
> both via the vetted `cryptography` lib) and is the lock that actually guarantees the data; the chaos
> AEAD (`aead.py`) is the exposed outer wall. The two locks NEVER share a key — split with HKDF-SHA256
> under distinct labels (`...|inner-vault|v1`, `...|outer-wall|v1`). The outer layer encrypts+authenticates
> `alg(1)||inner_nonce(12)||inner_ct`, so the blob is self-describing (open needs no hint) and the inner
> cipher id can't be read or tampered. **Order rationale:** the lock the plaintext ultimately depends on
> MUST be the vetted one → it goes INSIDE; chaos goes OUTSIDE because that's where we want the unproven
> experiment exposed to real attacks. (Considered and rejected chaos-inside/vetted-outside — that would
> make a chaos break expose the plaintext — and a shared key — basic hygiene says split.)
> **The guarantee, MEASURED not asserted (`attacks/twolock_attack.py`, 5/5).** Part 1 HEADLINE: grant the
> attacker a TOTAL chaos break (hand them the outer key). They peel the wall clean off and hit
> AES-256-GCM with no inner key — plaintext not in the recovered bytes, 0/67 wrong-key guesses opened the
> vault, only the legit inner key opens it. Part 2: still holding the outer key, the attacker tampers the
> data and re-seals a VALID outer layer; the outer-alone accepts it but the inner AES-GCM catches the
> forgery → proves the inner lock is real, not redundant. Part 3: keys independent (mean bit-diff
> 127.7/256; one-bit master flip avalanches both ≈128/256) → breaking the outer key leaks nothing about
> the inner. Part 4: ordinary attacker (no keys) — 10/10 tamper/wrong-key/wrong-aad rejected, both inner
> ciphers. Part 5: honest framing.
> **Verified:** full suite **145 pass** (was 129; +16 `tests/test_twolock.py`); all 5 attack scripts PASS;
> ruff clean. Touched NO engine/keystream code → `kat/vectors.json` unchanged and **Rust parity+fuzz
> re-ran 8/8** → Phase-4 Rust contract intact. THREAT_MODEL.md updated (new "chaos broken at all" threat
> row + residual-risk note). New files: `twolock.py`, `attacks/twolock_attack.py`, `tests/test_twolock.py`.
> **Honest scope:** this proves the DEPLOYMENT is safe — an unvetted outer wall cannot endanger data
> behind a vetted inner vault. It does NOT make the chaos keystream proven-secure; it stays UNVETTED, by
> design. Two-lock is non-deterministic (random nonces in both layers) so there is no KAT vector for it.
> ▶ **Phase 6 COMPLETE.** Only **Phase 7 (external review)** remains on the master roadmap. Side-roads
> still open: authenticated PQ handshake, port the Phase-5/6 shell to Rust, parked AsturAI Option-B bridge.

### ✅ DONE 2026-06-29: Phase 5 — harden the shell (4/4: key-commitment · streaming · forward-secret session · PQ-hybrid)
> Branch `phase5-aead-harden` (off `branchless-core`). Four shell-level security features, each BUILT
> and ATTACKED/measured (project ethos), all riding vetted HMAC/SHA/ML-KEM — the chaos keystream stays
> UNVETTED and that is labelled in every new file.
> **#6 KEY-COMMITMENT.** New `commit.py`: `C = HMAC(HMAC(key,"commit-key"), salt‖aad)`, a CMT-4
> commitment binding key+salt+aad, wired into `aead.py` and `siv.py` (new wire field; the integrity tag
> now also covers it). Closes the key-confusion attack that breaks AES-GCM/ChaCha20-Poly1305. Honest:
> our HMAC tag was already a committing MAC, so we'd largely avoided it; the explicit field makes it
> provable. `attacks/commitment_attack.py` measures a birthday search for a colliding key — fitted
> exponent 0.467 ≈ the 0.5 law → ~2^128 to forge, infeasible. Caught a latent smell: `aead.py` and
> `siv.py` define SEPARATE `InvalidTag` classes (the attack must catch both).
> **B. STREAMING AEAD.** New `streaming.py` (STREAM construction, like age/Tink): encrypt a big file or
> live feed chunk-by-chunk; each chunk's HMAC binds its index + a `final` flag, so reorder/drop/
> duplicate/truncate are all caught on top of tamper. Header carries a key-commitment too.
> `attacks/streaming_attack.py` + 16 tests confirm all five manipulations rejected.
> **A. FORWARD-SECRET SESSION (wires the ratchet in).** New `ratchet_aead.py`: a session of messages,
> each keyed from a one-way HMAC chain that burns the prior key, sealed with the committing AEAD.
> Capture the live state at message C → read C onward, never 0..C-1. `attacks/ratchet_aead_attack.py`
> + 9 tests. Honest scope: forward (past) secrecy only — future-secrecy after a live capture needs the
> asymmetric/PQ ratchet; in-order delivery assumed.
> **F. POST-QUANTUM HYBRID KEX.** New `pq_keyexchange.py`: classical DH (RFC 3526 MODP-2048) mixed with
> **vetted ML-KEM-768** (FIPS 203, from `cryptography`/OpenSSL 3.5 — explicitly NOT hand-rolled, per the
> standing rule) via a transcript-bound SHA-512 combiner. Key is safe if EITHER primitive holds →
> defeats harvest-now-decrypt-later. `attacks/pq_hybrid_attack.py`: hybrid survival 64/64 each side,
> one-bit avalanche 128.6/256. 8 tests, auto-skip if ML-KEM absent. Unauthenticated by design (parallels
> `keyexchange.py`); active-MITM still needs `auth_keyexchange.py` + a future PQ signature.
> **Verified:** full suite **129 pass** (was 93); ruff clean; THREAT_MODEL.md updated (4 new threat
> rows + closed-item notes); SIV KAT regenerated — DIFF confirmed ONLY the `siv` vector changed, the
> five engine/keystream vectors are byte-identical, and the Rust parity+fuzz tests re-ran green, so the
> Phase-4 Rust contract is intact. New functional dep: `cryptography` (already present) now also powers
> the PQ KEM. Still UNVETTED. Commit: see git log on `phase5-aead-harden`.
> ▶ **Phase 5 COMPLETE.** Next: **Phase 6** — two-locks integration (chaos outer wall over a vetted
> inner AEAD vault, "Option B"), or external review (Phase 7).

### ✅ DONE 2026-06-29: Phase 4 Stage F — differential fuzz (Rust == Python over thousands of random inputs)
> Branch `branchless-core`. The frozen KAT pins only 7 fixed points; this widens the correctness net to
> broad random evidence. New `tests/test_rust_fuzz.py` draws hundreds of random cases from a FIXED seed
> (reproducible, never flaky), computes the Python reference live (same classes as `kat/generate_kat.py`)
> and asserts the Rust binary matches byte-for-byte across ALL four shipped modes (ks, from_master,
> multimap, ratchet). Mixes deliberate edge values (0, M and neighbours, half-grid, u128 ceiling) and
> small ratchet `epoch_bytes` vs longer lengths so most cases cross several re-key seams. On failure it
> prints the exact replay command; it also self-guards that every mode actually ran (no vacuous pass).
> **Result: zero divergence over a 3000-case soak**; default suite run is 240 cases (~1s). Full Python
> suite now **93/93** (was 92). The port's correctness now rests on a frozen contract AND random evidence.
> Tunable via `CHAOS_FUZZ_ITERS`. Files: `tests/test_rust_fuzz.py`. Commit `7b02e76`.
> ▶ **Stage F complete — Phase 4 is feature-complete for the shipped cipher.** Everything Python does,
> Rust now does, proven equal (hot loop, constant-time divide, KDF + 4-map combiner, ratchet + zeroize,
> benchmark, fuzz). Only the unstarted CTR-blocks feature remains on the Phase 4 line (a design choice,
> not a port gap). Natural next: a fresh idea/phase, or pick up the parked AsturAI Option-B bridge.

### ✅ DONE 2026-06-29: Phase 4 Stage E — batch the 4-map combiner + honest benchmark vs AES/ChaCha
> Branch `branchless-core`. The shipped cipher runs 4 independent maps XOR-combined; the old combiner
> interleaved them one byte at a time behind separate buffer branches, hiding their independence.
> **Built:** restructured `MultiMapEngine` to step all maps in a batch and XOR their per-step blocks
> (new `ChaosEngine::next_block`), exposing map-level instruction parallelism. Added a `benchmm` CLI.
> **Bit-identical** — proven by KAT parity holding 7/7 (a combined byte is still XOR-over-maps of each
> map's step bytes; buffering never affects the byte sequence). Full suite 92/92, Rust 4/4.
> **HONEST result — small win, clear cause:** 4-map went 56.9 → 61.4 MB/s (**+8% only**). Measured 1/4/8
> maps: 1-map 196, 4-map 61, 8-map 31 MB/s — throughput drops ~linearly with map count. That linearity is
> the diagnosis: the combiner is **execution-port-bound on the 256-bit multiplies** (all maps queue for
> the same multiplier units), NOT latency-bound — so overlapping maps can't help much. The 256-bit
> multiply is unavoidable (the Stage-B reciprocal turns the core divide into a genuine ~255-bit multiply).
> **Reality-check vs industrial ciphers (hardware-accelerated):** ChaCha20 ≈ 2,272 MB/s (**37× faster**),
> AES-128-CTR ≈ 9,082 MB/s (**149× faster**) — measured via Python `cryptography` + `openssl speed`.
> Confirms the project's own design: chaos is the UNVETTED *outer wall* over a fast vetted vault (Option
> B); speed is the inner cipher's job. We're still **~35× faster than the original Python** (~1.7 MB/s) —
> plenty for an outer layer on business records.
> **Deliberately NOT done:** SIMD-across-maps or a different arithmetic scheme — a large, platform-
> specific, bit-identity-risky rewrite, disproportionate for an outer-wall cipher whose speed isn't the
> point (Prime Directive: no over-engineering). Logged as a future option. Still UNVETTED. Files:
> `rust/src/lib.rs` (combiner + `next_block`), `rust/src/main.rs` (`benchmm`). Commit `028da56`.
> ▶ **Stage E complete.** Remaining Phase 4: differential fuzz Rust==KAT (random inputs, low-risk); CTR
> blocks deferred by design. After that the Rust core is feature-complete for the shipped cipher.

### ✅ DONE 2026-06-29: Phase 4 Stage D — port the auto-rekey ratchet + zeroize burned keys
> Branch `branchless-core`. The ratchet — the layer that re-keys the stream every so often and forgets
> the old key (so a stolen key can't decrypt past messages, and the stream never repeats) — existed only
> in Python. Ported it to Rust as `RatchetEngine` over `MultiMapEngine`, bit-for-bit identical to Python.
> **Added:** a one-way **HMAC-SHA256** key chain via the vetted `hmac` crate (NOT hand-rolled — same
> rule as SHA-512: security-critical KDF rides a reviewed primitive). Per epoch: `MK_i = HMAC(chain,
> V|"epoch|"|idx)`, next `K_{i+1} = HMAC(chain, V|"chain|"|idx)`, fresh `MultiMapEngine(MK_i, nonce|"|ep|"
> |idx, 4)`; idx is the 8-byte big-endian epoch index. New CLI mode `ratchet <key> <nonce> <epoch_bytes>
> <n>` feeds the parity test.
> **PROVEN bit-identical to the frozen ratchet KAT:** 80-byte vector that deliberately crosses 2+ re-key
> seams (32-byte epochs) — a one-byte slip in the chain or epoch nonce would break it exactly there; it
> matched byte-for-byte (verified manually + a new permanent parity test). Parity now **7/7** (was 6),
> full Python suite **92/92**, Rust 4/4. Still bit-identical AFTER adding zeroize.
> **zeroize CLOSED (with an honest residual):** `zeroize` crate wipes each retired chain key K_i in place
> the moment the chain steps past it, the live key on drop, and each epoch key MK_i once the engine has
> absorbed it — the forward-secrecy guarantee Python could only *intend* (immutable, GC'd bytes). NOT
> scrubbed: transient stack copies of the NEXT key (the one kept anyway) + key schedules inside the
> trusted `hmac`/`sha2` crates — needs upstream support, out of scope for a research core. Wrote this
> plainly into THREAT_MODEL.md §known-open + CONSTANT_TIME.md rather than claiming a clean close.
> Still UNVETTED. Files: `rust/src/lib.rs`, `rust/src/main.rs`, `rust/Cargo.toml`,
> `tests/test_rust_parity.py`, `THREAT_MODEL.md`, `CONSTANT_TIME.md`. Commit `5db8f38`.
> ▶ **Stage D complete.** Next Phase 4: parallelize the 4 maps + CTR + benchmark the shipped stream vs
> AES/ChaCha; differential fuzz Rust==KAT. The Rust core now makes the full forward-secret cipher.

### ✅ DONE 2026-06-29: Phase 4 Stage C — port multimap + KDF (Rust makes the REAL shipped keystream)
> Branch `branchless-core`. Until now the Rust core ran only a SINGLE engine; the cipher people
> actually use is the 4-map XOR combiner, each map keyed by a SHA-512 KDF. Ported both so Rust now
> produces the real shipped output, bit-for-bit identical to Python.
> **Added:** real **SHA-512** via the vetted `sha2` crate — NOT hand-rolled. (The KDF is the security
> ceiling, so it rests on a standard reviewed primitive; only the bespoke chaos math is hand-written.)
> `ChaosEngine::from_master(key, nonce)` mirrors engine.py's seed KDF; `MultiMapEngine::new(key, nonce,
> n_maps)` mirrors multimap.py — N independent engines, each from a domain-separated, index-folded hash,
> XOR-combined per byte. **The subtle part:** the hash gives 192-bit seed_key/control, but the engine
> takes u128; Python reduces them `% M` / `% HALF` inside __init__. Rust reduces the 192-bit value (via
> U256) before calling `new()` — idempotent with the engine's own reduction, so it lands on the exact
> same state. Two new CLI modes (`from_master`, `multimap`) feed the parity test.
> **PROVEN bit-identical to the frozen KAT:** from_master, multimap n=1, and multimap n=4 (the shipped
> cipher) all match byte-for-byte — verified manually against vectors.json AND wired into 3 new permanent
> parity tests (`test_rust_matches_kat_from_master`, `..._multimap[n_maps=1/4]`). Parity now **6/6** (was
> 3); full Python suite **91/91** (was 88); Rust 4/4; clippy clean (2 cosmetic style notes left as-is).
> **HONEST:** the 4 maps run sequentially, so the 4-map path is ~4× the single-engine cost (~19 MB/s
> expected) — parallelizing them is the next optimization, and the right place for a real shipped-stream
> benchmark vs AES/ChaCha. Still UNVETTED. Files: `rust/src/lib.rs`, `rust/src/main.rs`,
> `rust/Cargo.toml`, `tests/test_rust_parity.py`.
> ▶ **Stage C complete.** Next Phase 4: parallelize maps + CTR + benchmark; port the auto-rekey ratchet
> (HMAC-SHA512 + zeroize) and extend KAT parity to it; differential fuzz Rust==KAT.

### ✅ DONE 2026-06-29: Phase 4 Stage B — constant-time reciprocal divide (timing-leak #2 CLOSED)
> Branch `branchless-core`. The second slice of the Rust port: kill the last secret-dependent operation
> in the per-byte hot loop. Stage A still divided by the secret `p` / `HALF-p` with `ruint`'s big-int
> `/` — a hardware divide whose latency leaks the divisor. **Fix (Barrett-style precomputed reciprocal):**
> at key setup, compute `V = floor(M · 2^127 / d)` ONCE for each of the two fixed divisors (the only
> divides by the secret, off the hot path). Per step the "division" becomes `q_approx = (num·V) >> 127`
> plus ONE branchless correction (`+1` iff the remainder is still `>= den`). Proven exact: the truncation
> error is `< 1/2` because every divisor is `< 2^126`, so `q_approx` is always `q-1` or `q`. `M·num` is
> formed as `(num<<127) - num` (no multiply, since `M = 2^127-1`); the reciprocal is chosen per region by
> a hand-rolled branchless limb `select` (no big multiply, no branch). The hot loop now runs the same
> fixed-width instruction sequence regardless of the secret.
> **PROVEN, not assumed — four gates:** (1) bit-identical to the frozen KAT, 3/3 `engine_raw` vectors —
> closing the leak changed NOTHING about the output. (2) the reciprocal path vs the Stage-A big-int divide
> as a referee oracle: **~4.8M random (num,den) pairs, 0 mismatches** (`recip_div_matches_bigint_oracle`),
> including the region-3 `num==den+1` edge. (3) 88/88 Python tests. (4) 4/4 Rust unit tests.
> **Timing-leak #2 CLOSED, measured:** new `chaos_core timing <keys>` probe times the native hot loop
> across many DIFFERENT secret keys (each a different `p`); per-byte floors sit at min 4.721 / median
> 4.731 / p95 4.741 ns/byte → **0.41% secret-dependent spread** (Phase-3 Python had 3.6%, interpreter-
> masked). A first naive `(max-min)/mean` metric cried "39%" off one scheduler hiccup — the robust
> min-of-reps + percentile spread showed it was noise, the same cry-wolf lesson as the ratchet seam test.
> **HONEST findings:** (a) speed stayed **~75 MB/s** (no gain vs Stage A) — `ruint`'s U256 divide is about
> as costly as the couple of U256 multiplies that replace it; the deliverable here is constant-time, NOT
> throughput (more speed would need a hand-rolled limb multiply, noted for later). (b) Caught a stale
> Stage-A comment claiming `num <= den` — region 3 at `x==HALF` actually gives `num == den+1`; the
> reciprocal is built exact across the true range. (c) Deviated from the written plan: Barrett (not
> Montgomery), `ruint` U256 + branchless `select` (not the `subtle` crate); `zeroize` still pending (no
> ratchet in Rust yet). Updated `CONSTANT_TIME.md` (leak #2 → CLOSED with the measurement + deviations)
> and `THREAT_MODEL.md` §4. Files: `rust/src/lib.rs`, `rust/src/main.rs`. Still UNVETTED.
> ▶ **Phase 4 Stage B complete.** Next Phase 4: parallel maps + CTR; port multimap/ratchet (SHA-512/HMAC
> + zeroize) and extend KAT parity to those layers; differential fuzz Rust==KAT; benchmark vs AES/ChaCha.

### ✅ DONE 2026-06-29: Phase 4 Stage A — Rust hot-loop core (bit-identical to KAT, ~43× faster)
> Branch `branchless-core`. First slice of the Rust port (the speed blocker). Installed Rust 1.96
> (rustup, `--no-modify-path`). New `rust/` crate (`chaos_core`): a faithful port of the per-byte
> engine — the init avalanche, the integer PWLCM step, the nonlinear `finalize` mixer, and the
> 4-bytes-per-step output buffer — mirroring engine.py line-for-line. The PWLCM step is written as
> the Stage-B shape already: ONE division per step on a constant-time-masked numerator/divisor select
> (only the in-region candidate contributes). Mod-M math uses the Mersenne fold; the step division
> uses the `ruint` big-int crate for now (Stage A = correctness + speed first).
> **PROVEN correct, not assumed:** bit-identical to the frozen KAT on all 3 `engine_raw` vectors
> (typical, the all-zero-key edge that exercises the init avalanche + dead-state, and max-ish), via new
> `tests/test_rust_parity.py` (runs the binary, compares to vectors.json; auto-SKIPS if unbuilt — same
> skip-don't-error rule as /check) plus 3 Rust unit tests (division invariant, finalize known-answer,
> determinism). **Measured ~43× speedup:** 74.3 MB/s (Rust) vs 1.74 MB/s (Python), single-engine path —
> and that's WITH big-int division still in the loop; Stage B should add more. `rust/target/` gitignored;
> Cargo.lock kept. 88/88 Python tests pass (85 + 3 parity).
> ▶ **Phase 4 Stage A complete.** Next: Stage B — the constant-time precomputed reciprocal (closes
> timing-leak #2, drops ruint from the hot loop). HONEST status: Stage A still divides by the secret, so
> the timing leak is NOT yet closed here — same open state as Python, by design; Stage B is where it closes.

### ✅ DONE 2026-06-28: Phase 3 — Freeze + write the contract → PHASE 3 COMPLETE
> Branch `branchless-core`. The "freeze the design + write the honest contract" phase. Three pieces,
> each built AND measured (not asserted):
> **(§3) Frozen KAT vectors.** New `kat/generate_kat.py` computes a known-answer set for EVERY
> deterministic layer the Rust port must reproduce bit-for-bit — the finalize mixer, the raw PWLCM
> engine (including the all-zero-key edge that exercises the init avalanche), the from_master KDF,
> the multimap combiner (n=1 and the default 4), the ratchet stream across TWO re-key seams, and the
> deterministic SIV AEAD end-to-end. Frozen to `kat/vectors.json` via `--write`. New `tests/test_kat.py`
> (4 tests) recomputes from live code and asserts equality. PROVEN to bite: a simulated one-char mixer
> drift (`>>31`→`>>30`) was caught. This is the regression guard today + the port oracle for Phase 4.
> **(E) Threat model + bit-security claim.** New `THREAT_MODEL.md`: attacker capabilities, a
> threat→answer table, and an HONEST **~254-bit** claim = the *smallest* credible attack cost (MITM
> ~2^254, worst-case TMTO ~2^254, key 2^256), not the biggest number we could quote. States plainly the
> true ceiling is key/KDF recovery (why we stopped at 4 maps) and lists the residual risks.
> **(constant-time spec) MEASURED, not asserted.** New `bench/timing_leak.py` + `CONSTANT_TIME.md`:
> the secret-dependent BRANCH leak is CLOSED (measured 1.0% step-time spread across the four PWLCM
> regions = noise); the secret-dependent DIVIDE leak is OPEN (3.6% spread = NO clean Python-level
> signal because interpreter overhead masks the hardware divide — honestly a Rust/hardware concern, not
> Python-exploitable). The precomputed-reciprocal (Barrett/Montgomery) fix is specced for the port.
> 85/85 tests pass (81 + 4 KAT). ruff clean.
> ▶ **Phase 3 COMPLETE.** Next: Phase 4 — Rust core; the §4 reciprocal closes timing leak #2.

### ✅ DONE 2026-06-28: Phase 2 (#7) — heavy randomness on the shipped stream → PHASE 2 COMPLETE
> Branch `branchless-core`. Last Phase-2 item; ran the serious statistical suites on the REAL shipped
> keystream (the 4-map combiner under the auto-rekey ratchet — what a user actually gets, including the
> re-key seams). New tooling: `bench/stream_keystream.py` (streams raw keystream to stdout) +
> rewritten `bench/randomness.sh` (4-map/ratchet labels, PractRand via streaming pipe, ent, dieharder
> if present); `bench/nist_lite.py` repointed from the single-map engine to the shipped ratchet stream.
> Built **PractRand 0.95** from source (not in Homebrew; dieharder was removed from Homebrew core, and
> PractRand supersedes it anyway).
> **Results — all clean:** PractRand was spotless through 128 MB (199 tests); at 256 MB it flagged ONE
> result, `[Low1/8]DC6-9x1Bytes-1`, at its *mildest* "unusual" level (216 others clean). Rather than
> assert "that's noise," ran a 512 MB confirmation: the blip VANISHED (232 tests clean). A real flaw
> escalates with more data; a blip that disappears is multiple-testing chance noise. **Confirmed noise.**
> `ent` (64 MB): entropy 7.999997/8 bits/byte, 0% compressible, serial corr −0.0001, Monte-Carlo π
> error 0.00%. NIST-lite (monobit/runs/block-freq) passes across ~30 re-key seams. 81/81 tests pass.
> ▶ **Phase 2 COMPLETE (5/5).** Next: Phase 3 — threat model (E), freeze the KAT test vectors (§3),
> constant-time spec (the divide-by-secret-p timing leak #2 is still open, slated for the Rust port).

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

