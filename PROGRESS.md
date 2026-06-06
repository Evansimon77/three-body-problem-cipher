# Chaos Cipher (Progress)

Last updated: 2026-06-06 | Branch: auth-dh-handshake (pre-merge) | Status: 🔬 SECURITY-HARDENING PHASE — **all 3 hardening suggestions DONE.** Suggestion 1 (cryptanalysis) + Suggestion 2 (SIV seatbelt) merged to main; Suggestion 3 (authenticated DH / "secret handshake") DONE & measured: built `auth_keyexchange.py` — triple-DH (static+ephemeral, Noise/X3DH pattern); the active man-in-the-middle that broke plain DH now FAILS automatically. 71/71 tests pass. Resume point: decide merge to main, then specify the **Option-B integration contract** with AsturAI (where the chaos layer sits over a vetted AEAD). End-goal unchanged: harden, then deploy as **outer layer over a vetted primitive** ("Option B") for AsturAI client data.

## 🎯 Goal
Build and **rigorously prove/disprove** a chaos-based stream cipher (integer PWLCM keystream)
as a research/learning project. "Prove it works" = try hard to break it and measure it against
real standards. Engine-first; any real application is deferred until the evidence justifies it
(and even then, only as a layer over a vetted primitive).

## ⏭️ NEXT
**New phase (2026-06-06): strengthen the cipher's security**, then deploy as the *outer* layer over a
vetted primitive ("Option B" / defense-in-depth) to protect AsturAI client data — never the only lock.
Each hardening idea must be *measured/attacked*, not asserted (project ethos). Three-step plan agreed
with user (Suggestion 1 → 2 → 3):
- [x] **Suggestion 1 — clever-burglar cryptanalysis** (`attacks/core_cryptanalysis.py`, REPORT v6). DONE & merged to main.
      Bias hunt = clean (2.52 σ), independence = confirmed (1.71 σ), MITM = honest correction 2^159→~2^122.
- [x] **Suggestion 2 — nonce-misuse resistance** ("the seatbelt", `siv.py`, REPORT v7). DONE, pre-merge on `nonce-misuse-siv`.
      Deterministic SIV AEAD: IV = HMAC(K, aad‖plaintext) used as both keystream IV and auth tag. No nonce to reuse;
      different messages never share a keystream (C0⊕C1=M0⊕M1 two-time-pad equality no longer holds). 61/61 tests pass.
- [x] **Suggestion 3 — DH authentication** (`auth_keyexchange.py`, REPORT v8). DONE, pre-merge on `auth-dh-handshake`.
      Triple-DH (static+ephemeral, Noise/X3DH pattern): session key mixes ee + es + se, so a MITM lacking a
      party's static private can't derive it. `attacks/auth_dh_mitm.py` shows the old MITM now FAILS. 71/71 tests pass.
- [ ] **Specify the Option-B integration contract** with AsturAI: where the chaos layer sits, what vetted AEAD it wraps, the order of operations. ← NEXT after merging Suggestion 3 (the bridge to real use).
- [ ] (Deferred) Heavyweight randomness (dieharder/PractRand) — decided against 2026-06-06 unless explicitly wanted; randomness ≠ security.

Optional capability polish (no security claim, lower priority):
- [ ] Wire `SeekableCTR` into `aead.py` as a selectable mode for large-file random access.

✅ `ent` battery (Fourmilab) on **100 MB** of the shipped 3-map keystream — PASSED (entropy 7.999998/8,
chi-square 261.62 @ 37%, mean 127.4968, serial corr 0.0001). NIST-lite subset passes too. Strong PRNG;
does NOT change UNVETTED status. See REPORT.md "Randomness battery".

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
