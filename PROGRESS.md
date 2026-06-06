# Chaos Cipher (Progress)

Last updated: 2026-06-06 | Branch: main | Status: v2 complete, on GitHub

## 🎯 Goal
Build and **rigorously prove/disprove** a chaos-based stream cipher (integer PWLCM keystream)
as a research/learning project. "Prove it works" = try hard to break it and measure it against
real standards. Engine-first; any real application is deferred until the evidence justifies it
(and even then, only as a layer over a vetted primitive).

## ⏭️ NEXT (pick one to branch on)
- [ ] **Combine multiple chaotic maps** — run several PWLCMs and mix their outputs (the original
      three-body intuition). Strengthens against the invertibility / state-recovery finding (#3).
- [ ] **CTR-style seekable mode** — keystream addressable by counter so you can random-access.
- [ ] **Key-exchange layer** — let Alice & Bob agree a key without pre-sharing.
- [ ] Install `ent` + `dieharder` (`brew install ent dieharder`) and run the full randomness battery on ≥100 MB.

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
