# PROGRESS Changelog — Chaos Cipher

Detailed changelog entries live here; `PROGRESS.md` keeps the current compass + recent work.
The full append-only narrative (including dead ends) is in Obsidian: `Chaos Cipher.md`.

---

## 2026-06-06 — v2: AEAD shell, GitHub, three-pillar workflow
- `engine.py`: weak-parameter rejection band (`MIN_P = 2^40`); `from_master(master_key, nonce)`
  SHA-512 KDF → well-distributed seed + control (weak keys unreachable).
- `aead.py`: `seal()`/`open_()`; wire format `nonce(16) || ciphertext || tag(32)`; encrypt-then-MAC
  HMAC-SHA256 with a domain-separated MAC key; constant-time `compare_digest`; AAD length-prefixed.
- `tests/test_aead.py`: 10 tests — roundtrip, empty, fresh-nonce (no two-time-pad), tamper
  (ct + tag), truncation, wrong-key, AAD binding, malformed, weak-key-no-collapse. 18/18 total.
- Git repo initialized; pushed to private `Evansimon77/chaos-cipher`. Folder renamed to `chaos-cipher`.

## 2026-06-06 — v1: engine + adversarial harness
- `engine.py` (PWLCM core), `demo.py` (Alice/Bob/Eve, labeled non-proof).
- `tests/`: correctness, period (Brent's cycle detection), avalanche (~0.5000).
- `attacks/`: `two_time_pad.py` (full recovery on nonce reuse), `known_plaintext.py` (map
  invertibility + scaled state-recovery predicting future keystream).
- `bench/`: `nist_lite.py` (pure-Python NIST subset), `randomness.sh`, `speed.py` (~700–800× slower than AES/ChaCha).
- `REPORT.md`: honest claim-by-claim verdict.
