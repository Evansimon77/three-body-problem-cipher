# chaos-engine

A discretized, pure-integer **Piecewise Linear Chaotic Map (PWLCM)** stream cipher, built to
be **adversarially tested** — not trusted. This is the "engine first" phase: a self-contained
research artifact with zero application/website code.

> **Security status: UNVETTED RESEARCH. Do not protect real data with this.**
> See [`REPORT.md`](REPORT.md) for the empirical verdict on what held up and what broke.

## What it is

- `engine.py` — the chaotic core: integer PWLCM (modulus `M = 2^61 - 1`) used as a keystream,
  XOR'd with plaintext. Pure-integer math => bit-identical keystream on any CPU/OS (solves the
  floating-point "finite precision paradox"). Now also rejects the weak-parameter band and
  exposes `from_master()` (hash KDF) so no caller can pick a weak key.
- `aead.py` — **the simple, safe interface: `seal()` / `open_()`.** Wraps the core with a
  fresh random nonce per message (no two-time pad) and encrypt-then-MAC authentication
  (HMAC-SHA256) so tampering and wrong keys are rejected. Use this, not the raw engine.
- `demo.py` — Alice/Bob/Eve. Shows determinism + key sensitivity **only** (not security).

### Safe usage (the one you actually call)

```python
from aead import seal, open_, InvalidTag

key  = b"any shared secret bytes"
blob = seal(key, b"secret message")          # nonce || ciphertext || tag
msg  = open_(key, blob)                       # raises InvalidTag if tampered / wrong key
```

## The proof harness (this is the point)

| Area | File | What it answers |
|------|------|-----------------|
| Correctness | `tests/test_correctness.py` | round-trip, determinism, key/nonce separation |
| **Period** | `tests/test_period.py` | does the integer keystream cycle? (Brent's algorithm) |
| Avalanche | `tests/test_avalanche.py` | does 1 key/nonce bit flip ~50% of output bits? |
| Randomness | `bench/nist_lite.py`, `bench/randomness.sh` | NIST-subset (+ ent/dieharder if installed) |
| **Two-time pad** | `attacks/two_time_pad.py` | reuse (key,nonce) => recover both messages |
| **Known-plaintext** | `attacks/known_plaintext.py` | map is invertible; full state-recovery at small scale |
| AEAD shell | `tests/test_aead.py` | tamper/truncation/wrong-key/AAD all rejected; no two-time pad |
| Speed | `bench/speed.py` | MB/s vs AES-256-CTR and ChaCha20 |

## Run it

```bash
pip install -r requirements.txt

python demo.py                 # Alice/Bob/Eve sanity
pytest tests/ -v               # correctness + period + avalanche thresholds
python tests/test_period.py    # printed period measurements
python tests/test_avalanche.py # printed avalanche numbers
python bench/nist_lite.py      # randomness screen (zero deps)
bash  bench/randomness.sh /tmp/ks.bin 10   # dump 10MB + ent/dieharder if installed
python attacks/two_time_pad.py     # demonstrates the nonce-reuse break
python attacks/known_plaintext.py  # invertibility + scaled state-recovery
python bench/speed.py          # throughput vs AES/ChaCha
```

## Honest headline

The construction is deterministic, statistically clean on the screens run, and has good
avalanche — but it is a **homemade, unvetted cipher**, it is **~700–800x slower** than
AES/ChaCha, it has **weak-key/parameter classes** (e.g. trivial control values collapse the
period), and it is **trivially broken by keystream reuse**. The "mathematically unhackable /
no structure to exploit" claims are **false** — the map is invertible and carries algebraic
structure. Read `REPORT.md` before doing anything else with it.
