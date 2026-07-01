# chaos-cipher

A discretized, pure-integer **Piecewise Linear Chaotic Map (PWLCM)** stream cipher, built to
be **adversarially tested** — not trusted. This is the "engine first" phase: a self-contained
research artifact with zero application/website code.

> **Security status: UNVETTED RESEARCH. Do not protect real data with this.**
> See [`REPORT.md`](REPORT.md) for the empirical verdict on what held up and what broke.

## What it is

- `engine.py` — the single chaotic core: integer PWLCM (modulus `M = 2^61 - 1`) used as a
  keystream, XOR'd with plaintext. Pure-integer math => bit-identical keystream on any CPU/OS
  (solves the floating-point "finite precision paradox"). Rejects the weak-parameter band and
  exposes `from_master()` (hash KDF) so no caller can pick a weak key.
- `multimap.py` — **the "three-body" keystream: 3 independent PWLCMs XOR-combined.** Hides each
  map's invertibility footprint behind the others, defeating the single-map state-recovery attack
  (see `attacks/known_plaintext.py` Part C). Maps are independent (uncoupled) to avoid chaos sync.
- `ctr.py` — **seekable counter (CTR) mode: `SeekableCTR`.** Same 3-map keystream, but cut into
  counter-addressed blocks so `keystream(n, offset=k)` returns global bytes `k..k+n-1` directly —
  random access without spooling from the start (like AES-CTR). ~1.2× the streaming cost.
- `aead.py` — **the simple, safe interface: `seal()` / `open_()`.** Uses the 3-map keystream by
  default + a fresh random nonce per message (no two-time pad) + encrypt-then-MAC authentication
  (HMAC-SHA256) so tampering and wrong keys are rejected. Use this, not the raw engine.
- `keyexchange.py` — **agree a key over an open channel with no pre-shared secret (`DHParty`).**
  Classic finite-field **Diffie-Hellman** over a standard RFC 3526 safe prime (pure-integer
  `pow()`), then the agreed secret feeds straight into `seal()`. Deliberately *vetted math for the
  key, chaos for the bulk* — not a homemade chaos key exchange. (Caveat: plain DH is unauthenticated
  — see the MITM demo.)
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
| **Multi-map** | `tests/test_multimap.py` | 3-map round-trip, determinism, avalanche, no short cycle |
| **Seekable CTR** | `tests/test_ctr.py` | windowed read == full-stream slice; random access skips earlier blocks |
| **Period** | `tests/test_period.py` | does the integer keystream cycle? (Brent's algorithm) |
| Avalanche | `tests/test_avalanche.py` | does 1 key/nonce bit flip ~50% of output bits? |
| Randomness | `bench/nist_lite.py`, `bench/randomness.sh` | NIST-subset (+ ent/dieharder if installed) |
| **Two-time pad** | `attacks/two_time_pad.py` | reuse (key,nonce) => recover both messages |
| **Known-plaintext** | `attacks/known_plaintext.py` | map is invertible; full state-recovery at small scale |
| **DH man-in-the-middle** | `attacks/dh_mitm.py` | passive eavesdropper fails; active MITM breaks unauthenticated DH |
| Key exchange | `tests/test_keyexchange.py` | both sides agree; peer-value validation; end-to-end with AEAD |
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
python keyexchange.py              # agree a key with no pre-shared secret, then encrypt
python attacks/dh_mitm.py          # passive eavesdropper fails; active MITM breaks plain DH
python bench/speed.py          # throughput vs AES/ChaCha
```

## Naming conventions

The Python and Rust halves follow their respective language conventions. The same concept may
have a different name in each half — this is deliberate, not drift.

| Concept | Python | Rust | Why |
|---------|--------|------|-----|
| Chaos engine class | `DiscreteChaoticEngine` | `ChaosEngine` | Python descriptive; Rust concise |
| AEAD open | `open_()` | `aead_open()` | Trailing `_` avoids `open` builtin conflict |
| AEAD seal | `seal()` | `aead_seal()` | Python module-namespaced; Rust exports globally |
| Stream seal (one-shot) | `seal_stream()` | `stream_seal()` | Same shape, different word order — function name prefix vs module prefix |
| Output mixer | `_finalize()` | `finalize()` | Python underscore = module-private; Rust `pub(crate)` = crate-private |
| Map count default | `DEFAULT_N_MAPS` | `DEFAULT_N_MAPS` | Same name in both (the one constant kept identical) |

## Honest headline

The construction is deterministic, statistically clean on the screens run, and has good
avalanche — but it is a **homemade, unvetted cipher**, it is **~700–800x slower** than
AES/ChaCha, it has **weak-key/parameter classes** (e.g. trivial control values collapse the
period), and it is **trivially broken by keystream reuse**. The "mathematically unhackable /
no structure to exploit" claims are **false** — the map is invertible and carries algebraic
structure. Read `REPORT.md` before doing anything else with it.
