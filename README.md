# Three-Body Problem Cipher (3BP)

*Encryption built on the problem no one can solve.*

---

Three objects in space, pulling on each other by gravity alone. You know their masses, their positions, their velocities. The rules are three lines of math. And yet — there is no formula that tells you where they'll be. Not "we haven't found one yet." Mathematically, provably, the future is *open*. The tiniest difference in where you start — a millimeter, a microsecond — and the paths diverge into entirely different histories.

A stream cipher wants the same thing: a system so sensitive to its starting conditions that flipping a single bit of the key produces a completely different keystream, with no detectable pattern connecting the two. Deterministic — the same key always gives the same output — but indistinguishable from random to anyone who doesn't hold the key.

**That's what this is.** Not a simulation of orbital mechanics. A different kind of mathematical chaos — four piecewise linear maps on a 2¹²⁷−1 grid, XOR-combined, pushed through a nonlinear mixer, re-keyed every 64 KiB by a one-way chain that burns the old key. Simple rules. Unpredictable output.

Built as a research artifact. Attacked hard from every angle. Wrapped in two independent locks so that even if the chaos wall falls, the data is still behind AES-256-GCM. The honest bet is that nobody can break it — and the whole point of making it public is to find out.

> **⚠️ UNVETTED — do not protect real data with this.** No outside cryptographer has reviewed it. The claims are measured, not proven. See [`REPORT.md`](REPORT.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md).

## What makes it interesting

**The engine.** Four independent piecewise linear chaotic maps (integer PWLCM on a 2¹²⁷−1 grid), XOR-combined into one keystream. Each map is branchless and constant-time. The output goes through a nonlinear ARX mixer so the keystream can't be rolled back to the internal state.

**The ratchet.** A one-way HMAC-SHA256 key chain re-keys every 64 KiB and burns the old key — forward secrecy (stealing the live key can't decrypt past messages) and effectively unbounded length.

**The shell.** AEAD with encrypt-then-MAC, key commitment (CMT-4), streaming/chunked mode, nonce-misuse resistance (SIV), and forward-secret sessions.

**Two locks.** The chaos AEAD wraps a vetted inner vault (AES-256-GCM or ChaCha20-Poly1305) with independent keys. Even a total chaos break leaves the data behind AES-256-GCM.

**Post-quantum key exchange.** Hybrid confidentiality (classical DH + ML-KEM-768) and hybrid authentication (triple-DH + ML-DSA-65 signatures) — an attacker must break both legs to impersonate.

**Fast Rust core.** ~35× faster than the Python reference (~61 MB/s), bit-identical to the frozen test vectors, with Python↔Rust interop both directions.

**Honest self-attack.** 15 attack scripts try to break every layer. The ones that succeed at small scale are documented with what stops them at full scale. The honest bit-security claim is **~254-bit** (the smallest credible attack cost, not the biggest number we could quote).

## Quick start

```bash
# Python (the reference implementation)
pip install -r requirements.txt
pytest tests/ -q                          # 183 tests

# Rust (the fast core — ~35× faster)
. "$HOME/.cargo/env"
cd rust && cargo build --release && cargo test --release   # 28 tests

# Cross-implementation verfication
python -m pytest tests/test_rust_parity.py -q    # Rust == Python, 36 tests
python -m pytest tests/test_rust_fuzz.py -q      # Random fuzz, hundreds of cases
```

## Safe usage (the one you actually call)

```python
from twolock import seal, open_

key = b"any shared secret bytes"
blob = seal(key, b"secret message")        # chaos outer + AES-256-GCM inner
msg = open_(key, blob)                      # raises InvalidTag if tampered or wrong key
```

For a single wall (research/experimentation only):

```python
from aead import seal, open_, InvalidTag

blob = seal(key, b"secret message")
msg  = open_(key, blob)
```

## Architecture

```
master key (256-bit)
     │
     ├──→ HKDF-SHA256 ──→ chaos AEAD key ──→ [OUTER WALL: 4-map chaos AEAD]
     │                                              │
     └──→ HKDF-SHA256 ──→ inner vault key ──→ [INNER VAULT: AES-256-GCM]
                                                    │
                                              plaintext depends on THIS one
```

The inner vault is what actually guarantees the data. The chaos wall is the exposed, sacrificial barrier — unvetted but interesting, and if it ever cracks, the inner vault still holds.

## What's in the box

| Layer | Python | Rust | What it does |
|-------|--------|------|-------------|
| Engine | `engine.py` | `engine.rs` | Single PWLCM map, branchless, constant-time |
| Multi-map | `multimap.py` | `multimap.rs` | 4 independent maps XOR-combined |
| Ratchet | `ratchet.py` | `ratchet.rs` | Auto-rekey, forward secrecy |
| AEAD | `aead.py` | `aead.rs` | Seal/open, encrypt-then-MAC, key commitment |
| Streaming | `streaming.py` | `streaming.rs` | Chunked AEAD, catches reorder/drop/truncate |
| Ratchet AEAD | `ratchet_aead.py` | `ratchet_aead.rs` | Forward-secret message sessions |
| SIV | `siv.py` | `siv.rs` | Nonce-misuse resistance |
| Two-locks | `twolock.py` | `twolock.rs` | Chaos outer + vetted inner vault |
| Classical KEX | `keyexchange.py` | `keyexchange.rs` | Diffie-Hellman over RFC 3526 MODP-2048 |
| PQ-hybrid KEX | `pq_keyexchange.py` | `keyexchange.rs` | DH + ML-KEM-768 hybrid |
| Auth-PQ KEX | `auth_pq_keyexchange.py` | `auth_pq.rs` | Hybrid auth (triple-DH + ML-DSA-65) |
| CTR mode | `ctr.py` | `ctr.rs` | Seekable random-access keystream |

## The attack battery

Every security claim is measured, not asserted. Each attack script tries to break one layer and reports honestly.

```bash
for a in attacks/*.py; do python3 "$a"; done
```

| Attack | What it tries | Result at full scale |
|--------|--------------|---------------------|
| Two-time pad | Reuse key+nonce → recover plaintext | ❌ Broken (nonces are mandatory) |
| Known plaintext | Recover state from output | Survives (state space ~2⁵⁰⁸, MITM ~2²⁵⁴) |
| Core cryptanalysis | Bias hunt + meet-in-the-middle | Survives (MITM ~2²⁵⁴ time+memory) |
| Differential | Single-bit input → output bias | Survives (at noise floor) |
| Period census | Short cycles, traps | Survives (√M law, 0 traps / 300 keys) |
| Map count | Fewer maps weaker? | Survives (4 maps independent, corr 0.008) |
| Ratchet | Forward secrecy, re-key seams | Survives (past unrecoverable, seams clean) |
| Commitment | Cross-key forgery | Survives (~2¹²⁸ via HMAC-SHA256) |
| Streaming | Reorder, drop, truncate | Survives (all caught) |
| Ratchet AEAD | Past message recovery | Survives (burned keys can't decrypt past) |
| Two-locks | Total chaos break → plaintext? | Survives (inner AES-256-GCM still holds, 0/67) |
| PQ hybrid | Break one primitive | Survives (other leg still holds, 64/64) |
| Auth PQ | Break one auth leg | Survives (other leg still holds, 6/6) |

## Honest numbers

| Metric | Value | Note |
|--------|-------|------|
| Bit-security claim | ~254-bit | Smallest of MITM ~2²⁵⁴, TMTO ~2²⁵⁴, key 2²⁵⁶ |
| Rust speed | ~61 MB/s | 4-map combiner, single-threaded |
| Rust vs ChaCha20 | ~37× slower | ChaCha20 ~2,272 MB/s (hardware-accelerated) |
| Rust vs AES-NI | ~149× slower | AES-256-CTR ~9,082 MB/s |
| Python speed | ~1.7 MB/s | Reference only — use the Rust core |
| Keystream period | ~2²⁴⁷ | 4-map combined before ratchet; ratchet dissolves the limit |
| Forward secrecy | Yes | 64 KiB epochs, burned keys zeroized in Rust |
| Constant-time | Yes | Branchless map + reciprocal divide, measured 0.41% spread |
| Post-quantum | Hybrid only | Relies on vetted ML-KEM-768 + ML-DSA-65, not chaos math |

## Project status

**Phase 8 of 8 complete.** The Rust core now mirrors every Python capability. Only Phase 7 (external review) remains on the roadmap.

See [`PROGRESS.md`](PROGRESS.md) for the full build history and roadmap.

## License

[MIT](LICENSE) — free for any use, research or commercial. This project is unvetted; use at your own risk.

---

Built by **Evan Simonenko** · [asturai.com](https://asturai.com) · contact@asturai.com
