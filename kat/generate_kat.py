"""
KAT generator — produces the FROZEN known-answer test vectors (§3 of the roadmap).

WHY THIS EXISTS
---------------
A known-answer test (KAT) is a locked list of "this exact input must produce this exact
output." Once frozen, it is the contract the cipher can never silently break:

  * REGRESSION GUARD (today, Python): any edit that changes a single output byte fails
    tests/test_kat.py. Refactors that are meant to be behaviour-preserving are PROVEN so;
    accidental behaviour changes are caught the moment they happen.
  * PORT ORACLE (Phase 4, Rust): the Rust core is "done" only when it reproduces every
    vector here bit-for-bit. The KAT turns "I think the port matches" into "it provably
    matches" — the same role NIST's KATs play for AES/SHA implementations.

WHAT IS COVERED — every DETERMINISTIC layer the port must reproduce, bottom-up:
  1. finalize     — the nonlinear ARX output mixer (_finalize), the trickiest bit-math.
  2. engine_raw   — the integer PWLCM core keystream from fixed (seed, control, nonce),
                    including the all-zero key edge (exercises the init avalanche + dead-state).
  3. from_master  — the hash-KDF seeding path the AEAD layers actually use.
  4. multimap     — the shipped N-map XOR combiner (n_maps = 1 and the default 4).
  5. ratchet      — the shipped auto-rekey stream, with a TINY epoch so the vector crosses
                    two re-key seams (proves the seam math is frozen too).
  6. siv          — the fully deterministic AEAD (seal_siv), a full-stack end-to-end vector.

The AEAD `seal()` in aead.py is deliberately NOT here: it draws a fresh random nonce, so it
has no fixed answer by design. Its determinism is covered by its own round-trip tests.

USAGE
-----
    python3 kat/generate_kat.py            # print the vectors as JSON to stdout
    python3 kat/generate_kat.py --write    # (re)write kat/vectors.json  -- FREEZING ACTION

Regenerating with --write is a deliberate, reviewed act: it re-freezes the contract to the
CURRENT code. Do it only when you INTEND to change the cipher's output (and say so in the
commit). Never run it just to make a failing test pass.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import M, DiscreteChaoticEngine, _finalize  # noqa: E402
from multimap import MultiMapEngine  # noqa: E402
from ratchet import RatchetEngine  # noqa: E402
from siv import seal_siv  # noqa: E402

VECTORS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")

# Fixed, arbitrary-but-pinned inputs. These are PUBLIC test inputs, not secrets.
_KEY_INT = 0x0123456789ABCDEF0123456789ABCDEF  # gitleaks:allow — public KAT test input, not a secret
_CTRL_INT = 0xFEDCBA9876543210FEDCBA9876543210
_NONCE_INT = 0xA5A5A5A5
_KEY_BYTES = b"chaos-kat-master-key-v1"
_NONCE_BYTES = b"chaos-kat-nonce-v1"


def compute_vectors() -> dict:
    """Recompute every KAT vector from the CURRENT code. The frozen vectors.json is a
    snapshot of this function's output; tests/test_kat.py compares the two."""
    v: dict = {"_meta": {
        "about": "Frozen known-answer vectors for the chaos PWLCM cipher. See generate_kat.py.",
        "modulus_M": hex(M),
    }}

    # 1. finalize — the nonlinear output mixer, across edge + interior states.
    finalize_inputs = [0, 1, 2, M - 1, M, M // 2, (1 << 64), (1 << 127) - 3,
                       0xDEADBEEFCAFEBABE, 0x0123456789ABCDEF0123456789ABCDEF]
    v["finalize"] = [
        {"z": hex(z), "out": hex(_finalize(z))} for z in finalize_inputs
    ]

    # 2. engine_raw — the bare PWLCM core. Includes the all-zero-key edge (init avalanche).
    raw_cases = [
        {"label": "typical", "seed": _KEY_INT, "control": _CTRL_INT, "nonce": _NONCE_INT},
        {"label": "all-zero-key", "seed": 0, "control": 0, "nonce": 0},
        {"label": "max-ish", "seed": M - 1, "control": M - 1, "nonce": M - 1},
    ]
    v["engine_raw"] = []
    for c in raw_cases:
        ks = DiscreteChaoticEngine(c["seed"], c["control"], c["nonce"]).keystream(64)
        v["engine_raw"].append({**c, "seed": hex(c["seed"]), "control": hex(c["control"]),
                                "nonce": hex(c["nonce"]), "keystream": ks.hex()})

    # 3. from_master — the hash-KDF seeding path used by the AEAD layers.
    ks = DiscreteChaoticEngine.from_master(_KEY_BYTES, _NONCE_BYTES).keystream(64)
    v["from_master"] = {"key": _KEY_BYTES.hex(), "nonce": _NONCE_BYTES.hex(), "keystream": ks.hex()}

    # 4. multimap — the shipped XOR combiner, single-map and the default 4-map.
    v["multimap"] = []
    for n in (1, 4):
        ks = MultiMapEngine(_KEY_BYTES, _NONCE_BYTES, n_maps=n).keystream(64)
        v["multimap"].append({"n_maps": n, "key": _KEY_BYTES.hex(),
                              "nonce": _NONCE_BYTES.hex(), "keystream": ks.hex()})

    # 5. ratchet — the shipped auto-rekey stream. epoch_bytes=32 so 80 bytes crosses TWO seams
    #    (at 32 and 64), freezing the re-key seam math, not just one epoch.
    ks = RatchetEngine(_KEY_BYTES, _NONCE_BYTES, epoch_bytes=32).keystream(80)
    v["ratchet"] = {"key": _KEY_BYTES.hex(), "nonce": _NONCE_BYTES.hex(),
                    "epoch_bytes": 32, "length": 80, "keystream": ks.hex()}

    # 6. siv — the fully deterministic AEAD, full stack end-to-end (siv || ciphertext).
    pt = b"known-answer plaintext for the deterministic SIV AEAD path."
    aad = b"kat-aad"
    blob = seal_siv(_KEY_BYTES, pt, aad)
    v["siv"] = {"key": _KEY_BYTES.hex(), "aad": aad.hex(),
                "plaintext": pt.hex(), "blob": blob.hex()}

    return v


def main() -> None:
    vectors = compute_vectors()
    if "--write" in sys.argv:
        with open(VECTORS_PATH, "w") as f:
            json.dump(vectors, f, indent=2)
            f.write("\n")
        print(f"Froze {VECTORS_PATH}")
    else:
        print(json.dumps(vectors, indent=2))


if __name__ == "__main__":
    main()
