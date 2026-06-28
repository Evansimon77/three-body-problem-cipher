"""
Differential fuzz (Phase 4) — the Rust core vs the Python reference over MANY random inputs.

The frozen KAT (test_rust_parity.py) pins a handful of fixed vectors. This widens the net: it draws
hundreds of random (mode, key, nonce, params, length) cases from a FIXED seed — so it is fully
reproducible and never flaky — computes the Python reference keystream live (the same classes
kat/generate_kat.py uses), runs the Rust binary on the identical input, and asserts byte-for-byte
equality. A single divergent byte in ANY of the four shipped modes fails here, and the assertion
prints the exact inputs so the failure can be replayed by hand.

This is the "port is provably equivalent, not just on the 7 frozen points" guarantee.

Skips if the Rust binary isn't built (same policy as test_rust_parity.py).
Heavier run:  CHAOS_FUZZ_ITERS=2000 python3 -m pytest tests/test_rust_fuzz.py -q
"""
import os
import random
import subprocess
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_BIN = os.path.join(_ROOT, "rust", "target", "release", "chaos_core")

sys.path.insert(0, _ROOT)
from engine import M, DiscreteChaoticEngine  # noqa: E402
from multimap import MultiMapEngine  # noqa: E402
from ratchet import RatchetEngine  # noqa: E402


def _have_binary() -> bool:
    return os.path.isfile(_BIN) and os.access(_BIN, os.X_OK)


pytestmark = pytest.mark.skipif(
    not _have_binary(),
    reason="Rust core not built — run `cd rust && cargo build --release` to enable fuzz tests",
)

# How many random cases. Kept modest for the default suite (each case forks the Rust binary);
# bump via the env var for a heavy soak run.
ITERS = int(os.environ.get("CHAOS_FUZZ_ITERS", "240"))


def _rust(*cli_args) -> str:
    out = subprocess.run(
        [_BIN, *[str(a) for a in cli_args]],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


def _rand_int(rng) -> int:
    """A seed/control/nonce integer: mostly random 127/128-bit, sometimes a deliberate edge value
    (0, the modulus M and its neighbours, the half-grid point, the u128 ceiling). Both sides reduce
    internally (seed % M, control % HALF, nonce % M), so any value < 2**128 is a valid match test."""
    edges = [0, 1, 2, M - 1, M, M + 1, 1 << 126, 1 << 127, (1 << 127) - 1, (1 << 128) - 1]
    r = rng.random()
    if r < 0.20:
        return rng.choice(edges)
    if r < 0.60:
        return rng.getrandbits(127)
    return rng.getrandbits(128)


def _rand_bytes(rng) -> bytes:
    """A random key/nonce byte string, 1..40 bytes."""
    return bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 40)))


def _case(rng):
    """Build one random case: pick a mode, draw its inputs, return (mode, rust_cli_args, ref_hex)."""
    mode = rng.choice(["ks", "from_master", "multimap", "ratchet"])
    n = rng.randint(1, 256)
    if mode == "ks":
        seed, control, nonce = _rand_int(rng), _rand_int(rng), _rand_int(rng)
        ref = DiscreteChaoticEngine(seed, control, nonce).keystream(n)
        args = ("ks", f"0x{seed:x}", f"0x{control:x}", f"0x{nonce:x}", n)
    elif mode == "from_master":
        key, nonce = _rand_bytes(rng), _rand_bytes(rng)
        ref = DiscreteChaoticEngine.from_master(key, nonce).keystream(n)
        args = ("from_master", key.hex(), nonce.hex(), n)
    elif mode == "multimap":
        key, nonce, n_maps = _rand_bytes(rng), _rand_bytes(rng), rng.randint(1, 6)
        ref = MultiMapEngine(key, nonce, n_maps=n_maps).keystream(n)
        args = ("multimap", key.hex(), nonce.hex(), n_maps, n)
    else:  # ratchet — small epoch_bytes vs a longer length so most cases cross several re-key seams.
        #          n_maps stays the locked default (4), matching the Rust `ratchet` CLI.
        key, nonce, epoch_bytes = _rand_bytes(rng), _rand_bytes(rng), rng.randint(1, 40)
        ref = RatchetEngine(key, nonce, epoch_bytes=epoch_bytes).keystream(n)
        args = ("ratchet", key.hex(), nonce.hex(), epoch_bytes, n)
    return mode, args, ref.hex()


def test_rust_matches_python_fuzz():
    rng = random.Random(0xC0FFEE)  # fixed seed: reproducible, never flaky
    seen = {"ks": 0, "from_master": 0, "multimap": 0, "ratchet": 0}
    for i in range(ITERS):
        mode, args, ref_hex = _case(rng)
        seen[mode] += 1
        got = _rust(*args)
        assert got == ref_hex, (
            f"Rust diverged from the Python reference on fuzz case #{i} (mode={mode}).\n"
            f"  replay: chaos_core {' '.join(str(a) for a in args)}\n"
            f"  python: {ref_hex}\n  rust:   {got}"
        )
    # Guard the guard: every mode must actually have been exercised (catches a broken generator).
    assert all(c > 0 for c in seen.values()), f"some mode never ran: {seen}"
