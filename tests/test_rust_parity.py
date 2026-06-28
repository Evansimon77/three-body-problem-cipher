"""
Rust-port parity (Phase 4) — the Rust core must reproduce the frozen KAT byte-for-byte.

This is the port oracle: it runs the compiled Rust binary on the same fixed inputs as the
`engine_raw` vectors in kat/vectors.json and asserts the keystream matches exactly. If the
binary isn't built, the test SKIPS (never errors) — same philosophy as /check, so CI/other
machines without a Rust toolchain still pass the Python suite.

Build the binary first:  cd rust && cargo build --release
"""
import json
import os
import subprocess

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_BIN = os.path.join(_ROOT, "rust", "target", "release", "chaos_core")
_VECTORS = os.path.join(_ROOT, "kat", "vectors.json")


def _have_binary() -> bool:
    return os.path.isfile(_BIN) and os.access(_BIN, os.X_OK)


pytestmark = pytest.mark.skipif(
    not _have_binary(),
    reason="Rust core not built — run `cd rust && cargo build --release` to enable parity tests",
)


def _frozen(key):
    with open(_VECTORS) as f:
        return json.load(f)[key]


def _frozen_engine_raw():
    return _frozen("engine_raw") if _have_binary() else []


def _frozen_multimap():
    return _frozen("multimap") if _have_binary() else []


def _rust(*cli_args) -> str:
    out = subprocess.run(
        [_BIN, *[str(a) for a in cli_args]],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


@pytest.mark.parametrize("case", _frozen_engine_raw(), ids=lambda c: c["label"])
def test_rust_matches_kat_engine_raw(case):
    n = len(bytes.fromhex(case["keystream"]))
    got = _rust("ks", case["seed"], case["control"], case["nonce"], n)
    assert got == case["keystream"], (
        f"Rust core diverged from the frozen KAT for case '{case['label']}'. "
        "The port is NOT bit-identical."
    )


def test_rust_matches_kat_from_master():
    """The seed KDF (SHA-512 -> seed/control, reduced mod M / HALF) + single engine."""
    case = _frozen("from_master")
    n = len(bytes.fromhex(case["keystream"]))
    got = _rust("from_master", case["key"], case["nonce"], n)
    assert got == case["keystream"], "Rust from_master KDF diverged from the frozen KAT."


@pytest.mark.parametrize("case", _frozen_multimap(), ids=lambda c: f"n_maps={c['n_maps']}")
def test_rust_matches_kat_multimap(case):
    """The shipped keystream: N independent maps (multimap KDF, index-folded) XOR-combined."""
    n = len(bytes.fromhex(case["keystream"]))
    got = _rust("multimap", case["key"], case["nonce"], case["n_maps"], n)
    assert got == case["keystream"], (
        f"Rust multimap (n_maps={case['n_maps']}) diverged from the frozen KAT."
    )


def test_rust_matches_kat_ratchet():
    """The forward-secret stream: a one-way HMAC-SHA256 key chain re-keying every `epoch_bytes`.
    The KAT length spans several epochs (80 bytes over 32-byte epochs), so this exercises >=2 re-key
    seams — if the chain step or the epoch nonce diverged by a byte, the keystream would break here."""
    case = _frozen("ratchet")
    n = case["length"]
    got = _rust("ratchet", case["key"], case["nonce"], case["epoch_bytes"], n)
    assert got == case["keystream"], "Rust ratchet diverged from the frozen KAT (chain or epoch seam)."
