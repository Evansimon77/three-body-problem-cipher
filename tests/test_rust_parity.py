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


def _frozen_engine_raw():
    with open(_VECTORS) as f:
        return json.load(f)["engine_raw"]


def _rust_keystream(seed: str, control: str, nonce: str, n: int) -> str:
    out = subprocess.run(
        [_BIN, "ks", seed, control, nonce, str(n)],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


@pytest.mark.parametrize("case", _frozen_engine_raw() if _have_binary() else [],
                         ids=lambda c: c["label"])
def test_rust_matches_kat_engine_raw(case):
    n = len(bytes.fromhex(case["keystream"]))
    got = _rust_keystream(case["seed"], case["control"], case["nonce"], n)
    assert got == case["keystream"], (
        f"Rust core diverged from the frozen KAT for case '{case['label']}'. "
        "The port is NOT bit-identical."
    )
