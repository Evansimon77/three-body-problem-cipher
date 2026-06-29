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


def test_rust_matches_kat_aead_seal():
    """The committing AEAD (Phase 8.1): Rust seal of the fixed (key, nonce, aad, plaintext) must equal
    the frozen blob byte-for-byte (nonce || commit || ciphertext || tag) — proves the HMAC tag, the
    key-commitment, and the keystream XOR all match Python."""
    c = _frozen("aead")
    got = _rust("aead_seal", c["key"], c["nonce"], c["aad"], c["plaintext"], c["n_maps"])
    assert got == c["blob"], "Rust aead_seal diverged from the frozen KAT blob."


def test_rust_aead_open_roundtrip():
    """Rust open of the frozen blob returns the original plaintext."""
    c = _frozen("aead")
    got = _rust("aead_open", c["key"], c["aad"], c["blob"], c["n_maps"])
    assert got == c["plaintext"], "Rust aead_open did not recover the plaintext."


def test_rust_aead_open_rejects_tamper():
    """A flipped ciphertext byte must make Rust open fail closed (prints INVALID, no plaintext)."""
    c = _frozen("aead")
    blob = bytearray(bytes.fromhex(c["blob"]))
    blob[16 + 32 + 1] ^= 0x01           # flip a ciphertext byte (past nonce + commitment)
    got = _rust("aead_open", c["key"], c["aad"], blob.hex(), c["n_maps"])
    assert got == "INVALID", "Rust aead_open accepted a tampered blob."


def test_python_opens_rust_sealed_blob():
    """Real interop: a blob SEALED by the Rust core must OPEN under the Python shell (and vice versa is
    covered by test_rust_aead_open_roundtrip on the Python-generated KAT blob). This proves the two
    implementations are wire-compatible, not just internally self-consistent."""
    import sys
    sys.path.insert(0, _ROOT)
    from aead import open_  # noqa: E402

    c = _frozen("aead")
    rust_blob = bytes.fromhex(_rust("aead_seal", c["key"], c["nonce"], c["aad"],
                                    c["plaintext"], c["n_maps"]))
    opened = open_(bytes.fromhex(c["key"]), rust_blob, aad=bytes.fromhex(c["aad"]),
                   n_maps=c["n_maps"])
    assert opened == bytes.fromhex(c["plaintext"]), "Python could not open the Rust-sealed blob."


def test_rust_matches_kat_stream_seal():
    """The streaming AEAD (Phase 8.2): Rust seal of the fixed (key, salt, aad, chunks) must equal the
    frozen blob — proves header, per-chunk framing, nonces, tags and the final-flag all match Python."""
    c = _frozen("stream")
    got = _rust("stream_seal", c["key"], c["salt"], c["aad"], c["n_maps"], *c["chunks"])
    assert got == c["blob"], "Rust stream_seal diverged from the frozen KAT blob."


def test_rust_stream_open_roundtrip():
    c = _frozen("stream")
    got = _rust("stream_open", c["key"], c["aad"], c["n_maps"], c["blob"])
    assert got == c["plaintext"], "Rust stream_open did not recover the concatenated plaintext."


def test_rust_stream_open_rejects_tamper():
    c = _frozen("stream")
    blob = bytearray(bytes.fromhex(c["blob"]))
    blob[16 + 32 + 4 + 1] ^= 0x01        # flip a byte in the first chunk's ciphertext
    got = _rust("stream_open", c["key"], c["aad"], c["n_maps"], blob.hex())
    assert got == "INVALID", "Rust stream_open accepted a tampered stream."


def test_python_opens_rust_sealed_stream():
    """Interop: a stream sealed by Rust must open under the Python streaming shell."""
    import sys
    sys.path.insert(0, _ROOT)
    from streaming import open_stream  # noqa: E402

    c = _frozen("stream")
    rust_blob = bytes.fromhex(_rust("stream_seal", c["key"], c["salt"], c["aad"],
                                    c["n_maps"], *c["chunks"]))
    opened = open_stream(bytes.fromhex(c["key"]), rust_blob, aad=bytes.fromhex(c["aad"]),
                         n_maps=c["n_maps"])
    assert opened == bytes.fromhex(c["plaintext"]), "Python could not open the Rust-sealed stream."
