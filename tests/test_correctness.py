"""Correctness & determinism — the floor any cipher must pass."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import DiscreteChaoticEngine  # noqa: E402

KEY = 11223344556677889900
CTRL = 99887766554433221100
NONCE = 7


def test_roundtrip():
    msg = b"the quick brown fox jumps over the lazy dog" * 10
    ct = DiscreteChaoticEngine(KEY, CTRL, NONCE).encrypt(msg)
    pt = DiscreteChaoticEngine(KEY, CTRL, NONCE).decrypt(ct)
    assert pt == msg
    assert ct != msg


def test_determinism_two_instances():
    a = DiscreteChaoticEngine(KEY, CTRL, NONCE).keystream(256)
    b = DiscreteChaoticEngine(KEY, CTRL, NONCE).keystream(256)
    assert a == b, "Same key+nonce must produce identical keystream (cross-machine sync)"


def test_nonce_changes_keystream():
    a = DiscreteChaoticEngine(KEY, CTRL, 1).keystream(256)
    b = DiscreteChaoticEngine(KEY, CTRL, 2).keystream(256)
    assert a != b, "Different nonce must yield a different keystream"


def test_key_changes_keystream():
    a = DiscreteChaoticEngine(KEY, CTRL, NONCE).keystream(256)
    b = DiscreteChaoticEngine(KEY + 1, CTRL, NONCE).keystream(256)
    assert a != b, "Key off by 1 must yield a different keystream"


def test_empty_and_single():
    assert DiscreteChaoticEngine(KEY, CTRL, NONCE).encrypt(b"") == b""
    ct = DiscreteChaoticEngine(KEY, CTRL, NONCE).encrypt(b"\x00")
    pt = DiscreteChaoticEngine(KEY, CTRL, NONCE).decrypt(ct)
    assert pt == b"\x00"
