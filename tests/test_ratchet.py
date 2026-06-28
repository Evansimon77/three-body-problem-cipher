"""Tests for the auto-rekey RatchetEngine (forward-secret, unbounded keystream)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ratchet import RatchetEngine, DEFAULT_EPOCH_BYTES  # noqa: E402

KEY = b"a shared ratchet secret of any length!"
NONCE = b"ratchet-nonce-0001"


def test_roundtrip_within_one_epoch():
    msg = b"short message inside a single epoch"
    ct = RatchetEngine(KEY, NONCE).encrypt(msg)
    pt = RatchetEngine(KEY, NONCE).decrypt(ct)
    assert pt == msg and ct != msg


def test_roundtrip_across_many_epochs():
    # tiny epochs so the message spans dozens of re-keys
    msg = bytes(range(256)) * 20          # 5,120 bytes
    eb = 64
    ct = RatchetEngine(KEY, NONCE, epoch_bytes=eb).encrypt(msg)
    pt = RatchetEngine(KEY, NONCE, epoch_bytes=eb).decrypt(ct)
    assert pt == msg and ct != msg
    assert len(msg) // eb >= 40           # really did cross many epochs


def test_determinism():
    a = RatchetEngine(KEY, NONCE, epoch_bytes=64).keystream(1000)
    b = RatchetEngine(KEY, NONCE, epoch_bytes=64).keystream(1000)
    assert a == b


def test_nonce_changes_keystream():
    a = RatchetEngine(KEY, b"nonce-A", epoch_bytes=64).keystream(512)
    b = RatchetEngine(KEY, b"nonce-B", epoch_bytes=64).keystream(512)
    assert a != b


def test_epoch_size_changes_boundaries():
    # different epoch sizes => different re-key schedule => different keystream
    a = RatchetEngine(KEY, NONCE, epoch_bytes=64).keystream(512)
    b = RatchetEngine(KEY, NONCE, epoch_bytes=128).keystream(512)
    assert a != b


def test_no_short_repeat():
    ks = RatchetEngine(KEY, NONCE, epoch_bytes=64).keystream(8192)
    for period in (16, 64, 128, 256, 1024):
        assert ks[:period] != ks[period:2 * period], f"keystream repeats at period {period}"


def test_checkpoint_resume_matches():
    # generate the first two epochs, checkpoint, then resume and continue
    eb = 64
    full = RatchetEngine(KEY, NONCE, epoch_bytes=eb)
    _ = full.keystream(2 * eb)                       # consume exactly two epochs
    chain, next_idx = full.checkpoint()
    resumed = RatchetEngine.from_chain_key(chain, next_idx, NONCE, epoch_bytes=eb)
    # a fresh engine's bytes 2*eb .. 4*eb must equal the resumed engine's first 2*eb bytes
    fresh = RatchetEngine(KEY, NONCE, epoch_bytes=eb)
    _ = fresh.keystream(2 * eb)
    assert fresh.keystream(2 * eb) == resumed.keystream(2 * eb)


def test_default_epoch_is_64kib():
    assert DEFAULT_EPOCH_BYTES == (1 << 16)


def test_decrypt_is_encrypt_inverse_default_epoch():
    # exercise the real default epoch size with a message larger than one epoch
    msg = os.urandom(DEFAULT_EPOCH_BYTES + 4096)
    ct = RatchetEngine(KEY, NONCE).encrypt(msg)
    pt = RatchetEngine(KEY, NONCE).decrypt(ct)
    assert pt == msg
