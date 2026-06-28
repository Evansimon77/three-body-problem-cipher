"""Tests for SeekableCTR — counter mode over the 3-map chaos keystream.

The headline property is SEEKABILITY: keystream(n, offset=k) must equal the global keystream
bytes k..k+n-1, no matter how the stream is sliced. Everything else (round-trip, determinism,
separation, avalanche, no short cycle) must still hold like the streaming modes.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ctr import SeekableCTR  # noqa: E402

KEY = b"a shared secret of arbitrary length!!"
NONCE = b"unique-nonce-0001"


def _bit_diff_fraction(a: bytes, b: bytes) -> float:
    diff = sum(bin(x ^ y).count("1") for x, y in zip(a, b))
    return diff / (len(a) * 8)


def test_roundtrip():
    msg = b"counter mode over chaos" * 8
    ct = SeekableCTR(KEY, NONCE).encrypt(msg)
    pt = SeekableCTR(KEY, NONCE).decrypt(ct)
    assert pt == msg and ct != msg


def test_determinism():
    a = SeekableCTR(KEY, NONCE).keystream(256)
    b = SeekableCTR(KEY, NONCE).keystream(256)
    assert a == b, "same key+nonce must produce identical keystream"


def test_seek_matches_full_stream():
    """The core CTR guarantee: any windowed read equals that slice of the full keystream."""
    c = SeekableCTR(KEY, NONCE)
    full = c.keystream(1000)
    bs = SeekableCTR.BLOCK_SIZE
    # probe a spread of offsets, deliberately crossing block boundaries
    for offset in (0, 1, bs - 1, bs, bs + 1, 137, 2 * bs, 500, 999):
        for length in (1, 7, bs, bs + 3, 200):
            if offset + length > len(full):
                continue
            window = c.keystream(length, offset=offset)
            assert window == full[offset:offset + length], (
                f"seek mismatch at offset={offset} length={length}")


def test_encrypt_at_offset_matches_full():
    """Encrypting a slice at its offset must equal the corresponding slice of a full encryption."""
    c = SeekableCTR(KEY, NONCE)
    data = bytes((i * 37) & 0xFF for i in range(500))
    full_ct = c.encrypt(data)
    off = 200
    part = data[off:off + 100]
    part_ct = c.encrypt(part, offset=off)
    assert part_ct == full_ct[off:off + 100]
    # and it decrypts back with only the offset known
    assert SeekableCTR(KEY, NONCE).decrypt(part_ct, offset=off) == part


def test_random_access_skips_earlier_blocks(monkeypatch=None):
    """Reading far into the stream must derive only the covering block(s), not everything before."""
    c = SeekableCTR(KEY, NONCE)
    derived = []
    real = c._block_keystream

    def spy(block_index):
        derived.append(block_index)
        return real(block_index)

    c._block_keystream = spy
    bs = SeekableCTR.BLOCK_SIZE
    far_pos = 1_000_000
    c.keystream(1, offset=far_pos)
    assert derived == [far_pos // bs], (
        f"expected exactly the covering block, derived {derived}")


def test_nonce_and_key_separation():
    base = SeekableCTR(KEY, NONCE).keystream(256)
    assert SeekableCTR(KEY, b"different-nonce!!").keystream(256) != base
    assert SeekableCTR(KEY + b"x", NONCE).keystream(256) != base


def test_blocks_are_independent():
    """Distinct counter blocks are domain-separated => unrelated keystreams."""
    c = SeekableCTR(KEY, NONCE)
    assert c._block_keystream(0) != c._block_keystream(1)
    assert c._block_keystream(0) != c._block_keystream(1_000_000)


def test_avalanche_near_half():
    base = SeekableCTR(KEY, NONCE).keystream(2048)
    fracs = []
    for i in range(16):
        flipped_key = bytes([KEY[0] ^ (1 << (i % 8))]) + KEY[1:]
        other = SeekableCTR(flipped_key, NONCE).keystream(2048)
        fracs.append(_bit_diff_fraction(base, other))
    avg = sum(fracs) / len(fracs)
    assert 0.45 <= avg <= 0.55, f"CTR avalanche {avg:.4f} too far from 0.5"


def test_no_short_cycle_in_sample():
    ks = SeekableCTR(KEY, NONCE).keystream(100_000)
    for period in (16, 64, 256, 1024):
        assert ks[:period] != ks[period:2 * period], f"keystream repeats at period {period}"


def test_default_is_four_maps():
    assert SeekableCTR(KEY, NONCE).n_maps == 4   # #2 decision 2026-06-28: 3 -> 4 independent maps
