"""Tests for the SIV "seatbelt" — nonce-misuse-resistant AEAD.

Proves the two things that make SIV worth having on top of aead.py:
  1. Same authenticated-encryption guarantees (roundtrip, tamper/wrong-key rejection, AAD binding).
  2. Misuse resistance: DIFFERENT messages never share a keystream even though there is no nonce,
     so the two-time-pad break that kills the plain shell under nonce reuse is structurally gone.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from siv import SIV_LEN, InvalidTag, open_siv, seal_siv  # noqa: E402

KEY = b"a shared secret of arbitrary length!!"
MSG = b"the quick brown fox jumps over the lazy dog" * 5


# --- standard AEAD guarantees -------------------------------------------------

def test_roundtrip():
    assert open_siv(KEY, seal_siv(KEY, MSG)) == MSG


def test_empty_message():
    assert open_siv(KEY, seal_siv(KEY, b"")) == b""


def test_tamper_ciphertext_rejected():
    blob = bytearray(seal_siv(KEY, MSG))
    blob[SIV_LEN + 3] ^= 0x01              # flip a ciphertext bit
    with pytest.raises(InvalidTag):
        open_siv(KEY, bytes(blob))


def test_tamper_siv_rejected():
    blob = bytearray(seal_siv(KEY, MSG))
    blob[0] ^= 0x80                        # flip a bit in the SIV / tag
    with pytest.raises(InvalidTag):
        open_siv(KEY, bytes(blob))


def test_truncation_rejected():
    blob = seal_siv(KEY, MSG)
    with pytest.raises(InvalidTag):
        open_siv(KEY, blob[:-1])           # drop a byte


def test_wrong_key_rejected():
    blob = seal_siv(KEY, MSG)
    with pytest.raises(InvalidTag):
        open_siv(b"a different secret key.............xx", blob)


def test_aad_binding():
    blob = seal_siv(KEY, MSG, aad=b"context-A")
    assert open_siv(KEY, blob, aad=b"context-A") == MSG
    with pytest.raises(InvalidTag):
        open_siv(KEY, blob, aad=b"context-B")   # AAD mismatch must fail


def test_malformed_short_blob():
    with pytest.raises(InvalidTag):
        open_siv(KEY, b"\x00" * (SIV_LEN - 1))


# --- the misuse-resistance properties ----------------------------------------

def test_deterministic_same_message():
    # No random nonce: the same input always seals identically. This is the SIV contract.
    assert seal_siv(KEY, MSG) == seal_siv(KEY, MSG)


def test_different_messages_never_share_keystream():
    # The whole point: even a 1-bit difference yields an unrelated keystream, so XORing two
    # ciphertexts can NEVER cancel the keystream the way a two-time pad does.
    m0 = b"X" * 64
    m1 = b"X" * 63 + b"Y"                  # differs by one byte
    c0 = seal_siv(KEY, m0)[SIV_LEN:]
    c1 = seal_siv(KEY, m1)[SIV_LEN:]
    ks0 = bytes(a ^ b for a, b in zip(c0, m0))   # recover each keystream
    ks1 = bytes(a ^ b for a, b in zip(c1, m1))
    assert ks0 != ks1, "different messages reused the same keystream — misuse resistance broken"


def test_two_time_pad_cancellation_does_not_leak():
    # Classic two-time-pad attack: C0 ^ C1 == M0 ^ M1 iff the keystream was reused. With SIV the
    # keystreams differ, so this equality must NOT hold -> the attack yields nothing.
    m0 = b"Attack at dawn!!"
    m1 = b"Retreat at dusk!"
    c0 = seal_siv(KEY, m0)[SIV_LEN:]
    c1 = seal_siv(KEY, m1)[SIV_LEN:]
    xor_ct = bytes(a ^ b for a, b in zip(c0, c1))
    xor_pt = bytes(a ^ b for a, b in zip(m0, m1))
    assert xor_ct != xor_pt, "C0^C1 leaked M0^M1 — keystream was reused (two-time pad)"


def test_aad_separates_identical_plaintexts():
    # Determinism leaks only that two plaintexts are equal; a distinct aad (e.g. a counter or a
    # random salt) makes even identical plaintexts seal differently — the escape hatch.
    a = seal_siv(KEY, MSG, aad=b"msg-#1")
    b = seal_siv(KEY, MSG, aad=b"msg-#2")
    assert a != b
    assert open_siv(KEY, a, aad=b"msg-#1") == open_siv(KEY, b, aad=b"msg-#2") == MSG
