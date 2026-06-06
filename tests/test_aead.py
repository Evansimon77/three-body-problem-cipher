"""Tests for the AEAD shell — confidentiality + integrity + safe key/nonce handling."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from aead import NONCE_LEN, TAG_LEN, InvalidTag, open_, seal  # noqa: E402

KEY = b"a shared secret of arbitrary length!!"
MSG = b"the quick brown fox jumps over the lazy dog" * 5


def test_roundtrip():
    assert open_(KEY, seal(KEY, MSG)) == MSG


def test_empty_message():
    assert open_(KEY, seal(KEY, b"")) == b""


def test_fresh_nonce_no_two_time_pad():
    # Same key + same plaintext must produce different blobs (random nonce per seal).
    a, b = seal(KEY, MSG), seal(KEY, MSG)
    assert a != b
    assert open_(KEY, a) == open_(KEY, b) == MSG


def test_tamper_ciphertext_rejected():
    blob = bytearray(seal(KEY, MSG))
    blob[NONCE_LEN + 3] ^= 0x01            # flip a ciphertext bit
    with pytest.raises(InvalidTag):
        open_(KEY, bytes(blob))


def test_tamper_tag_rejected():
    blob = bytearray(seal(KEY, MSG))
    blob[-1] ^= 0x80                       # flip a tag bit
    with pytest.raises(InvalidTag):
        open_(KEY, bytes(blob))


def test_truncation_rejected():
    blob = seal(KEY, MSG)
    with pytest.raises(InvalidTag):
        open_(KEY, blob[:-1])              # drop a byte


def test_wrong_key_rejected():
    blob = seal(KEY, MSG)
    with pytest.raises(InvalidTag):
        open_(b"a different secret key.............xx", blob)


def test_aad_binding():
    blob = seal(KEY, MSG, aad=b"context-A")
    assert open_(KEY, blob, aad=b"context-A") == MSG
    with pytest.raises(InvalidTag):
        open_(KEY, blob, aad=b"context-B")   # AAD mismatch must fail


def test_malformed_short_blob():
    with pytest.raises(InvalidTag):
        open_(KEY, b"\x00" * (NONCE_LEN + TAG_LEN - 1))


def test_weak_key_class_no_longer_collapses():
    # The old period-1 weak class (key=1, ctrl=1) is unreachable through the KDF; verify a
    # tiny/degenerate-looking master key still yields healthy, non-constant ciphertext.
    blob = seal(b"\x01", b"\x00" * 64)
    ct = blob[NONCE_LEN:-TAG_LEN]
    assert len(set(ct)) > 16, "keystream looks constant — weak-key collapse not fixed"
