"""Tests for the streaming / chunked AEAD (item B).

Two groups:
  1. Standard AEAD guarantees per chunk (roundtrip, tamper / wrong-key / aad rejection).
  2. The stream-specific attacks the framing must defeat: reorder, drop, duplicate, truncate,
     append-after-final — none may slip past.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from aead import InvalidTag  # noqa: E402
from streaming import (  # noqa: E402
    HEADER_LEN,
    StreamOpener,
    StreamSealer,
    open_stream,
    seal_stream,
)

KEY = b"a shared secret of arbitrary length!!"
PARTS = [b"the quick brown fox ", b"jumps over " * 4, b"the lazy dog" * 10, b"tail"]


# --- helpers: split a seal_stream blob into (header, [frame, ...]) so tests can manipulate it ----

def _split(blob: bytes):
    header, frames, pos = blob[:HEADER_LEN], [], HEADER_LEN
    while pos < len(blob):
        flen = int.from_bytes(blob[pos:pos + 4], "big")
        pos += 4
        frames.append(blob[pos:pos + flen])
        pos += flen
    return header, frames


def _join(header: bytes, frames: list) -> bytes:
    out = bytearray(header)
    for f in frames:
        out += len(f).to_bytes(4, "big") + f
    return bytes(out)


# --- standard guarantees ------------------------------------------------------

def test_roundtrip_oneshot():
    assert open_stream(KEY, seal_stream(KEY, PARTS)) == b"".join(PARTS)


def test_roundtrip_incremental():
    s = StreamSealer(KEY, aad=b"f")
    wire = bytearray(s.header)
    for i, p in enumerate(PARTS):
        wire += s.seal_chunk(p, final=(i == len(PARTS) - 1))
    # Decrypt incrementally using the known frame layout.
    o = StreamOpener(KEY, bytes(wire[:HEADER_LEN]), aad=b"f")
    pos, got = HEADER_LEN, bytearray()
    for i, p in enumerate(PARTS):
        frame = bytes([wire[pos]]) + bytes(wire[pos + 1:pos + 1 + len(p)]) + bytes(wire[pos + 1 + len(p):pos + 1 + len(p) + 32])
        pt, final = o.open_chunk(frame)
        got += pt
        pos += 1 + len(p) + 32
        assert final == (i == len(PARTS) - 1)
    o.finish()
    assert bytes(got) == b"".join(PARTS)


def test_empty_stream():
    assert open_stream(KEY, seal_stream(KEY, [])) == b""


def test_single_chunk():
    assert open_stream(KEY, seal_stream(KEY, [b"solo"])) == b"solo"


def test_empty_chunks_in_the_middle():
    parts = [b"a", b"", b"b", b"", b"c"]
    assert open_stream(KEY, seal_stream(KEY, parts)) == b"abc"


def test_wrong_key_rejected():
    blob = seal_stream(KEY, PARTS)
    with pytest.raises(InvalidTag):
        open_stream(b"a different secret key.............xx", blob)


def test_aad_binding():
    blob = seal_stream(KEY, PARTS, aad=b"context-A")
    assert open_stream(KEY, blob, aad=b"context-A") == b"".join(PARTS)
    with pytest.raises(InvalidTag):
        open_stream(KEY, blob, aad=b"context-B")


def test_tamper_chunk_ciphertext_rejected():
    header, frames = _split(seal_stream(KEY, PARTS))
    f = bytearray(frames[1])
    f[5] ^= 0x01                      # flip a ciphertext bit in chunk 1
    frames[1] = bytes(f)
    with pytest.raises(InvalidTag):
        open_stream(KEY, _join(header, frames))


def test_tamper_header_commitment_rejected():
    blob = bytearray(seal_stream(KEY, PARTS))
    blob[HEADER_LEN - 1] ^= 0x01      # flip a bit in the header commitment
    with pytest.raises(InvalidTag):
        open_stream(KEY, bytes(blob))


# --- the stream-specific attacks ----------------------------------------------

def test_reorder_rejected():
    header, frames = _split(seal_stream(KEY, PARTS))
    frames[0], frames[1] = frames[1], frames[0]      # swap first two chunks
    with pytest.raises(InvalidTag):
        open_stream(KEY, _join(header, frames))


def test_drop_middle_chunk_rejected():
    header, frames = _split(seal_stream(KEY, PARTS))
    del frames[1]                                    # delete a middle chunk
    with pytest.raises(InvalidTag):
        open_stream(KEY, _join(header, frames))


def test_duplicate_chunk_rejected():
    header, frames = _split(seal_stream(KEY, PARTS))
    frames.insert(1, frames[1])                      # replay chunk 1 twice
    with pytest.raises(InvalidTag):
        open_stream(KEY, _join(header, frames))


def test_truncate_drop_final_rejected():
    header, frames = _split(seal_stream(KEY, PARTS))
    frames = frames[:-1]                             # cut off the final chunk
    with pytest.raises(InvalidTag):
        open_stream(KEY, _join(header, frames))


def test_append_after_final_rejected():
    header, frames = _split(seal_stream(KEY, PARTS))
    frames.append(frames[-1])                        # add a chunk after the final one
    with pytest.raises(InvalidTag):
        open_stream(KEY, _join(header, frames))


def test_opener_finish_requires_final():
    # A sealer that never marks a chunk final must fail finish() — the truncation guard.
    s = StreamSealer(KEY)
    frame = s.seal_chunk(b"only piece", final=False)
    o = StreamOpener(KEY, s.header)
    o.open_chunk(frame)
    with pytest.raises(InvalidTag):
        o.finish()


def test_cannot_seal_after_final():
    s = StreamSealer(KEY)
    s.seal_chunk(b"first", final=True)
    with pytest.raises(ValueError):
        s.seal_chunk(b"too late")
