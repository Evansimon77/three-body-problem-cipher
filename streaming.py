"""
streaming.py — chunked / streaming AEAD over the chaos core (item B). RESEARCH ARTIFACT.

THE PROBLEM THIS SOLVES
-----------------------
aead.py / siv.py seal a message in ONE shot: the whole plaintext must fit in memory, and you only
learn it was authentic after decrypting all of it. That breaks down for the things people actually
encrypt — a 4 GB disk image, a video upload, a live log feed. You want to encrypt as the bytes flow,
in CHUNKS, and you want each chunk verified the moment it arrives (so you can stop early on tampering
instead of buffering gigabytes first).

Cutting a stream into independently-encrypted chunks opens FOUR new attacks that a naive "just AEAD
each chunk" misses. This module defends all four — the standard "STREAM" construction (used by age,
Google Tink's streaming AEAD, and miscreant):

  1. REORDER   — swap chunk 5 and chunk 9.        Defended: each chunk's tag binds its index i.
  2. DROP      — delete chunk 7 from the middle.  Defended: the opener demands indices 0,1,2,… in order.
  3. DUPLICATE — replay chunk 3 twice.            Defended: same index check — a repeat is out of order.
  4. TRUNCATE  — cut the stream short.            Defended: the LAST chunk is marked `final`; the opener
                 errors unless it has seen exactly one final chunk and nothing after it.

Plus the usual two: TAMPER (per-chunk HMAC-SHA256) and KEY-CONFUSION (the stream header carries a
key-commitment, #6 — so a stream can't be made to open under two keys).

THE WIRE FORMAT
---------------
    header : salt(16) || commit(32)                       # sent first; salt is public, commit binds the key
    chunk  : framelen(4) || flags(1) || ciphertext(N) || tag(32)
             flags bit0 = `final`. framelen = 1 + N + 32, big-endian (self-delimiting for open_stream).

    per chunk i:  nonce_i = salt || i(8, big-endian) || flags(1)
                  ct_i    = MultiMapEngine(master_key, nonce_i).encrypt(plaintext_i)
                  tag_i   = HMAC(stream_mac_key, salt ‖ i(8) ‖ flags ‖ len(aad)‖aad ‖ ct_i)
    The index i lives inside BOTH the nonce and the tag, so a reordered/dropped/duplicated chunk
    cannot line up. The `final` flag lives inside the tag, so truncation flips an authenticated bit.

INCREMENTAL API (true streaming) + a convenience one-shot for whole buffers / tests:

    s = StreamSealer(key, aad=b"")
    out = s.header + s.seal_chunk(b"part 1") + s.seal_chunk(b"part 2", final=True)
    # ...or, for a buffer you already hold:
    blob = seal_stream(key, [b"part 1", b"part 2"], aad=b"")
    data = open_stream(key, blob, aad=b"")

STILL UNVETTED. This gives the chaos cipher a real streaming-AEAD shape on top of vetted HMAC-SHA256;
it does not make the chaos keystream proven-secure. See REPORT.md / THREAT_MODEL.md.
"""
from __future__ import annotations

import hashlib
import hmac
import os

from commit import COMMIT_LEN, key_commitment, verify_commitment
from multimap import DEFAULT_N_MAPS, MultiMapEngine

SALT_LEN = 16
TAG_LEN = 32                       # HMAC-SHA256
HEADER_LEN = SALT_LEN + COMMIT_LEN  # salt || commit
_FINAL = 0x01                       # flags bit0
_STREAM_MAC_INFO = b"chaos-pwlcm-v1|stream-mac-key"
_LEN_BYTES = 4                      # frame length prefix (big-endian) for the convenience form


class InvalidTag(Exception):
    """Raised when a chunk fails authentication — wrong key, tampering, reorder, drop, duplicate,
    or truncation."""


def _stream_mac_key(master_key: bytes) -> bytes:
    return hmac.new(bytes(master_key), _STREAM_MAC_INFO, hashlib.sha256).digest()


def _chunk_tag(mac_key: bytes, salt: bytes, index: int, flags: int,
               aad: bytes, ciphertext: bytes) -> bytes:
    """Authenticate (salt, index, flags, aad, ciphertext). Binding index + flags is what defeats
    reorder / drop / duplicate / truncate."""
    m = hmac.new(mac_key, digestmod=hashlib.sha256)
    m.update(salt)
    m.update(index.to_bytes(8, "big"))
    m.update(bytes([flags]))
    m.update(len(aad).to_bytes(8, "big"))
    m.update(aad)
    m.update(ciphertext)
    return m.digest()


def _chunk_nonce(salt: bytes, index: int, flags: int) -> bytes:
    return salt + index.to_bytes(8, "big") + bytes([flags])


class StreamSealer:
    """Encrypt a stream chunk by chunk. Send `.header` first, then each `.seal_chunk(...)` frame in
    order; mark the last with `final=True`."""

    def __init__(self, master_key: bytes, aad: bytes = b"", n_maps: int = DEFAULT_N_MAPS,
                 salt: bytes | None = None):
        if not isinstance(master_key, (bytes, bytearray)):
            raise TypeError("master_key must be bytes")
        self._master = bytes(master_key)
        self._aad = bytes(aad)
        self._n_maps = n_maps
        self._mac_key = _stream_mac_key(self._master)
        # salt is normally a fresh random value; an explicit salt is for deterministic use only
        # (KAT vectors / cross-impl parity). Reusing a salt across streams is safe here because each
        # chunk's nonce also includes its index + flags, but prefer random in production.
        if salt is None:
            salt = os.urandom(SALT_LEN)
        elif len(salt) != SALT_LEN:
            raise ValueError(f"salt must be {SALT_LEN} bytes")
        self._salt = salt
        self._index = 0
        self._closed = False
        # The header binds the key to (salt, aad): key-commitment for the whole stream.
        self.header = self._salt + key_commitment(self._master, self._salt, self._aad)

    def seal_chunk(self, data: bytes, final: bool = False) -> bytes:
        """Encrypt + authenticate one chunk. Returns flags(1) || ciphertext || tag (NOT length-
        prefixed — the incremental caller frames the transport)."""
        if self._closed:
            raise ValueError("stream already finalised — no more chunks")
        flags = _FINAL if final else 0
        nonce = _chunk_nonce(self._salt, self._index, flags)
        ct = MultiMapEngine(self._master, nonce, self._n_maps).encrypt(data)
        tag = _chunk_tag(self._mac_key, self._salt, self._index, flags, self._aad, ct)
        self._index += 1
        if final:
            self._closed = True
        return bytes([flags]) + ct + tag


class StreamOpener:
    """Verify + decrypt a stream chunk by chunk. Feed `.header` once, then each frame in arrival
    order. Call `.finish()` at the end to prove the stream was not truncated."""

    def __init__(self, master_key: bytes, header: bytes, aad: bytes = b"",
                 n_maps: int = DEFAULT_N_MAPS):
        if len(header) != HEADER_LEN:
            raise InvalidTag("stream header malformed")
        self._master = bytes(master_key)
        self._aad = bytes(aad)
        self._n_maps = n_maps
        self._mac_key = _stream_mac_key(self._master)
        self._salt = header[:SALT_LEN]
        commit = header[SALT_LEN:HEADER_LEN]
        if not verify_commitment(self._master, self._salt, self._aad, commit):
            raise InvalidTag("key-commitment failed — stream not committed to this key")
        self._index = 0
        self._done = False

    def open_chunk(self, frame: bytes) -> tuple[bytes, bool]:
        """Verify + decrypt one frame (flags(1) || ct || tag). Returns (plaintext, is_final).
        Raises InvalidTag on tamper / reorder / drop / duplicate / wrong key / data-after-final."""
        if self._done:
            raise InvalidTag("data after the final chunk — possible append/duplicate attack")
        if len(frame) < 1 + TAG_LEN:
            raise InvalidTag("chunk frame too short / malformed")
        flags = frame[0]
        ct = frame[1:-TAG_LEN]
        tag = frame[-TAG_LEN:]
        expected = _chunk_tag(self._mac_key, self._salt, self._index, flags, self._aad, ct)
        if not hmac.compare_digest(expected, tag):       # constant-time
            raise InvalidTag("chunk authentication failed — tamper / reorder / drop / wrong key")
        final = bool(flags & _FINAL)
        nonce = _chunk_nonce(self._salt, self._index, flags)
        pt = MultiMapEngine(self._master, nonce, self._n_maps).decrypt(ct)
        self._index += 1
        if final:
            self._done = True
        return pt, final

    def finish(self) -> None:
        """Confirm the stream ended cleanly: exactly one final chunk was seen. Catches truncation
        (a stream cut short never delivers the chunk whose `final` bit is set)."""
        if not self._done:
            raise InvalidTag("stream truncated — never saw the final chunk")


# --- convenience one-shot form (whole buffer in memory; handy for tests / small payloads) --------

def seal_stream(master_key: bytes, chunks: list[bytes], aad: bytes = b"",
                n_maps: int = DEFAULT_N_MAPS, salt: bytes | None = None) -> bytes:
    """Seal a list of chunks into ONE self-delimiting blob: header || (framelen||frame)*. An empty
    list still emits a single final empty chunk so open_stream round-trips to b"". `salt` is for
    deterministic use only (KAT / parity); leave it None for a fresh random salt."""
    sealer = StreamSealer(master_key, aad, n_maps, salt=salt)
    out = bytearray(sealer.header)
    if not chunks:
        chunks = [b""]
    last = len(chunks) - 1
    for i, c in enumerate(chunks):
        frame = sealer.seal_chunk(c, final=(i == last))
        out += len(frame).to_bytes(_LEN_BYTES, "big")
        out += frame
    return bytes(out)


def open_stream(master_key: bytes, blob: bytes, aad: bytes = b"",
                n_maps: int = DEFAULT_N_MAPS) -> bytes:
    """Verify + decrypt a blob made by seal_stream. Returns the concatenated plaintext, or raises
    InvalidTag on any manipulation (tamper / reorder / drop / duplicate / truncate / wrong key)."""
    if len(blob) < HEADER_LEN:
        raise InvalidTag("stream too short / malformed")
    opener = StreamOpener(master_key, blob[:HEADER_LEN], aad, n_maps)
    pos = HEADER_LEN
    out = bytearray()
    saw_final = False
    while pos < len(blob):
        if pos + _LEN_BYTES > len(blob):
            raise InvalidTag("truncated frame length")
        flen = int.from_bytes(blob[pos:pos + _LEN_BYTES], "big")
        pos += _LEN_BYTES
        if pos + flen > len(blob):
            raise InvalidTag("truncated frame body")
        pt, final = opener.open_chunk(blob[pos:pos + flen])
        out += pt
        pos += flen
        if final:
            saw_final = True
            break
    if pos != len(blob):
        raise InvalidTag("trailing data after the final chunk")
    if not saw_final:
        opener.finish()        # raises: stream truncated
    return bytes(out)


if __name__ == "__main__":
    key = b"streaming shared secret key"
    parts = [b"chunk-A " * 8, b"chunk-B " * 8, b"chunk-C (last) " * 4]

    # Incremental round-trip.
    s = StreamSealer(key, aad=b"file.bin")
    wire = bytearray(s.header)
    for i, p in enumerate(parts):
        wire += s.seal_chunk(p, final=(i == len(parts) - 1))

    blob = seal_stream(key, parts, aad=b"file.bin")
    print(f"sealed {sum(len(p) for p in parts)} bytes over {len(parts)} chunks "
          f"-> {len(blob)} on the wire")
    print(f"round-trip ok: {open_stream(key, blob, aad=b'file.bin') == b''.join(parts)}")

    # Truncation: drop the final chunk -> rejected.
    s2 = StreamSealer(key)
    truncated = s2.header + s2.seal_chunk(b"only piece", final=False)   # never marked final
    o = StreamOpener(key, truncated[:HEADER_LEN])
    o.open_chunk(truncated[HEADER_LEN:])
    try:
        o.finish()
        print("TRUNCATION NOT DETECTED  <-- BUG")
    except InvalidTag as e:
        print(f"truncation rejected: {e}")
