"""
AEAD shell around the chaos PWLCM core — the SIMPLE, SAFE interface.

This is the "deep module, simple interface" layer. The chaotic keystream in engine.py is
the untouched heart; this file wraps it so a caller cannot trip the three foot-guns that
adversarial testing exposed:

  1. Weak keys        -> handled: keys go through a hash KDF (engine.from_master), and the
                         weak-parameter band is rejected. You cannot pick a bad key.
  2. Keystream reuse  -> handled: every seal() draws a FRESH RANDOM nonce, so the same
                         message encrypted twice yields different output. No two-time pad.
  3. Tampering        -> handled: encrypt-then-MAC (HMAC-SHA256). open() verifies the tag
                         in constant time BEFORE decrypting and raises if anything changed.
  4. Key-confusion    -> handled: a key-COMMITMENT (#6) binds the blob to exactly one key, so a
                         single ciphertext cannot be made to open under two different keys (the
                         attack that breaks AES-GCM / ChaCha20-Poly1305). See commit.py.

Interface is just two calls:

    blob = seal(master_key, plaintext, aad=b"")
    plaintext = open_(master_key, blob, aad=b"")     # raises InvalidTag on tamper/wrong key

Wire format (bytes):  nonce(16) || commit(32) || ciphertext(N) || tag(32)

STILL UNVETTED. This makes the engine structurally CORRECT (it now looks like a real AEAD,
same shape as ChaCha20-Poly1305). It does NOT make the underlying chaos math proven-secure.
See REPORT.md.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from commit import COMMIT_LEN, key_commitment, verify_commitment
from constants import DEFAULT_N_MAPS
from multimap import MultiMapEngine

NONCE_LEN = 16
TAG_LEN = 32           # HMAC-SHA256
_MAC_INFO = b"chaos-pwlcm-v1|mac-key"


class InvalidTag(Exception):
    """Raised when authentication fails — wrong key, or the ciphertext was tampered with."""


def _mac_key(master_key: bytes) -> bytes:
    """Derive an independent MAC key from the master key (domain-separated from the
    keystream, which is derived with a different label inside the engine)."""
    return hmac.new(master_key, _MAC_INFO, hashlib.sha256).digest()


def _tag(master_key: bytes, nonce: bytes, commit: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """Authenticate nonce + commitment + AAD + ciphertext (encrypt-then-MAC). Length-prefix AAD so
    (aad, ct) boundaries can't be shifted by an attacker. Covering the commitment means the whole
    blob sits under one integrity boundary."""
    m = hmac.new(_mac_key(master_key), digestmod=hashlib.sha256)
    m.update(nonce)
    m.update(commit)
    m.update(len(aad).to_bytes(8, "big"))
    m.update(aad)
    m.update(ciphertext)
    return m.digest()


def seal(master_key: bytes, plaintext: bytes, aad: bytes = b"",
         n_maps: int = DEFAULT_N_MAPS, nonce: bytes | None = None) -> bytes:
    """Encrypt + authenticate. Returns nonce || ciphertext || tag.

    Keystream comes from `n_maps` independent chaotic maps XOR-combined (default 4 — the
    multi-body design that defeats the single-map state-recovery attack). A fresh random nonce
    is generated every call, so encrypting the same plaintext twice gives different output and
    keystream reuse cannot happen.

    `nonce` is optional and exists ONLY to pin the one source of nondeterminism for a known-answer
    test / Rust-parity vector (mirrors streaming.seal_stream's `salt=`). Leave it None in production
    — a fresh random nonce is the safe default. Callers that pass it (e.g. ratchet_aead's session
    KAT path) are responsible for never reusing one under the same key."""
    if not isinstance(master_key, (bytes, bytearray)):
        raise TypeError("master_key must be bytes")
    if nonce is None:
        nonce = os.urandom(NONCE_LEN)
    elif len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be exactly {NONCE_LEN} bytes")
    ciphertext = MultiMapEngine(master_key, nonce, n_maps).encrypt(plaintext)
    commit = key_commitment(master_key, nonce, aad)
    tag = _tag(master_key, nonce, commit, aad, ciphertext)
    return nonce + commit + ciphertext + tag


def open_(master_key: bytes, blob: bytes, aad: bytes = b"",
          n_maps: int = DEFAULT_N_MAPS) -> bytes:
    """Verify + decrypt. Raises InvalidTag if the key is wrong or anything was tampered
    with — the plaintext is NEVER returned for a bad tag. `n_maps` must match the value used
    by seal()."""
    if len(blob) < NONCE_LEN + COMMIT_LEN + TAG_LEN:
        raise InvalidTag("ciphertext too short / malformed")
    nonce = blob[:NONCE_LEN]
    commit = blob[NONCE_LEN:NONCE_LEN + COMMIT_LEN]
    tag = blob[-TAG_LEN:]
    ciphertext = blob[NONCE_LEN + COMMIT_LEN:-TAG_LEN]

    expected = _tag(master_key, nonce, commit, aad, ciphertext)
    if not hmac.compare_digest(expected, tag):       # constant-time: no timing leak
        raise InvalidTag("authentication failed — wrong key or tampered ciphertext")
    # Key-commitment (#6): this blob must commit to exactly THIS key. Independent of the tag, so the
    # property holds even if the MAC-key derivation had a weakness. Constant-time compare inside.
    if not verify_commitment(master_key, nonce, aad, commit):
        raise InvalidTag("key-commitment failed — blob not committed to this key")

    return MultiMapEngine(master_key, nonce, n_maps).decrypt(ciphertext)


if __name__ == "__main__":
    key = b"my shared secret key (any bytes)"
    msg = b"Attack at dawn. Wire $40,000 by Friday."

    blob = seal(key, msg)
    print(f"sealed ({len(blob)} bytes): {blob.hex()[:48]}...")
    print(f"opened: {open_(key, blob)!r}")

    # same message twice -> different blobs (fresh nonce, no two-time pad)
    print(f"two seals differ: {seal(key, msg) != seal(key, msg)}")

    # tamper one byte in the ciphertext -> rejected
    bad = bytearray(blob)
    bad[NONCE_LEN + COMMIT_LEN] ^= 0x01
    try:
        open_(key, bytes(bad))
        print("TAMPER NOT DETECTED  <-- BUG")
    except InvalidTag as e:
        print(f"tamper rejected: {e}")

    # wrong key -> rejected
    try:
        open_(b"the wrong key................", blob)
        print("WRONG KEY ACCEPTED  <-- BUG")
    except InvalidTag as e:
        print(f"wrong key rejected: {e}")
