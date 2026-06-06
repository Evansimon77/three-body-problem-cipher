"""
SIV "seatbelt" — nonce-MISUSE-resistant AEAD over the chaos PWLCM core.

THE PROBLEM THIS SOLVES
-----------------------
The normal shell (aead.py) is safe ONLY as long as every message gets a fresh, never-repeated
nonce. That is a foot-gun: if a nonce is ever reused (a buggy caller hard-codes one, a counter
resets after a crash, a random draw collides), the SAME keystream encrypts two messages and the
cipher falls to a classic two-time-pad break. The safety depends on the caller never slipping.

SIV removes the foot-gun entirely: there is NO nonce for the caller to get wrong. Instead the IV
is *synthesised from the message itself* (a keyed hash of aad + plaintext). This is the proven
SIV / "deterministic AEAD" construction (Rogaway-Shrimpton; RFC 5297 uses it for AES-SIV).

WHAT YOU GET
------------
  * No nonce argument at all -> impossible to reuse one.
  * Two DIFFERENT messages -> different synthetic IV -> different keystream. No two-time pad,
    EVER, no matter how the caller behaves.
  * Two IDENTICAL messages (same key, aad, plaintext) -> identical output. That leaks only the
    single fact "these two ciphertexts hide the same plaintext" — the unavoidable minimum for any
    deterministic scheme, and far better than a full keystream-reuse break.
  * Authentication for free: the synthetic IV *is* the tag. Decrypt, recompute the IV from the
    recovered plaintext, constant-time compare. Any tampering changes the plaintext and the IV
    won't match -> rejected, plaintext never returned.

Interface mirrors aead.py, minus the nonce:

    blob = seal_siv(master_key, plaintext, aad=b"")
    plaintext = open_siv(master_key, blob, aad=b"")   # raises InvalidTag on tamper/wrong key

Wire format (bytes):  siv(32) || ciphertext(N)        # the 32-byte SIV is both IV and tag

TRADE-OFF (honest): deterministic encryption means identical plaintexts are detectable as equal.
If you must hide even that, add a real random nonce into the `aad` before sealing — then the SIV
becomes message-unique again while keeping misuse-resistance for the rest of the input.

STILL UNVETTED. This makes the construction structurally match a real misuse-resistant AEAD
(same shape as AES-SIV). It does NOT make the underlying chaos math proven-secure. See REPORT.md.
"""

from __future__ import annotations

import hashlib
import hmac

from multimap import DEFAULT_N_MAPS, MultiMapEngine

SIV_LEN = 32              # HMAC-SHA256 output: serves as BOTH the IV and the auth tag
_SIV_INFO = b"chaos-pwlcm-v1|siv-key"


class InvalidTag(Exception):
    """Raised when authentication fails — wrong key, or the ciphertext was tampered with."""


def _siv_key(master_key: bytes) -> bytes:
    """Derive an independent key for the synthetic-IV PRF, domain-separated from the keystream
    derivation (which uses a different label inside the engine) and from aead.py's MAC key."""
    return hmac.new(master_key, _SIV_INFO, hashlib.sha256).digest()


def _synthesise_iv(master_key: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """The heart of SIV: IV = keyed hash of (aad, plaintext). Length-prefix the aad so an
    attacker cannot slide the (aad | plaintext) boundary. Deterministic in all inputs."""
    m = hmac.new(_siv_key(master_key), digestmod=hashlib.sha256)
    m.update(len(aad).to_bytes(8, "big"))
    m.update(aad)
    m.update(plaintext)
    return m.digest()


def seal_siv(master_key: bytes, plaintext: bytes, aad: bytes = b"",
             n_maps: int = DEFAULT_N_MAPS) -> bytes:
    """Encrypt + authenticate with NO caller-supplied nonce. Returns siv || ciphertext.

    The IV is derived from the message itself, so the same plaintext always seals the same way
    (deterministic) while any two different messages get unrelated keystreams. Keystream reuse
    across different messages is structurally impossible."""
    if not isinstance(master_key, (bytes, bytearray)):
        raise TypeError("master_key must be bytes")
    siv = _synthesise_iv(master_key, aad, plaintext)
    ciphertext = MultiMapEngine(master_key, siv, n_maps).encrypt(plaintext)
    return siv + ciphertext


def open_siv(master_key: bytes, blob: bytes, aad: bytes = b"",
             n_maps: int = DEFAULT_N_MAPS) -> bytes:
    """Verify + decrypt. Decrypts with the received SIV, then re-derives the SIV from the
    recovered plaintext and compares in constant time. Raises InvalidTag on any mismatch —
    wrong key or tampering — and NEVER returns the plaintext in that case."""
    if len(blob) < SIV_LEN:
        raise InvalidTag("ciphertext too short / malformed")
    siv = blob[:SIV_LEN]
    ciphertext = blob[SIV_LEN:]

    plaintext = MultiMapEngine(master_key, siv, n_maps).decrypt(ciphertext)
    expected = _synthesise_iv(master_key, aad, plaintext)
    if not hmac.compare_digest(expected, siv):       # constant-time: no timing leak
        raise InvalidTag("authentication failed — wrong key or tampered ciphertext")

    return plaintext


if __name__ == "__main__":
    key = b"my shared secret key (any bytes)"
    msg = b"Attack at dawn. Wire $40,000 by Friday."

    blob = seal_siv(key, msg)
    print(f"sealed ({len(blob)} bytes): {blob.hex()[:48]}...")
    print(f"opened: {open_siv(key, blob)!r}")

    # THE SEATBELT: sealing the SAME message twice is deterministic (no random nonce needed)...
    print(f"two seals of same msg identical: {seal_siv(key, msg) == seal_siv(key, msg)}")

    # ...yet two DIFFERENT messages never share a keystream (no two-time pad, ever).
    a = seal_siv(key, b"AAAAAAAAAAAAAAAA")
    b = seal_siv(key, b"AAAAAAAAAAAAAAAB")            # differs by one bit
    ks_a = bytes(x ^ y for x, y in zip(a[SIV_LEN:], b"AAAAAAAAAAAAAAAA"))
    ks_b = bytes(x ^ y for x, y in zip(b[SIV_LEN:], b"AAAAAAAAAAAAAAAB"))
    print(f"different msgs -> different keystream: {ks_a != ks_b}")

    # tamper one byte in the ciphertext -> rejected
    bad = bytearray(blob)
    bad[SIV_LEN] ^= 0x01
    try:
        open_siv(key, bytes(bad))
        print("TAMPER NOT DETECTED  <-- BUG")
    except InvalidTag as e:
        print(f"tamper rejected: {e}")

    # wrong key -> rejected
    try:
        open_siv(b"the wrong key................", blob)
        print("WRONG KEY ACCEPTED  <-- BUG")
    except InvalidTag as e:
        print(f"wrong key rejected: {e}")
