"""
twolock.py — the SECURITY GOAL: two locks ("Option B"). RESEARCH ARTIFACT.

THE WHOLE POINT OF THE PROJECT
------------------------------
The chaos keystream is UNVETTED. We never trust it on its own. So we never deploy it on its own.
Instead we wrap the data in TWO independent locks, one inside the other:

      plaintext  --[ INNER vault: AES-256-GCM ]-->  --[ OUTER wall: chaos AEAD ]-->  on the wire

  * INNER vault  = a real, world-standard, peer-reviewed cipher (AES-256-GCM, or
                   ChaCha20-Poly1305). This is the lock that actually GUARANTEES the data.
  * OUTER wall   = our chaos AEAD (aead.py). This is the exposed, sacrificial extra barrier that
                   an attacker hits FIRST and has to defeat before they even reach the vault.

THE GUARANTEE (the honest, important part)
------------------------------------------
The attacker on the wire sees only the outer chaos ciphertext. To get anywhere they must first
break the chaos wall. Suppose they do — suppose the chaos cipher is COMPLETELY broken tomorrow and
the attacker peels the outer layer off entirely. What's underneath is still AES-256-GCM. They are
exactly where they'd be against AES alone: facing a ~2^128 wall, with the data fully protected.

So the confidentiality and integrity of the plaintext rest on the VETTED inner vault. The chaos
layer can fail outright and the client loses nothing. That is why an unvetted cipher is safe to
ship HERE and nowhere else: it is never the only lock, and never the lock that matters.

This does NOT make the chaos math secure. It makes the DEPLOYMENT safe in spite of the chaos math
being unproven. The chaos wall buys: (1) an extra, real barrier an attacker must also break, and
(2) the exposed surface that gets battle-tested by real-world attacks — exactly what an unvetted
design needs to earn (or lose) trust over time.

WHY THIS ORDER (vetted INSIDE, chaos OUTSIDE) — not the reverse
---------------------------------------------------------------
If we put chaos on the inside and the vetted cipher outside, the thing protecting the actual
plaintext would be the chaos layer — so a chaos break would expose the plaintext, and the vetted
cipher would only protect an already-broken blob. Useless. The lock that the plaintext ultimately
depends on MUST be the vetted one, so the vetted cipher is the INNER vault. (Bonus: chaos on the
outside is the part exposed to attackers, which is where we want our unvetted experiment to live.)

KEY SEPARATION
--------------
The two locks NEVER share a key. From the caller's master key we derive two independent keys with
HKDF-SHA256 (a vetted KDF) under distinct labels — one for the inner vault, one for the outer wall.
A weakness or related-key effect in one lock cannot reach the other, and recovering the outer key
(e.g. by breaking chaos) reveals nothing about the inner key (HKDF is one-way).

Interface mirrors the other shells:

    blob = seal_twolock(master_key, plaintext, aad=b"", inner="aes-256-gcm")
    plaintext = open_twolock(master_key, blob, aad=b"")   # raises InvalidTag on tamper/wrong key

Wire format: the blob IS the outer chaos AEAD blob. What the chaos layer encrypts (its plaintext)
is:  alg(1) || inner_nonce(12) || inner_ciphertext+tag(N)
The alg byte (which vetted cipher is inside) rides INSIDE the authenticated+encrypted outer layer,
so an attacker can neither read nor change it, and open_twolock is self-describing — the caller does
not have to remember which inner cipher was used.

STILL UNVETTED (the chaos half). But the data's security here rests on the vetted half. See
THREAT_MODEL.md ("two locks") and REPORT.md.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag as _CryptoInvalidTag

import aead as _outer

# Re-export so callers catch ONE exception type regardless of which lock rejected.
InvalidTag = _outer.InvalidTag

_HKDF_INNER_INFO = b"chaos-pwlcm-v1|twolock|inner-vault|v1"
_HKDF_OUTER_INFO = b"chaos-pwlcm-v1|twolock|outer-wall|v1"

INNER_NONCE_LEN = 12          # both AES-GCM and ChaCha20-Poly1305 take a 96-bit nonce
_KEY_LEN = 32                 # AES-256 / ChaCha20 key, and the outer master key

# alg id -> (name, AEAD class). The id is authenticated inside the outer layer.
_AES = 0x01
_CHACHA = 0x02
_INNER_BY_NAME = {"aes-256-gcm": _AES, "chacha20-poly1305": _CHACHA}
_INNER_BY_ID = {_AES: AESGCM, _CHACHA: ChaCha20Poly1305}


def _derive_keys(master_key: bytes) -> tuple[bytes, bytes]:
    """Split the caller's master key into two independent 32-byte keys via HKDF-SHA256 — one for the
    outer chaos wall, one for the inner vetted vault. Distinct info labels keep them domain-separated;
    HKDF's one-wayness means leaking one does not leak the other."""
    if not isinstance(master_key, (bytes, bytearray)):
        raise TypeError("master_key must be bytes")
    km = bytes(master_key)
    k_outer = HKDF(hashes.SHA256(), _KEY_LEN, None, _HKDF_OUTER_INFO).derive(km)
    k_inner = HKDF(hashes.SHA256(), _KEY_LEN, None, _HKDF_INNER_INFO).derive(km)
    return k_outer, k_inner


def seal_twolock(master_key: bytes, plaintext: bytes, aad: bytes = b"",
                 inner: str = "aes-256-gcm", *,
                 inner_nonce: bytes | None = None, outer_nonce: bytes | None = None) -> bytes:
    """Encrypt under two independent locks: the vetted inner vault, then the chaos outer wall.

    `aad` is bound to BOTH locks (defense in depth — both layers authenticate the context). `inner`
    selects the vetted cipher ("aes-256-gcm" default, or "chacha20-poly1305"). Returns the outer
    chaos blob; each call uses fresh random nonces in both layers, so the same plaintext seals
    differently every time.

    `inner_nonce` / `outer_nonce` are keyword-only and exist ONLY to pin the two sources of
    nondeterminism for a known-answer test / Rust parity vector (mirrors aead.seal's `nonce=` and
    streaming.seal_stream's `salt=`). Leave them None in real use — fresh random nonces are the safe
    default; reusing a nonce across two different plaintexts breaks the vetted vault."""
    try:
        alg = _INNER_BY_NAME[inner]
    except KeyError:
        raise ValueError(f"unknown inner cipher {inner!r}; "
                         f"choose one of {sorted(_INNER_BY_NAME)}") from None

    k_outer, k_inner = _derive_keys(master_key)

    # INNER vault: real, vetted AEAD with its own fresh nonce (pinned only for a KAT).
    if inner_nonce is None:
        inner_nonce = os.urandom(INNER_NONCE_LEN)
    elif len(inner_nonce) != INNER_NONCE_LEN:
        raise ValueError(f"inner_nonce must be exactly {INNER_NONCE_LEN} bytes")
    inner_ct = _INNER_BY_ID[alg](k_inner).encrypt(inner_nonce, plaintext, aad)
    inner_blob = bytes([alg]) + inner_nonce + inner_ct

    # OUTER wall: our chaos AEAD wraps the whole inner blob (and binds the same aad again). The outer
    # nonce, when pinned, is forwarded to aead.seal's own KAT hook; None there means a fresh random one.
    return _outer.seal(k_outer, inner_blob, aad=aad, nonce=outer_nonce)


def open_twolock(master_key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Peel the outer chaos wall, then open the inner vetted vault. Raises InvalidTag if EITHER lock
    rejects — wrong key or tampering at any layer — and NEVER returns plaintext in that case. The
    inner cipher is read from the (authenticated) blob, so the caller need not specify it."""
    k_outer, k_inner = _derive_keys(master_key)

    # OUTER wall: chaos AEAD verifies + decrypts; raises InvalidTag on tamper/wrong outer key.
    inner_blob = _outer.open_(k_outer, blob, aad=aad)
    if len(inner_blob) < 1 + INNER_NONCE_LEN:
        raise InvalidTag("inner blob too short / malformed")

    alg = inner_blob[0]
    cls = _INNER_BY_ID.get(alg)
    if cls is None:
        raise InvalidTag(f"unknown inner cipher id {alg:#x}")
    inner_nonce = inner_blob[1:1 + INNER_NONCE_LEN]
    inner_ct = inner_blob[1 + INNER_NONCE_LEN:]

    # INNER vault: the lock that actually guarantees the data. Even if the outer chaos wall were
    # fully broken, an attacker would still be stopped right here by the vetted cipher.
    try:
        return cls(k_inner).decrypt(inner_nonce, inner_ct, aad)
    except _CryptoInvalidTag:
        raise InvalidTag("inner vault authentication failed — wrong key or tampered ciphertext") from None


if __name__ == "__main__":
    key = b"my shared secret key (any bytes)"
    msg = b"Attack at dawn. Wire $40,000 by Friday."

    blob = seal_twolock(key, msg)
    print(f"sealed ({len(blob)} bytes): {blob.hex()[:48]}...")
    print(f"opened: {open_twolock(key, blob)!r}")

    # ChaCha20-Poly1305 inner works too, and the blob is self-describing on open.
    cblob = seal_twolock(key, msg, inner="chacha20-poly1305")
    print(f"chacha inner opened: {open_twolock(key, cblob)!r}")

    # Same message twice -> different blobs (fresh nonces in both layers).
    print(f"two seals differ: {seal_twolock(key, msg) != seal_twolock(key, msg)}")

    # Tamper one byte -> rejected by the outer wall.
    bad = bytearray(blob)
    bad[-1] ^= 0x01
    try:
        open_twolock(key, bytes(bad))
        print("TAMPER NOT DETECTED  <-- BUG")
    except InvalidTag as e:
        print(f"tamper rejected: {e}")

    # Wrong key -> rejected.
    try:
        open_twolock(b"the wrong key................", blob)
        print("WRONG KEY ACCEPTED  <-- BUG")
    except InvalidTag as e:
        print(f"wrong key rejected: {e}")
