"""
pq_keyexchange.py — POST-QUANTUM HYBRID key agreement (item F). RESEARCH ARTIFACT.

THE PROBLEM IT SOLVES
---------------------
keyexchange.py agrees a key with Diffie-Hellman. Its whole security rests on the discrete-log problem
being hard — which a large quantum computer running Shor's algorithm would solve, breaking DH outright.
The danger is not hypothetical-future-only: an attacker can RECORD today's DH traffic and decrypt it
years later once a quantum machine exists ("harvest now, decrypt later"). Long-lived secrets need a
defence today.

THE FIX — HYBRID, not replace:
  Combine the classical DH with a POST-QUANTUM key-encapsulation mechanism (KEM) and mix BOTH shared
  secrets into the final key. The result is secure if EITHER primitive holds:
    * a quantum computer breaks DH  -> the ML-KEM secret still protects you;
    * some classical break is found in the (newer, less battle-tested) ML-KEM -> the 2048-bit DH,
      studied for decades, still protects you.
  This belt-and-suspenders hybrid is exactly what NIST (SP 800-56C), the IETF (hybrid KEX drafts), and
  Signal (PQXDH) recommend for the migration period. You do not bet everything on the new thing.

VETTED PRIMITIVES, NOT HOMEMADE (the project's standing rule):
  The post-quantum part is **ML-KEM-768** (FIPS 203, NIST security level 3), taken straight from the
  `cryptography` library's OpenSSL 3.5 backend — a reviewed, standardised implementation. We do NOT
  hand-roll Kyber/ML-KEM (its NTT/polynomial math is a footgun); inventing it would be the exact
  overclaim this project exists to avoid. The classical part is the same RFC 3526 MODP-2048 DH as
  keyexchange.py. The only thing this module ADDS is the secure COMBINER that mixes the two secrets.

THE HANDSHAKE (initiator = Alice, responder = Bob):
  Alice -> Bob :  dh_A = g^a ,  kem_pk_A           (her DH public + a fresh ML-KEM public key)
  Bob   -> Alice: dh_B = g^b ,  kem_ct             (his DH public + a KEM ciphertext to her pk)
  classical = DH(a, dh_B) = DH(b, dh_A)            (both sides, symmetric)
  pq        = decapsulate(kem_ct) = the encapsulated secret   (both sides get the same 32 bytes)
  key       = SHA-512( label ‖ classical ‖ pq ‖ info ‖ transcript )[:32]
  transcript = dh_A ‖ dh_B ‖ kem_pk_A ‖ kem_ct    (binds the whole exchange; tampering -> different key)

HONEST CAVEATS:
  * UNAUTHENTICATED, like keyexchange.py: this stops a PASSIVE recorder (now and post-quantum), not an
    active man-in-the-middle who can replace messages. Authentication is the separate triple-DH /
    signature layer (auth_keyexchange.py); a fully PQ-secure *authenticated* handshake would also need
    a PQ signature (ML-DSA) — noted as future work.
  * Security level: ML-KEM-768 ≈ NIST level 3 (~AES-192-equivalent against quantum); classical DH ≈
    112–128-bit. The hybrid key is as strong as the STRONGER surviving primitive in each threat model.
  * The chaos bulk cipher downstream is still UNVETTED. DH and ML-KEM are the sound parts; chaos is the toy.
"""
from __future__ import annotations

import hashlib

from keyexchange import DH_BYTES, DHParty

# ML-KEM lives in cryptography's OpenSSL 3.5+ backend. Guard the import so the rest of the project
# (and CI on an older OpenSSL) still loads; callers get a clear error, tests auto-skip.
try:
    from cryptography.hazmat.primitives.asymmetric import mlkem
    MLKEM_AVAILABLE = True
except Exception:                                    # pragma: no cover - platform dependent
    MLKEM_AVAILABLE = False

_KDF_LABEL = b"chaos-pwlcm-v1|pq-hybrid|dh-2048+ml-kem-768|v1"


def _require_mlkem() -> None:
    if not MLKEM_AVAILABLE:                           # pragma: no cover - platform dependent
        raise RuntimeError(
            "ML-KEM unavailable — needs `cryptography` built against OpenSSL 3.5+. "
            "The hybrid handshake cannot run without the vetted post-quantum KEM."
        )


def _enc_dh(x: int) -> bytes:
    """Fixed-width encoding of a DH group element (so the transcript is unambiguous)."""
    return x.to_bytes(DH_BYTES, "big")


def _transcript(dh_a: int, dh_b: int, kem_pk_a: bytes, kem_ct: bytes) -> bytes:
    """All four public values, in a fixed order. Both sides build the identical transcript; binding it
    into the KDF means any tampered public value yields a different key (the handshake fails closed)."""
    return _enc_dh(dh_a) + _enc_dh(dh_b) + kem_pk_a + kem_ct


def _combine(classical: bytes, pq: bytes, transcript: bytes, info: bytes) -> bytes:
    """The hybrid combiner (NIST SP 800-56C concatenation style): hash BOTH secrets together with the
    transcript. The final key is unknown unless you hold BOTH secrets, so it survives the loss of
    either one. Each field is length-prefixed to remove any concatenation ambiguity."""
    h = hashlib.sha512()
    h.update(_KDF_LABEL)
    for part in (classical, pq, info, transcript):
        h.update(len(part).to_bytes(8, "big"))
        h.update(part)
    return h.digest()[:32]


class HybridInitiator:
    """Alice. Holds a classical DH keypair + a fresh ML-KEM keypair. Publishes (dh_public,
    kem_public); after receiving Bob's (dh_public, kem_ciphertext), derives the shared key."""

    def __init__(self):
        _require_mlkem()
        self._dh = DHParty()
        self._kem_sk = mlkem.MLKEM768PrivateKey.generate()
        self.dh_public = self._dh.public
        self.kem_public = self._kem_sk.public_key().public_bytes_raw()

    def shared_key(self, dh_peer_public: int, kem_ciphertext: bytes, info: bytes = b"") -> bytes:
        """Mix DH(a, dh_B) with the decapsulated ML-KEM secret into the 32-byte session key."""
        classical = self._dh.raw_shared_secret(dh_peer_public)       # validates the peer value
        pq = self._kem_sk.decapsulate(kem_ciphertext)
        transcript = _transcript(self.dh_public, dh_peer_public, self.kem_public, kem_ciphertext)
        return _combine(classical, pq, transcript, info)


class HybridResponder:
    """Bob. Holds a classical DH keypair. Given Alice's (dh_public, kem_public), produces the KEM
    ciphertext to send back AND the shared key in one step."""

    def __init__(self):
        _require_mlkem()
        self._dh = DHParty()
        self.dh_public = self._dh.public

    def respond(self, dh_peer_public: int, kem_peer_public: bytes,
                info: bytes = b"") -> tuple[bytes, bytes]:
        """Returns (kem_ciphertext, shared_key). Send the ciphertext (and self.dh_public) to Alice."""
        classical = self._dh.raw_shared_secret(dh_peer_public)       # validates the peer value
        peer_pk = mlkem.MLKEM768PublicKey.from_public_bytes(kem_peer_public)
        pq, kem_ct = peer_pk.encapsulate()
        transcript = _transcript(dh_peer_public, self.dh_public, kem_peer_public, kem_ct)
        return kem_ct, _combine(classical, pq, transcript, info)


def hybrid_agree(initiator: HybridInitiator, responder: HybridResponder,
                 info: bytes = b"") -> bytes:
    """Convenience: run the full two-message handshake and assert both sides agree. Returns the key."""
    kem_ct, key_b = responder.respond(initiator.dh_public, initiator.kem_public, info)
    key_a = initiator.shared_key(responder.dh_public, kem_ct, info)
    if key_a != key_b:
        raise RuntimeError("hybrid agreement failed — parties derived different keys")
    return key_a


if __name__ == "__main__":
    _require_mlkem()
    from aead import open_, seal

    # 1) Alice & Bob have never shared a secret. Two messages, and they agree a key that resists BOTH
    #    a passive eavesdropper today AND a future quantum computer replaying the recording.
    alice, bob = HybridInitiator(), HybridResponder()
    kem_ct, key_bob = bob.respond(alice.dh_public, alice.kem_public)
    key_alice = alice.shared_key(bob.dh_public, kem_ct)
    print(f"Alice key: {key_alice.hex()}")
    print(f"Bob   key: {key_bob.hex()}")
    print(f"keys match (classical + post-quantum mixed): {key_alice == key_bob}")
    print(f"on the wire: dh {len(_enc_dh(alice.dh_public))}B + kem_pk "
          f"{len(alice.kem_public)}B + kem_ct {len(kem_ct)}B")

    # 2) End to end with the chaos AEAD.
    blob = seal(key_alice, b"safe even against harvest-now-decrypt-later")
    print(f"Alice seals -> Bob opens: {open_(key_bob, blob)!r}")
