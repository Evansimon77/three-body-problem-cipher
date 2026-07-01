"""
auth_pq_keyexchange.py — AUTHENTICATED, POST-QUANTUM key agreement. RESEARCH ARTIFACT.

WHAT THIS CLOSES
----------------
We already had two separate pieces:
  * pq_keyexchange.py  — hybrid CONFIDENTIALITY (classical DH + ML-KEM-768): safe against a passive
                         recorder, today and after quantum ("harvest now, decrypt later"). But it is
                         UNAUTHENTICATED — an active man-in-the-middle can impersonate either side.
  * auth_keyexchange.py — AUTHENTICATION via triple-DH (static + ephemeral): an impostor can't derive
                         the key. But its authentication rests entirely on the discrete-log problem,
                         which a quantum computer breaks — so the authentication is NOT post-quantum.

This module fuses them into one handshake that is BOTH authenticated AND post-quantum on every axis:
confidentiality survives quantum, and so does the proof of who you're talking to.

HYBRID ON BOTH AXES (secure if EITHER primitive in each pair holds — the project's standing rule)
-------------------------------------------------------------------------------------------------
  CONFIDENTIALITY = classical ephemeral DH  ⊕  ML-KEM-768 (post-quantum KEM)
        → a quantum break of DH leaves ML-KEM; a classical break of ML-KEM leaves 2048-bit DH.

  AUTHENTICATION  = triple-DH STATIC binding  ⊕  ML-DSA-65 signatures (post-quantum, FIPS 204)
        → if a quantum computer breaks DH (so the static binding is forgeable), the ML-DSA signature
          still proves identity; if some classical break hits the newer ML-DSA, the decades-studied
          static-DH binding still proves identity. An attacker must defeat BOTH to impersonate.

VETTED PRIMITIVES, NOT HOMEMADE: ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204) both come straight
from the `cryptography` library's OpenSSL backend. The classical DH is RFC 3526 MODP-2048. We invent
only the COMBINER and the transcript binding — never the cryptographic primitives.

THE HANDSHAKE (initiator = Alice, responder = Bob; both verified each other's identity fingerprint once)
-------------------------------------------------------------------------------------------------------
  flight 1  A → B : dh_A , kem_pk_A                      (Alice's ephemeral DH pub + fresh ML-KEM pub)
  flight 2  B → A : dh_B , kem_ct , sig_B                (Bob's ephemeral DH pub + KEM ciphertext +
                                                          Bob's ML-DSA signature over the FULL transcript)
  flight 3  A → B : sig_A                                (Alice's ML-DSA signature over the transcript)

  Each side derives:
     ee = DH(my_ephemeral, peer_ephemeral)               classical, forward secrecy
     pq = ML-KEM shared secret                           post-quantum confidentiality
     es = DH(my_ephemeral, peer_STATIC), se = DH(my_STATIC, peer_ephemeral)   static identity binding
     key = SHA-512( label ‖ ee ‖ pq ‖ sort(es,se) ‖ transcript ‖ info )[:32]
  …and each VERIFIES the peer's ML-DSA signature over the transcript. Any failure → the handshake
  raises (impersonation/tamper caught); the key is never returned.

  transcript = both identities (sig_pub + static_pub) ‖ dh_A ‖ kem_pk_A ‖ dh_B ‖ kem_ct, fixed order.
  Binding both identities + every public value means a tampered value or a swapped identity changes the
  transcript, so the signatures don't verify and the derived keys don't match. Defeats unknown-key-share
  and identity-misbinding too.

HONEST CAVEATS
  * Identities are trust-on-first-use: you verify the peer's fingerprint (over BOTH their signature and
    static keys) out-of-band ONCE. Trust the wrong key → you authenticated the wrong person; no math
    fixes mis-verified identity. Same as accepting a forged certificate.
  * Three flights for MUTUAL authentication (each side must sign a transcript that includes the other's
    contribution — the standard SIGMA/TLS pattern; you cannot sign a nonce you haven't seen yet).
  * The chaos bulk cipher downstream is still UNVETTED. DH, ML-KEM and ML-DSA are the sound parts.
"""
from __future__ import annotations

import hashlib
from typing import NamedTuple

from keyexchange import DH_BYTES, DHParty

# Post-quantum primitives live in cryptography's OpenSSL 3.5+ backend. Guard the imports so the rest
# of the project still loads on an older OpenSSL; callers get a clear error and tests auto-skip.
try:
    from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
    PQ_AVAILABLE = True
except Exception:                                    # pragma: no cover - platform dependent
    PQ_AVAILABLE = False

_KDF_LABEL = b"chaos-pwlcm-v1|auth-pq|dh2048+mlkem768+mldsa65|v1"
_SIG_CTX_INITIATOR = b"chaos-pwlcm-v1|auth-pq|sig|initiator|v1"
_SIG_CTX_RESPONDER = b"chaos-pwlcm-v1|auth-pq|sig|responder|v1"


def _require_pq() -> None:
    if not PQ_AVAILABLE:                              # pragma: no cover - platform dependent
        raise RuntimeError(
            "ML-KEM / ML-DSA unavailable — needs `cryptography` built against OpenSSL 3.5+. "
            "The authenticated post-quantum handshake cannot run without the vetted PQ primitives."
        )


class PublicIdentity(NamedTuple):
    """A peer's long-term PUBLIC identity: their ML-DSA signature public key (raw bytes) and their
    static classical DH public (int). You verify its fingerprint() out-of-band once, then store it."""
    sig_public: bytes
    static_public: int

    def fingerprint(self) -> str:
        """Short human-verifiable hash binding BOTH identity keys, so one check covers both."""
        h = hashlib.sha256()
        h.update(self.sig_public)
        h.update(self.static_public.to_bytes(DH_BYTES, "big"))
        return h.hexdigest()[:16]


class Identity:
    """A long-term identity: an ML-DSA-65 signature keypair + a static classical DH keypair. Create
    once, keep the private parts secret, publish `.public` (a PublicIdentity) and verify its
    fingerprint out-of-band so peers know it is really you."""

    def __init__(self):
        _require_pq()
        self._sig_sk = mldsa.MLDSA65PrivateKey.generate()
        self._static = DHParty()                     # classical static DH for the triple-DH binding
        self.public = PublicIdentity(
            sig_public=self._sig_sk.public_key().public_bytes_raw(),
            static_public=self._static.public,
        )

    def fingerprint(self) -> str:
        return self.public.fingerprint()

    def _sign(self, message: bytes) -> bytes:
        return self._sig_sk.sign(message)


def _enc_dh(x: int) -> bytes:
    return x.to_bytes(DH_BYTES, "big")


def _transcript(init: PublicIdentity, resp: PublicIdentity,
                dh_i: int, kem_pk_i: bytes, dh_r: int, kem_ct: bytes) -> bytes:
    """All identities + every public value, in a fixed initiator-then-responder order. Length-prefix
    each field so no boundary can be slid. Both sides build the identical transcript."""
    h = hashlib.sha512()
    for part in (init.sig_public, _enc_dh(init.static_public),
                 resp.sig_public, _enc_dh(resp.static_public),
                 _enc_dh(dh_i), kem_pk_i, _enc_dh(dh_r), kem_ct):
        h.update(len(part).to_bytes(8, "big"))
        h.update(part)
    return h.digest()


def _combine(ee: bytes, pq: bytes, es: bytes, se: bytes, transcript: bytes, info: bytes) -> bytes:
    """Mix confidentiality secrets (ee, pq) AND the static identity-binding terms (es, se, sorted for
    role-independence) with the transcript. Length-prefixed; first 32 bytes of SHA-512 are the key."""
    lo, hi = sorted((es, se))
    h = hashlib.sha512()
    h.update(_KDF_LABEL)
    for part in (ee, pq, lo, hi, transcript, info):
        h.update(len(part).to_bytes(8, "big"))
        h.update(part)
    return h.digest()[:32]


class _Msg1(NamedTuple):
    dh_i: int
    kem_pk_i: bytes


class _Msg2(NamedTuple):
    dh_r: int
    kem_ct: bytes
    sig_r: bytes


class Initiator:
    """Alice. Knows her own Identity and Bob's verified PublicIdentity."""

    def __init__(self, identity: Identity, peer: PublicIdentity, info: bytes = b""):
        _require_pq()
        self.identity = identity
        self.peer = peer
        self._info = info
        self._dh = DHParty()                         # fresh ephemeral DH
        self._kem_sk = mlkem.MLKEM768PrivateKey.generate()
        self._key: bytes | None = None

    def start(self) -> _Msg1:
        """flight 1: publish the ephemeral DH public + a fresh ML-KEM public key."""
        return _Msg1(self._dh.public, self._kem_sk.public_key().public_bytes_raw())

    def finish(self, msg2: _Msg2) -> bytes:
        """flight 3 input/output: verify Bob's signature, derive the key, and return Alice's signature
        (sig_A) to send to Bob. Raises InvalidSignature if Bob's signature does not verify."""
        kem_pk_i = self._kem_sk.public_key().public_bytes_raw()
        transcript = _transcript(self.identity.public, self.peer,
                                 self._dh.public, kem_pk_i, msg2.dh_r, msg2.kem_ct)
        # Verify the RESPONDER's signature over the transcript (post-quantum identity proof).
        mldsa.MLDSA65PublicKey.from_public_bytes(self.peer.sig_public).verify(
            msg2.sig_r, _SIG_CTX_RESPONDER + transcript)   # verify(signature, data); raises on mismatch

        ee = self._dh.raw_shared_secret(msg2.dh_r)                       # eph x peer eph
        pq = self._kem_sk.decapsulate(msg2.kem_ct)
        es = self._dh.raw_shared_secret(self.peer.static_public)         # eph x peer STATIC
        se = self.identity._static.raw_shared_secret(msg2.dh_r)          # STATIC x peer eph
        self._key = _combine(ee, pq, es, se, transcript, self._info)
        sig_i = self.identity._sign(_SIG_CTX_INITIATOR + transcript)
        return sig_i

    @property
    def key(self) -> bytes:
        if self._key is None:
            raise RuntimeError("call finish() before reading the session key")
        return self._key


class Responder:
    """Bob. Knows his own Identity and Alice's verified PublicIdentity."""

    def __init__(self, identity: Identity, peer: PublicIdentity, info: bytes = b""):
        _require_pq()
        self.identity = identity
        self.peer = peer
        self._info = info
        self._dh = DHParty()                         # fresh ephemeral DH
        self._key: bytes | None = None
        self._transcript: bytes | None = None

    def respond(self, msg1: _Msg1) -> _Msg2:
        """flight 2: encapsulate to Alice's ML-KEM key, derive the session key, and sign the full
        transcript with ML-DSA. Returns (dh_R, kem_ct, sig_R)."""
        peer_kem = mlkem.MLKEM768PublicKey.from_public_bytes(msg1.kem_pk_i)
        pq, kem_ct = peer_kem.encapsulate()
        transcript = _transcript(self.peer, self.identity.public,
                                 msg1.dh_i, msg1.kem_pk_i, self._dh.public, kem_ct)
        self._transcript = transcript

        ee = self._dh.raw_shared_secret(msg1.dh_i)                       # eph x peer eph
        es = self.identity._static.raw_shared_secret(msg1.dh_i)         # STATIC x peer eph
        se = self._dh.raw_shared_secret(self.peer.static_public)         # eph x peer STATIC
        self._key = _combine(ee, pq, se, es, transcript, self._info)     # note: combine sorts es/se
        sig_r = self.identity._sign(_SIG_CTX_RESPONDER + transcript)
        return _Msg2(self._dh.public, kem_ct, sig_r)

    def confirm(self, sig_i: bytes) -> bytes:
        """flight 3: verify Alice's signature over the transcript. Raises InvalidSignature on
        mismatch; otherwise returns the agreed session key."""
        if self._transcript is None or self._key is None:
            raise RuntimeError("call respond() before confirm()")
        mldsa.MLDSA65PublicKey.from_public_bytes(self.peer.sig_public).verify(
            sig_i, _SIG_CTX_INITIATOR + self._transcript)  # verify(signature, data); raises on mismatch
        return self._key

    @property
    def key(self) -> bytes:
        if self._key is None:
            raise RuntimeError("call respond() before reading the session key")
        return self._key


def authenticated_pq_agree(initiator: Initiator, responder: Responder) -> bytes:
    """Run the full three-flight handshake and assert both sides agree. Returns the session key.
    Raises InvalidSignature if either party's identity proof fails (impersonation/tamper)."""
    msg1 = initiator.start()
    msg2 = responder.respond(msg1)
    sig_i = initiator.finish(msg2)
    key_b = responder.confirm(sig_i)
    key_a = initiator.key
    if key_a != key_b:
        raise RuntimeError("authenticated PQ agreement failed — parties derived different keys")
    return key_a


if __name__ == "__main__":
    _require_pq()
    from aead import open_, seal

    # 0) One-time setup: long-term identities. Alice and Bob verify each other's fingerprint ONCE.
    alice_id, bob_id = Identity(), Identity()
    print(f"Alice fingerprint (sig+static): {alice_id.fingerprint()}")
    print(f"Bob   fingerprint (sig+static): {bob_id.fingerprint()}")

    # 1) An authenticated, post-quantum session.
    alice = Initiator(alice_id, bob_id.public)
    bob = Responder(bob_id, alice_id.public)
    key = authenticated_pq_agree(alice, bob)
    print(f"\nkeys match (authenticated + post-quantum): {alice.key == bob.key}")
    print(f"on the wire: dh {DH_BYTES}B + kem_pk {len(alice.start().kem_pk_i)}B "
          f"+ ml-dsa sig ~{len(bob_id._sign(b'x'))}B")

    # 2) End to end with the chaos AEAD.
    blob = seal(key, b"authenticated AND quantum-safe")
    print(f"Alice seals -> Bob opens: {open_(bob.key, blob)!r}")
