"""
keyexchange.py — agree a shared key over an OPEN channel (Diffie-Hellman). RESEARCH ARTIFACT.

THE PROBLEM IT SOLVES:
  Until now Alice and Bob had to *already* share a secret master_key to call seal()/open_(). But
  how do they get that shared secret in the first place without mailing it to each other (where an
  eavesdropper could copy it)? Diffie-Hellman lets them derive the SAME secret by exchanging only
  PUBLIC values — a passive eavesdropper who sees everything on the wire still can't compute it.

DESIGN DECISION — use real, vetted math, NOT homemade chaos:
  This is the project's stated philosophy made concrete (REPORT.md): "run the chaos as a layer on
  top of a vetted primitive." Key AGREEMENT is done with classic finite-field Diffie-Hellman over a
  standard published safe prime (RFC 3526 MODP Group 14, 2048-bit) — pure-integer modular
  exponentiation, the same stdlib aesthetic as the engine. The chaos cipher then does the bulk
  encryption with the agreed key. We deliberately do NOT invent a chaos-synchronization key
  exchange: those are a graveyard of broken schemes, and inventing one would be the exact kind of
  overclaim this project exists to disprove.

HOW IT WORKS (the math, plainly):
  Public, agreed by everyone:  a big prime p and a generator g.
  Alice picks secret a, sends  A = g^a mod p.
  Bob   picks secret b, sends  B = g^b mod p.
  Both compute the SAME secret: Alice does B^a = g^(ba), Bob does A^b = g^(ab). Equal.
  An eavesdropper sees p, g, A, B but must solve the discrete-log problem to get a or b — believed
  hard for a 2048-bit group. That gap is the whole security.

HONEST CAVEATS (demonstrated in attacks/dh_mitm.py):
  * Textbook DH is UNAUTHENTICATED: a man-in-the-middle who can intercept and REPLACE messages
    runs two exchanges (one with each side) and reads everything. DH alone proves nobody *passive*
    can read you; it does NOT prove you're talking to the right person. Real systems bolt on
    authentication (signatures / certificates / a pre-shared fingerprint).
  * The chaos bulk cipher downstream is still UNVETTED. DH is the sound part; chaos is the toy.
"""

from __future__ import annotations

import hashlib
import os

# --- RFC 3526 MODP Group 14 (2048-bit). A standard, published safe prime. ---
# p = 2^2048 - 2^1984 - 1 + 2^64 * ([2^1918 pi] + 124476)
_P_HEX = """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F
83655D23DCA3AD961C62F356208552BB9ED529077096966D
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9
DE2BCBF6955817183995497CEA956AE515D2261898FA0510
15728E5A8AACAA68FFFFFFFFFFFFFFFF
"""
P = int(_P_HEX.replace("\n", "").replace(" ", ""), 16)
G = 2
DH_BYTES = (P.bit_length() + 7) // 8  # 256 bytes for the 2048-bit group
_PRIV_BITS = 256       # exponent size — 128-bit security, matched to the 2048-bit group
_KDF_LABEL = b"chaos-pwlcm-v1|dh-shared-key"


class DHParty:
    """One side of a Diffie-Hellman exchange over RFC 3526 Group 14.

    Usage::

        alice = DHParty()
        bob   = DHParty()
        key_a = alice.shared_key(bob.public)     # both sides get the SAME 32 bytes
        key_b = bob.shared_key(alice.public)
        # key_a == key_b  ->  hand it straight to aead.seal(key_a, msg)
    """

    def __init__(self, private: int | None = None):
        # Secret exponent in [2, p-2]. Fresh CSPRNG randomness unless one is supplied (tests).
        if private is None:
            private = 2 + int.from_bytes(os.urandom(_PRIV_BITS // 8), "big") % (P - 3)
        if not (2 <= private <= P - 2):
            raise ValueError("private exponent out of range")
        self._private = private
        self.public = pow(G, private, P)        # the value safe to send on the wire

    @staticmethod
    def _validate_peer(peer_public: int) -> None:
        """Reject degenerate / malicious peer values. 0, 1, p-1 (and out-of-range) force the
        shared secret into a tiny set — a classic small-subgroup style footgun."""
        if not (2 <= peer_public <= P - 2):
            raise ValueError("peer public value out of range")
        if peer_public in (1, P - 1):
            raise ValueError("peer public value in a small subgroup — rejected")

    def raw_shared_secret(self, peer_public: int) -> bytes:
        """The validated raw DH group element g^(ab) mod p as fixed-width bytes — NO KDF applied.

        This is the building block for authenticated handshakes (see auth_keyexchange.py) that need
        to MIX several DH results together before hashing. For a plain shared key, use shared_key()
        which hashes this. Never hand the raw element to a cipher directly — it has algebraic bias."""
        self._validate_peer(peer_public)
        secret = pow(peer_public, self._private, P)
        return secret.to_bytes(DH_BYTES, "big")

    def shared_key(self, peer_public: int, info: bytes = b"") -> bytes:
        """Compute the shared secret g^(ab) mod p, then hash it down to a 32-byte master key.

        We never use the raw group element as the key — it has algebraic structure and bias. A
        SHA-512 KDF (domain-separated, optional `info` for binding) turns it into uniform bytes
        suitable as the chaos AEAD master_key. Both parties derive identical bytes."""
        secret_bytes = self.raw_shared_secret(peer_public)
        return hashlib.sha512(_KDF_LABEL + b"|" + info + b"|" + secret_bytes).digest()[:32]


def agree_key(alice: DHParty, bob: DHParty, info: bytes = b"") -> bytes:
    """Convenience: run the exchange both ways and assert agreement. Returns the shared key."""
    ka = alice.shared_key(bob.public, info)
    kb = bob.shared_key(alice.public, info)
    if ka != kb:
        raise RuntimeError("key agreement failed — parties derived different keys")
    return ka


if __name__ == "__main__":
    from aead import open_, seal

    # 1) Alice and Bob have NEVER shared a secret. They each make a keypair...
    alice, bob = DHParty(), DHParty()
    # ...and exchange ONLY their public values (safe to shout across the room).
    key_a = alice.shared_key(bob.public)
    key_b = bob.shared_key(alice.public)
    print(f"Alice's derived key: {key_a.hex()}")
    print(f"Bob's   derived key: {key_b.hex()}")
    print(f"keys match (no secret was ever sent): {key_a == key_b}")

    # 2) Use the agreed key with the chaos AEAD — end to end, zero pre-shared secret.
    blob = seal(key_a, b"meet me where we agreed, bring the maps")
    print(f"\nAlice seals -> Bob opens: {open_(key_b, blob)!r}")

    # 3) A passive eavesdropper saw p, g, alice.public, bob.public — and is stuck.
    #    The obvious wrong guess (multiplying the publics) is NOT the shared secret:
    wrong = hashlib.sha512(
        _KDF_LABEL + b"||" + ((alice.public * bob.public) % P).to_bytes(256, "big")
    ).digest()[:32]
    print(f"\neavesdropper's naive guess == real key? {wrong == key_a}  (must be False)")
    print("to actually get the key Eve must solve discrete log on a 2048-bit group — believed hard.")
