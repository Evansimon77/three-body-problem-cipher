"""
auth_keyexchange.py — AUTHENTICATED Diffie-Hellman (the "secret handshake"). RESEARCH ARTIFACT.

THE PROBLEM IT SOLVES:
  Plain DH (keyexchange.py) proves nobody *passively listening* can read you — but it does NOT prove
  *who* you are talking to. A man-in-the-middle (Mallory) intercepts the public values, swaps in her
  own, and runs two exchanges (one with each side), reading and editing everything. See
  attacks/dh_mitm.py: plain DH has no authentication, so the only defence was a human eyeballing a
  fingerprint every time. This module bakes the identity check INTO the math, so the impostor is
  defeated automatically — a wrong party simply cannot derive the session key.

DESIGN DECISION — vetted construction, not homemade crypto (the project's standing rule):
  This is the **triple-DH / static+ephemeral** pattern used by the Noise framework and Signal's X3DH.
  Each side has a long-term STATIC identity keypair whose public is verified out-of-band ONCE (its
  fingerprint — like adding a contact / SSH known_hosts / Signal safety number). Each session also
  uses a fresh EPHEMERAL keypair (for forward secrecy). The session key mixes THREE DH results:

      ee = DH(my_ephemeral, peer_ephemeral)     # forward secrecy (fresh every session)
      es = DH(my_ephemeral, peer_STATIC)         # binds the peer's verified identity
      se = DH(my_STATIC,    peer_ephemeral)      # binds my verified identity

  Both parties compute the SAME three group elements (DH is symmetric: g^(xy) = g^(yx)), so they
  derive the same key. The two cross-terms are sorted before hashing so both sides agree on order
  regardless of who is "Alice".

WHY THE MAN-IN-THE-MIDDLE NOW FAILS (the whole point):
  To read Alice, Mallory must compute Alice's session key, which contains the term
  es = DH(Alice_ephemeral, Bob_STATIC) = g^(alice_eph · bob_static). To compute that, Mallory needs
  either Alice's ephemeral private OR Bob's static private — she has NEITHER (the static private
  never leaves Bob; the ephemeral private never leaves Alice). So Mallory cannot derive the key, the
  ciphertext won't open, and the attack collapses with NO human fingerprint check during the session.
  The fingerprint is verified just once, when the identity is first added.

HONEST CAVEATS:
  * Security still rests on the 2048-bit discrete-log assumption (the vetted part) — NOT on chaos.
  * The static identities must be authentic: you verify the peer's fingerprint out-of-band the first
    time (trust-on-first-use or in person). If you trust the WRONG static key, you authenticated the
    wrong person — same as accepting a forged certificate. The math can't fix mis-verified identity.
  * The chaos bulk cipher downstream is still UNVETTED. DH is the sound part; chaos is the toy.
"""

from __future__ import annotations

import hashlib

from keyexchange import DHParty

_KDF_LABEL = b"chaos-pwlcm-v1|auth-dh|triple-dh-v1"


class Identity:
    """A long-term STATIC identity keypair. Create once, keep it; publish only `.public` and verify
    its `.fingerprint()` out-of-band so peers know it is really you."""

    def __init__(self, private: int | None = None):
        self._static = DHParty(private)      # reuse the group, keygen and peer-validation
        self.public = self._static.public

    def fingerprint(self) -> str:
        """Short human-verifiable hash of the identity public key (SSH/Signal-style safety number).
        Verified ONCE, out-of-band, when a peer first adds you."""
        return hashlib.sha256(self.public.to_bytes(256, "big")).hexdigest()[:16]


class AuthHandshake:
    """One side of an authenticated handshake. Holds my static identity + the peer's VERIFIED static
    public, and generates a fresh ephemeral keypair per session.

    Usage::

        alice_id, bob_id = Identity(), Identity()          # long-term; fingerprints verified once
        a = AuthHandshake(alice_id, bob_id.public)         # Alice knows Bob's verified identity
        b = AuthHandshake(bob_id,   alice_id.public)        # Bob knows Alice's
        key_a = a.session_key(b.public)                     # exchange only the EPHEMERAL publics
        key_b = b.session_key(a.public)
        # key_a == key_b  ->  hand to aead.seal(key_a, msg); a man-in-the-middle cannot match it.
    """

    def __init__(self, identity: Identity, peer_identity_public: int):
        DHParty._validate_peer(peer_identity_public)     # reject degenerate identity keys
        self.identity = identity
        self.peer_identity_public = peer_identity_public
        self._ephemeral = DHParty()                       # fresh per session (forward secrecy)
        self.public = self._ephemeral.public              # the value to send on the wire

    def session_key(self, peer_ephemeral_public: int, info: bytes = b"") -> bytes:
        """Derive the 32-byte authenticated session key by mixing three DH results.

        The two identity-binding cross-terms are sorted so both parties hash them in the same order
        without needing to agree who is 'Alice'. A man-in-the-middle who lacks a static private key
        cannot reproduce `es`, so cannot derive this key."""
        ee = self._ephemeral.raw_shared_secret(peer_ephemeral_public)       # eph  x peer eph
        es = self._ephemeral.raw_shared_secret(self.peer_identity_public)   # eph  x peer STATIC
        se = self.identity._static.raw_shared_secret(peer_ephemeral_public) # STATIC x peer eph
        lo, hi = sorted((es, se))                                           # role-independent order
        return hashlib.sha512(
            _KDF_LABEL + b"|" + info + b"|" + ee + b"|" + lo + b"|" + hi
        ).digest()[:32]


def authenticated_agree(alice: AuthHandshake, bob: AuthHandshake, info: bytes = b"") -> bytes:
    """Convenience: run the handshake both ways and assert agreement. Returns the session key."""
    ka = alice.session_key(bob.public, info)
    kb = bob.session_key(alice.public, info)
    if ka != kb:
        raise RuntimeError("authenticated agreement failed — parties derived different keys")
    return ka


if __name__ == "__main__":
    from aead import open_, seal

    # 0) One-time setup: long-term identities. Alice & Bob verify each other's fingerprint ONCE
    #    (in person / out-of-band), then store the public. After that, no manual check is needed.
    alice_id, bob_id = Identity(), Identity()
    print(f"Alice identity fingerprint: {alice_id.fingerprint()}")
    print(f"Bob   identity fingerprint: {bob_id.fingerprint()}")

    # 1) A session: each side knows the other's VERIFIED static identity, makes a fresh ephemeral,
    #    and they exchange only the ephemeral public values.
    a = AuthHandshake(alice_id, bob_id.public)
    b = AuthHandshake(bob_id, alice_id.public)
    key_a = a.session_key(b.public)
    key_b = b.session_key(a.public)
    print(f"\nkeys match (authenticated): {key_a == key_b}")

    # 2) End to end with the chaos AEAD.
    blob = seal(key_a, b"meet me where we agreed, bring the maps")
    print(f"Alice seals -> Bob opens: {open_(key_b, blob)!r}")

    # 3) A man-in-the-middle WITHOUT Bob's static private cannot derive Alice's key.
    mallory_id = Identity()                       # Mallory's own identity (not Bob's!)
    a_to_fake = AuthHandshake(alice_id, bob_id.public)   # Alice still targets the REAL Bob identity
    mallory = AuthHandshake(mallory_id, alice_id.public) # Mallory only has her own static
    k_alice = a_to_fake.session_key(mallory.public)      # Alice's key (peer eph = Mallory's)
    k_mallory = mallory.session_key(a_to_fake.public)    # Mallory's attempt
    print(f"\nMallory matches Alice's key? {k_alice == k_mallory}  (must be False)")
    print("Mallory lacks Bob's static private, so the es term differs -> handshake fails. Caught.")
