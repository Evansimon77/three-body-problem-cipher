"""
ATTACK 3 — Man-in-the-middle on UNAUTHENTICATED Diffie-Hellman (keyexchange.py).

This is the honest caveat of the key-exchange layer, demonstrated rather than asserted.
Diffie-Hellman defeats a PASSIVE eavesdropper (someone who only listens). It does NOT defeat an
ACTIVE attacker who can intercept and REPLACE messages on the wire — because plain DH never checks
*who* you're talking to. Mallory simply runs two separate exchanges:

    Alice  <--(DH)-->  Mallory  <--(DH)-->  Bob

Alice thinks she shares a key with Bob, but really shares one with Mallory. Bob likewise. Mallory
sits in the middle: she decrypts everything Alice sends (her key with Alice), reads/edits it, then
re-encrypts to Bob (her key with Bob). Neither end can tell.

THE LESSON: DH gives you *confidentiality against passive listeners*, not *authentication*. Real
protocols (TLS, Signal, SSH) bolt authentication on top — signatures, certificates, or a
pre-shared/verified fingerprint. This file shows the attack working, then shows that a verified
fingerprint would have caught it.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import hashlib  # noqa: E402

from aead import InvalidTag, open_, seal  # noqa: E402
from keyexchange import DHParty  # noqa: E402


def fingerprint(public: int) -> str:
    """A short human-verifiable hash of a public key (like an SSH/Signal safety number)."""
    return hashlib.sha256(public.to_bytes(256, "big")).hexdigest()[:16]


def demo_passive_eavesdropper_fails():
    print("=" * 70)
    print("PART A — passive eavesdropper (only listens): DH holds")
    print("=" * 70)
    alice, bob = DHParty(), DHParty()
    # Eve records everything on the wire: alice.public and bob.public.
    key_a = alice.shared_key(bob.public)
    key_b = bob.shared_key(alice.public)
    print(f"  Alice/Bob agree a key: {key_a == key_b}")
    # Eve has the publics but no private exponent; she cannot derive the shared secret without
    # solving discrete log. Her best guess from public info alone (e.g. hashing the publics) is
    # NOT the real key:
    from keyexchange import P
    eve_guess = hashlib.sha512(
        b"chaos-pwlcm-v1|dh-shared-key||"
        + ((alice.public * bob.public) % P).to_bytes(256, "big")
    ).digest()[:32]
    blob = seal(key_a, b"the real plan")
    try:
        open_(eve_guess, blob)
        print("  Eve READ the message  <-- would be a break")
    except InvalidTag:
        print("  Eve cannot open the message (no shared secret from public values alone). PASS")


def demo_active_mitm_succeeds():
    print("\n" + "=" * 70)
    print("PART B — ACTIVE man-in-the-middle (intercepts + replaces): DH alone BREAKS")
    print("=" * 70)
    alice, bob = DHParty(), DHParty()
    mallory_for_alice = DHParty()   # Mallory's keypair facing Alice
    mallory_for_bob = DHParty()     # Mallory's keypair facing Bob

    # Mallory intercepts the public exchange and substitutes her own values:
    #   Alice receives Mallory's key (thinks it's Bob's); Bob receives Mallory's (thinks Alice's).
    key_alice_side = alice.shared_key(mallory_for_alice.public)      # Alice <-> Mallory
    key_mallory_alice = mallory_for_alice.shared_key(alice.public)
    key_bob_side = bob.shared_key(mallory_for_bob.public)            # Bob <-> Mallory
    key_mallory_bob = mallory_for_bob.shared_key(bob.public)

    # Alice sends to "Bob". Mallory intercepts, decrypts, tampers, re-encrypts to Bob.
    original = b"send 100 to account #12345"
    blob_from_alice = seal(key_alice_side, original)

    mallory_reads = open_(key_mallory_alice, blob_from_alice)        # Mallory decrypts Alice
    tampered = mallory_reads.replace(b"#12345", b"#99999")           # ...edits the account...
    blob_to_bob = seal(key_mallory_bob, tampered)                    # ...re-encrypts to Bob

    bob_receives = open_(key_bob_side, blob_to_bob)                  # Bob opens it cleanly
    print(f"  Alice sent : {original!r}")
    print(f"  Mallory read: {mallory_reads!r}   <-- she saw the plaintext")
    print(f"  Bob received: {bob_receives!r}   <-- silently altered")
    print(f"  MITM succeeded: {bob_receives != original}  (DH alone has no authentication)")


def demo_fingerprint_catches_it():
    print("\n" + "=" * 70)
    print("PART C — the fix: a VERIFIED fingerprint detects the impostor")
    print("=" * 70)
    bob = DHParty()
    mallory = DHParty()
    # If Alice has Bob's REAL fingerprint (verified out-of-band: in person, prior contact),
    # she compares it against the key she actually received.
    real_bob_fp = fingerprint(bob.public)
    received_fp = fingerprint(mallory.public)   # but Mallory swapped in her key
    print(f"  Bob's true fingerprint     : {real_bob_fp}")
    print(f"  Fingerprint Alice received : {received_fp}")
    print(f"  Match? {real_bob_fp == received_fp}  -> mismatch exposes the man-in-the-middle.")
    print("  Conclusion: DH needs an authentication layer. That's why TLS/Signal/SSH exist.")


if __name__ == "__main__":
    demo_passive_eavesdropper_fails()
    demo_active_mitm_succeeds()
    demo_fingerprint_catches_it()
