"""
ATTACK 4 — the same man-in-the-middle, now run against AUTHENTICATED DH (auth_keyexchange.py).

attacks/dh_mitm.py showed that PLAIN DH falls to an active man-in-the-middle: Mallory swaps the
public values, runs two exchanges, and silently reads + edits everything. This file runs the exact
same attack against the authenticated handshake and shows it now FAILS — without any human checking
a fingerprint mid-session. The identity check is baked into the key.

THE SETUP (identical to attack 3):
    Alice  <--(handshake)-->  Mallory  <--(handshake)-->  Bob
Alice wants to talk to Bob; Mallory sits in the middle and substitutes her own ephemeral keys.

THE DIFFERENCE: Alice mixes Bob's VERIFIED static identity into her key (the `es` term), and Mallory
does not possess Bob's static private. So Mallory cannot compute Alice's session key — the message
she intercepts will not open, and any message she forges to Bob will not open on Bob's side either.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aead import InvalidTag, open_, seal  # noqa: E402
from auth_keyexchange import AuthHandshake, Identity  # noqa: E402


def demo_legit_handshake_works():
    print("=" * 70)
    print("PART A — honest parties with verified identities: handshake agrees")
    print("=" * 70)
    alice_id, bob_id = Identity(), Identity()
    a = AuthHandshake(alice_id, bob_id.public)
    b = AuthHandshake(bob_id, alice_id.public)
    key_a = a.session_key(b.public)
    key_b = b.session_key(a.public)
    print(f"  Alice/Bob derive the same key: {key_a == key_b}")
    blob = seal(key_a, b"the real plan")
    print(f"  Bob opens Alice's message: {open_(key_b, blob)!r}  PASS")


def demo_active_mitm_now_fails():
    print("\n" + "=" * 70)
    print("PART B — ACTIVE man-in-the-middle vs AUTHENTICATED DH: attack FAILS")
    print("=" * 70)
    alice_id, bob_id = Identity(), Identity()
    mallory_id = Identity()        # Mallory has her OWN identity, NOT Bob's static private

    # Alice targets the REAL Bob identity (verified fingerprint). Mallory intercepts and substitutes
    # her own ephemeral public, exactly as in the plain-DH break.
    alice = AuthHandshake(alice_id, bob_id.public)
    mallory_facing_alice = AuthHandshake(mallory_id, alice_id.public)

    key_alice_side = alice.session_key(mallory_facing_alice.public)   # Alice's key (got Mallory eph)
    key_mallory_guess = mallory_facing_alice.session_key(alice.public)  # Mallory's best attempt

    print(f"  Alice's key == Mallory's key? {key_alice_side == key_mallory_guess}  (False = good)")

    # Mallory tries to READ Alice's message with her derived key:
    blob_from_alice = seal(key_alice_side, b"send 100 to account #12345")
    try:
        stolen = open_(key_mallory_guess, blob_from_alice)
        print(f"  Mallory READ it: {stolen!r}   <-- would be a break")
    except InvalidTag:
        print("  Mallory CANNOT open Alice's message (lacks Bob's static private). ATTACK FAILS")

    # And anything Mallory forges toward Bob won't open under Bob's authenticated key either:
    bob = AuthHandshake(bob_id, alice_id.public)
    mallory_facing_bob = AuthHandshake(mallory_id, bob_id.public)
    key_bob_side = bob.session_key(mallory_facing_bob.public)
    key_mallory_to_bob = mallory_facing_bob.session_key(bob.public)
    forged = seal(key_mallory_to_bob, b"send 100 to account #99999")
    try:
        open_(key_bob_side, forged)
        print("  Bob accepted Mallory's forgery  <-- would be a break")
    except InvalidTag:
        print("  Bob REJECTS Mallory's forged message (her key != Bob's). ATTACK FAILS")


def demo_wrong_identity_is_caught():
    print("\n" + "=" * 70)
    print("PART C — trusting the WRONG static identity is the only remaining gap")
    print("=" * 70)
    print("  The math authenticates whoever's static key you verified. If Alice is tricked into")
    print("  verifying Mallory's fingerprint as 'Bob' (a first-contact mistake), she authenticates")
    print("  Mallory correctly. Lesson: verify the fingerprint out-of-band ONCE, carefully — same")
    print("  trust root as TLS certificates / SSH known_hosts. The handshake can't fix mis-trust.")


if __name__ == "__main__":
    demo_legit_handshake_works()
    demo_active_mitm_now_fails()
    demo_wrong_identity_is_caught()
