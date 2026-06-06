"""Tests for the AUTHENTICATED Diffie-Hellman handshake (auth_keyexchange.py).

Proves the two things that make it worth having over plain DH:
  1. Honest parties with verified identities still agree on one key (and it feeds the AEAD).
  2. A man-in-the-middle who lacks a party's STATIC private key cannot derive the session key —
     the authentication is baked into the math, not a manual fingerprint check.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from aead import InvalidTag, open_, seal  # noqa: E402
from auth_keyexchange import AuthHandshake, Identity, authenticated_agree  # noqa: E402
from keyexchange import P  # noqa: E402


# --- correctness --------------------------------------------------------------

def test_both_parties_derive_same_key():
    alice_id, bob_id = Identity(), Identity()
    a = AuthHandshake(alice_id, bob_id.public)
    b = AuthHandshake(bob_id, alice_id.public)
    assert a.session_key(b.public) == b.session_key(a.public)


def test_key_is_32_bytes():
    alice_id, bob_id = Identity(), Identity()
    a = AuthHandshake(alice_id, bob_id.public)
    b = AuthHandshake(bob_id, alice_id.public)
    assert len(a.session_key(b.public)) == 32


def test_independent_sessions_differ():
    # Fresh ephemerals each session => different session keys even with the same identities.
    alice_id, bob_id = Identity(), Identity()
    k1 = authenticated_agree(AuthHandshake(alice_id, bob_id.public),
                             AuthHandshake(bob_id, alice_id.public))
    k2 = authenticated_agree(AuthHandshake(alice_id, bob_id.public),
                             AuthHandshake(bob_id, alice_id.public))
    assert k1 != k2


def test_info_binds_the_session():
    alice_id, bob_id = Identity(), Identity()
    a = AuthHandshake(alice_id, bob_id.public)
    b = AuthHandshake(bob_id, alice_id.public)
    # Same handshake, different context label => different keys (channel binding).
    assert a.session_key(b.public, info=b"ctx-A") != b.session_key(a.public, info=b"ctx-B")
    assert a.session_key(b.public, info=b"ctx-A") == b.session_key(a.public, info=b"ctx-A")


def test_feeds_the_aead_end_to_end():
    alice_id, bob_id = Identity(), Identity()
    a = AuthHandshake(alice_id, bob_id.public)
    b = AuthHandshake(bob_id, alice_id.public)
    key_a = a.session_key(b.public)
    key_b = b.session_key(a.public)
    msg = b"bring the maps"
    assert open_(key_b, seal(key_a, msg)) == msg


# --- the authentication property ---------------------------------------------

def test_mitm_cannot_derive_alices_key():
    # Mallory substitutes her own ephemeral but lacks Bob's STATIC private. Alice mixes Bob's real
    # static identity into her key (the `es` term), so Mallory's derived key cannot match.
    alice_id, bob_id, mallory_id = Identity(), Identity(), Identity()
    alice = AuthHandshake(alice_id, bob_id.public)          # Alice targets the REAL Bob identity
    mallory = AuthHandshake(mallory_id, alice_id.public)    # Mallory has only her own static
    key_alice = alice.session_key(mallory.public)
    key_mallory = mallory.session_key(alice.public)
    assert key_alice != key_mallory


def test_mitm_cannot_read_alices_message():
    alice_id, bob_id, mallory_id = Identity(), Identity(), Identity()
    alice = AuthHandshake(alice_id, bob_id.public)
    mallory = AuthHandshake(mallory_id, alice_id.public)
    key_alice = alice.session_key(mallory.public)
    key_mallory = mallory.session_key(alice.public)
    blob = seal(key_alice, b"send 100 to account #12345")
    with pytest.raises(InvalidTag):
        open_(key_mallory, blob)               # Mallory's key is wrong => cannot open


def test_impersonator_with_wrong_static_fails():
    # If someone tries to impersonate Bob using a DIFFERENT static identity, Alice (who verified the
    # real Bob fingerprint) will not agree a key with them.
    alice_id, bob_id, impostor_id = Identity(), Identity(), Identity()
    alice = AuthHandshake(alice_id, bob_id.public)             # expects real Bob
    impostor = AuthHandshake(impostor_id, alice_id.public)     # is NOT Bob
    assert alice.session_key(impostor.public) != impostor.session_key(alice.public)


def test_degenerate_peer_identity_rejected():
    alice_id = Identity()
    with pytest.raises(ValueError):
        AuthHandshake(alice_id, 1)             # small-subgroup identity key must be rejected
    with pytest.raises(ValueError):
        AuthHandshake(alice_id, P - 1)


def test_fingerprint_is_stable_and_distinct():
    a, b = Identity(), Identity()
    assert a.fingerprint() == a.fingerprint()      # deterministic for the same identity
    assert a.fingerprint() != b.fingerprint()      # different identities differ
