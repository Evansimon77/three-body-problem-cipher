"""Tests for the authenticated post-quantum handshake (auth_pq_keyexchange.py).

Auto-skips if `cryptography` has no ML-KEM / ML-DSA (needs OpenSSL 3.5+) — same skip-don't-fail rule
the Rust parity and pq_keyexchange tests use, so the suite stays green on older platforms.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from auth_pq_keyexchange import (  # noqa: E402
    PQ_AVAILABLE,
    Identity,
    Initiator,
    Responder,
    authenticated_pq_agree,
)
from keyexchange import DHParty  # noqa: E402

pytestmark = pytest.mark.skipif(
    not PQ_AVAILABLE, reason="ML-KEM/ML-DSA need cryptography w/ OpenSSL 3.5+")

if PQ_AVAILABLE:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import mlkem
    from auth_pq_keyexchange import _SIG_CTX_RESPONDER, _Msg2, _transcript


def _session():
    aid, bid = Identity(), Identity()
    return aid, bid, Initiator(aid, bid.public), Responder(bid, aid.public)


def test_roundtrip_agrees():
    _aid, _bid, alice, bob = _session()
    key = authenticated_pq_agree(alice, bob)
    assert len(key) == 32
    assert alice.key == bob.key == key


def test_manual_three_flight_agrees():
    _aid, _bid, alice, bob = _session()
    msg1 = alice.start()
    msg2 = bob.respond(msg1)
    sig_i = alice.finish(msg2)
    assert bob.confirm(sig_i) == alice.key


def test_two_sessions_differ():
    # Fresh ephemerals + ML-KEM each time -> different session keys.
    aid, bid = Identity(), Identity()
    k1 = authenticated_pq_agree(Initiator(aid, bid.public), Responder(bid, aid.public))
    k2 = authenticated_pq_agree(Initiator(aid, bid.public), Responder(bid, aid.public))
    assert k1 != k2


def test_fingerprint_binds_both_keys():
    bid = Identity()
    # Same identity -> stable fingerprint; a different identity -> different fingerprint.
    assert bid.public.fingerprint() == bid.public.fingerprint()
    assert Identity().public.fingerprint() != bid.public.fingerprint()


def test_mitm_with_own_keys_rejected():
    # Mallory signs as herself while pretending to be Bob; Alice (expecting real Bob) rejects.
    aid, bid, mid = Identity(), Identity(), Identity()
    alice = Initiator(aid, bid.public)
    msg1 = alice.start()
    eph = DHParty()
    peer_kem = mlkem.MLKEM768PublicKey.from_public_bytes(msg1.kem_pk_i)
    _pq, kem_ct = peer_kem.encapsulate()
    transcript = _transcript(aid.public, bid.public, msg1.dh_i, msg1.kem_pk_i, eph.public, kem_ct)
    forged_sig = mid._sign(_SIG_CTX_RESPONDER + transcript)   # signed by Mallory, not Bob
    with pytest.raises(InvalidSignature):
        alice.finish(_Msg2(eph.public, kem_ct, forged_sig))


def test_tampered_kem_ct_rejected():
    _aid, _bid, alice, bob = _session()
    msg1 = alice.start()
    msg2 = bob.respond(msg1)
    bad = bytearray(msg2.kem_ct)
    bad[0] ^= 0x01
    with pytest.raises(InvalidSignature):
        alice.finish(_Msg2(msg2.dh_r, bytes(bad), msg2.sig_r))


def test_tampered_signature_rejected():
    _aid, _bid, alice, bob = _session()
    msg1 = alice.start()
    msg2 = bob.respond(msg1)
    bad = bytearray(msg2.sig_r)
    bad[0] ^= 0x01
    with pytest.raises(InvalidSignature):
        alice.finish(_Msg2(msg2.dh_r, msg2.kem_ct, bytes(bad)))


def test_responder_rejects_forged_initiator_sig():
    # An impostor who can't sign as Alice fails the responder's confirm() check.
    aid, bid, mid = Identity(), Identity(), Identity()
    alice = Initiator(aid, bid.public)
    bob = Responder(bid, aid.public)
    msg1 = alice.start()
    msg2 = bob.respond(msg1)
    alice.finish(msg2)                       # Alice computes her real sig (discarded below)
    # Mallory submits a signature made with her own key in place of Alice's.
    from auth_pq_keyexchange import _SIG_CTX_INITIATOR
    forged = mid._sign(_SIG_CTX_INITIATOR + bob._transcript)
    with pytest.raises(InvalidSignature):
        bob.confirm(forged)


def test_end_to_end_with_chaos_aead():
    from aead import open_, seal
    _aid, _bid, alice, bob = _session()
    key = authenticated_pq_agree(alice, bob)
    assert open_(bob.key, seal(key, b"authenticated and quantum-safe")) == b"authenticated and quantum-safe"
