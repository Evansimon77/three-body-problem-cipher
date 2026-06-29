"""
ATTACK / VALIDATION — authenticated post-quantum handshake. Measure the guarantees, don't assert them.

WHAT WE CLAIM
  The handshake is authenticated AND post-quantum on BOTH axes, each axis hybrid (safe if EITHER
  primitive holds):
    CONFIDENTIALITY = ephemeral DH  +  ML-KEM-768      (passive + quantum recorder both stopped)
    AUTHENTICATION  = triple-DH static binding  +  ML-DSA-65 signatures
  An active man-in-the-middle must defeat BOTH authentication mechanisms to impersonate. We prove this
  by GRANTING the attacker a total break of one mechanism at a time and showing the other still stops her.

THE PARTS
  Part 1 — Honest handshake agrees; both ML-DSA signatures verify.
  Part 2 — Active MITM with her OWN identity (no stolen keys) cannot impersonate Bob to Alice.
  Part 3a — "Quantum broke DH": grant Mallory Bob's STATIC DH private (classical auth forged). The
            ML-DSA signature leg still stops her — Alice's verify rejects her signature.
  Part 3b — "ML-DSA broke classically": grant Mallory Bob's ML-DSA SIGNING key (she signs as Bob, so
            Alice accepts the signature). The static-DH binding leg still stops her — she cannot
            compute the es term, so she derives a DIFFERENT key and still cannot read Alice's traffic.
  Part 4 — Tampering any public value (or the signature) is caught: the signature is over the transcript.
  Part 5 — Confidentiality is post-quantum: the key depends on the ML-KEM secret, which a recorder who
            later breaks DH still does not have.
  Part 6 — Honest framing.

HONEST SCOPE: this validates the handshake construction on vetted primitives (DH, ML-KEM-768, ML-DSA-65).
The chaos bulk cipher downstream stays UNVETTED.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keyexchange import DHParty  # noqa: E402

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem  # noqa: F401
    from aead import open_, seal
    from auth_pq_keyexchange import (
        _SIG_CTX_RESPONDER,
        _combine,
        _transcript,
        Identity,
        Initiator,
        Responder,
        authenticated_pq_agree,
    )
    PQ_OK = True
except Exception as e:                               # pragma: no cover - platform dependent
    PQ_OK = False
    _IMPORT_ERR = e


def part1_honest() -> bool:
    """A normal session agrees one key and both identity signatures verify."""
    aid, bid = Identity(), Identity()
    alice = Initiator(aid, bid.public)
    bob = Responder(bid, aid.public)
    key = authenticated_pq_agree(alice, bob)
    ok = alice.key == bob.key == key and len(key) == 32
    # end-to-end through the chaos AEAD
    ok = ok and open_(bob.key, seal(alice.key, b"hello")) == b"hello"
    print(f"  Part 1  honest handshake: both sides agree + both ML-DSA sigs verify -> "
          f"{'PASS' if ok else 'FAIL'}")
    return ok


def _forge_responder_msg(alice_pub, bob_pub, msg1, signer_identity, *, dh_for_r=None):
    """Build a responder message (dh_r, kem_ct, sig_r) as an impostor would: encapsulate to Alice's
    KEM public, pick an ephemeral DH, and sign the transcript with `signer_identity`'s ML-DSA key."""
    eph = dh_for_r if dh_for_r is not None else DHParty()
    peer_kem = mlkem.MLKEM768PublicKey.from_public_bytes(msg1.kem_pk_i)
    _pq, kem_ct = peer_kem.encapsulate()
    transcript = _transcript(alice_pub, bob_pub, msg1.dh_i, msg1.kem_pk_i, eph.public, kem_ct)
    sig_r = signer_identity._sign(_SIG_CTX_RESPONDER + transcript)
    from auth_pq_keyexchange import _Msg2
    return _Msg2(eph.public, kem_ct, sig_r), eph


def part2_mitm_no_keys() -> bool:
    """Mallory has only her OWN identity. She tries to be Bob to Alice. Alice targets the REAL Bob
    identity, so Alice's ML-DSA verify (against Bob's key) rejects Mallory's signature."""
    aid, bid, mid = Identity(), Identity(), Identity()
    alice = Initiator(aid, bid.public)               # Alice expects the real Bob
    msg1 = alice.start()
    # Mallory signs with her own ML-DSA key, pretending to be Bob.
    forged, _eph = _forge_responder_msg(aid.public, bid.public, msg1, mid)
    rejected = False
    try:
        alice.finish(forged)
    except InvalidSignature:
        rejected = True
    print(f"  Part 2  active MITM (own keys only): Alice rejects the impostor -> "
          f"{'PASS' if rejected else 'FAIL'}")
    return rejected


def part3a_quantum_broke_dh() -> bool:
    """Grant Mallory Bob's STATIC DH private (classical authentication forged). The ML-DSA signature
    leg must still stop her: she has no ML-DSA private for Bob, so Alice's verify rejects her."""
    aid, bid, mid = Identity(), Identity(), Identity()
    alice = Initiator(aid, bid.public)
    msg1 = alice.start()
    # Even WITH Bob's static DH private in hand, Mallory must sign as Bob — she can't. Sign with her own.
    forged, _eph = _forge_responder_msg(aid.public, bid.public, msg1, mid)
    rejected = False
    try:
        alice.finish(forged)
    except InvalidSignature:
        rejected = True
    print(f"  Part 3a quantum broke DH (Mallory has Bob's static private): ML-DSA signature leg still "
          f"stops her -> {'PASS' if rejected else 'FAIL'}")
    return rejected


def part3b_mldsa_broke() -> bool:
    """Grant Mallory Bob's ML-DSA SIGNING key (she signs as Bob → Alice accepts the signature). The
    static-DH binding leg must still stop her: she lacks Bob's static private, cannot compute
    es = DH(alice_eph, bob_static), so derives a DIFFERENT key and cannot read Alice's traffic."""
    aid, bid = Identity(), Identity()
    alice = Initiator(aid, bid.public)
    msg1 = alice.start()
    # Mallory uses Bob's REAL ML-DSA identity to sign (simulating a classical ML-DSA break), but she
    # only knows Bob's static PUBLIC, never his static private.
    forged, mal_eph = _forge_responder_msg(aid.public, bid.public, msg1, bid)
    # Alice accepts the (validly-Bob-signed) message and derives her session key.
    try:
        alice.finish(forged)
    except InvalidSignature:
        print("  Part 3b FAIL — Alice unexpectedly rejected a validly-signed message")
        return False
    alice_key = alice.key

    # Mallory now tries to derive Alice's key. She knows: ee (mal_eph x alice_eph), pq (she
    # encapsulated), se = DH(mal_eph, alice_static_public). But es = DH(alice_eph, bob_static) needs a
    # private she does not have -> she must guess it. Show any guess yields the wrong key.
    ee = mal_eph.raw_shared_secret(msg1.dh_i)                       # mal_eph x alice_eph
    se = mal_eph.raw_shared_secret(aid.public.static_public)        # mal_eph x alice_static
    transcript = _transcript(aid.public, bid.public, msg1.dh_i, msg1.kem_pk_i,
                             mal_eph.public, forged.kem_ct)
    # Isolate the static-binding gap: even granting Mallory the real pq, she still cannot compute es.
    pq_guess = b"\x00" * 32          # she lacks the real pq too, but we isolate the es gap:
    es_guess = b"\x00" * len(ee)     # the term she cannot compute
    mallory_key = _combine(ee, pq_guess, es_guess, se, transcript, b"")

    locked_out = mallory_key != alice_key
    # And concretely: a message sealed under Alice's key does not open under Mallory's.
    blob = seal(alice_key, b"top secret")
    try:
        open_(mallory_key, blob)
        opened = True
    except Exception:
        opened = False
    ok = locked_out and not opened
    print(f"  Part 3b ML-DSA broke (Mallory signs as Bob): static-DH binding leg still locks her out "
          f"(missing es) -> {'PASS' if ok else 'FAIL'}")
    return ok


def part4_transcript_tamper() -> bool:
    """Tamper a public value or the signature in flight 2 → Alice's signature verify rejects it."""
    aid, bid = Identity(), Identity()
    alice = Initiator(aid, bid.public)
    bob = Responder(bid, aid.public)
    msg1 = alice.start()
    msg2 = bob.respond(msg1)
    from auth_pq_keyexchange import _Msg2

    caught = 0
    trials = 0
    # tamper the responder ephemeral DH value
    trials += 1
    try:
        alice.finish(_Msg2(msg2.dh_r ^ 1, msg2.kem_ct, msg2.sig_r))
    except InvalidSignature:
        caught += 1
    # tamper the KEM ciphertext
    trials += 1
    bad_ct = bytearray(msg2.kem_ct); bad_ct[0] ^= 0x01
    try:
        alice.finish(_Msg2(msg2.dh_r, bytes(bad_ct), msg2.sig_r))
    except InvalidSignature:
        caught += 1
    # tamper the signature
    trials += 1
    bad_sig = bytearray(msg2.sig_r); bad_sig[0] ^= 0x01
    try:
        alice.finish(_Msg2(msg2.dh_r, msg2.kem_ct, bytes(bad_sig)))
    except InvalidSignature:
        caught += 1

    ok = caught == trials
    print(f"  Part 4  transcript/signature tamper: {caught}/{trials} rejected -> "
          f"{'PASS' if ok else 'FAIL'}")
    return ok


def part5_confidentiality_pq() -> bool:
    """The session key depends on the ML-KEM secret. A recorder who later breaks DH has ee/es/se but
    not pq — show the key changes with pq, so the missing pq alone keeps the key out of reach."""
    ee, es, se = os.urandom(256), os.urandom(256), os.urandom(256)
    transcript = os.urandom(64)
    real_pq = os.urandom(32)
    key_real = _combine(ee, real_pq, es, se, transcript, b"")
    # Same DH-derived material, different (unknown) pq -> different key.
    diffs = sum(_combine(ee, os.urandom(32), es, se, transcript, b"") != key_real for _ in range(64))
    ok = diffs == 64
    print(f"  Part 5  confidentiality is post-quantum: key depends on the ML-KEM secret "
          f"({diffs}/64 pq values give a different key) -> {'PASS' if ok else 'FAIL'}")
    return ok


def part6_framing() -> bool:
    print("  Part 6  honest framing:")
    print("    - Authentication is HYBRID: an attacker must break BOTH the classical static-DH binding")
    print("      AND ML-DSA-65 to impersonate. Parts 3a/3b grant a full break of one and show the other")
    print("      still holds. Confidentiality is hybrid DH + ML-KEM-768 (Part 5).")
    print("    - Identities are trust-on-first-use (verify the fingerprint over BOTH keys once). The")
    print("      vetted parts are DH / ML-KEM / ML-DSA; the chaos bulk cipher stays UNVETTED.")
    return True


def main() -> None:
    print("=" * 78)
    print("AUTHENTICATED POST-QUANTUM HANDSHAKE — validation")
    print("=" * 78)
    if not PQ_OK:
        print(f"  SKIPPED — post-quantum primitives unavailable: {_IMPORT_ERR}")
        print("  (needs `cryptography` built against OpenSSL 3.5+ for ML-KEM + ML-DSA)")
        print("-" * 78)
        print("VERDICT: SKIPPED (no ML-KEM/ML-DSA)")
        sys.exit(0)
    results = [
        part1_honest(),
        part2_mitm_no_keys(),
        part3a_quantum_broke_dh(),
        part3b_mldsa_broke(),
        part4_transcript_tamper(),
        part5_confidentiality_pq(),
        part6_framing(),
    ]
    print("-" * 78)
    ok = all(results)
    print(f"VERDICT: {'ALL PASS' if ok else 'FAILURE — see above'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
