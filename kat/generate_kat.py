"""
KAT generator — produces the FROZEN known-answer test vectors (§3 of the roadmap).

WHY THIS EXISTS
---------------
A known-answer test (KAT) is a locked list of "this exact input must produce this exact
output." Once frozen, it is the contract the cipher can never silently break:

  * REGRESSION GUARD (today, Python): any edit that changes a single output byte fails
    tests/test_kat.py. Refactors that are meant to be behaviour-preserving are PROVEN so;
    accidental behaviour changes are caught the moment they happen.
  * PORT ORACLE (Phase 4, Rust): the Rust core is "done" only when it reproduces every
    vector here bit-for-bit. The KAT turns "I think the port matches" into "it provably
    matches" — the same role NIST's KATs play for AES/SHA implementations.

WHAT IS COVERED — every DETERMINISTIC layer the port must reproduce, bottom-up:
  1. finalize     — the nonlinear ARX output mixer (_finalize), the trickiest bit-math.
  2. engine_raw   — the integer PWLCM core keystream from fixed (seed, control, nonce),
                    including the all-zero key edge (exercises the init avalanche + dead-state).
  3. from_master  — the hash-KDF seeding path the AEAD layers actually use.
  4. multimap     — the shipped N-map XOR combiner (n_maps = 1 and the default 4).
  5. ratchet      — the shipped auto-rekey stream, with a TINY epoch so the vector crosses
                    two re-key seams (proves the seam math is frozen too).
  6. siv          — the fully deterministic AEAD (seal_siv), a full-stack end-to-end vector.
  7. aead         — the committing AEAD (aead.seal), full stack, with its nonce PINNED for the KAT.
  8. stream       — the streaming AEAD (seal_stream), multi-chunk self-delimiting blob, salt pinned.
  9. ratchet_aead — the forward-secret SESSION AEAD, a 3-message session crossing two chain seams.
  10. twolock     — the two-locks wrapper: chaos OUTER wall over a VETTED inner vault (AES-256-GCM
                    and ChaCha20-Poly1305), HKDF key-split, both nonces pinned.
  11. keyexchange — classical Diffie-Hellman over RFC 3526 MODP-2048 (g^a, g^b, g^(ab), the KDF key),
                    secret exponents pinned. Pure integer pow + hashlib, no chaos engine, no ML-KEM.
  12. pq_hybrid   — the post-quantum hybrid handshake: classical DH mixed with ML-KEM-768 via the
                    SP 800-56C combiner. The ML-KEM ciphertext is pinned as frozen test data (encaps is
                    randomised in Python's API, like NIST's own ML-KEM KATs); both backends DECAPSULATE
                    it to the same secret, and the combiner is a pure SHA-512 over the secrets+transcript.

Anything random by design (a fresh nonce/salt drawn per call) is pinned via a keyword-only KAT hook
so it has a fixed answer here; in real use those default to fresh randomness. Round-trip + attack
tests cover the non-frozen behaviour.

USAGE
-----
    python3 kat/generate_kat.py            # print the vectors as JSON to stdout
    python3 kat/generate_kat.py --write    # (re)write kat/vectors.json  -- FREEZING ACTION

Regenerating with --write is a deliberate, reviewed act: it re-freezes the contract to the
CURRENT code. Do it only when you INTEND to change the cipher's output (and say so in the
commit). Never run it just to make a failing test pass.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aead import _tag  # noqa: E402
from commit import key_commitment  # noqa: E402
from engine import M, DiscreteChaoticEngine, _finalize  # noqa: E402
from keyexchange import P, DHParty  # noqa: E402
from pq_keyexchange import (  # noqa: E402
    MLKEM_AVAILABLE, _combine, _transcript, mlkem,
)
from multimap import MultiMapEngine  # noqa: E402
from ratchet import RatchetEngine  # noqa: E402
from ratchet_aead import SenderSession  # noqa: E402
from siv import seal_siv  # noqa: E402
from streaming import seal_stream  # noqa: E402
from twolock import seal_twolock  # noqa: E402

VECTORS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")

# Fixed, arbitrary-but-pinned inputs. These are PUBLIC test inputs, not secrets.
_KEY_INT = 0x0123456789ABCDEF0123456789ABCDEF  # gitleaks:allow — public KAT test input, not a secret
_CTRL_INT = 0xFEDCBA9876543210FEDCBA9876543210
_NONCE_INT = 0xA5A5A5A5
_KEY_BYTES = b"chaos-kat-master-key-v1"
_NONCE_BYTES = b"chaos-kat-nonce-v1"

# --- Phase 8.5 frozen ML-KEM-768 test data (PUBLIC, not secret). ML-KEM encapsulation is randomised in
# Python's high-level API, so — exactly as NIST's own ML-KEM KAT files do — we PIN the ciphertext as
# frozen test data. Both Python (OpenSSL 3.5) and Rust (RustCrypto `ml-kem`) DECAPSULATE it to the
# identical 32-byte secret; that shared, deterministic decapsulation is the portable contract. The seed
# and encaps message derive from fixed labels; the encapsulation key + ciphertext + decapsulated secret
# were produced once by the Rust deterministic encapsulation and are frozen here so this generator runs
# WITHOUT the ML-KEM backend (e.g. on an older OpenSSL). When the backend IS present, compute_vectors()
# self-checks these constants below so they can never silently drift.
_MLKEM_EK_HEX = "e0ec065a4ab9832598f285ce17132c08311f5ab79b0aa272cc7a530f5551abd7503c1773fda0bc551cbefcf3352ad2cb50099b69868bd818c92f4ca4d30971b7d4796fb5a8e355b87620356542543b34cc9f633cdc9984d7466ff4391905ba98185631b37294d6308c12dc51961b3733da00fb50650ef8b7bda19b24c10983937c9dfaa56931668659a966907423b145e7cc090e982b562366a343cdf1a42b7f546159c8539d70cfa89933688c83ad5a4a36d03cde007c854354c6a18ef885a3bd4b3970399b083170110b4a06a1c37b656e5a1056f127b8cd6cb6212ba27b0cc681093c74a760d7055233e2954a3674f611c370e826bd7108d93338842a448769af323a2e4ac67111e0b1ed1cad0c0c8967744c751046e749689cfb4da3b697c10002bfb14e89116d09bcbef1cc7841294fedea4218f9098ed925e7bc8060567e8fd9b12c94b2020c9d321026a3195801e0a53c1acb08c933722861a6144832d9506e3c63072802cc1b91614339edb8b01cf1a2f86ab436477767db4c94e15064613997caab28ec78377759fec599955598c1bb7537c8bff298c6080c9d26e772f88916805c07ee7806f3f9075f733dd705802784a2b3c28c362ac097119efad173a3b10c410166a30832ff347e5be2347258748b8a855ab30a03fc258729c97b4ba1dd0b43f48b00bd934626c879b00749f61a6e509bb2128c4ca2ca80d7582c91f18a2788121a4949bcc140050959aea69e06e25c8e12142cb29c75068bfb348aa2786c75d892e276742b935948154ae2b6228638849eec760f778cc3721fee08307d295cbec546e9e540254425210477394922a9bb5d6293a520e7c041cb63d042c59d82b91df20583d9bc4c6abc327431f7b0baeda28f69b177b79b8229379c17f6bca581119d69a221c2231cca038c187449b03a272508e374179e6c247f8b427e818ba86668791c2162a7252e3b95f02634419a264bc941c9d43b9aca7a5312a7c567c5782371407612f911457ef981ce092edfb95080c02762d2acda2a7dfcfa97ddd34f6cb1a60ca98031731bd672270c363773e85ce4c69facb120463225a4b4b374ca7820d08031d875cb88a6116c32674bbaed13a4d443830ff34e6d30b69da2427294ce45a698611b3928a0260260a05bc28cdb563afae515020a5a2ba5be3d05847bdc9fb091b82a84348023240b454ffc2542e5216a03016cd52c0bb0e0521c117320f45c0e426ec8daa4fb6c6b4149bbbea6024c59042840aa2dd8bdfb12a3c7b403f769514f4b62765c424484ac92f97a2d780b1dd84ebb152b7f8c5083439e1baa29d892309936bdd9851ee3e2181dfc4ecd9a12be6349c0526c1b74427189acb632c59e98900500b26cfa7c91395bfac757b0ec08abfa6a2071491ca8ae64e11a6695058d8805d3e030dbe323ec520f8a56b54fb22a28a1a29e118e3cf485559c9ddd5b6eaae651643a53e3c89b1b2a3af22827690a266c78c23700a4df4591df527f5002c3888905d342150b49a8412883cf155de2552dab5b97f6c90d7c7cb759d977850921917622c95b0763956f0232ac3d71bbbb02c020c809ef4274d43c0d72f2ccb24682c8c81c76733da2769d5d660f795c1ecbbd19b673e15b06773f3c8f79f8f728a95a361c4744a2948d680c5b52222c66"
_MLKEM_CT_HEX = "09d2ad465bf9925cfd322a773f9d2639d326cd7924129dc7c5a6b46ce8284a290c20ecd4181c120430727f99f68940bd3761f913878baa858603fededa32df0c940e5c19cbdeacbb6f428c0d655467fe5115a563c83f19f8b9c86270ba0ef02a46a36179580e47f0078f12688e11a70cfa58dcda6caec626479f02d6ed01b537376584e1b897502ea3705e3974df9c50c738ce828ea32917974cca632b1881f2ec79f3cb60628ffe12ba59c22b117b9846c713433870adb9f98526931704a43ef4682f95a4b60446890d61f995aaba2040b695fee85aaa756724f72318320936557710cc0a5062569199e700df81004143db7d1ae99ad9a6f2f587563b00b2f2bd53fe9485f890c02db273e9de6f5cd8fbc7267caecb1a0041a4cff5eb1948453d4ac8b99d577912e338c14a60c3344cebfdd7df1d37f90788565e3c87f5d0b82cca6318e5e1c0f1a9d388cded06840bc0e520f7d7262205740c29372bb9b7b22efe852e8479889c91ced6d0db7d30eb809cfa3bf49501842ca05406016675e54311f20cb27015229f19d0737e233aabec6308d58c4299e237f0f34a3ea9f9275f48d8def26522c151ece82360185b1b67c08617a797d51465358bcbb157f5e2e08f153f8c4f9d8f127d38c698f5d0d8cc3a3ce061d7e3faa97a1b01186f28a8c47ec04befc00e3b377db94a05954db29136ecdc31b91291ec908ecc2b5c9943392904f01a18ec9296bab26b5836abb29970a4f815f4cfc8af50ff55977ea600014250dfc42c79c7d40eb4e1313d1c841abfb892fa9f3f4681f177c63c502b2429f2f3bac3d00d271b356444b0e7484a530056a708d9e8fa07d134f3068bb142a90cbd571f9f562a5124eb6da1db1e37106bde4ce9e41d28388ffcb0c87466ab4e9bba3c90caaa23d396918a04d083722b8e9668fec5663de483f21f30cffbf84adc3e33a7e5ad0c36d21e09f745dd34bf307db77d5ed8f6f33532004db7d6b31ea3c97ad02c29babe213e97d2b6c3936ff5492164c5589f15ca8b0e4dced7138e6ccb6ccb7df574c59b663a0122b1d2e229c51c14289d15824e3fad6900f444940075b852605f609d503b6edcb3cc686166a39fd54a2b4691a8025834cadf3c33b298f1f8f39aab34a446c52f6bb480ed22d0d446d1e5ecfde9ae3779b81699dd2b37fffd2283d20819d72a5db5600432cd4b2c9ec6a4512be8cda9981248825251b54bf30ad3f9ae6e55cdbede55d79fc44413e1587e87ba11f029cf4d61ee283ec607f7de2f2153703ecb43ce2cbe14551bd859da8bfb0c49ed0fc0c841956873b164b2f725d3df66b6f66196d684322133f7e37c0224d1111079ab928d90443fca438ec4650fc9ac5b2cb849707a3170c2f3c1275428832bb8bf1597bc8895a8105928895a6e143b941cf69f0ad39106fd080a4b5b14ec6cf5feacbe55165ae4dcc9d56cf94934cc3f618dec7b9f5e1ae09a7551136f8d7dda0620deae36043978d1997711b7fd3f5790e7ff5572c4a7e2b3c6876e92d446f6e71fa35762"
_MLKEM_PQ_SECRET_HEX = "f84276c2b40b92bc77c508c1929a0ca0d9dbf18bc868f7e6a9e4ce283a7e879d"


def compute_vectors() -> dict:
    """Recompute every KAT vector from the CURRENT code. The frozen vectors.json is a
    snapshot of this function's output; tests/test_kat.py compares the two."""
    v: dict = {"_meta": {
        "about": "Frozen known-answer vectors for the chaos PWLCM cipher. See generate_kat.py.",
        "modulus_M": hex(M),
    }}

    # 1. finalize — the nonlinear output mixer, across edge + interior states.
    finalize_inputs = [0, 1, 2, M - 1, M, M // 2, (1 << 64), (1 << 127) - 3,
                       0xDEADBEEFCAFEBABE, 0x0123456789ABCDEF0123456789ABCDEF]
    v["finalize"] = [
        {"z": hex(z), "out": hex(_finalize(z))} for z in finalize_inputs
    ]

    # 2. engine_raw — the bare PWLCM core. Includes the all-zero-key edge (init avalanche).
    raw_cases = [
        {"label": "typical", "seed": _KEY_INT, "control": _CTRL_INT, "nonce": _NONCE_INT},
        {"label": "all-zero-key", "seed": 0, "control": 0, "nonce": 0},
        {"label": "max-ish", "seed": M - 1, "control": M - 1, "nonce": M - 1},
    ]
    v["engine_raw"] = []
    for c in raw_cases:
        ks = DiscreteChaoticEngine(c["seed"], c["control"], c["nonce"]).keystream(64)
        v["engine_raw"].append({**c, "seed": hex(c["seed"]), "control": hex(c["control"]),
                                "nonce": hex(c["nonce"]), "keystream": ks.hex()})

    # 3. from_master — the hash-KDF seeding path used by the AEAD layers.
    ks = DiscreteChaoticEngine.from_master(_KEY_BYTES, _NONCE_BYTES).keystream(64)
    v["from_master"] = {"key": _KEY_BYTES.hex(), "nonce": _NONCE_BYTES.hex(), "keystream": ks.hex()}

    # 4. multimap — the shipped XOR combiner, single-map and the default 4-map.
    v["multimap"] = []
    for n in (1, 4):
        ks = MultiMapEngine(_KEY_BYTES, _NONCE_BYTES, n_maps=n).keystream(64)
        v["multimap"].append({"n_maps": n, "key": _KEY_BYTES.hex(),
                              "nonce": _NONCE_BYTES.hex(), "keystream": ks.hex()})

    # 5. ratchet — the shipped auto-rekey stream. epoch_bytes=32 so 80 bytes crosses TWO seams
    #    (at 32 and 64), freezing the re-key seam math, not just one epoch.
    ks = RatchetEngine(_KEY_BYTES, _NONCE_BYTES, epoch_bytes=32).keystream(80)
    v["ratchet"] = {"key": _KEY_BYTES.hex(), "nonce": _NONCE_BYTES.hex(),
                    "epoch_bytes": 32, "length": 80, "keystream": ks.hex()}

    # 6. siv — the fully deterministic AEAD, full stack end-to-end (siv || ciphertext).
    pt = b"known-answer plaintext for the deterministic SIV AEAD path."
    aad = b"kat-aad"
    blob = seal_siv(_KEY_BYTES, pt, aad)
    v["siv"] = {"key": _KEY_BYTES.hex(), "aad": aad.hex(),
                "plaintext": pt.hex(), "blob": blob.hex()}

    # 7. aead — the committing AEAD (aead.py), full stack end-to-end. seal() draws a RANDOM nonce, so
    #    here we build the identical blob with a FIXED nonce (its only nondeterminism) so the Rust port
    #    can pin a full encrypt/decrypt: nonce || commit || ciphertext || tag.
    aead_pt = b"known-answer plaintext for the committing AEAD path."
    aead_aad = b"kat-aead-aad"
    aead_nonce = b"chaos-kat-nonce1"          # 16 bytes, fixed for the KAT only
    aead_nmaps = 4
    aead_ct = MultiMapEngine(_KEY_BYTES, aead_nonce, n_maps=aead_nmaps).encrypt(aead_pt)
    aead_commit = key_commitment(_KEY_BYTES, aead_nonce, aead_aad)
    aead_tag = _tag(_KEY_BYTES, aead_nonce, aead_commit, aead_aad, aead_ct)
    v["aead"] = {"key": _KEY_BYTES.hex(), "nonce": aead_nonce.hex(), "aad": aead_aad.hex(),
                 "plaintext": aead_pt.hex(), "n_maps": aead_nmaps,
                 "blob": (aead_nonce + aead_commit + aead_ct + aead_tag).hex()}

    # 8. stream — the streaming AEAD (streaming.py), multi-chunk, full self-delimiting blob. The salt
    #    is the only nondeterminism, so we pin it; the blob freezes the header, per-chunk framing,
    #    nonces and tags across several chunks (incl. the final-flag).
    stream_chunks = [b"first streaming chunk", b"second chunk, a bit longer than the first", b"3rd"]
    stream_aad = b"kat-stream-aad"
    stream_salt = b"chaos-kat-salt!!"        # 16 bytes, fixed for the KAT only
    stream_nmaps = 4
    stream_blob = seal_stream(_KEY_BYTES, stream_chunks, stream_aad,
                              n_maps=stream_nmaps, salt=stream_salt)
    v["stream"] = {"key": _KEY_BYTES.hex(), "salt": stream_salt.hex(), "aad": stream_aad.hex(),
                   "n_maps": stream_nmaps, "chunks": [c.hex() for c in stream_chunks],
                   "plaintext": b"".join(stream_chunks).hex(), "blob": stream_blob.hex()}

    # 9. ratchet_aead — the forward-secret SESSION AEAD (ratchet_aead.py). A 3-message session whose
    #    index advances 0->1->2, so the vector freezes the one-way chain across TWO seams (chain_0 ->
    #    chain_1 -> chain_2). The inner committing AEAD's nonce is the only nondeterminism, so we PIN
    #    one fixed inner nonce per message (safe: each message already has a unique chain-derived key).
    #    The blobs freeze the whole stack: chain init, per-message key derivation, index-bound aad, and
    #    the full committing-AEAD blob for each message.
    ra_master = _KEY_BYTES
    ra_session_nonce = b"chaos-kat-ra-non1"          # session nonce (feeds chain_0)
    ra_session_aad = b"kat-ra-session-aad"           # session-level aad
    ra_nmaps = 4
    ra_messages = [b"first session message", b"", b"third message, the final one here"]
    ra_inner_nonces = [b"ra-kat-nonce-000", b"ra-kat-nonce-001", b"ra-kat-nonce-002"]  # 16 bytes each
    ra_sender = SenderSession(ra_master, ra_session_nonce, aad=ra_session_aad)
    ra_wires = [ra_sender.seal(m, inner_nonce=n)
                for m, n in zip(ra_messages, ra_inner_nonces)]
    v["ratchet_aead"] = {"master": ra_master.hex(), "nonce": ra_session_nonce.hex(),
                         "aad": ra_session_aad.hex(), "n_maps": ra_nmaps,
                         "inner_nonces": [n.hex() for n in ra_inner_nonces],
                         "plaintexts": [m.hex() for m in ra_messages],
                         "wires": [w.hex() for w in ra_wires]}

    # 10. twolock — the two-locks wrapper (twolock.py): the chaos OUTER wall over a VETTED inner vault,
    #     keys split by HKDF-SHA256. We pin BOTH nonces (inner 12-byte, outer 16-byte) — the only
    #     nondeterminism. One blob per inner cipher (AES-256-GCM default + ChaCha20-Poly1305) freezes the
    #     whole stack end-to-end: HKDF key-split, the vetted inner AEAD, the self-describing alg byte, and
    #     the outer chaos AEAD over the inner blob. The outer wall uses the default 4 maps (twolock.py
    #     calls aead.seal without n_maps), so the Rust parity test passes n_maps=4 to match.
    tl_master = _KEY_BYTES
    tl_aad = b"kat-twolock-aad"
    tl_outer_nonce = b"chaos-kat-tl-non"          # 16 bytes (outer chaos AEAD nonce)
    tl_inner_nonce = b"tl-kat-non12"              # 12 bytes (inner vault nonce)
    tl_pt = b"two independent locks: a vetted vault inside the chaos wall."
    tl_blobs = {}
    for name in ("aes-256-gcm", "chacha20-poly1305"):
        blob = seal_twolock(tl_master, tl_pt, aad=tl_aad, inner=name,
                            inner_nonce=tl_inner_nonce, outer_nonce=tl_outer_nonce)
        tl_blobs[name] = blob.hex()
    v["twolock"] = {"master": tl_master.hex(), "outer_nonce": tl_outer_nonce.hex(),
                    "inner_nonce": tl_inner_nonce.hex(), "aad": tl_aad.hex(),
                    "plaintext": tl_pt.hex(), "n_maps": 4, "blobs": tl_blobs}

    # 11. keyexchange (DH) — classical Diffie-Hellman over RFC 3526 MODP-2048 (keyexchange.py). Both secret
    #     exponents are pinned, so the whole exchange is deterministic: g^a, g^b, the raw shared element
    #     g^(ab), and the SHA-512-derived 32-byte master key are frozen. Pure integer pow + hashlib (no
    #     chaos engine, no ML-KEM), so this vector reproduces on any machine.
    _DH_W = (P.bit_length() + 7) // 8                      # 256 bytes for the 2048-bit group
    kx_priv_a = int.from_bytes(hashlib.sha256(b"chaos-kat-dh-priv-a-v1").digest(), "big")
    kx_priv_b = int.from_bytes(hashlib.sha256(b"chaos-kat-dh-priv-b-v1").digest(), "big")
    kx_info = b"kat-dh-info"
    kx_a, kx_b = DHParty(kx_priv_a), DHParty(kx_priv_b)
    kx_raw = kx_a.raw_shared_secret(kx_b.public)
    v["keyexchange"] = {"private_a": kx_priv_a.to_bytes(32, "big").hex(),
                        "private_b": kx_priv_b.to_bytes(32, "big").hex(),
                        "public_a": kx_a.public.to_bytes(_DH_W, "big").hex(),
                        "public_b": kx_b.public.to_bytes(_DH_W, "big").hex(),
                        "raw_shared": kx_raw.hex(),
                        "info": kx_info.hex(),
                        "shared_key": kx_a.shared_key(kx_b.public, kx_info).hex()}

    # 12. pq_hybrid — the post-quantum hybrid handshake (pq_keyexchange.py): classical DH mixed with
    #     ML-KEM-768 through the SP 800-56C combiner. The ML-KEM ek/ct/secret are the frozen constants
    #     above (encaps is randomised in Python, so we pin them like NIST's ML-KEM KATs); both backends
    #     decapsulate the ciphertext to the same secret. The session key is a real hybrid: classical = the
    #     DH g^(ab) from vector 11, pq = the decapsulated secret, mixed by _combine over the full transcript
    #     (initiator DH, responder DH, initiator KEM pk, ciphertext). The combiner is pure SHA-512, so this
    #     whole vector reproduces WITHOUT the ML-KEM backend.
    pqh_seed = hashlib.sha512(b"chaos-kat-mlkem-seed-v1").digest()
    pqh_msg = hashlib.sha256(b"chaos-kat-mlkem-encaps-msg-v1").digest()
    pqh_ek = bytes.fromhex(_MLKEM_EK_HEX)
    pqh_ct = bytes.fromhex(_MLKEM_CT_HEX)
    pqh_pq_secret = bytes.fromhex(_MLKEM_PQ_SECRET_HEX)
    if MLKEM_AVAILABLE:                                    # self-check the frozen constants when we can
        _sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(pqh_seed)
        assert _sk.public_key().public_bytes_raw() == pqh_ek, "frozen ML-KEM ek drifted from the seed"
        assert _sk.decapsulate(pqh_ct) == pqh_pq_secret, "frozen ML-KEM ct/secret drifted"
    pqh_info = b"kat-pq-hybrid-info"
    pqh_transcript = _transcript(kx_a.public, kx_b.public, pqh_ek, pqh_ct)
    pqh_key = _combine(kx_raw, pqh_pq_secret, pqh_transcript, pqh_info)
    v["pq_hybrid"] = {"seed": pqh_seed.hex(), "encaps_msg": pqh_msg.hex(),
                      "ek": pqh_ek.hex(), "ct": pqh_ct.hex(), "pq_secret": pqh_pq_secret.hex(),
                      "classical": kx_raw.hex(), "info": pqh_info.hex(),
                      "dh_a": kx_a.public.to_bytes(_DH_W, "big").hex(),
                      "dh_b": kx_b.public.to_bytes(_DH_W, "big").hex(),
                      "transcript": pqh_transcript.hex(), "key": pqh_key.hex()}

    return v


def main() -> None:
    vectors = compute_vectors()
    if "--write" in sys.argv:
        with open(VECTORS_PATH, "w") as f:
            json.dump(vectors, f, indent=2)
            f.write("\n")
        print(f"Froze {VECTORS_PATH}")
    else:
        print(json.dumps(vectors, indent=2))


if __name__ == "__main__":
    main()
