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

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aead import _tag  # noqa: E402
from commit import key_commitment  # noqa: E402
from engine import M, DiscreteChaoticEngine, _finalize  # noqa: E402
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
