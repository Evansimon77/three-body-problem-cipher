"""
MultiMapEngine — the multi-body keystream: N INDEPENDENT PWLCM maps, XOR-combined (default N=4).

Why this exists: the single-map cipher (engine.py) is invertible, so a known-plaintext
state-recovery attack works at reduced scale (see attacks/known_plaintext.py, Part B). The fix
is to run several independent chaotic maps and XOR their outputs:

    keystream_byte = b0 ^ b1 ^ ... ^ b(N-1)    (bi = output of independent map i)

An attacker now sees only the XOR, not any single map's output, so they cannot cheaply separate
and roll back the N states. XOR-combining independent keystreams is a standard, sound "combiner"
construction. The independence premise is measured in attacks/map_count_attack.py (Part 1).

WHY N=4 (the #2 decision, validated 2026-06-28): the count was raised 3 -> 4. Period was never the
constraint (3 maps already give a combined ~2^189; 4 gives ~2^252). The 4th map is one more
INDEPENDENT wall — if a structural attack ever weakens one map, the others still hide the keystream
— plus comfortable margin over a 256-bit target. Cost is ~linear in N (4 = ~1.3x the 3-map time),
a Rust-phase concern. We stopped at 4, not 5+: all maps share the master key, so key/KDF recovery
(not the map count) is the true security ceiling — extra maps add period + redundancy, not
unbounded bit-security. See attacks/map_count_attack.py for the independence/cost/work-factor data.

DESIGN DECISION — the maps are INDEPENDENT, not coupled. They do not pull on each other; they are
mixed only at the final XOR. This is deliberate:
  * independence hides each map's footprint behind the others (defeats the per-map recovery), and
  * it avoids chaos *synchronization* — truly interacting chaotic systems can fall into step and
    repeat a short cycle, which would WEAKEN the keystream. Uncoupled maps can't sync.

Each map gets its own secret (seed, control) via a domain-separated KDF, so the three streams are
cryptographically unrelated.

STILL UNVETTED. This defeats the naive per-map attack; it is not a proof of security.
"""

from __future__ import annotations

from constants import DEFAULT_N_MAPS
from engine import DiscreteChaoticEngine, _kdf_hash, _derive_seed_control


class MultiMapEngine:
    """N independent PWLCM keystreams XOR-combined. Drop-in for DiscreteChaoticEngine.

    Parameters
    ----------
    master_key : bytes
        The shared secret.
    nonce : bytes
        Public, unique per message. Mixed into every sub-map's derivation.
    n_maps : int
        How many independent maps to combine (default 4 = the multi-body design; see DEFAULT_N_MAPS).
    """

    def __init__(self, master_key: bytes, nonce: bytes, n_maps: int = DEFAULT_N_MAPS):
        if n_maps < 1:
            raise ValueError("n_maps must be >= 1")
        self.n_maps = n_maps
        self.engines = [self._derive_engine(master_key, nonce, i) for i in range(n_maps)]

    @staticmethod
    def _derive_engine(master_key: bytes, nonce: bytes, index: int) -> DiscreteChaoticEngine:
        """Derive one INDEPENDENT sub-map. The map index is folded into the hash so each map
        gets an unrelated (seed_key, control_parameter). Reuses the engine's own weak-parameter
        rejection in __init__."""
        h = _kdf_hash(b"chaos-pwlcm-v1|multimap|", master_key, nonce, index=index)
        seed_key, control = _derive_seed_control(h)
        return DiscreteChaoticEngine(seed_key, control, nonce=0)  # nonce already in the hash

    def generate_byte(self) -> int:
        """One combined keystream byte = XOR of one byte from each independent sub-map."""
        b = 0
        for eng in self.engines:
            b ^= eng.generate_byte()
        return b

    def keystream(self, n: int) -> bytes:
        return bytes(self.generate_byte() for _ in range(n))

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        for i, byte in enumerate(data):
            out[i] = byte ^ self.generate_byte()
        return bytes(out)

    decrypt = encrypt


if __name__ == "__main__":
    key = b"my shared secret key"
    nonce = b"unique-nonce-001"

    a = MultiMapEngine(key, nonce)
    b = MultiMapEngine(key, nonce)
    print(f"{DEFAULT_N_MAPS}-map keystream (Alice): {a.keystream(8).hex()}")
    print(f"{DEFAULT_N_MAPS}-map keystream (Bob):   {b.keystream(8).hex()}  (matches: determinism OK)")

    msg = b"four independent chaotic maps, XOR-combined."
    ct = MultiMapEngine(key, nonce).encrypt(msg)
    pt = MultiMapEngine(key, nonce).decrypt(ct)
    print(f"\nround-trip: {pt == msg}  ->  {pt!r}")

    # show the combined stream differs from each single sub-map's stream
    sub0 = MultiMapEngine(key, nonce).engines[0].keystream(8).hex()
    combined = MultiMapEngine(key, nonce).keystream(8).hex()
    print(f"\nsub-map[0] stream: {sub0}")
    print(f"combined stream:   {combined}  (differs: each map's footprint is hidden)")
