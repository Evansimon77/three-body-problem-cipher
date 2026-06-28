"""
RatchetEngine — auto-rekey ("A"): a one-way key chain that re-keys the keystream every epoch and
BURNS the old key. Drop-in keystream source (same interface as MultiMapEngine).

WHY THIS EXISTS — two payoffs:
  1. FORWARD SECRECY. The key advances through a one-way chain:
         K_{i+1} = HMAC(K_i, "chain"||i)      (next chain key)
         MK_i    = HMAC(K_i, "epoch"||i)       (this epoch's keystream key)
     After deriving both we DROP K_i. Because HMAC-SHA256 is one-way, an attacker who captures the
     LIVE state during epoch i holds K_{i+1} (future) but CANNOT compute K_{i-1} or any earlier MK
     — so messages from past epochs stay secret even if the current key leaks. (Recovering the
     FUTURE from a live capture needs the asymmetric/DH ratchet — that is item F, a later phase.)
  2. DISSOLVES THE PERIOD LIMIT. Each epoch is a FRESH, independent MultiMapEngine (its own seeds,
     its own ~2^62 orbit). We re-key every `epoch_bytes` (default 64 KiB) — astronomically before
     any single orbit could repeat — so the usable stream length is effectively unbounded.

SYNC: the chain is fully deterministic from (master_key, nonce, epoch_bytes, n_maps). Alice and Bob
ratchet in lockstep. Like `n_maps`, **`epoch_bytes` must match on both sides** (it sets the epoch
boundaries). `from_chain_key()` lets a legitimate party resume from a saved checkpoint.

BURNING KEYS — honest limitation: Python `bytes` are immutable and GC'd, so we cannot guarantee the
old key is wiped from memory; we drop every reference promptly and document the intent. The Rust
core (#5) will `zeroize` the old chain key in place. This module gives the right *construction*; the
*guarantee* comes with the port.

STILL UNVETTED — this adds forward secrecy + unbounded length to the keystream; it is not a proof of
security. Validated in attacks/ratchet_attack.py (forward secrecy, epoch independence, clean seams).
"""

from __future__ import annotations

import hashlib
import hmac

from multimap import DEFAULT_N_MAPS, MultiMapEngine

# 64 KiB per epoch: fine-grained forward secrecy (a live capture exposes at most the current epoch
# onward, never earlier), while the per-epoch re-key cost (a couple of HMACs + fresh map setup) stays
# negligible against generating 64 KiB. Purely a forward-secrecy/perf knob — far below any period.
DEFAULT_EPOCH_BYTES = 1 << 16

_V = b"chaos-ratchet-v1|"


def _kdf(key: bytes, label: bytes) -> bytes:
    """One-way key-derivation step (HMAC-SHA256). Used for both the chain and the epoch keys."""
    return hmac.new(key, label, hashlib.sha256).digest()


class RatchetEngine:
    """Forward-secret, unbounded keystream via a one-way re-keying chain. Drop-in for MultiMapEngine.

    Parameters
    ----------
    master_key : bytes
        The shared secret. The live chain key K_0 is DERIVED from it (never used raw).
    nonce : bytes
        Public, unique per message. Folded into the chain seed and every epoch's sub-keys.
    epoch_bytes : int
        Re-key after this many keystream bytes. Must match on both sides. Default 64 KiB.
    n_maps : int
        Independent maps per epoch (forwarded to MultiMapEngine; default = the locked count).
    """

    def __init__(self, master_key: bytes, nonce: bytes,
                 epoch_bytes: int = DEFAULT_EPOCH_BYTES, n_maps: int = DEFAULT_N_MAPS):
        if epoch_bytes < 1:
            raise ValueError("epoch_bytes must be >= 1")
        self._nonce = bytes(nonce)
        self._epoch_bytes = epoch_bytes
        self._n_maps = n_maps
        # K_0 — derived from the master key, so the raw secret never seeds a map directly.
        self._chain_key = _kdf(bytes(master_key), _V + b"init|" + self._nonce)
        self._epoch_index = -1
        self._engine: MultiMapEngine | None = None
        self._remaining = 0
        self._advance()                      # enter epoch 0

    @classmethod
    def from_chain_key(cls, chain_key: bytes, next_epoch_index: int, nonce: bytes,
                       epoch_bytes: int = DEFAULT_EPOCH_BYTES,
                       n_maps: int = DEFAULT_N_MAPS) -> "RatchetEngine":
        """Resume a ratchet from a saved chain key at the start of `next_epoch_index`. Legitimate
        checkpoint/restore (and the exact capability a memory-capture attacker would have: it can go
        FORWARD from the captured key, never backward — that is the whole forward-secrecy point)."""
        self = cls.__new__(cls)
        self._nonce = bytes(nonce)
        self._epoch_bytes = epoch_bytes
        self._n_maps = n_maps
        self._chain_key = bytes(chain_key)
        self._epoch_index = next_epoch_index - 1
        self._engine = None
        self._remaining = 0
        self._advance()
        return self

    def _advance(self) -> None:
        """Step the chain: derive this epoch's keystream engine + the next chain key from the current
        chain key, then BURN the current chain key (drop the reference)."""
        self._epoch_index += 1
        idx = self._epoch_index.to_bytes(8, "big")
        epoch_key = _kdf(self._chain_key, _V + b"epoch|" + idx)   # MK_i
        next_chain = _kdf(self._chain_key, _V + b"chain|" + idx)  # K_{i+1}
        # Burn K_i: overwrite the only reference. (Best-effort in Python; Rust will zeroize.)
        self._chain_key = next_chain
        # Fresh, independent keystream for this epoch (its own seeds + ~2^62 orbit).
        epoch_nonce = self._nonce + b"|ep|" + idx
        self._engine = MultiMapEngine(epoch_key, epoch_nonce, n_maps=self._n_maps)
        self._remaining = self._epoch_bytes
        del epoch_key

    @property
    def epoch_index(self) -> int:
        """The epoch currently being emitted."""
        return self._epoch_index

    def checkpoint(self) -> tuple[bytes, int]:
        """(chain_key, next_epoch_index) to resume later via from_chain_key(). The chain key resumes
        the NEXT epoch — by construction it cannot reproduce any already-finished epoch."""
        return self._chain_key, self._epoch_index + 1

    def generate_byte(self) -> int:
        """One keystream byte, re-keying transparently at each epoch boundary."""
        if self._remaining == 0:
            self._advance()
        self._remaining -= 1
        return self._engine.generate_byte()

    def keystream(self, n: int) -> bytes:
        return bytes(self.generate_byte() for _ in range(n))

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        for i, b in enumerate(data):
            out[i] = b ^ self.generate_byte()
        return bytes(out)

    decrypt = encrypt


if __name__ == "__main__":
    key = b"ratchet shared secret"
    nonce = b"ratchet-nonce-001"
    # Small epochs so the demo crosses several re-keys.
    msg = b"auto-rekey ratchet: forward secrecy + unbounded length. " * 40
    ct = RatchetEngine(key, nonce, epoch_bytes=64).encrypt(msg)
    pt = RatchetEngine(key, nonce, epoch_bytes=64).decrypt(ct)
    print(f"spans many epochs, round-trip: {pt == msg}  ({len(msg)} bytes, 64-byte epochs)")
    a = RatchetEngine(key, nonce).keystream(16).hex()
    b = RatchetEngine(key, nonce).keystream(16).hex()
    print(f"deterministic (Alice==Bob): {a == b}  ->  {a}")
