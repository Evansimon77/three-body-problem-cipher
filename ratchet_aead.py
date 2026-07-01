"""
ratchet_aead.py — FORWARD-SECRET session AEAD (wires item A, the auto-rekey ratchet, into the shell).

THE PROBLEM THIS SOLVES
-----------------------
aead.py and siv.py seal every message under the same master key. That is fine until the key leaks —
and then EVERY message ever sent under it, past and future, is readable. Real conversations want
FORWARD SECRECY: if the key is stolen today, yesterday's messages stay secret.

ratchet.py already built the engine for this — a one-way HMAC key chain that re-keys and burns the
old key — but nothing in the shell used it. This module wires it in at MESSAGE granularity: a session
of many messages where each message gets its own key from the chain, and the key (and the chain link
that made it) is burned once used. Capture the live session state after message N and you can read
message N onward (that is the live state) but NOT messages 0..N-1 — their keys are gone and the chain
is one-way, so they cannot be recomputed.

HOW IT COMPOSES WHAT WE ALREADY HAVE
------------------------------------
  * The forward-secret CHAIN is the same construction as ratchet.py (HMAC-SHA256, one-way, burn the
    old link). Here it advances once PER MESSAGE instead of per 64 KiB.
  * Each message is sealed with the ordinary committing AEAD (aead.seal / #6), keyed by that message's
    chain key. So every message inherits confidentiality + integrity + key-commitment for free; this
    module only adds the forward-secret keying on top.

      chain_0          = HMAC(master_key, "…|init|" ‖ nonce)
      msg_key_i        = HMAC(chain_i,    "…|msg|"  ‖ i)      # this message's AEAD key
      chain_{i+1}      = HMAC(chain_i,    "…|chain|"‖ i)      # next link; then BURN chain_i
      wire_i           = i(8, big-endian) ‖ aead.seal(msg_key_i, plaintext, aad ‖ i)

The message index i is sealed INTO the inner AEAD's aad, so tampering with the wire index makes the
inner open fail. The receiver advances its own chain in lockstep, burning links as it goes.

ORDER / SYNC (honest scope): messages must be processed in order (0,1,2,…); a receiver that has
advanced past i has BURNED key i and cannot go back — that is the whole point of forward secrecy, not
a bug. Gaps are tolerated by fast-forwarding (and burning) the skipped links. Out-of-order or
best-effort transports need a buffering layer on top; out of scope for this research artifact.

BURNING KEYS — same honest limit as ratchet.py: Python `bytes` are immutable + GC'd, so burning is
best-effort (drop the reference); the Rust core zeroizes in place. The CONSTRUCTION is forward-secret;
the in-memory GUARANTEE comes with the port.

STILL UNVETTED — adds forward secrecy to the shell; not a proof the chaos keystream is secure.
Validated in attacks/ratchet_aead_attack.py.
"""
from __future__ import annotations

from aead import InvalidTag, open_, seal
from ratchet import _kdf

_V = b"chaos-ratchet-aead-v1|"


def _init_chain(master_key: bytes, nonce: bytes) -> bytes:
    """chain_0, derived from the master key so the raw secret never keys a message directly."""
    return _kdf(bytes(master_key), _V + b"init|" + bytes(nonce))


def _derive(chain: bytes, index: int) -> tuple[bytes, bytes]:
    """From chain_i return (msg_key_i, chain_{i+1}). The caller burns chain_i afterwards."""
    idx = index.to_bytes(8, "big")
    return _kdf(chain, _V + b"msg|" + idx), _kdf(chain, _V + b"chain|" + idx)


def _bind_aad(aad: bytes, index: int) -> bytes:
    """Authenticate the message index inside the inner AEAD: length-prefix the caller's aad, then
    append the index. A tampered wire index won't match here -> inner open fails."""
    return len(aad).to_bytes(8, "big") + aad + index.to_bytes(8, "big")


class _Session:
    """Shared chain state for a forward-secret session. Sender and receiver each hold one and advance
    it in lockstep."""

    def __init__(self, master_key: bytes, nonce: bytes, aad: bytes = b""):
        if not isinstance(master_key, (bytes, bytearray)):
            raise TypeError("master_key must be bytes")
        self._aad = bytes(aad)
        self._chain = _init_chain(master_key, nonce)
        self._index = 0

    @property
    def index(self) -> int:
        """The next message index this session will produce / expect."""
        return self._index

    def _step(self) -> tuple[int, bytes]:
        """Advance one link: return (this index, its message key) and burn the consumed chain link."""
        i = self._index
        msg_key, next_chain = _derive(self._chain, i)
        self._chain = next_chain          # burn chain_i: overwrite the only reference (best-effort)
        self._index += 1
        return i, msg_key


class SenderSession(_Session):
    """Seal a sequence of messages with per-message forward secrecy."""

    def seal(self, plaintext: bytes, inner_nonce: bytes | None = None) -> bytes:
        """Seal the next message. Returns index(8) || committing-AEAD blob. After this returns, the
        key for THIS message is gone from the session — only the live message onward is recoverable.

        `inner_nonce` is optional and only for determinism in a known-answer / Rust-parity vector
        (parallels aead.seal's `nonce=`). In production leave it None: the inner AEAD draws a fresh
        random nonce. It is safe to pin here because every message already gets a UNIQUE key from the
        one-way chain, so a fixed inner nonce can never cause keystream reuse across messages."""
        i, msg_key = self._step()
        blob = seal(msg_key, plaintext, aad=_bind_aad(self._aad, i), nonce=inner_nonce)
        del msg_key
        return i.to_bytes(8, "big") + blob


class ReceiverSession(_Session):
    """Open a sequence of messages sealed by a SenderSession, advancing the chain in lockstep."""

    def open(self, wire: bytes) -> bytes:
        """Open the next message. Raises InvalidTag on tampering / wrong key, or ValueError if the
        index is in the past (its key was already burned — forward secrecy working as intended)."""
        if len(wire) < 8:
            raise InvalidTag("session message too short / malformed")
        i = int.from_bytes(wire[:8], "big")
        if i < self._index:
            raise ValueError(f"message {i} is in the past — its key was burned (forward secrecy)")
        # Tolerate gaps: fast-forward (and burn) any skipped links so we land on chain_i.
        while self._index < i:
            self._step()
        j, msg_key = self._step()
        assert j == i
        try:
            return open_(msg_key, wire[8:], aad=_bind_aad(self._aad, i))
        finally:
            del msg_key


if __name__ == "__main__":
    master = b"forward-secret session master key"
    nonce = b"session-nonce-001"
    convo = [b"hello", b"the package is in locker 12", b"code is 4471", b"burn after reading"]

    alice = SenderSession(master, nonce)
    bob = ReceiverSession(master, nonce)
    wires = [alice.seal(m) for m in convo]
    opened = [bob.open(w) for w in wires]
    print(f"session round-trip: {opened == convo}")

    # Forward secrecy: a fresh receiver that has advanced past message 1 cannot reopen message 0.
    late = ReceiverSession(master, nonce)
    late.open(wires[0]); late.open(wires[1])          # now poised at index 2; keys 0,1 burned
    try:
        late.open(wires[0])
        print("PAST MESSAGE RE-OPENED  <-- forward secrecy broken")
    except ValueError as e:
        print(f"past message protected: {e}")
