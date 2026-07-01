"""Shared bench utilities — avoids copy-paste across the bench/ scripts."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from constants import DEFAULT_N_MAPS  # noqa: E402
from multimap import MultiMapEngine  # noqa: E402
from ratchet import RatchetEngine  # noqa: E402


def build_multimap(key: bytes = None, nonce: bytes = None, n_maps: int = DEFAULT_N_MAPS):
    """Factory for a fresh MultiMapEngine with predictable defaults."""
    return MultiMapEngine(
        key or b"bench-key", nonce or b"bench-nonce", n_maps,
    )


def build_ratchet(key: bytes = None, nonce: bytes = None, epoch_bytes: int = 65536,
                  n_maps: int = DEFAULT_N_MAPS):
    """Factory for a fresh RatchetEngine with predictable defaults."""
    return RatchetEngine(
        key or b"bench-key", nonce or b"bench-nonce", epoch_bytes, n_maps,
    )
