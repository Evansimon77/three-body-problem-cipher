"""
KAT regression test (§3) — the cipher's frozen contract.

Loads the frozen kat/vectors.json and recomputes every vector from the live code. Any single
byte that differs fails here. This is what makes "behaviour-preserving refactor" a provable
claim, and what the Rust port (Phase 4) must satisfy to be called bit-identical.

If you INTEND to change the cipher's output, regenerate with `python3 kat/generate_kat.py
--write` and say so in the commit. Never regenerate just to silence a failure.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kat.generate_kat import VECTORS_PATH, compute_vectors  # noqa: E402


def _frozen() -> dict:
    with open(VECTORS_PATH) as f:
        return json.load(f)


def test_frozen_file_exists_and_parses():
    frozen = _frozen()
    assert "finalize" in frozen and "ratchet" in frozen, "vectors.json missing expected sections"


def test_all_vectors_match_frozen():
    """The whole live recomputation must equal the frozen snapshot, exactly."""
    live = compute_vectors()
    frozen = _frozen()
    assert live == frozen, (
        "Live output diverged from the frozen KAT. Either a real regression, or an "
        "intended change that needs `python3 kat/generate_kat.py --write` + a commit note."
    )


def test_each_section_individually():
    """Per-section asserts so a failure points at the exact layer that drifted."""
    live = compute_vectors()
    frozen = _frozen()
    for section in ("finalize", "engine_raw", "from_master", "multimap", "ratchet", "siv"):
        assert live[section] == frozen[section], f"KAT drift in section: {section}"


def test_ratchet_vector_actually_crosses_seams():
    """Guard the guard: the ratchet KAT is only meaningful if it spans >1 epoch."""
    frozen = _frozen()
    r = frozen["ratchet"]
    assert r["length"] > 2 * r["epoch_bytes"], "ratchet KAT must cross at least two re-key seams"
