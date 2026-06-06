"""
ATTACK 1 — Two-time pad (keystream reuse).

This break has NOTHING to do with how good the chaotic map is. It is the single most
likely way this cipher dies in practice. If you ever encrypt two messages with the same
(key, nonce), the keystream K cancels under XOR:

    C1 = P1 ^ K
    C2 = P2 ^ K
    C1 ^ C2 = P1 ^ P2          <-- keystream gone, no key needed

From P1^P2 an attacker recovers both plaintexts via crib-dragging (guessing a common
word and sliding it along). We demonstrate full recovery here. The lesson: nonces are
mandatory and must NEVER repeat under the same key.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import DiscreteChaoticEngine  # noqa: E402

KEY = 555555555555555555
CTRL = 777777777777777777
NONCE = 1234  # <-- reused for both messages: the fatal mistake

P1 = b"Attack at dawn. Bring the documents to the south gate immediately."
P2 = b"The wire transfer of $40,000 will clear by Friday afternoon, ok?"


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def crib_drag(c1_xor_c2, crib):
    """Slide `crib` across C1^C2. Where the result is printable ASCII, the crib likely
    aligns with one plaintext and the output reveals the OTHER plaintext there."""
    hits = []
    for pos in range(len(c1_xor_c2) - len(crib) + 1):
        chunk = c1_xor_c2[pos:pos + len(crib)]
        guess = xor(chunk, crib)
        if all(32 <= b < 127 for b in guess):
            hits.append((pos, guess.decode("ascii")))
    return hits


def main():
    c1 = DiscreteChaoticEngine(KEY, CTRL, NONCE).encrypt(P1)
    c2 = DiscreteChaoticEngine(KEY, CTRL, NONCE).encrypt(P2)

    print("Two ciphertexts, SAME key+nonce (the mistake):")
    print(f"  C1 = {c1.hex()}")
    print(f"  C2 = {c2.hex()}\n")

    x = xor(c1, c2)
    print(f"C1 ^ C2 (keystream cancels) = {x.hex()}\n")

    # Full recovery: if the attacker guesses ANY plaintext, the other falls out instantly.
    # In reality they'd crib-drag; here we show both directions.
    recovered_p2 = xor(x, P1)  # attacker who knows/guesses P1 gets P2 for free
    print("Crib-dragging the word ' the ':")
    for pos, txt in crib_drag(x, b" the ")[:6]:
        print(f"   pos {pos:>2}: ...{txt!r} (reveals the other message around here)")

    print(f"\nGiven P1, recovered P2 = {recovered_p2!r}")
    assert recovered_p2 == P2[:len(recovered_p2)]
    print("\n[BROKEN] Keystream reuse fully exposes both messages. "
          "Verdict: nonces are mandatory; never reuse (key,nonce).")


if __name__ == "__main__":
    main()
