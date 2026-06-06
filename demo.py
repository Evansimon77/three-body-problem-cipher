"""
Functional sanity demo: Alice / Bob / Eve.

IMPORTANT — what this proves and what it does NOT:
  PROVES:    the cipher is deterministic (Alice & Bob sync) and key-sensitive
             (Eve, with a near-miss key, gets garbage).
  DOES NOT PROVE: that the cipher is secure. "Wrong key -> garbage" is true of every
             stream cipher ever made, including broken ones. Real proof is in tests/
             and attacks/. See REPORT.md.
"""

from engine import DiscreteChaoticEngine

KEY = 987654321012345987654321
CONTROL_P = 333333333333333222111
NONCE = 42

message = b"Secure this message using digital chaos."

# Alice encrypts
alice = DiscreteChaoticEngine(KEY, CONTROL_P, NONCE)
ciphertext = alice.encrypt(message)
print(f"Plaintext : {message!r}")
print(f"Ciphertext: {ciphertext.hex().upper()}\n")

# Bob (same key, control, nonce) decrypts — fresh engine reproduces the keystream
bob = DiscreteChaoticEngine(KEY, CONTROL_P, NONCE)
decrypted = bob.decrypt(ciphertext)
print(f"Bob   (correct key)      -> {decrypted!r}")
assert decrypted == message, "Bob failed to decrypt — determinism broken!"

# Eve guesses a key off by ONE
eve = DiscreteChaoticEngine(KEY + 1, CONTROL_P, NONCE)
eve_out = eve.decrypt(ciphertext)
print(f"Eve   (key off by 1)     -> {eve_out!r}")

# Eve guesses the control parameter off by one
eve2 = DiscreteChaoticEngine(KEY, CONTROL_P + 1, NONCE)
print(f"Eve2  (control off by 1) -> {eve2.decrypt(ciphertext)!r}")

print("\n[OK] Alice & Bob synced; Eve got garbage.")
print("     This shows determinism + key sensitivity ONLY — not security.")
print("     Run `pytest tests/` and `python attacks/*.py` for the real evaluation.")
