"""
BIT4138 - Week 7: Block Cipher Cryptanalysis
Implements differential cryptanalysis simulation, frequency analysis,
algebraic XOR key recovery, and avalanche effect testing.
"""

from collections import Counter
import random

# ── Simple block cipher for demonstration ─────────────────────
SBOX = {i: (i * 7 + 3) % 16 for i in range(16)}

def simple_encrypt(plaintext, key):
    """Simple XOR + S-Box cipher for cryptanalysis demo"""
    result = []
    for char in plaintext:
        val = ord(char) & 0xFF
        val = val ^ key
        val = (SBOX[val & 0xF] | (SBOX[(val >> 4) & 0xF] << 4))
        result.append(val)
    return bytes(result)

def xor_encrypt(plaintext, key):
    """Pure XOR cipher (weak - vulnerable to algebraic attack)"""
    return bytes([ord(c) ^ key for c in plaintext])

# ── Differential Cryptanalysis ────────────────────────────────

def differential_analysis(p1, p2, key):
    """Simulate differential cryptanalysis"""
    c1 = simple_encrypt(p1, key)
    c2 = simple_encrypt(p2, key)

    input_diff = bytes([ord(a) ^ ord(b) for a, b in zip(p1, p2)])
    output_diff = bytes([a ^ b for a, b in zip(c1, c2)])

    print(f"  Plaintext 1    : {p1}")
    print(f"  Plaintext 2    : {p2}")
    print(f"  Input XOR diff : {input_diff.hex()}")
    print(f"  Ciphertext 1   : {c1.hex()}")
    print(f"  Ciphertext 2   : {c2.hex()}")
    print(f"  Output XOR diff: {output_diff.hex()}")

    same_bytes = sum(1 for a, b in zip(c1, c2) if a == b)
    diff_bytes = len(c1) - same_bytes
    print(f"  Bytes changed  : {diff_bytes}/{len(c1)} ({diff_bytes/len(c1)*100:.1f}%)")
    print(f"  Avalanche OK   : {'YES - Strong' if diff_bytes/len(c1) >= 0.4 else 'WEAK - Poor diffusion'}")
    return input_diff, output_diff

# ── Frequency Analysis (Linear Cryptanalysis basis) ───────────

def frequency_analysis(ciphertext_bytes):
    """Frequency analysis - foundation of linear cryptanalysis"""
    counts = Counter(ciphertext_bytes)
    total = len(ciphertext_bytes)
    expected = total / 256

    print(f"  Total bytes analysed : {total}")
    print(f"  Expected frequency   : {expected:.2f} per byte value")
    print(f"  Unique byte values   : {len(counts)}")
    print(f"\n  Top 10 most frequent bytes:")
    print(f"  {'Byte':<8} {'Count':<8} {'Freq%':<10} {'Bias'}")
    print(f"  {'-'*40}")
    for byte_val, count in counts.most_common(10):
        freq = count / total * 100
        bias = abs(count - expected) / total
        print(f"  0x{byte_val:02X}   {count:<8} {freq:<10.2f} {bias:.4f}")

    max_bias = max(abs(c - expected) / total for c in counts.values())
    print(f"\n  Max statistical bias : {max_bias:.4f}")
    print(f"  Cipher randomness    : {'GOOD (low bias)' if max_bias < 0.02 else 'POOR (high bias - exploitable)'}")

# ── Algebraic Attack: XOR Key Recovery ────────────────────────

def algebraic_xor_recovery(plaintext, ciphertext_bytes):
    """Demonstrate algebraic attack on weak XOR cipher"""
    print(f"  Known plaintext  : {plaintext}")
    print(f"  Known ciphertext : {ciphertext_bytes.hex()}")
    print(f"\n  Attempting algebraic key recovery (K = P XOR C)...")

    recovered_keys = []
    for p, c in zip(plaintext, ciphertext_bytes):
        k = ord(p) ^ c
        recovered_keys.append(k)

    unique_keys = set(recovered_keys)
    print(f"  Recovered key bytes : {[hex(k) for k in recovered_keys[:8]]}...")
    if len(unique_keys) == 1:
        print(f"  Single key found    : {hex(list(unique_keys)[0])} = {list(unique_keys)[0]}")
        print(f"  Attack SUCCESS      : Key fully recovered!")
    else:
        print(f"  Multiple key values : Cipher may use key mixing")
        print(f"  Attack PARTIAL      : {len(unique_keys)} unique key bytes found")
    return recovered_keys

# ── Avalanche Effect ──────────────────────────────────────────

def avalanche_comparison(message, key):
    """Compare encryption of two similar messages"""
    modified = message[:-1] + chr(ord(message[-1]) ^ 1)
    enc1 = simple_encrypt(message, key)
    enc2 = simple_encrypt(modified, key)

    bit_diff = sum(bin(a ^ b).count('1') for a, b in zip(enc1, enc2))
    total_bits = len(enc1) * 8
    pct = bit_diff / total_bits * 100

    print(f"  Original  : '{message}'  -> {enc1.hex()[:32]}...")
    print(f"  Modified  : '{modified}'  -> {enc2.hex()[:32]}...")
    print(f"  Bits changed : {bit_diff}/{total_bits} ({pct:.1f}%)")
    print(f"  Avalanche    : {'STRONG (>=40%)' if pct >= 40 else 'MODERATE' if pct >= 20 else 'WEAK'}")

# ── Main ──────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("   BIT4138 Advanced Cryptography - Week 7")
    print("   Block Cipher Cryptanalysis Toolkit")
    print("=" * 55)

    KEY = 42

    while True:
        print("\n  [1] Differential Cryptanalysis Simulation")
        print("  [2] Frequency Analysis (Linear Cryptanalysis basis)")
        print("  [3] Algebraic Attack - XOR Key Recovery")
        print("  [4] Avalanche Effect Comparison")
        print("  [5] Full Attack Demo (all methods)")
        print("  [6] Exit")
        choice = input("\nSelect option: ").strip()

        if choice == "1":
            print("\n" + "-"*55)
            print("  Differential Cryptanalysis Simulation")
            print("-"*55)
            p1 = input("  Enter plaintext 1 (e.g. HELLO WORLD): ").strip() or "HELLO WORLD"
            p2 = input("  Enter plaintext 2 (1 char different): ").strip() or "HELLo WORLD"
            if len(p1) != len(p2):
                p2 = p2[:len(p1)].ljust(len(p1))
            print()
            differential_analysis(p1, p2, KEY)

        elif choice == "2":
            print("\n" + "-"*55)
            print("  Frequency Analysis")
            print("-"*55)
            msg = input("  Enter message to encrypt and analyse: ").strip() or "Advanced Cryptography BIT4138 Security Analysis"
            ciphertext = simple_encrypt(msg, KEY)
            print(f"\n  Encrypted {len(msg)} bytes. Analysing distribution...\n")
            frequency_analysis(ciphertext)

        elif choice == "3":
            print("\n" + "-"*55)
            print("  Algebraic Attack - XOR Key Recovery")
            print("-"*55)
            msg = input("  Enter plaintext message: ").strip() or "Hello BIT4138"
            secret_key = int(input("  Enter secret XOR key (1-255): ").strip() or "77")
            ciphertext = xor_encrypt(msg, secret_key)
            print(f"\n  Cipher used pure XOR with key {secret_key}")
            print(f"  Attacker only knows plaintext + ciphertext:\n")
            algebraic_xor_recovery(msg, ciphertext)

        elif choice == "4":
            print("\n" + "-"*55)
            print("  Avalanche Effect Comparison")
            print("-"*55)
            msg = input("  Enter message (e.g. HELLO WORLD): ").strip() or "HELLO WORLD"
            print()
            avalanche_comparison(msg, KEY)

        elif choice == "5":
            print("\n" + "="*55)
            print("  FULL CRYPTANALYSIS DEMONSTRATION")
            print("="*55)
            msg = "CRYPTOGRAPHY"
            mod = "CRYPTOGRAPHy"
            print("\n--- 1. Differential Cryptanalysis ---")
            differential_analysis(msg, mod, KEY)
            print("\n--- 2. Frequency Analysis ---")
            frequency_analysis(simple_encrypt(msg * 10, KEY))
            print("\n--- 3. XOR Key Recovery ---")
            algebraic_xor_recovery(msg, xor_encrypt(msg, KEY))
            print("\n--- 4. Avalanche Effect ---")
            avalanche_comparison(msg, KEY)

        elif choice == "6":
            print("\n  Exiting. Goodbye!")
            break
        else:
            print("  Invalid option. Please choose 1-6.")

if __name__ == "__main__":
    main()
