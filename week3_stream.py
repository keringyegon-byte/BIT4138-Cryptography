"""
BIT4138 - Week 3: Stream Ciphers and Randomness Testing
Implements LFSR generator, RC4 cipher, and statistical randomness tests.
"""

import random
import math
import time

# ── LFSR Generator ────────────────────────────────────────────

def lfsr_generator(seed, taps, length=64):
    """
    Linear Feedback Shift Register (LFSR)
    seed : initial state as list of bits e.g. [1,0,1,1]
    taps : feedback tap positions e.g. [3, 0]
    """
    state = list(seed)
    n = len(state)
    sequence = []
    states_seen = set()

    for _ in range(length):
        state_tuple = tuple(state)
        if state_tuple in states_seen:
            break
        states_seen.add(state_tuple)
        output_bit = state[-1]
        sequence.append(output_bit)
        feedback = 0
        for tap in taps:
            feedback ^= state[tap]
        state = [feedback] + state[:-1]

    return sequence

# ── Randomness Tests ──────────────────────────────────────────

def frequency_test(bits):
    """Frequency (Monobit) Test - checks balance of 0s and 1s"""
    n = len(bits)
    ones = sum(bits)
    zeros = n - ones
    ratio = ones / n
    passed = 0.4 <= ratio <= 0.6
    return {"ones": ones, "zeros": zeros, "ratio": round(ratio, 4), "passed": passed}

def runs_test(bits):
    """Runs Test - checks how often the sequence changes"""
    runs = 1
    for i in range(1, len(bits)):
        if bits[i] != bits[i - 1]:
            runs += 1
    n = len(bits)
    expected = (2 * n - 1) / 3
    passed = abs(runs - expected) < (n * 0.2)
    return {"runs": runs, "expected": round(expected, 2), "passed": passed}

def mean_test(bits):
    """Mean Test - mean should be close to 0.5"""
    mean = sum(bits) / len(bits)
    passed = 0.4 <= mean <= 0.6
    return {"mean": round(mean, 4), "passed": passed}

def chi_square_test(bits):
    """Chi-Square Test - checks uniform distribution"""
    n = len(bits)
    ones = sum(bits)
    zeros = n - ones
    expected = n / 2
    chi2 = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected
    passed = chi2 < 3.841  # critical value at 95% confidence
    return {"chi_square": round(chi2, 4), "critical_value": 3.841, "passed": passed}

def run_all_tests(bits, label="Sequence"):
    print(f"\n{'='*55}")
    print(f"  Randomness Tests: {label}")
    print(f"  Sequence length : {len(bits)} bits")
    print(f"  Sequence sample : {''.join(map(str, bits[:30]))}...")
    print(f"{'='*55}")

    freq = frequency_test(bits)
    print(f"\n  [1] Frequency Test")
    print(f"      Ones  : {freq['ones']}  |  Zeros : {freq['zeros']}")
    print(f"      Ratio : {freq['ratio']}  (ideal: 0.5)")
    print(f"      Result: {'PASS' if freq['passed'] else 'FAIL'}")

    runs = runs_test(bits)
    print(f"\n  [2] Runs Test")
    print(f"      Runs found : {runs['runs']}  |  Expected : {runs['expected']}")
    print(f"      Result     : {'PASS' if runs['passed'] else 'FAIL'}")

    mean = mean_test(bits)
    print(f"\n  [3] Mean Test")
    print(f"      Mean   : {mean['mean']}  (ideal: 0.5)")
    print(f"      Result : {'PASS' if mean['passed'] else 'FAIL'}")

    chi = chi_square_test(bits)
    print(f"\n  [4] Chi-Square Test")
    print(f"      Chi^2  : {chi['chi_square']}  (critical: {chi['critical_value']})")
    print(f"      Result : {'PASS' if chi['passed'] else 'FAIL'}")

    total = sum([freq['passed'], runs['passed'], mean['passed'], chi['passed']])
    print(f"\n  Overall: {total}/4 tests passed")
    print(f"{'='*55}")

# ── RC4 Stream Cipher ─────────────────────────────────────────

def rc4(key, data):
    """RC4 Key Scheduling and Pseudo-Random Generation"""
    key_bytes = [ord(c) for c in key]
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    keystream = []
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        keystream.append(k)
        result.append(byte ^ k)

    return bytes(result), keystream

# ── Main ──────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("   BIT4138 Advanced Cryptography - Week 3")
    print("   Stream Ciphers and Randomness Testing")
    print("=" * 55)

    while True:
        print("\n  [1] LFSR Generator + Sequence Output")
        print("  [2] Randomness Tests on LFSR Sequence")
        print("  [3] RC4 Stream Cipher Encryption")
        print("  [4] Performance Comparison")
        print("  [5] Exit")
        choice = input("\nSelect option: ").strip()

        if choice == "1":
            print("\n" + "-" * 55)
            print("  LFSR Generator")
            print("-" * 55)
            seed = [1, 0, 1, 1]
            taps = [3, 0]
            seq = lfsr_generator(seed, taps, length=100)
            print(f"  Seed     : {seed}")
            print(f"  Taps     : {taps}")
            print(f"  Period   : {len(seq)} bits")
            print(f"  Sequence : {''.join(map(str, seq))}")
            print(f"\n  4-bit LFSR max period = 2^4 - 1 = 15")
            print(f"  Actual period found   = {len(seq)}")

        elif choice == "2":
            seed = [1, 0, 1, 1]
            taps = [3, 0]
            seq = lfsr_generator(seed, taps, length=100)
            # extend for better stats
            full_seq = (seq * 20)[:200]
            run_all_tests(full_seq, "LFSR Output (200 bits)")
            # also test true random for comparison
            rand_bits = [random.randint(0, 1) for _ in range(200)]
            run_all_tests(rand_bits, "Python random module (200 bits)")

        elif choice == "3":
            print("\n" + "-" * 55)
            print("  RC4 Stream Cipher")
            print("-" * 55)
            key = input("  Enter encryption key (e.g. CRYPTOKEY): ").strip() or "CRYPTOKEY"
            message = input("  Enter message to encrypt: ").strip() or "Hello from BIT4138 Advanced Cryptography!"
            data = message.encode()
            ciphertext, keystream = rc4(key, data)
            decrypted, _ = rc4(key, ciphertext)
            print(f"\n  Key        : {key}")
            print(f"  Plaintext  : {message}")
            print(f"  Keystream  : {keystream[:16]}...")
            print(f"  Ciphertext : {ciphertext.hex()}")
            print(f"  Decrypted  : {decrypted.decode()}")
            print(f"  Match      : {'YES - Correct!' if decrypted.decode() == message else 'NO - Error'}")

        elif choice == "4":
            print("\n" + "-" * 55)
            print("  Performance Test")
            print("-" * 55)
            sizes = [100, 500, 1000, 5000]
            key = "PERFTEST"
            for size in sizes:
                data = bytes([random.randint(0, 255) for _ in range(size)])
                start = time.time()
                for _ in range(100):
                    rc4(key, data)
                elapsed = (time.time() - start) / 100 * 1000
                print(f"  RC4 {size:>5} bytes : {elapsed:.4f} ms per operation")

        elif choice == "5":
            print("\n  Exiting. Goodbye!")
            break
        else:
            print("  Invalid option. Please choose 1-5.")

if __name__ == "__main__":
    main()
