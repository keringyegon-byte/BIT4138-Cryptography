"""
BIT4138 - Week 5: RSA Encryption and Feistel Cipher (CAT 1)
Implements RSA key pair generation, encryption/decryption,
and a Feistel cipher with avalanche effect demonstration.
"""

import os
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# ── RSA Key Generation ────────────────────────────────────────

def generate_rsa_keypair(bits=2048):
    """Generate RSA public/private key pair"""
    print(f"  Generating RSA-{bits} key pair... (this may take a moment)")
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_keys(private_key, public_key):
    with open("private_key.pem", "wb") as f:
        f.write(private_key)
    with open("public_key.pem", "wb") as f:
        f.write(public_key)
    print("  Keys saved: private_key.pem and public_key.pem")

def load_keys():
    with open("private_key.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    with open("public_key.pem", "rb") as f:
        public_key = RSA.import_key(f.read())
    return private_key, public_key

# ── RSA Encrypt / Decrypt ─────────────────────────────────────

def rsa_encrypt(message, public_key_pem):
    pub_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(pub_key)
    ciphertext = cipher.encrypt(message.encode())
    return ciphertext

def rsa_decrypt(ciphertext, private_key_pem):
    priv_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(priv_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()

# ── Feistel Cipher (CAT 1) ────────────────────────────────────

def feistel_round_function(data, subkey):
    """Simple round function: XOR with subkey then rotate bits"""
    result = data ^ subkey
    result = ((result << 2) | (result >> 6)) & 0xFF
    return result

def feistel_encrypt(plaintext, key, rounds=4):
    """Feistel cipher encryption"""
    # Pad to even length
    if len(plaintext) % 2 != 0:
        plaintext += " "

    # Generate subkeys
    subkeys = [(key + i * 37) % 256 for i in range(rounds)]

    result = []
    # Process in 2-byte blocks
    for i in range(0, len(plaintext), 2):
        block = plaintext[i:i+2]
        L = ord(block[0])
        R = ord(block[1])

        for r in range(rounds):
            f_output = feistel_round_function(R, subkeys[r])
            new_R = L ^ f_output
            L = R
            R = new_R

        result.append(L)
        result.append(R)

    return bytes(result)

def feistel_decrypt(ciphertext, key, rounds=4):
    """Feistel cipher decryption (reverse round order)"""
    subkeys = [(key + i * 37) % 256 for i in range(rounds)]

    result = []
    for i in range(0, len(ciphertext), 2):
        L = ciphertext[i]
        R = ciphertext[i+1]

        for r in reversed(range(rounds)):
            f_output = feistel_round_function(L, subkeys[r])
            new_L = R ^ f_output
            R = L
            L = new_L

        result.append(chr(L))
        result.append(chr(R))

    return "".join(result).rstrip()

def count_bit_differences(b1, b2):
    """Count number of different bits between two byte sequences (Hamming distance)"""
    diff = 0
    for x, y in zip(b1, b2):
        xor = x ^ y
        diff += bin(xor).count('1')
    return diff

def avalanche_test(message, key):
    """Test avalanche effect - change one character, compare ciphertext"""
    print(f"\n  Original message  : '{message}'")
    enc1 = feistel_encrypt(message, key)
    print(f"  Encrypted (hex)   : {enc1.hex()}")

    # Change just one character
    modified = chr(ord(message[0]) + 1) + message[1:]
    print(f"\n  Modified message  : '{modified}' (1 char changed)")
    enc2 = feistel_encrypt(modified, key)
    print(f"  Encrypted (hex)   : {enc2.hex()}")

    bit_diff = count_bit_differences(enc1, enc2)
    total_bits = len(enc1) * 8
    pct = (bit_diff / total_bits) * 100
    print(f"\n  Bits changed      : {bit_diff} / {total_bits} ({pct:.1f}%)")
    print(f"  Avalanche Effect  : {'STRONG (>30%)' if pct > 30 else 'MODERATE' if pct > 15 else 'WEAK'}")

# ── Main ──────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("   BIT4138 Advanced Cryptography - Week 5")
    print("   RSA Encryption + Feistel Cipher (CAT 1)")
    print("=" * 55)

    private_key = None
    public_key = None

    while True:
        print("\n  [1] Generate RSA Key Pair")
        print("  [2] Encrypt Message with Public Key")
        print("  [3] Decrypt Message with Private Key")
        print("  [4] Feistel Cipher Simulation (CAT 1)")
        print("  [5] Avalanche Effect Test (CAT 1)")
        print("  [6] Full RSA Validation Test")
        print("  [7] Exit")
        choice = input("\nSelect option: ").strip()

        if choice == "1":
            start = time.time()
            private_key, public_key = generate_rsa_keypair(2048)
            elapsed = time.time() - start
            save_keys(private_key, public_key)
            print(f"\n  Key generation time : {elapsed:.2f} seconds")
            print(f"\n  Public Key (first 5 lines):")
            for line in public_key.decode().split('\n')[:5]:
                print(f"  {line}")
            print(f"  ...")
            print(f"\n  Private Key (first 3 lines):")
            for line in private_key.decode().split('\n')[:3]:
                print(f"  {line}")
            print(f"  ...")

        elif choice == "2":
            if public_key is None:
                print("  No keys found. Please generate keys first (option 1).")
                continue
            message = input("  Enter message to encrypt: ").strip()
            if not message:
                print("  Error: Message cannot be empty.")
                continue
            ciphertext = rsa_encrypt(message, public_key)
            print(f"\n  Plaintext  : {message}")
            print(f"  Ciphertext : {ciphertext.hex()[:64]}...")
            print(f"  Length     : {len(ciphertext)} bytes")
            # store for decryption
            with open("rsa_ciphertext.bin", "wb") as f:
                f.write(ciphertext)
            print(f"  Saved to   : rsa_ciphertext.bin")

        elif choice == "3":
            if private_key is None:
                print("  No keys found. Please generate keys first (option 1).")
                continue
            if not os.path.exists("rsa_ciphertext.bin"):
                print("  No ciphertext found. Please encrypt a message first (option 2).")
                continue
            with open("rsa_ciphertext.bin", "rb") as f:
                ciphertext = f.read()
            decrypted = rsa_decrypt(ciphertext, private_key)
            print(f"\n  Ciphertext : {ciphertext.hex()[:64]}...")
            print(f"  Decrypted  : {decrypted}")
            print(f"  Status     : SUCCESS")

        elif choice == "4":
            print("\n" + "-" * 55)
            print("  Feistel Cipher Simulation (CAT 1)")
            print("-" * 55)
            message = input("  Enter message (even length recommended): ").strip() or "Hello BIT"
            key_val = 42
            rounds = 4
            subkeys = [(key_val + i * 37) % 256 for i in range(rounds)]
            print(f"\n  Message   : '{message}'")
            print(f"  Key       : {key_val}")
            print(f"  Rounds    : {rounds}")
            print(f"  Subkeys   : {subkeys}")

            # Show round-by-round for first block
            if len(message) >= 2:
                block = message[:2] if len(message) >= 2 else message + " "
                L = ord(block[0])
                R = ord(block[1])
                print(f"\n  Block '{block}': L={L} ({chr(L)}), R={R} ({chr(R)})")
                print(f"  {'Round':<8} {'L':<6} {'R':<6} {'F(R,K)':<10}")
                print(f"  {'-'*30}")
                for r in range(rounds):
                    f_out = feistel_round_function(R, subkeys[r])
                    new_R = L ^ f_out
                    L, R = R, new_R
                    print(f"  {r+1:<8} {L:<6} {R:<6} {f_out:<10}")

            encrypted = feistel_encrypt(message, key_val, rounds)
            decrypted = feistel_decrypt(encrypted, key_val, rounds)
            print(f"\n  Full message encrypted : {encrypted.hex()}")
            print(f"  Decrypted              : '{decrypted}'")
            print(f"  Correct                : {'YES' if decrypted.strip() == message.strip() else 'NO'}")

        elif choice == "5":
            print("\n" + "-" * 55)
            print("  Avalanche Effect Test (CAT 1)")
            print("-" * 55)
            message = input("  Enter test message: ").strip() or "Hello BIT4138"
            avalanche_test(message, 42)

        elif choice == "6":
            print("\n" + "-" * 55)
            print("  Full RSA Validation Test")
            print("-" * 55)
            if private_key is None:
                print("  Generating keys for test...")
                private_key, public_key = generate_rsa_keypair(2048)

            test_messages = [
                "Secure message from BIT4138",
                "Advanced Cryptography Unit",
                "RSA validation test passed",
            ]
            all_passed = True
            for msg in test_messages:
                enc = rsa_encrypt(msg, public_key)
                dec = rsa_decrypt(enc, private_key)
                status = "PASS" if dec == msg else "FAIL"
                if dec != msg:
                    all_passed = False
                print(f"  [{status}] '{msg}'")

            print(f"\n  Overall: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")

        elif choice == "7":
            print("\n  Exiting. Goodbye!")
            break
        else:
            print("  Invalid option. Please choose 1-7.")

if __name__ == "__main__":
    main()
