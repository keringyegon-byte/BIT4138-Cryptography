"""
BIT4138 - Week 4: AES Block Cipher
Implements AES-256 encryption and decryption with key generation,
file encryption, and performance testing.
"""

import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# ── Key Generation ────────────────────────────────────────────

def generate_aes_key(key_size=256):
    """Generate a secure random AES key (128, 192, or 256 bits)"""
    key = os.urandom(key_size // 8)
    return key

def generate_iv():
    """Generate a random 128-bit Initialization Vector"""
    return os.urandom(16)

# ── AES Encryption / Decryption ───────────────────────────────

def aes_encrypt(plaintext, key):
    """AES-CBC encryption with PKCS7 padding"""
    iv = generate_iv()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext  # prepend IV for storage

def aes_decrypt(ciphertext_with_iv, key):
    """AES-CBC decryption with PKCS7 unpadding"""
    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode()

# ── File Encryption ───────────────────────────────────────────

def encrypt_file(input_path, output_path, key):
    with open(input_path, 'r') as f:
        content = f.read()
    encrypted = aes_encrypt(content, key)
    with open(output_path, 'wb') as f:
        f.write(encrypted)
    return len(encrypted)

def decrypt_file(input_path, key):
    with open(input_path, 'rb') as f:
        ciphertext = f.read()
    return aes_decrypt(ciphertext, key)

# ── Main ──────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("   BIT4138 Advanced Cryptography - Week 4")
    print("   AES Block Cipher Implementation")
    print("=" * 55)

    # Generate key once for the session
    key = generate_aes_key(256)
    print(f"\n  AES-256 Key Generated:")
    print(f"  {key.hex()}")
    print(f"  Key size : {len(key) * 8} bits ({len(key)} bytes)")

    while True:
        print("\n  [1] Encrypt a Message")
        print("  [2] Encrypt a File")
        print("  [3] Decrypt a File")
        print("  [4] Performance Test")
        print("  [5] Generate New Key")
        print("  [6] Exit")
        choice = input("\nSelect option: ").strip()

        if choice == "1":
            message = input("  Enter message to encrypt: ").strip()
            if not message:
                print("  Error: Message cannot be empty.")
                continue
            start = time.time()
            encrypted = aes_encrypt(message, key)
            elapsed = (time.time() - start) * 1000
            decrypted = aes_decrypt(encrypted, key)
            print(f"\n  Original  : {message}")
            print(f"  Encrypted : {encrypted.hex()[:64]}...")
            print(f"  IV        : {encrypted[:16].hex()}")
            print(f"  Decrypted : {decrypted}")
            print(f"  Time      : {elapsed:.4f} ms")
            print(f"  Match     : {'YES - Correct!' if decrypted == message else 'NO - Error'}")

        elif choice == "2":
            # Create a sample file and encrypt it
            sample_path = "sample_plaintext.txt"
            encrypted_path = "sample_encrypted.bin"
            with open(sample_path, 'w') as f:
                f.write("BIT4138 Advanced Cryptography\n")
                f.write("Week 4: AES Block Cipher Lab\n")
                f.write("This file demonstrates AES file encryption.\n")
                f.write("Student practical logbook entry.\n")
            size = encrypt_file(sample_path, encrypted_path, key)
            print(f"\n  File created      : {sample_path}")
            print(f"  Encrypted to      : {encrypted_path}")
            print(f"  Encrypted size    : {size} bytes")
            print(f"  Key (hex)         : {key.hex()[:32]}...")
            print(f"  Status            : File encrypted successfully")

        elif choice == "3":
            encrypted_path = "sample_encrypted.bin"
            if not os.path.exists(encrypted_path):
                print("  No encrypted file found. Please encrypt a file first (option 2).")
                continue
            recovered = decrypt_file(encrypted_path, key)
            print(f"\n  Decrypted content:")
            print(f"  {'-'*40}")
            for line in recovered.strip().split('\n'):
                print(f"  {line}")
            print(f"  {'-'*40}")
            print(f"  Decryption Status : SUCCESS")

        elif choice == "4":
            print(f"\n  {'Size':<12} {'Encrypt (ms)':<18} {'Decrypt (ms)':<18} {'Speed'}")
            print(f"  {'-'*60}")
            sizes = [64, 256, 1024, 4096, 16384]
            for size in sizes:
                data = "A" * size
                start = time.time()
                for _ in range(50):
                    enc = aes_encrypt(data, key)
                elapsed_enc = (time.time() - start) / 50 * 1000

                start = time.time()
                for _ in range(50):
                    aes_decrypt(enc, key)
                elapsed_dec = (time.time() - start) / 50 * 1000

                throughput = (size / 1024) / (elapsed_enc / 1000)
                print(f"  {size:<12} {elapsed_enc:<18.4f} {elapsed_dec:<18.4f} {throughput:.1f} KB/s")

        elif choice == "5":
            key = generate_aes_key(256)
            print(f"\n  New AES-256 Key:")
            print(f"  {key.hex()}")
            print(f"  Key size : {len(key) * 8} bits")

        elif choice == "6":
            print("\n  Exiting. Goodbye!")
            break
        else:
            print("  Invalid option. Please choose 1-6.")

if __name__ == "__main__":
    main()
