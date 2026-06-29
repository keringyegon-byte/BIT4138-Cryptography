"""
BIT4138 - Week 8: PKI, Asymmetric Ciphers and Diffie-Hellman
Implements Diffie-Hellman key exchange, PKI certificate inspection
using OpenSSL, and a full secure communication demo using DH + AES.
"""

import os
import subprocess
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.backends import default_backend

# ── Diffie-Hellman Key Exchange ───────────────────────────────

def dh_exchange(p, g, alice_private, bob_private):
    """Perform Diffie-Hellman key exchange and display all steps"""
    print(f"\n  Public Parameters:")
    print(f"  Prime (p)         : {p}")
    print(f"  Generator (g)     : {g}")
    print(f"\n  Private Keys (kept secret):")
    print(f"  Alice private (a) : {alice_private}")
    print(f"  Bob private (b)   : {bob_private}")

    # Generate public keys
    alice_public = pow(g, alice_private, p)
    bob_public = pow(g, bob_private, p)

    print(f"\n  Public Keys (exchanged openly):")
    print(f"  Alice public A = g^a mod p = {g}^{alice_private} mod {p} = {alice_public}")
    print(f"  Bob public   B = g^b mod p = {g}^{bob_private} mod {p} = {bob_public}")

    # Compute shared secrets
    alice_secret = pow(bob_public, alice_private, p)
    bob_secret = pow(alice_public, bob_private, p)

    print(f"\n  Shared Secret Computation:")
    print(f"  Alice: S = B^a mod p = {bob_public}^{alice_private} mod {p} = {alice_secret}")
    print(f"  Bob  : S = A^b mod p = {alice_public}^{bob_private} mod {p} = {bob_secret}")

    print(f"\n  Shared Secret Match : {'YES - Key exchange successful!' if alice_secret == bob_secret else 'NO - ERROR'}")
    print(f"  Shared Secret Value : {alice_secret}")
    return alice_secret

def dh_large(bits=256):
    """Demonstrate DH with large prime for real-world security"""
    # Safe prime (2048-bit would be used in practice; we use a known safe prime)
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2
    a = int.from_bytes(os.urandom(32), 'big')
    b = int.from_bytes(os.urandom(32), 'big')
    A = pow(g, a, p)
    B = pow(g, b, p)
    S_alice = pow(B, a, p)
    S_bob = pow(A, b, p)
    shared = S_alice.to_bytes(256, 'big')[:32]  # 256-bit key
    print(f"  Large DH public key A (hex, first 32 chars): {hex(A)[:32]}...")
    print(f"  Large DH public key B (hex, first 32 chars): {hex(B)[:32]}...")
    print(f"  Shared secret (first 32 hex chars)         : {shared.hex()[:32]}...")
    print(f"  Keys match: {'YES' if S_alice == S_bob else 'NO'}")
    return shared

# ── PKI Certificate Inspection ────────────────────────────────

def inspect_certificate():
    """Generate a self-signed certificate and inspect it using OpenSSL"""
    print("  Generating RSA key and self-signed certificate...")
    # Generate key
    r1 = subprocess.run(["openssl","genrsa","-out","demo_key.pem","2048"],
                        capture_output=True,text=True)
    if r1.returncode != 0:
        print(f"  Error generating key: {r1.stderr[:100]}")
        return

    # Generate CSR
    r2 = subprocess.run(["openssl","req","-new","-key","demo_key.pem",
                         "-out","demo_csr.pem","-subj",
                         "/C=KE/ST=Nairobi/L=Nairobi/O=BIT4138/CN=eddy.kering"],
                        capture_output=True,text=True)

    # Self-sign
    r3 = subprocess.run(["openssl","x509","-req","-days","365",
                         "-in","demo_csr.pem","-signkey","demo_key.pem",
                         "-out","demo_cert.pem"],
                        capture_output=True,text=True)

    # Inspect
    r4 = subprocess.run(["openssl","x509","-in","demo_cert.pem","-text","-noout"],
                        capture_output=True,text=True)

    if r4.returncode == 0:
        lines = r4.stdout.split('\n')
        for line in lines:
            if any(kw in line for kw in ['Issuer','Subject','Not Before','Not After','Public Key','Signature Alg','Serial']):
                print(f"  {line.strip()}")
        print("\n  Certificate files saved: demo_key.pem, demo_cert.pem")
    else:
        print(f"  Error: {r4.stderr[:200]}")

# ── DH + AES Secure Communication ────────────────────────────

def aes_encrypt_with_key(plaintext, key_bytes):
    key = key_bytes[:32].ljust(32, b'\x00')
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return iv + ct

def aes_decrypt_with_key(ct_with_iv, key_bytes):
    key = key_bytes[:32].ljust(32, b'\x00')
    iv, ct = ct_with_iv[:16], ct_with_iv[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()

def full_secure_demo(message):
    """DH key exchange then AES encryption using shared secret"""
    print(f"  Message to send securely: '{message}'")
    print(f"\n  Step 1: Diffie-Hellman key exchange...")
    p, g = 23, 5
    a, b = 6, 15
    alice_public = pow(g, a, p)
    bob_public = pow(g, b, p)
    shared = pow(bob_public, a, p)
    print(f"  Shared secret = {shared}")
    key = shared.to_bytes(32, 'big')

    print(f"\n  Step 2: Alice encrypts message with AES using shared secret...")
    ciphertext = aes_encrypt_with_key(message, key)
    print(f"  Ciphertext (hex): {ciphertext.hex()[:48]}...")

    print(f"\n  Step 3: Bob decrypts using the same shared secret...")
    decrypted = aes_decrypt_with_key(ciphertext, key)
    print(f"  Decrypted message: '{decrypted}'")
    print(f"\n  Secure communication: {'SUCCESS' if decrypted == message else 'FAILED'}")

# ── Main ──────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("   BIT4138 Advanced Cryptography - Week 8")
    print("   PKI, Asymmetric Ciphers and Diffie-Hellman")
    print("=" * 55)

    while True:
        print("\n  [1] Diffie-Hellman Key Exchange (textbook example)")
        print("  [2] Diffie-Hellman with Large Prime (real-world)")
        print("  [3] PKI - Generate and Inspect Certificate (OpenSSL)")
        print("  [4] Full Secure Communication Demo (DH + AES)")
        print("  [5] NP-Completeness Demo (Discrete Log difficulty)")
        print("  [6] Exit")
        choice = input("\nSelect option: ").strip()

        if choice == "1":
            print("\n" + "-"*55)
            print("  Diffie-Hellman Key Exchange")
            print("-"*55)
            p = int(input("  Enter prime p (default 23): ").strip() or "23")
            g = int(input("  Enter generator g (default 5): ").strip() or "5")
            a = int(input("  Alice private key (default 6): ").strip() or "6")
            b = int(input("  Bob private key (default 15): ").strip() or "15")
            dh_exchange(p, g, a, b)

        elif choice == "2":
            print("\n" + "-"*55)
            print("  Diffie-Hellman with Large Prime (2048-bit)")
            print("-"*55)
            print("  Using RFC 3526 2048-bit safe prime...")
            start = time.time()
            shared = dh_large()
            print(f"  Computation time: {(time.time()-start)*1000:.2f} ms")

        elif choice == "3":
            print("\n" + "-"*55)
            print("  PKI - Generate RSA Key + Self-Signed Certificate")
            print("-"*55)
            inspect_certificate()

        elif choice == "4":
            print("\n" + "-"*55)
            print("  Full Secure Communication Demo")
            print("-"*55)
            msg = input("  Enter message to send securely: ").strip() or "Hello Bob, this message is encrypted!"
            print()
            full_secure_demo(msg)

        elif choice == "5":
            print("\n" + "-"*55)
            print("  Discrete Logarithm Difficulty Demo")
            print("-"*55)
            p, g = 23, 5
            print(f"  Public: p={p}, g={g}")
            for a in [3, 6, 11, 15]:
                pub = pow(g, a, p)
                print(f"  Private a={a:<3} -> Public A = {g}^{a} mod {p} = {pub:<4}  [finding a from {pub} requires solving discrete log]")
            print(f"\n  With large primes (2048-bit), brute-forcing this")
            print(f"  would take longer than the age of the universe.")

        elif choice == "6":
            print("\n  Exiting. Goodbye!")
            break
        else:
            print("  Invalid option. Please choose 1-6.")

if __name__ == "__main__":
    main()
