"""
BIT4138 - Week 9: RSA Cryptosystem, Miller-Rabin Primality Test
and Pollard Rho Factorization

Full RSA Security System implementing:
- RSA key generation (large primes via Miller-Rabin)
- Encryption / Decryption
- Digital signature (SHA-256 + RSA sign/verify)
- Miller-Rabin primality testing demo
"""

import random
import hashlib
import time

# ── Miller-Rabin Primality Test ───────────────────────────────

def miller_rabin(n, k=20):
    """Miller-Rabin probabilistic primality test"""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits=16):
    """Generate a random prime number of given bit length using Miller-Rabin"""
    while True:
        candidate = random.getrandbits(bits) | (1 << bits - 1) | 1
        if miller_rabin(candidate):
            return candidate

# ── Pollard Rho Factorization ─────────────────────────────────

def pollard_rho(n):
    """Pollard Rho factorization algorithm - finds one non-trivial factor"""
    if n % 2 == 0:
        return 2
    x = random.randint(2, n - 1)
    y = x
    c = random.randint(1, n - 1)
    d = 1

    def f(x):
        return (x * x + c) % n

    while d == 1:
        x = f(x)
        y = f(f(y))
        d = gcd(abs(x - y), n)

    return d if d != n else None

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# ── RSA Key Generation ────────────────────────────────────────

def mod_inverse(e, phi):
    """Extended Euclidean Algorithm for modular inverse"""
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x1, y1 = egcd(b % a, a)
        return g, y1 - (b // a) * x1, x1
    g, x, _ = egcd(e, phi)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    return x % phi

def generate_rsa_keys(bits=16):
    """Generate RSA public and private key pair"""
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    d = mod_inverse(e, phi)

    return {
        "p": p, "q": q, "n": n, "phi": phi,
        "public_key": (e, n), "private_key": (d, n)
    }

# ── RSA Encrypt / Decrypt ─────────────────────────────────────

def rsa_encrypt_char(char_code, public_key):
    e, n = public_key
    return pow(char_code, e, n)

def rsa_decrypt_char(cipher_val, private_key):
    d, n = private_key
    return pow(cipher_val, d, n)

def rsa_encrypt_message(message, public_key):
    return [rsa_encrypt_char(ord(c), public_key) for c in message]

def rsa_decrypt_message(encrypted, private_key):
    return "".join(chr(rsa_decrypt_char(c, private_key)) for c in encrypted)

# ── Digital Signature ─────────────────────────────────────────

def hash_message(message):
    """SHA-256 hash of message, reduced to fit modulus"""
    h = hashlib.sha256(message.encode()).hexdigest()
    return int(h, 16)

def sign_message(message, private_key, n):
    d, _ = private_key
    hash_val = hash_message(message) % n
    signature = pow(hash_val, d, n)
    return hash_val, signature

def verify_signature(message, signature, public_key, n):
    e, _ = public_key
    original_hash = hash_message(message) % n
    recovered_hash = pow(signature, e, n)
    return original_hash == recovered_hash, original_hash, recovered_hash

# ── Main Menu ──────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("   BIT4138 Advanced Cryptography - Week 9")
    print("   RSA Cryptosystem, Miller-Rabin & Pollard Rho")
    print("=" * 55)

    keys = None
    last_encrypted = None
    last_message = None
    last_signature = None
    last_hash = None

    while True:
        print("\n" + "=" * 33)
        print("        RSA SECURITY SYSTEM")
        print("=" * 33)
        print("  1. Generate RSA Keys")
        print("  2. Encrypt Message")
        print("  3. Decrypt Message")
        print("  4. Sign Message")
        print("  5. Verify Signature")
        print("  6. Miller-Rabin Prime Test")
        print("  7. Pollard Rho Factorization Demo")
        print("  8. Exit")
        choice = input("\nSelect option: ").strip()

        if choice == "1":
            print("\n" + "-" * 55)
            print("  RSA Key Generation")
            print("-" * 55)
            bits = input("  Enter prime bit length (default 16, max 24): ").strip()
            bits = int(bits) if bits else 16
            bits = min(bits, 24)
            print(f"\n  Generating two {bits}-bit primes using Miller-Rabin test...")
            start = time.time()
            keys = generate_rsa_keys(bits)
            elapsed = time.time() - start

            print(f"\n  Prime P          : {keys['p']}")
            print(f"  Prime Q          : {keys['q']}")
            print(f"  Modulus n        : {keys['n']}")
            print(f"  Euler Totient    : {keys['phi']}")
            print(f"  Public Key (e,n) : {keys['public_key']}")
            print(f"  Private Key(d,n) : {keys['private_key']}")
            print(f"  Generation time  : {elapsed*1000:.2f} ms")

        elif choice == "2":
            if not keys:
                print("  No keys generated yet. Please use option 1 first.")
                continue
            print("\n" + "-" * 55)
            print("  Encrypt Message")
            print("-" * 55)
            message = input("  Enter message (e.g. HELLO WORLD): ").strip() or "HELLO WORLD"
            encrypted = rsa_encrypt_message(message, keys['public_key'])
            last_encrypted = encrypted
            last_message = message

            print(f"\n  {'Char':<8}{'ASCII':<10}{'Encrypted'}")
            print(f"  {'-'*45}")
            for ch, code, enc in zip(message, [ord(c) for c in message], encrypted):
                display_ch = ch if ch != ' ' else '(space)'
                print(f"  {display_ch:<8}{code:<10}{enc}")

            print(f"\n  Original  : {message}")
            print(f"  Encrypted : {encrypted}")

        elif choice == "3":
            if not keys:
                print("  No keys generated yet. Please use option 1 first.")
                continue
            if last_encrypted is None:
                print("  No encrypted message found. Please encrypt one first (option 2).")
                continue
            print("\n" + "-" * 55)
            print("  Decrypt Message")
            print("-" * 55)
            decrypted = rsa_decrypt_message(last_encrypted, keys['private_key'])

            print(f"\n  {'Encrypted':<15}{'Decrypted ASCII':<18}{'Character'}")
            print(f"  {'-'*45}")
            for enc, ch in zip(last_encrypted, decrypted):
                display_ch = ch if ch != ' ' else '(space)'
                print(f"  {enc:<15}{ord(ch):<18}{display_ch}")

            print(f"\n  Encrypted values   : {last_encrypted}")
            print(f"  Decrypted ASCII    : {[ord(c) for c in decrypted]}")
            print(f"  Original Message   : {decrypted}")
            print(f"  Match              : {'YES - Correct!' if decrypted == last_message else 'NO - Error'}")

        elif choice == "4":
            if not keys:
                print("  No keys generated yet. Please use option 1 first.")
                continue
            print("\n" + "-" * 55)
            print("  Digital Signature - Sign Message")
            print("-" * 55)
            message = input("  Enter message to sign: ").strip() or "BIT4138 Advanced Cryptography"
            hash_val, signature = sign_message(message, keys['private_key'], keys['n'])
            last_signature = signature
            last_message = message
            last_hash = hash_val

            print(f"\n  Message          : {message}")
            print(f"  SHA-256 (full)   : {hashlib.sha256(message.encode()).hexdigest()}")
            print(f"  Original Hash    : {hash_val} (mod n)")
            print(f"  Digital Signature: {signature}")

        elif choice == "5":
            if not keys or last_signature is None:
                print("  No signature found. Please sign a message first (option 4).")
                continue
            print("\n" + "-" * 55)
            print("  Verify Signature")
            print("-" * 55)
            valid, orig_hash, recovered_hash = verify_signature(
                last_message, last_signature, keys['public_key'], keys['n'])

            print(f"\n  Message           : {last_message}")
            print(f"  Original Hash     : {orig_hash}")
            print(f"  Recovered Hash    : {recovered_hash}")
            print(f"  Result            : {'Signature Valid' if valid else 'Signature Invalid'}")

        elif choice == "6":
            print("\n" + "-" * 55)
            print("  Miller-Rabin Primality Test")
            print("-" * 55)
            test_numbers = [random.randint(10, 200) for _ in range(10)]
            print(f"\n  {'Number':<12}{'Result'}")
            print(f"  {'-'*30}")
            for num in test_numbers:
                result = "Prime" if miller_rabin(num) else "Composite"
                print(f"  {num:<12}{result}")

        elif choice == "7":
            print("\n" + "-" * 55)
            print("  Pollard Rho Factorization Demo")
            print("-" * 55)
            n_input = input("  Enter a composite number to factor (e.g. 8051): ").strip()
            n = int(n_input) if n_input else 8051
            print(f"\n  Factoring n = {n}...")
            start = time.time()
            factor = pollard_rho(n)
            elapsed = time.time() - start
            if factor:
                other = n // factor
                print(f"  Factor found : {factor}")
                print(f"  Other factor : {other}")
                print(f"  Verification : {factor} x {other} = {factor*other} ({'Correct' if factor*other==n else 'Error'})")
                print(f"  Time taken   : {elapsed*1000:.3f} ms")
            else:
                print(f"  Could not find a factor (may need to retry - n could be prime)")

        elif choice == "8":
            print("\n  Exiting. Goodbye!")
            break
        else:
            print("  Invalid option. Please choose 1-8.")

if __name__ == "__main__":
    main()
