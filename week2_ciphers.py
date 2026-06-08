"""
BIT4138 - Week 2: Classical Ciphers
Implements Caesar Cipher and Vigenere Cipher with user input.
"""

# ── Caesar Cipher ─────────────────────────────────────────────

def caesar_encrypt(plaintext, shift):
    result = ""
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

# ── Vigenere Cipher ───────────────────────────────────────────

def vigenere_encrypt(plaintext, key):
    key = key.upper()
    result = ""
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    result = ""
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

# ── Input Validation ──────────────────────────────────────────

def validate_text(text):
    if not text or not text.strip():
        raise ValueError("Input text cannot be empty.")
    return text.strip()

def validate_shift(shift_str):
    if not shift_str.isdigit():
        raise ValueError("Shift must be a positive integer.")
    shift = int(shift_str)
    if shift < 1 or shift > 25:
        raise ValueError("Shift must be between 1 and 25.")
    return shift

def validate_key(key):
    if not key or not key.strip():
        raise ValueError("Key cannot be empty.")
    if not key.strip().isalpha():
        raise ValueError("Key must contain only letters (no spaces or numbers).")
    return key.strip()

# ── Main Menu ─────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("   BIT4138 Advanced Cryptography - Week 2")
    print("   Classical Cipher Implementation")
    print("=" * 55)

    while True:
        print("\n  [1] Caesar Cipher")
        print("  [2] Vigenere Cipher")
        print("  [3] Run Demonstration (all ciphers)")
        print("  [4] Exit")
        choice = input("\nSelect option: ").strip()

        if choice == "1":
            try:
                text = validate_text(input("Enter plaintext: "))
                shift = validate_shift(input("Enter shift (1-25): "))
                encrypted = caesar_encrypt(text, shift)
                decrypted = caesar_decrypt(encrypted, shift)
                print(f"\n  Original  : {text}")
                print(f"  Shift     : {shift}")
                print(f"  Encrypted : {encrypted}")
                print(f"  Decrypted : {decrypted}")
            except ValueError as e:
                print(f"  Input Error: {e}")

        elif choice == "2":
            try:
                text = validate_text(input("Enter plaintext: "))
                key = validate_key(input("Enter keyword (letters only): "))
                encrypted = vigenere_encrypt(text, key)
                decrypted = vigenere_decrypt(encrypted, key)
                print(f"\n  Original  : {text}")
                print(f"  Key       : {key.upper()}")
                print(f"  Encrypted : {encrypted}")
                print(f"  Decrypted : {decrypted}")
            except ValueError as e:
                print(f"  Input Error: {e}")

        elif choice == "3":
            print("\n" + "-" * 55)
            print("  DEMONSTRATION - Caesar Cipher")
            print("-" * 55)
            samples = [
                ("Hello World", 3),
                ("Advanced Cryptography", 13),
                ("BIT4138 Unit", 7),
            ]
            for text, shift in samples:
                enc = caesar_encrypt(text, shift)
                dec = caesar_decrypt(enc, shift)
                print(f"  Plaintext : {text}")
                print(f"  Shift={shift:<3} Encrypted : {enc}")
                print(f"         Decrypted : {dec}")
                print()

            print("-" * 55)
            print("  DEMONSTRATION - Vigenere Cipher")
            print("-" * 55)
            vsamples = [
                ("Hello World", "KEY"),
                ("Advanced Cryptography", "CRYPTO"),
                ("BIT4138 Unit Test", "SECRET"),
            ]
            for text, key in vsamples:
                enc = vigenere_encrypt(text, key)
                dec = vigenere_decrypt(enc, key)
                print(f"  Plaintext : {text}")
                print(f"  Key={key:<8} Encrypted : {enc}")
                print(f"           Decrypted : {dec}")
                print()

        elif choice == "4":
            print("\n  Exiting. Goodbye!")
            break
        else:
            print("  Invalid option. Please choose 1-4.")

if __name__ == "__main__":
    main()
