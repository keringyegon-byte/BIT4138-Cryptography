"""
BIT4138 - Week 1: Environment Setup Test
Run this to confirm all tools are installed and working.
"""

import sys
import platform
import time

print("=" * 55)
print("   BIT4138 Advanced Cryptography - Week 1")
print("   Environment Setup Verification")
print("=" * 55)

# Python version
print(f"\n[1] Python Version : {sys.version}")
print(f"    Platform       : {platform.system()} {platform.release()}")

# Cryptography library
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.ciphers import Cipher
    import cryptography
    print(f"\n[2] cryptography library  : INSTALLED (v{cryptography.__version__})")
except ImportError:
    print("\n[2] cryptography library  : NOT FOUND - run: pip install cryptography")

# OpenSSL via cryptography
try:
    from cryptography.hazmat.backends import default_backend
    backend = default_backend()
    print(f"[3] OpenSSL backend       : AVAILABLE via cryptography")
except Exception as e:
    print(f"[3] OpenSSL backend       : ERROR - {e}")

# Quick encryption test
print("\n" + "-" * 55)
print("   Quick Encryption Test")
print("-" * 55)

key = Fernet.generate_key()
print(f"\nGenerated Key     : {key.decode()}")

f = Fernet(key)
message = b"BIT4138 Cryptography - Environment Test Successful!"
encrypted = f.encrypt(message)
decrypted = f.decrypt(encrypted)

print(f"Original Message  : {message.decode()}")
print(f"Encrypted         : {encrypted[:60]}...")
print(f"Decrypted         : {decrypted.decode()}")
print(f"\nEncryption Test   : {'PASSED' if decrypted == message else 'FAILED'}")
print("\n" + "=" * 55)
print("   All systems ready. Environment setup complete!")
print("=" * 55)
