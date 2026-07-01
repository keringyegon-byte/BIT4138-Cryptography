"""
BIT4138 - Week 9: RSA Secure Chat (Creative Challenge / Innovation Task)
Two users (Alice and Bob) exchange RSA-encrypted messages.
Bonus features: colour terminal output, save to file, timestamps, multi-user.
"""

import json
import os
import time
import random
from datetime import datetime

# ── ANSI colour codes (bonus: colour terminal output) ─────────
class C:
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    MAGENTA = '\033[95m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

# ── RSA core (re-used from week9_rsa_system) ──────────────────

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x1, y1 = egcd(b % a, a)
        return g, y1 - (b // a) * x1, x1
    g, x, _ = egcd(e, phi)
    return x % phi

def miller_rabin(n, k=20):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
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
    while True:
        c = random.getrandbits(bits) | (1 << bits - 1) | 1
        if miller_rabin(c):
            return c

def generate_keys(bits=16):
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
    return {"public": (e, n), "private": (d, n)}

def rsa_encrypt(message, public_key):
    e, n = public_key
    return [pow(ord(c), e, n) for c in message]

def rsa_decrypt(encrypted, private_key):
    d, n = private_key
    return "".join(chr(pow(c, d, n)) for c in encrypted)

# ── User registry ──────────────────────────────────────────────

USERS = {}  # name -> {"public": (e,n), "private": (d,n)}
CHAT_LOG_FILE = "secure_chat_log.txt"
CHAT_LOG_JSON = "secure_chat_log.json"

def register_user(name, bits=16):
    print(f"{C.CYAN}  Generating RSA keys for {name}...{C.END}")
    USERS[name] = generate_keys(bits)
    print(f"{C.GREEN}  {name} registered. Public key: {USERS[name]['public']}{C.END}")

def send_message(sender, recipient, plaintext):
    if recipient not in USERS:
        print(f"{C.RED}  Error: {recipient} is not registered.{C.END}")
        return None

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    encrypted = rsa_encrypt(plaintext, USERS[recipient]["public"])

    print(f"\n{C.BOLD}{C.MAGENTA}  [{timestamp}] {sender} -> {recipient}{C.END}")
    print(f"{C.YELLOW}  Plaintext  : {plaintext}{C.END}")
    print(f"{C.CYAN}  Ciphertext : {encrypted[:6]}...{C.END}")

    # Bonus: decrypt immediately by recipient to confirm delivery
    decrypted = rsa_decrypt(encrypted, USERS[recipient]["private"])
    print(f"{C.GREEN}  {recipient} decrypts -> '{decrypted}'{C.END}")
    match = decrypted == plaintext
    print(f"{C.GREEN if match else C.RED}  Integrity check: {'PASSED' if match else 'FAILED'}{C.END}")

    record = {
        "timestamp": timestamp, "sender": sender, "recipient": recipient,
        "plaintext": plaintext, "ciphertext": encrypted, "verified": match
    }
    save_to_log(record)
    return record

def save_to_log(record):
    with open(CHAT_LOG_FILE, "a") as f:
        f.write(f"[{record['timestamp']}] {record['sender']} -> {record['recipient']}\n")
        f.write(f"  Plaintext : {record['plaintext']}\n")
        f.write(f"  Ciphertext: {record['ciphertext']}\n")
        f.write(f"  Verified  : {record['verified']}\n\n")

    history = []
    if os.path.exists(CHAT_LOG_JSON):
        with open(CHAT_LOG_JSON, "r") as f:
            try:
                history = json.load(f)
            except json.JSONDecodeError:
                history = []
    history.append(record)
    with open(CHAT_LOG_JSON, "w") as f:
        json.dump(history, f, indent=2)

def view_chat_history():
    if not os.path.exists(CHAT_LOG_JSON):
        print(f"{C.YELLOW}  No chat history found yet.{C.END}")
        return
    with open(CHAT_LOG_JSON, "r") as f:
        history = json.load(f)
    print(f"\n{C.BOLD}  Chat History ({len(history)} messages){C.END}")
    print("  " + "-" * 50)
    for msg in history:
        status = f"{C.GREEN}OK{C.END}" if msg["verified"] else f"{C.RED}FAIL{C.END}"
        print(f"  [{msg['timestamp']}] {msg['sender']} -> {msg['recipient']}  [{status}]")
        print(f"    \"{msg['plaintext']}\"")

# ── Main ──────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print(f"   {C.BOLD}BIT4138 Advanced Cryptography - Week 9{C.END}")
    print("   RSA Secure Chat (Innovation Task)")
    print("=" * 55)

    while True:
        print("\n  [1] Register New User")
        print("  [2] List Registered Users")
        print("  [3] Send Encrypted Message")
        print("  [4] View Chat History")
        print("  [5] Quick Demo (Alice & Bob)")
        print("  [6] Exit")
        choice = input("\nSelect option: ").strip()

        if choice == "1":
            name = input("  Enter username: ").strip() or "User"
            register_user(name)

        elif choice == "2":
            if not USERS:
                print(f"{C.YELLOW}  No users registered yet.{C.END}")
            else:
                print(f"\n  Registered users: {list(USERS.keys())}")
                for name, keys in USERS.items():
                    print(f"  {name:<12} Public Key: {keys['public']}")

        elif choice == "3":
            if len(USERS) < 2:
                print(f"{C.YELLOW}  Need at least 2 registered users. Use option 1 first.{C.END}")
                continue
            print(f"  Available users: {list(USERS.keys())}")
            sender = input("  Sender username: ").strip()
            recipient = input("  Recipient username: ").strip()
            message = input("  Message: ").strip()
            if sender in USERS and recipient in USERS:
                send_message(sender, recipient, message)
            else:
                print(f"{C.RED}  Invalid sender or recipient.{C.END}")

        elif choice == "4":
            view_chat_history()

        elif choice == "5":
            print(f"\n{C.BOLD}  Running Quick Demo: Alice and Bob{C.END}")
            register_user("Alice")
            register_user("Bob")
            send_message("Alice", "Bob", "Hey Bob, meeting at 3pm today!")
            send_message("Bob", "Alice", "Got it, see you then!")
            send_message("Alice", "Bob", "Bring the BIT4138 assignment notes.")
            print(f"\n{C.GREEN}  Demo complete. Use option 4 to view chat history.{C.END}")

        elif choice == "6":
            print("\n  Exiting. Goodbye!")
            break
        else:
            print("  Invalid option. Please choose 1-6.")

if __name__ == "__main__":
    main()
