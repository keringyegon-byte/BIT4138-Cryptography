"""
BIT4138 - Week 6: Substitution-Permutation Network (SPN)
Implements S-Box substitution, permutation, key mixing,
multi-round SPN encryption/decryption, and avalanche effect testing.
"""

SBOX = {0:14,1:4,2:13,3:1,4:2,5:15,6:11,7:8,8:3,9:10,10:6,11:12,12:5,13:9,14:0,15:7}
INV_SBOX = {v:k for k,v in SBOX.items()}
PBOX = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]

def substitute(block, box):
    result = 0
    for i in range(4):
        nibble = (block >> (i*4)) & 0xF
        result |= (box[nibble] << (i*4))
    return result

def permute(block, pbox):
    result = 0
    for i, pos in enumerate(pbox):
        bit = (block >> pos) & 1
        result |= (bit << i)
    return result

def inv_permute(block, pbox):
    result = 0
    for i, pos in enumerate(pbox):
        bit = (block >> i) & 1
        result |= (bit << pos)
    return result

def get_subkeys(key, rounds):
    return [(key ^ (i * 0x1234)) & 0xFFFF for i in range(rounds+1)]

def spn_encrypt(plaintext, key, rounds=3, verbose=True):
    sk = get_subkeys(key, rounds)
    s = plaintext
    if verbose: print(f"  Initial state   : {s:016b} ({s})")
    for r in range(rounds):
        s ^= sk[r]
        if verbose: print(f"  Round {r+1} key mix  : {s:016b}")
        s = substitute(s, SBOX)
        if verbose: print(f"  Round {r+1} sub      : {s:016b}")
        if r < rounds-1:
            s = permute(s, PBOX)
            if verbose: print(f"  Round {r+1} perm     : {s:016b}")
    s ^= sk[rounds]
    if verbose: print(f"  Ciphertext      : {s:016b} ({s})")
    return s

def spn_decrypt(ciphertext, key, rounds=3):
    sk = get_subkeys(key, rounds)
    s = ciphertext ^ sk[rounds]
    for r in range(rounds-1, -1, -1):
        if r < rounds-1:
            s = inv_permute(s, PBOX)
        s = substitute(s, INV_SBOX)
        s ^= sk[r]
    return s

def avalanche_test(plaintext, key, rounds=3):
    enc1 = spn_encrypt(plaintext, key, rounds, verbose=False)
    modified = plaintext ^ 1
    enc2 = spn_encrypt(modified, key, rounds, verbose=False)
    diff = bin(enc1 ^ enc2).count('1')
    pct = (diff/16)*100
    print(f"  Original  input  : {plaintext:016b} ({plaintext})")
    print(f"  Modified  input  : {modified:016b} ({modified})  [1 bit flipped]")
    print(f"  Original  cipher : {enc1:016b} ({enc1})")
    print(f"  Modified  cipher : {enc2:016b} ({enc2})")
    print(f"  Bits changed     : {diff}/16 ({pct:.1f}%)")
    print(f"  Avalanche effect : {'STRONG (>=50%)' if pct>=50 else 'MODERATE' if pct>=25 else 'WEAK'}")

def show_sbox():
    print(f"\n  {'Input':<8} {'Binary':<10} {'Output':<8} {'Binary'}")
    print(f"  {'-'*40}")
    for i in range(16):
        print(f"  {i:<8} {i:04b}      {SBOX[i]:<8} {SBOX[i]:04b}")
    print(f"\n  All outputs unique : {'YES - Secure' if len(set(SBOX.values()))==16 else 'NO - Insecure'}")

def main():
    print("=" * 55)
    print("   BIT4138 Advanced Cryptography - Week 6")
    print("   Substitution-Permutation Network (SPN)")
    print("=" * 55)

    KEY = 0b1010110011001010

    while True:
        print("\n  [1] Show S-Box Lookup Table")
        print("  [2] Demonstrate Substitution")
        print("  [3] Demonstrate Permutation")
        print("  [4] Full SPN Encryption and Decryption")
        print("  [5] Avalanche Effect Test")
        print("  [6] Exit")
        choice = input("\nSelect option: ").strip()

        if choice == "1":
            print("\n" + "-"*55)
            print("  S-Box Lookup Table")
            print("-"*55)
            show_sbox()

        elif choice == "2":
            print("\n" + "-"*55)
            print("  S-Box Substitution Demo")
            print("-"*55)
            val = int(input("  Enter a value (0-15): ") or "9") & 0xF
            out = SBOX[val]
            print(f"\n  Input         : {val}  ({val:04b})")
            print(f"  S-Box Output  : {out}  ({out:04b})")
            print(f"  Inv S-Box back: {INV_SBOX[out]}  ({INV_SBOX[out]:04b})")
            print(f"  Roundtrip OK  : {'YES' if INV_SBOX[out]==val else 'NO'}")

        elif choice == "3":
            print("\n" + "-"*55)
            print("  Permutation Demo")
            print("-"*55)
            block = int(input("  Enter 16-bit integer (e.g. 12345): ") or "12345") & 0xFFFF
            permuted = permute(block, PBOX)
            restored = inv_permute(permuted, PBOX)
            print(f"\n  Original   : {block:016b}  ({block})")
            print(f"  Permuted   : {permuted:016b}  ({permuted})")
            print(f"  Restored   : {restored:016b}  ({restored})")
            print(f"  Correct    : {'YES' if restored==block else 'NO'}")

        elif choice == "4":
            print("\n" + "-"*55)
            print("  Full SPN Encryption and Decryption")
            print("-"*55)
            plaintext = int(input("  Enter plaintext (0-65535, e.g. 9876): ") or "9876") & 0xFFFF
            print(f"\n  Key    : {KEY:016b}")
            print(f"  Rounds : 3\n")
            print("--- Encryption ---")
            ciphertext = spn_encrypt(plaintext, KEY, 3)
            print("\n--- Decryption ---")
            decrypted = spn_decrypt(ciphertext, KEY, 3)
            print(f"\n  Original  : {plaintext}")
            print(f"  Encrypted : {ciphertext}")
            print(f"  Decrypted : {decrypted}")
            print(f"  Match     : {'YES - Correct!' if decrypted==plaintext else 'NO - Error'}")

        elif choice == "5":
            print("\n" + "-"*55)
            print("  Avalanche Effect Test")
            print("-"*55)
            plaintext = int(input("  Enter plaintext (e.g. 9876): ") or "9876") & 0xFFFF
            print()
            avalanche_test(plaintext, KEY)

        elif choice == "6":
            print("\n  Exiting. Goodbye!")
            break
        else:
            print("  Invalid option. Please choose 1-6.")

if __name__ == "__main__":
    main()
