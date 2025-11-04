from encryption import *
from decryption import *
import numpy as np
import sys
import os

#ECRTYPTION
def aes_encrypt(plaintext, key):
    """AES encryption with 10 rounds"""
    # Convert to 4x4 matrix
    state = [list(plaintext[i:i+4]) for i in range(0, 16, 4)]
    round_key = [list(key[i:i+4]) for i in range(0, 16, 4)]
    
    # Initial round - just add round key
    state = add_round_key(state, round_key)
    
    # 9 main rounds with all transformations
    for round in range(9):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_key)
    
    # Final round (no MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_key)
    
    # Convert matrix back to bytes
    return bytes([state[i][j] for i in range(4) for j in range(4)])

#DECRYPTION
def aes_decrypt(ciphertext, key):
    """AES decryption with 10 rounds"""
    # Convert to 4x4 matrix
    state = [list(ciphertext[i:i+4]) for i in range(0, 16, 4)]
    round_key = [list(key[i:i+4]) for i in range(0, 16, 4)]
    
    # Initial round (inverse of final encryption round)
    state = add_round_key(state, round_key)
    state = InvShiftRows(state)
    state = InvSubBytes(state)
    
    # 9 main rounds with all inverse transformations
    for round in range(9):
        state = add_round_key(state, round_key)
        state = InvMixColumns(state)
        state = InvShiftRows(state)
        state = InvSubBytes(state)
    
    # Final round - just add round key
    state = add_round_key(state, round_key)
    
    # Convert matrix back to bytes
    return bytes([state[i][j] for i in range(4) for j in range(4)])


if __name__ == "__main__":
    # Check command line arguments
    if len(sys.argv) < 2:
        print("Usage: python aes.py [-e|-d] <plaintext/ciphertext> <key>")
        print("  -e : encryption mode")
        print("  -d : decryption mode")
        sys.exit(1)
    
    mode = sys.argv[1]
    
    if mode == '-e':
        # Encryption mode
        if len(sys.argv) < 3:
            print("Usage: python aes.py -e <plaintext> <key>")
            sys.exit(1)
        
        plaintext = sys.argv[2].encode()

        # If the user pass the key 
        if len(sys.argv) > 3:
            key = sys.argv[3].encode()
        else:
            # Generate random key 
            key = os.urandom(16)
            print("Generated random key (hex):", key.hex())
        
        # Pad plaintext to 16 bytes if necessary
        if len(plaintext) < 16:
            plaintext = plaintext + b' ' * (16 - len(plaintext))
        elif len(plaintext) > 16:
            plaintext = plaintext[:16]
        
        # Pad key to 16 bytes if necessary
        if len(key) < 16:
            key = key + b' ' * (16 - len(key))
        elif len(key) > 16:
            key = key[:16]
        
        print("Plaintext:", plaintext)
        encrypted = aes_encrypt(plaintext, key)
        print("Encrypted (hex):", encrypted.hex())
        
    elif mode == '-d':
        # Decryption mode
        if len(sys.argv) < 3:
            print("Usage: python aes.py -d <ciphertext_hex> <key>")
            sys.exit(1)
        
        ciphertext_hex = sys.argv[2]
        # If the user pass the key 
        if len(sys.argv) > 3:
            key_arg = sys.argv[3]
            try:
                # If the key is in hexadecimal format
                key = bytes.fromhex(key_arg)
            except ValueError:
                # If the key is a string
                key = key_arg.encode()
        else:
            # Generate random key 
            key = os.urandom(16)
            print("Generated random key (hex):", key.hex())
                
        # Convert hex to bytes
        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
        except ValueError:
            print("Error: Invalid hex string")
            sys.exit(1)
        
        # Pad key to 16 bytes if necessary
        if len(key) < 16:
            key = key + b' ' * (16 - len(key))
        elif len(key) > 16:
            key = key[:16]
        
        print("Ciphertext (hex):", ciphertext_hex)
        decrypted = aes_decrypt(ciphertext, key)
        print("Decrypted:", decrypted.decode())
        
    else:
        print("Error: Invalid mode. Use -e for encryption or -d for decryption")
        sys.exit(1)