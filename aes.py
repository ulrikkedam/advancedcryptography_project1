from encryption import *
from decryption import *
import numpy as np
import sys
import os

#ECRTYPTION
def aes_encrypt(plaintext, key):
    """AES encryption with 10 rounds"""
    # Convert to 4x4 matrix
    state = [list(plaintext[i:i+4]) for i in range(0, 16, 4)] # AES repræsenterer data som en 4×4 matrix af bytes (kaldet state). plaintext opdeles i fire rækker og fire kolonner.
    round_key = [list(key[i:i+4]) for i in range(0, 16, 4)] #Det samme for the key.
    
    # Initial round - just add round key
    state = add_round_key(state, round_key) # Hver byte i state XOR's med tilsvarende byte i round key. Det blander nøglen ind i data for første gang.
    
    # AES er en Substitution–Permutation Network (SPN), der arbejder i runder med transformationer af en 4×4 byte-matrix (state).
    # 9 main rounds with all transformations (last round omits MixColumns).
    for round in range(9):
        state = sub_bytes(state) # Hver state byte erstattes med en tilsvarende byte fra S-Boxen. Den giver ikke-lineær substitution, der øger sikkerheden. Eksempelvis a4. Så finder du a4's værdi i S-boxen og erstatter.
        state = shift_rows(state) # Skubber rækkerne i statem-matrixen mod venstre med forskellig offset (række 0 uændret, række 1 skubbes 1 til venstre, osv.). Det spreder byte-positionerne.
        state = mix_columns(state) # Hver kolonne i state betragtes om et polynomium over GF(2^8). Vi bruger funktionen xtime(a) til at udføre multiplikation mod det irreducible polynomium x^8 + x^4 + x^3 + x + 1.
        state = add_round_key(state, round_key) # Hver state byte XOR's med tilsvarende byte i round key. Det blander nøglen ind i data for denne runde.
    
    # Final round (no MixColumns).
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_key)
    
    # Convert matrix back to bytes
    return bytes([state[i][j] for i in range(4) for j in range(4)]) # Konverterer den 4x4 matrix tilbage til en byte-streng (16 bytes) (krypteret data). aes_encrypt returnerer denne byte-streng.

#DECRYPTION
def aes_decrypt(ciphertext, key):
    """AES decryption with 10 rounds"""
    # AES’ data behandles som en state matrix med 4 rækker og 4 kolonner (16 bytes = 128 bit).
    state = [list(ciphertext[i:i+4]) for i in range(0, 16, 4)] # Du konverterer plaintext til netop sådan en 4×4 byte-matrix.
    round_key = [list(key[i:i+4]) for i in range(0, 16, 4)] #Det samme for the key.
    
    # Initial round (inverse of final encryption round)
    state = add_round_key(state, round_key) # Starter med at fjerne rundnøglen ved at anvende add_round_key (XOR operation).
    state = InvShiftRows(state) # Anvender den inverse ShiftRows transformation for at gendanne de oprindelige rækkepositioner.
    state = InvSubBytes(state) # Anvender den inverse S-Box substitution for at gendanne de oprindelige byte-værdier.
    
    # 9 main rounds with all inverse transformations
    for round in range(9):
        state = add_round_key(state, round_key) # Først fjerner vi rundnøglen ved at anvende add_round_key (XOR operation).
        state = InvMixColumns(state) # Bruger multiplikation i GF(2^8) med den inverse matrix for at gendanne de oprindelige kolonner.
        state = InvShiftRows(state) # Skubber rækkerne til højre i stedet for venstre for at gendanne de oprindelige positioner.
        state = InvSubBytes(state) # Anvender den inverse S-Box substitution for at gendanne de oprindelige byte-værdier.
    
    # Final round - just add round key
    state = add_round_key(state, round_key) # Den sidste nøgle fjernes og gendanner den oprindelige plaintext.
    
    # Convert matrix back to bytes
    return bytes([state[i][j] for i in range(4) for j in range(4)]) # Konverterer den 4x4 matrix tilbage til en byte-streng (16 bytes) (dekrypteret data). aes_decrypt returnerer denne byte-streng.

if __name__ == "__main__":
    # Check command line arguments
    if len(sys.argv) < 2:
        print("Usage: python aes.py [-e|-d] <plaintext/ciphertext> <key>")
        print("  -e : encryption mode")
        print("  -d : decryption mode")
        sys.exit(1)
    
    mode = sys.argv[1] # Listen af argumenter og vælg mellem kryptering og dekryptering (brugerens input - altså -e eller -d).
    
    if mode == '-e':
        # Encryption mode
        if len(sys.argv) < 3:
            print("Usage: python aes.py -e <plaintext> <key>")
            sys.exit(1)
        
        plaintext = sys.argv[2].encode() # "hej verden" bliver til b'hej verden' (bytes).

        # If the user pass the key 
        if len(sys.argv) > 3:
            key = sys.argv[3].encode() # “secretkey1” bliver til b’secretkey1’ (bytes).
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
        if len(key) < 16: # AES kan kun arbejde med 16-byte blokke
            key = key + b' ' * (16 - len(key))
        elif len(key) > 16:
            key = key[:16]
        
        print("Plaintext:", plaintext)
        encrypted = aes_encrypt(plaintext, key) # Kald til vores AES implementering (vores version af Reijndael).
        print("Encrypted (hex):", encrypted.hex()) # Udskriver den krypterede tekst i hexadecimal format.
        
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