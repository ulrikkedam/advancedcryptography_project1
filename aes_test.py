from aes import aes_encrypt, aes_decrypt
import binascii

# Verify that plaintext encrypted and then decrypted returns the original plaintext.
def test_correctness():
    plaintext = b"test message1234"  # 16 bytes
    key = b"secretkey1secret"      # 16 bytes

    ciphertext = aes_encrypt(plaintext, key)
    decrypted = aes_decrypt(ciphertext, key)

    print("=== AES Correctness Test ===")
    print("Plaintext: ", plaintext)
    print("Ciphertext:", ciphertext.hex())
    print("Decrypted: ", decrypted)

    if decrypted == plaintext:
        print("Test passed: Decryption matches plaintext.\n")
    else:
        print("Test failed: Decrypted text differs!\n")

# Avalance-effect: change one bit in the message (around 50% of the output bits should change)
def test_avalanche_message():
    plaintext = b"test message1234"
    key = b"secretkey1secret"

    ciphertext1 = aes_encrypt(plaintext, key)

    modified = bytearray(plaintext)
    modified[0] ^= 0x01  # Flip én bit i første byte
    ciphertext2 = aes_encrypt(bytes(modified), key)

    diff_bits = sum(bin(a ^ b).count("1") for a, b in zip(ciphertext1, ciphertext2))

    print("=== AES Avalanche (Message) ===")
    print("Original ciphertext:", ciphertext1.hex())
    print("Modified ciphertext:", ciphertext2.hex())
    print(f"Bit differences: {diff_bits}/{len(ciphertext1)*8}\n")


# Avalance-effect: change one bit in the key (around 50% of the output bits should change)
def test_avalanche_key():
    plaintext = b"test message1234"
    key1 = bytearray(b"secretkey1secret")
    key2 = bytearray(key1)
    key2[0] ^= 0x01  # Flip én bit i første byte af nøglen

    ciphertext1 = aes_encrypt(plaintext, bytes(key1))
    ciphertext2 = aes_encrypt(plaintext, bytes(key2))

    diff_bits = sum(bin(a ^ b).count("1") for a, b in zip(ciphertext1, ciphertext2))

    print("=== AES Avalanche (Key) ===")
    print("Ciphertext (key1):", ciphertext1.hex())
    print("Ciphertext (key2):", ciphertext2.hex())
    print(f"Bit differences: {diff_bits}/{len(ciphertext1)*8}\n")


if __name__ == "__main__":
    test_correctness()
    test_avalanche_message()
    test_avalanche_key()