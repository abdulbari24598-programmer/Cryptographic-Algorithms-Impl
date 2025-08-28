from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# AES requires a key of specific size (16, 24, or 32 bytes) and a block size of 16 bytes.
key = get_random_bytes(16)  # Generate a 16-byte (128-bit) key
block_size = AES.block_size  # Block size for AES is always 16 bytes

def aes_encrypt(plain_text):
    print(f"KEY FOR ENCRYPTION IS: {key}")
    cipher = AES.new(key, AES.MODE_CBC)  # Create AES cipher object with CBC mode
    iv = cipher.iv  # Initialization vector
    padded_text = pad(plain_text.encode(), block_size)  # Pad the plain text to be a multiple of block size
    encrypted_text = cipher.encrypt(padded_text)  # Encrypt the padded plain text
    return iv + encrypted_text  # Return the IV followed by the encrypted text

def aes_decrypt(encrypted_text):
    iv = encrypted_text[:block_size]  # Extract the initialization vector from the beginning
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES cipher object with the same IV
    decrypted_padded_text = cipher.decrypt(encrypted_text[block_size:])  # Decrypt the encrypted text
    decrypted_text = unpad(decrypted_padded_text, block_size)  # Unpad the decrypted text
    return decrypted_text.decode()

# Taking input from the user
plain_text = input("Enter the text to be encrypted: ")

# Encrypt
encrypted_text = aes_encrypt(plain_text)
print(f"Encrypted text (in bytes): {encrypted_text}")

# Decrypt
decrypted_text = aes_decrypt(encrypted_text)
print(f"Decrypted text: {decrypted_text}")