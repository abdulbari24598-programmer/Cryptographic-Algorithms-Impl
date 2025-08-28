import hashlib
import os


# Key size and block size for AES
BLOCK_SIZE = 16  # AES block size is fixed at 16 bytes
KEY_SIZE = 32  # AES-256 uses 32-byte keys


def pad(data):
    """
    Padding to ensure the plaintext length is a multiple of BLOCK_SIZE.
    Uses PKCS#7 padding.
    """
    padding_length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    padding = bytes([padding_length]) * padding_length
    return data + padding


def unpad(data):
    """
    Removes padding from the data after decryption.
    """
    padding_length = data[-1]
    return data[:-padding_length]


def xor_bytes(a, b):
    """
    XOR operation between two byte sequences.
    """
    return bytes(i ^ j for i, j in zip(a, b))


def aes_encrypt_block(plain_text_block, key_schedule):
    """
    Encrypt a single block (16 bytes) using AES.
    For simplicity, this is a mock AES encryption function. In a real implementation,
    you'd perform the actual AES rounds (substitution, shift rows, mix columns, etc.).
    """
    return xor_bytes(plain_text_block, key_schedule)  # Mock encryption for illustration


def aes_decrypt_block(cipher_text_block, key_schedule):
    """
    Decrypt a single block (16 bytes) using AES.
    For simplicity, this is a mock AES decryption function.
    """
    return xor_bytes(cipher_text_block, key_schedule)  # Mock decryption for illustration


def generate_key(password, salt):
    """
    Generate a key from a password using PBKDF2 (Password-Based Key Derivation Function).
    """
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, KEY_SIZE)


def encrypt_aes(plain_text, password):
    """
    Encrypt the provided plaintext using AES with a password.
    """
    # Generate salt and key
    salt = os.urandom(16)
    key = generate_key(password, salt)
    
    # Pad the plaintext to a multiple of the block size
    padded_plain_text = pad(plain_text)
    
    # Initialize IV (initialization vector)
    iv = os.urandom(BLOCK_SIZE)
    
    cipher_text = iv  # Start with IV
    previous_block = iv  # IV is used as the first previous block in CBC mode
    
    # Encrypt each block
    for i in range(0, len(padded_plain_text), BLOCK_SIZE):
        plain_text_block = padded_plain_text[i:i + BLOCK_SIZE]
        block_to_encrypt = xor_bytes(plain_text_block, previous_block)
        cipher_text_block = aes_encrypt_block(block_to_encrypt, key)
        cipher_text += cipher_text_block
        previous_block = cipher_text_block
    
    return salt + cipher_text  # Return salt and ciphertext


def decrypt_aes(cipher_text, password):
    """
    Decrypt the provided ciphertext using AES with a password.
    """
    # Extract salt and IV
    salt = cipher_text[:16]
    iv = cipher_text[16:32]
    key = generate_key(password, salt)
    cipher_text = cipher_text[32:]
    
    # Decrypt each block
    previous_block = iv
    plain_text = b""
    
    for i in range(0, len(cipher_text), BLOCK_SIZE):
        cipher_text_block = cipher_text[i:i + BLOCK_SIZE]
        decrypted_block = aes_decrypt_block(cipher_text_block, key)
        plain_text_block = xor_bytes(decrypted_block, previous_block)
        plain_text += plain_text_block
        previous_block = cipher_text_block
    
    return unpad(plain_text)


# Main logic to take user input, encrypt and decrypt
if __name__ == '__main__':
    password = input("Enter the encryption password: ")
    user_input = input("Enter the text to encrypt: ")
    
    # Convert the user input to bytes
    plain_text = user_input.encode('utf-8')
    
    print("\nOriginal plaintext:", plain_text)

    # Encrypt the plaintext
    encrypted = encrypt_aes(plain_text, password)
    print("\nEncrypted ciphertext (in bytes):", encrypted)

    # Decrypt the ciphertext
    decrypted = decrypt_aes(encrypted, password)
    print("\nDecrypted plaintext:", decrypted.decode('utf-8'))
