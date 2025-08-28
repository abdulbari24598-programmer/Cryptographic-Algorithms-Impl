import rsa
import os

# Function to generate and save RSA keys
def generate_and_save_keys(public_key_file, private_key_file):
    public_key, private_key = rsa.newkeys(2048)

    # Saving public key
    with open(public_key_file, 'wb') as pub_file:
        pub_file.write(public_key.save_pkcs1('PEM'))
    
    # Saving private key
    with open(private_key_file, 'wb') as priv_file:
        priv_file.write(private_key.save_pkcs1('PEM'))

    print(f"Keys generated and saved: {public_key_file}, {private_key_file}")

# Loading Publci key
def load_public_key(public_key_file):
    with open(public_key_file, 'rb') as pub_file:
        public_key_data = pub_file.read()
    return rsa.PublicKey.load_pkcs1(public_key_data, 'PEM')

# Private key
def load_private_key(private_key_file):
    with open(private_key_file, 'rb') as priv_file:
        private_key_data = priv_file.read()
    return rsa.PrivateKey.load_pkcs1(private_key_data, 'PEM')

# Encrypt
def rsa_encrypt_file(input_file, output_file, public_key):
    with open(input_file, 'rb') as f:
        data = f.read()

    encrypted_data = []
    chunk_size = 190  
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        encrypted_chunk = rsa.encrypt(chunk, public_key)
        encrypted_data.append(encrypted_chunk)
    
    with open(output_file, 'wb') as f:
        for encrypted_chunk in encrypted_data:
            f.write(encrypted_chunk)

# decrypt 
def rsa_decrypt_file(input_file, output_file, private_key):
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = b""
    chunk_size = 256  # 2048-bit gives 256 chunks

    for i in range(0, len(encrypted_data), chunk_size):
        encrypted_chunk = encrypted_data[i:i + chunk_size]
        
        try:
            decrypted_chunk = rsa.decrypt(encrypted_chunk, private_key)
            decrypted_data += decrypted_chunk
            print(f"Decrypted chunk {i//chunk_size + 1}: {len(decrypted_chunk)} bytes")
        except rsa.DecryptionError as e:
            print(f"Decryption failed on chunk {i//chunk_size + 1}: {e}")
            break  # Stop decryption if one chunk fails
    
    if decrypted_data:
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        print(f"Decryption successful. Decrypted file saved as {output_file}.")
    else:
        print("Decryption failed, no data written to file.")

# Asking user for action and file type
action = input("Do you want to encrypt or decrypt? (Enter 'e' or 'd'): ").strip().lower()
file_type = input("Is it a text file or image file? (Enter 'text' or 'image'): ").strip().lower()

# File paths
input_file = input("Enter the input file path: ")
if file_type == 'text':
    encrypted_file = 'encrypted_text_rsa.bin'
    decrypted_file = 'decrypted_text_rsa.txt'
else:
    encrypted_file = 'encrypted_image_rsa.bin'
    decrypted_file = 'decrypted_image_rsa.png'

# Key file paths for demo prupose in rela wordl we would share keys
public_key_file = 'rsa_public_key.pem'
private_key_file = 'rsa_private_key.pem'

# Check if the keys already exist
if not os.path.exists(public_key_file) or not os.path.exists(private_key_file):
    print("Keys not found, generating new RSA keys.")
    generate_and_save_keys(public_key_file, private_key_file)
else:
    print("Keys found, loading from files.")

# Load keys
public_key = load_public_key(public_key_file)
private_key = load_private_key(private_key_file)

# Encrypt or Decrypt based on user choice
if action == 'e':
    rsa_encrypt_file(input_file, encrypted_file, public_key)
    print(f"File encrypted successfully and saved as {encrypted_file}.")
elif action == 'd':
    rsa_decrypt_file(input_file, decrypted_file, private_key)
else:
    print("Invalid action. Please select proper option!!")
