from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import time

def generate_and_save_keys(public_ekey_file, private_key_file):
    key = RSA.generate(2048)
    
    # Save public key
    with open(public_key_file, 'wb') as pub_file:
        pub_file.write(key.publickey().export_key())
    
    # Save private key
    with open(private_key_file, 'wb') as priv_file:
        priv_file.write(key.export_key())
    
    print(f"Keys generated and saved: {public_key_file}, {private_key_file}")

def load_public_key(public_key_file):
    with open(public_key_file, 'rb') as pub_file:
        return RSA.import_key(pub_file.read())

def load_private_key(private_key_file):
    with open(private_key_file, 'rb') as priv_file:
        return RSA.import_key(priv_file.read())

# encrypt
def pycryptodome_encrypt_file(input_file, output_file, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    
    with open(input_file, 'rb') as f:
        data = f.read()

    encrypted_data = []
    chunk_size = 190  
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        encrypted_chunk = cipher.encrypt(chunk)
        encrypted_data.append(encrypted_chunk)
    
    with open(output_file, 'wb') as f:
        for encrypted_chunk in encrypted_data:
            f.write(encrypted_chunk)

# Function to decrypt file content
def pycryptodome_decrypt_file(input_file, output_file, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = b""
    chunk_size = 256  # 2048-bit gives 256 chunks

    for i in range(0, len(encrypted_data), chunk_size):
        encrypted_chunk = encrypted_data[i:i + chunk_size]
        try:
            decrypted_chunk = cipher.decrypt(encrypted_chunk)
            decrypted_data += decrypted_chunk
            print(f"Decrypted chunk {i//chunk_size + 1}: {len(decrypted_chunk)} bytes")
        except ValueError as e:
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
    encrypted_file = 'encrypted_text_pycryptodome.bin'
    decrypted_file = 'decrypted_text_pycryptodome.txt'
else:
    encrypted_file = 'encrypted_image_pycryptodome.bin'
    decrypted_file = 'decrypted_image_pycryptodome.png'

# Key file paths
public_key_file = 'pycryptodome_public_key.pem'
private_key_file = 'pycryptodome_private_key.pem'

# Check if the keys already exist
if not os.path.exists(public_key_file) or not os.path.exists(private_key_file):
    print("Keys not found, generating new RSA keys.")
    generate_and_save_keys(public_key_file, private_key_file)
else:
    print("Keys found, loading from files.")

# Load keys
public_key = load_public_key(public_key_file)
private_key = load_private_key(private_key_file)


if action == 'e':
    start_time = time.time()*1000
    pycryptodome_encrypt_file(input_file, encrypted_file, public_key)
    execution_time = time.time()*1000 - start_time  # Calculate execution time
    print(f"Execution time encryption: {execution_time} milli seconds")
    print(f"File encrypted successfully and saved as {encrypted_file}.")
elif action == 'd':
    start_time = time.time()*1000
    pycryptodome_decrypt_file(input_file, decrypted_file, private_key)
    execution_time = time.time()*1000 - start_time  # Calculate execution time
    print(f"Execution time decryption: {execution_time} milli seconds")
    #print(f"File encrypted successfully and saved as {encrypted_file}.") 
else:
    print("Invalid action. Please select proper option!!")
