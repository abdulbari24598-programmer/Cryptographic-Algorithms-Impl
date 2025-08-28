import rsa
import os
import time

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

# Loading public key
def load_public_key(public_key_file):
    with open(public_key_file, 'rb') as pub_file:
        public_key_data = pub_file.read()
    return rsa.PublicKey.load_pkcs1(public_key_data, 'PEM')

# Loading private key
def load_private_key(private_key_file):
    with open(private_key_file, 'rb') as priv_file:
        private_key_data = priv_file.read()
    return rsa.PrivateKey.load_pkcs1(private_key_data, 'PEM')

# Encrypt file
def rsa_encrypt_file(input_file, output_file, public_key):
    with open(input_file, 'rb') as f:
        data = f.read()

    encrypted_data = []
    chunk_size = 190  # RSA max chunk size for 2048-bit key
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        encrypted_chunk = rsa.encrypt(chunk, public_key)
        encrypted_data.append(encrypted_chunk)
    
    with open(output_file, 'wb') as f:
        for encrypted_chunk in encrypted_data:
            f.write(encrypted_chunk)

    print(f"File encrypted successfully and saved as {output_file}.")

# Decrypt file
def rsa_decrypt_file(input_file, output_file, private_key):
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = b""
    chunk_size = 256  # RSA output size for 2048-bit key (256 bytes)

    for i in range(0, len(encrypted_data), chunk_size):
        encrypted_chunk = encrypted_data[i:i + chunk_size]
        
        # Ensure that we do not exceed the actual encrypted data length
        if len(encrypted_chunk) < chunk_size:
            print(f"Unexpected end of encrypted data at chunk {i//chunk_size + 1}")
            break
        
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

# Main execution
action = input("Do you want to encrypt or decrypt? (Enter 'e' for encrypt, 'd' for decrypt): ").strip().lower()
file_type = input("Enter the file type (text, image, video): ").strip().lower()
input_file = input("Enter the input file path: ")

# Determine file extensions and output paths based on file type
if file_type == 'text':
    encrypted_file = 'encrypted_text_rsa.bin'
    decrypted_file = 'decrypted_text_rsa.txt'
elif file_type == 'image':
    encrypted_file = 'encrypted_image_rsa.bin'
    decrypted_file = 'decrypted_image_rsa.png'
elif file_type == 'video':
    encrypted_file = 'encrypted_video_rsa.bin'
    decrypted_file = 'decrypted_video_rsa.mp4'
else:
    print("Unsupported file type. Please choose from text, image, or video.")
    exit(1)

# Key file paths
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
    start_time = time.time()*1000
    rsa_encrypt_file(input_file, encrypted_file, public_key)
    execution_time = time.time()*1000 - start_time  # Calculate execution time
    print(f"Execution time encryption: {execution_time} milli seconds")
elif action == 'd':
    start_time = time.time()*1000
    rsa_decrypt_file(input_file, decrypted_file, private_key)
    execution_time = time.time()*1000 - start_time  # Calculate execution time
    print(f"Execution time decryption: {execution_time} milli seconds")
else:
    print("Invalid action. Please select 'e' for encrypt or 'd' for decrypt.")
