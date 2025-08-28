from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import time

block_size = Blowfish.block_size  # Block size for Blowfish is typically 8 bytes

# Function to save key and IV to a file
def save_key_iv(key, iv, key_file):
    with open(key_file, "wb") as f:
        f.write(key + iv)  # Save both key and IV together

# Function to load key and IV from a file
def load_key_iv(key_file):
    with open(key_file, "rb") as f:
        data = f.read()
        return data[:16], data[16:]  # First 16 bytes are the key, the next 16 bytes are the IV

# Function to encrypt binary data using Blowfish
def blowfish_encrypt(binary_data, key_file):
    key = get_random_bytes(16)  # Generate a 16-byte (128-bit) key for Blowfish
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)  # Create Blowfish cipher object with CBC mode
    iv = cipher.iv  # Initialization vector
    padded_data = pad(binary_data, block_size)  # Pad the binary data to be a multiple of block size
    encrypted_data = cipher.encrypt(padded_data)  # Encrypt the padded binary data

    save_key_iv(key, iv, key_file)  # Save the key and IV for later decryption
    return encrypted_data  # Return only the encrypted data (IV is stored separately)

# Function to decrypt binary data using Blowfish
def blowfish_decrypt(encrypted_data, key_file):
    key, iv = load_key_iv(key_file)  # Load the key and IV from file
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)  # Create Blowfish cipher object with the loaded key and IV
    decrypted_padded_data = cipher.decrypt(encrypted_data)  # Decrypt the encrypted data
    decrypted_data = unpad(decrypted_padded_data, block_size)  # Unpad the decrypted data
    return decrypted_data

# Function to handle encryption of any file type
def encrypt_file(file_path):
    file_name, file_extension = os.path.splitext(file_path)  # Split filename and extension
    key_file = f"{file_name}_key.iv"  # Save key and IV to a separate file

    with open(file_path, "rb") as file:
        file_data = file.read()  # Read the file as binary data

    encrypted_data = blowfish_encrypt(file_data, key_file)  # Encrypt the file data

    encrypted_file_path = f"{file_name}_encrypted{file_extension}.bf"
    with open(encrypted_file_path, "wb") as file:
        file.write(encrypted_data)  # Write the encrypted data to a new file

    print(f"File encrypted and saved to {encrypted_file_path}")

# Function to handle decryption of any file type
def decrypt_file(encrypted_file_path,file_type_option):
    file_name, file_extension = os.path.splitext(encrypted_file_path)
    base_name_file = file_name.split('_')[0]
    key_file = f"{file_name.split('_')[0]}_key.iv"  # Look for the key and IV file
    
    with open(encrypted_file_path, "rb") as file:
        encrypted_data = file.read()  # Read the encrypted file as binary data

    decrypted_data = blowfish_decrypt(encrypted_data, key_file)  # Decrypt the file data
    
    decrypted_file_path = f"{base_name_file}_decrypted"

    if file_type_option == '1':
        decrypted_file_path = f"{decrypted_file_path}.txt"
    elif file_type_option == '2':
        decrypted_file_path = f"{decrypted_file_path}.png"
    elif file_type_option == '3':
        decrypted_file_path = f"{decrypted_file_path}.mp4"
    
    with open(decrypted_file_path, "wb") as file:
        file.write(decrypted_data)  # Write the decrypted data to a new file
    print(f"Before File Path {decrypted_file_path}")
    print(f"File decrypted and saved to {decrypted_file_path}")

# Main logic to choose encryption or decryption and file type based on user input
def main():
    print("Select file type for encryption or decryption:")
    print("1. Text file")
    print("2. Image file")
    print("3. Video file")

    file_type_option = input("Enter option number (1, 2, or 3): ")

    if file_type_option == '1':
        print("Selected: Text file")
    elif file_type_option == '2':
        print("Selected: Image file")
    elif file_type_option == '3':
        print("Selected: Video file")
    else:
        print("Invalid option. Please choose 1, 2, or 3.")
        return

    # Choose encryption or decryption
    option = input("Choose 'e' to encrypt or 'd' to decrypt: ").lower()
    file_path = input("Enter the path to the file: ")

    if option == 'e':
        #start_time = time.time()*1000
        encrypt_file(file_path)
        #execution_time = time.time()*1000 - start_time  # Calculate execution time
        #print(f"Execution time encryption: {execution_time} milli seconds")
    elif option == 'd':
        #start_time = time.time()*1000
        decrypt_file(file_path,file_type_option)
        #execution_time = time.time()*1000 - start_time  # Calculate execution time
        #print(f"Execution time decryption: {execution_time} milli seconds")
    else:
        print("Invalid option. Please choose 'e' to encrypt or 'd' to decrypt.")

if __name__ == "__main__":
    main()
