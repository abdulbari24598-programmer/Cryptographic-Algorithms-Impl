from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import time

block_size = 8  # Blowfish block size is 8 bytes

# Function to save key and IV to a file
def save_key_iv(key, iv, key_file):
    with open(key_file, "wb") as f:
        f.write(key + iv)

# Function to load key and IV from a file
def load_key_iv(key_file):
    with open(key_file, "rb") as f:
        data = f.read()
        return data[:16], data[16:]

# Function to encrypt binary data using Blowfish
def blowfish_encrypt(binary_data, key_file):
    key = os.urandom(16)
    iv = os.urandom(block_size)
    cipher = Cipher(Blowfish(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(block_size * 8).padder()
    padded_data = padder.update(binary_data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    save_key_iv(key, iv, key_file)
    return encrypted_data

# Function to decrypt binary data using Blowfish
def blowfish_decrypt(encrypted_data, key_file):
    key, iv = load_key_iv(key_file)
    cipher = Cipher(Blowfish(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data

# Function to handle encryption of a file
def encrypt_file(file_path):
    file_name, file_extension = os.path.splitext(file_path)
    key_file = f"{file_name}_key.iv"

    with open(file_path, "rb") as file:
        file_data = file.read()

    encrypted_data = blowfish_encrypt(file_data, key_file)
    encrypted_file_path = f"{file_name}_encrypted{file_extension}.bf"

    with open(encrypted_file_path, "wb") as file:
        file.write(encrypted_data)

    print(f"File encrypted and saved to {encrypted_file_path}")

# Function to handle decryption of a file
def decrypt_file(file_path, file_type_option):
    file_name, file_extension = os.path.splitext(file_path)
    base_name_file = file_name.split('_')[0]
    key_file = f"{base_name_file}_key.iv"

    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = blowfish_decrypt(encrypted_data, key_file)

    decrypted_file_path = f"{base_name_file}_decrypted"
    if file_type_option == '1':
        decrypted_file_path = f"{decrypted_file_path}.txt"
    elif file_type_option == '2':
        decrypted_file_path = f"{decrypted_file_path}.png"
    elif file_type_option == '3':
        decrypted_file_path = f"{decrypted_file_path}.mp4"

    with open(decrypted_file_path, "wb") as file:
        file.write(decrypted_data)

    print(f"File decrypted and saved to {decrypted_file_path}")

# Main function to handle user interaction
def main():
    # Ask for encryption or decryption
    action = input("Choose an action: 'e' for encryption or 'd' for decryption: ").lower()

    if action not in ['e', 'd']:
        print("Invalid action. Please choose 'e' for encryption or 'd' for decryption.")
        return

    # Ask for file type
    print("Select the file type:")
    print("1. Text file")
    print("2. Image file")
    print("3. Video file")

    file_type_option = input("Enter option number (1, 2, or 3): ")
    match file_type_option:
        case '1':
            print("Selected: Text file")
        case '2':
            print("Selected: Image file")
        case '3':
            print("Selected: Video file")
        case _:
            print("Invalid option. Please select 1, 2, or 3.")
            return

    # Ask for file path
    file_path = input("Enter the file path: ")
    if not os.path.exists(file_path):
        print("File not found. Please check the path and try again.")
        return

    # Perform the selected action
    if action == 'e':
        #start_time = time.time()*1000
        encrypt_file(file_path)
        #execution_time = time.time()*1000 - start_time  # Calculate execution time
        #print(f"Execution time encryption: {execution_time} milli seconds")
    elif action == 'd':
        #start_time = time.time()*1000
        decrypt_file(file_path,file_type_option)
        #execution_time = time.time()*1000 - start_time  # Calculate execution time
        #print(f"Execution time decryption: {execution_time} milli seconds")
        #decrypt_file(file_path, file_type_option)

if __name__ == "__main__":
    main()
