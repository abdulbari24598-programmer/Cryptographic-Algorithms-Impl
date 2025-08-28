import hashlib
import time

def sha512_hash_file(input_file, output_hash_file=None):
    sha512_hash = hashlib.sha512()
    
    with open(input_file, 'rb') as f:
        # Read and hash the content in chunks to handle large files
        while chunk := f.read(4096):
            sha512_hash.update(chunk)
    
    # Generate the final hex digest
    file_hash = sha512_hash.hexdigest()
    
    # Optionally, save the hash to the output file
    if output_hash_file:
        with open(output_hash_file, 'w') as f:
            f.write(file_hash)
        print(f"SHA-512 hash generated and saved to {output_hash_file}")
    
    print(f"Hash: {file_hash}")
    return file_hash

# Function to compare a file's hash with a known hash
def compare_hash(file_path, known_hash):
    file_hash = sha512_hash_file(file_path)
    
    if file_hash == known_hash:
        print("The file's hash matches the known hash. The file is identical.")
    else:
        print("The file's hash does NOT match the known hash. The file may be altered.")

action = input("Do you want to hash or compare? (Enter 'hash' or 'compare'): ").strip().lower()
file_type = input("Is it a text file or image file? (Enter 'text' or 'image' or 'video'): ").strip().lower()

# File paths
input_file = input("Enter the input file path: ")

if file_type == 'text':
    output_hash_file = 'text_file_sha512_hash.txt'
else:
    output_hash_file = 'image_file_sha512_hash.txt'

# Perform action based on user input
if action == 'hash':
    # Hash the input file and optionally save it
    start_time = time.time()*1000
    sha512_hash_file(input_file, output_hash_file)
    execution_time = time.time()*1000 - start_time  # Calculate execution time
    print(f"Execution time encryption: {execution_time} milli seconds")

elif action == 'compare':
    known_hash_source = input("Do you have the known hash as a file or a string? (Enter 'file' or 'string'): ").strip().lower()
    
    if known_hash_source == 'file':
        known_hash_file = input("Enter the known hash file path: ")
        with open(known_hash_file, 'r') as f:
            known_hash = f.read().strip()
    elif known_hash_source == 'string':
        known_hash = input("Enter the known hash string: ").strip()
    
    else:
        print("Invalid input. Please enter 'file' or 'string'.")
        exit()
    
    # Compare the hash of the input file with the known hash
    start_time = time.time()*1000
    compare_hash(input_file, known_hash)
    execution_time = time.time()*1000 - start_time  # Calculate execution time
    print(f"Execution time decryption: {execution_time} milli seconds")

else:
    print("Invalid action. Please enter 'hash' or 'compare'.")
