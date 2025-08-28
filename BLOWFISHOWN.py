import struct

# Function to load s-boxes and p-array from files
def load_sboxes_and_parray():
    s_boxes = []
    p_array = []

    try:
        # Load P-array from file (18 32-bit integers)
        with open("sboxes/p_array.bin", "rb") as f:
            p_array = list(struct.unpack(">18I", f.read()))  # Read 18 integers (18 * 4 = 72 bytes)

        # Load S-boxes from files (4 S-boxes, each containing 256 32-bit integers)
        for i in range(4):  # 4 S-boxes
            with open(f"sboxes/sbox_{i+1}.bin", "rb") as f:
                s_boxes.append(list(struct.unpack(">256I", f.read())))  # Read 256 integers (256 * 4 = 1024 bytes per S-box)

    except Exception as e:
        print(f"Error loading sboxes and p-array: {e}")
        return None, None

    return p_array, s_boxes

# Example function for encryption (simple example with a dummy plaintext)
def blowfish_encrypt(plaintext, p_array, s_boxes):
    left, right = struct.unpack(">II", plaintext)  # Unpack the 64-bit block into two 32-bit integers

    # Ensure the values are within the 32-bit unsigned range
    left &= 0xFFFFFFFF
    right &= 0xFFFFFFFF

    for i in range(16):
        left ^= p_array[i]  # XOR with corresponding P-array value
        f = feistel_function(left, s_boxes)  # Apply the Feistel function
        right ^= f  # XOR the result with the right half

        if i != 15:  # Avoid the last swap
            left, right = right, left

    left, right = right, left  # Final swap
    return struct.pack(">II", left, right)  # Return the encrypted 64-bit block

def feistel_function(x, s_boxes):
    a = (x >> 24) & 0xFF
    b = (x >> 16) & 0xFF
    c = (x >> 8) & 0xFF
    d = x & 0xFF
    f = s_boxes[0][a] + s_boxes[1][b]
    f ^= s_boxes[2][c]
    f += s_boxes[3][d]
    return f & 0xFFFFFFFF  # Ensure the result fits in a 32-bit value

# Example plaintext for encryption (64-bit block)
def encryption_example(s_boxes, p_array):
    plaintext = b"abcdefgh"  # 64-bit block (8 bytes)
    encrypted_data = blowfish_encrypt(plaintext, p_array, s_boxes)
    print(f"Encrypted data: {encrypted_data.hex()}")

# Main execution
p_array, s_boxes = load_sboxes_and_parray()

if p_array and s_boxes:
        encryption_example(s_boxes, p_array)
else:
    print("Error: Failed to load P-array or S-boxes.")
