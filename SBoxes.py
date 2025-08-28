import os
import struct
import random

# Function to generate and save the P-array and S-boxes
def generate_and_save_sboxes():
    # S-boxes initialization
    s_boxes = []
    for i in range(4):
        s_boxes.append([random.getrandbits(32) for _ in range(256)])  # Generate 256 entries (32-bit each)

    # P-array initialization (18 entries, each 32-bit)
    p_array = [random.getrandbits(32) for _ in range(18)]

    # Create the sboxes directory if it doesn't exist
    if not os.path.exists("sboxes"):
        os.makedirs("sboxes")

    # Save the P-array to a binary file
    with open("sboxes/p_array.bin", "wb") as f:
        for entry in p_array:
            f.write(struct.pack(">I", entry))  # Save each 32-bit entry in big-endian format

    # Save each S-box to a binary file
    for i, sbox in enumerate(s_boxes):
        with open(f"sboxes/sbox_{i+1}.bin", "wb") as f:
            for entry in sbox:
                f.write(struct.pack(">I", entry))  # Save each 32-bit entry

    print("P-array and S-boxes have been generated and saved.")

if __name__ == "__main__":
    generate_and_save_sboxes()
