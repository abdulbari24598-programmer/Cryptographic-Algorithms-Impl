# Specify the filename and desired size in bytes
filename = "1mb_file.txt"
size_in_bytes = 1 * 1024 * 1024  # 1 MB in bytes

# Generate a 1MB text file
with open(filename, "w") as file:
    line = "This is a sample line of text for the 1MB file.\n"
    while file.tell() < size_in_bytes:
        file.write(line)

print(f"{filename} of size approximately 1MB has been generated.")
