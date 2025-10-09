# create_test_files.py
import os
import base64

print("Creating test files for HashShield...")

# Test strings are now stored in Base64 format to avoid static detection
EICAR_B64 = b"WDVPIVAlQEFQWzRcUFpYNVQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVEVWSVJVUy1URVNULUZJTEUhJEgrSCo="
GTUBE_B64 = b"WEpTKkM0SkRCUUFETjEuTlNCTjMqMklETkVOOkdUVUJFLVNUQU5EQVJELUFOVEktVUJFLVRFU1QtRU1BSUwqQy4zNFg="
DUMMY_THREAT_B64 = b"SEFTSEhJRUxEX0RVTU1ZX1RIUkVBVF9GSUxFXzAx"

# A dictionary of files to create -> {filename: base64_content}
files_to_create = {
    "file_tes_eicar.txt": EICAR_B64,
    "file_tes_gtube.txt": GTUBE_B64,
    "file_tes_dummy.txt": DUMMY_THREAT_B64,
}

# Safe files can remain as plain text
safe_file_content = "This is a perfectly safe test file."

print("  Creating malicious test files...")
for filename, b64_content in files_to_create.items():
    try:
        # Decode the Base64 content before writing to the file
        content = base64.b64decode(b64_content).decode('utf-8')
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"    [OK] Created: {filename}")
    except IOError as e:
        print(f"    [ERROR] Could not create {filename}: {e}")

print("  Creating benign test file...")
try:
    with open("file_tes_aman.txt", "w", encoding="utf-8") as f:
        f.write(safe_file_content)
    print(f"    [OK] Created: file_tes_aman.txt")
except IOError as e:
    print(f"    [ERROR] Could not create file_tes_aman.txt: {e}")


print("\nTest files created successfully. You are now ready to run a scan.")