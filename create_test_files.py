# create_test_files.py
import os

print("Creating test files for HashShield...")

# A collection of standard and custom test strings
EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# A dictionary of files to be created -> {filename: content}
files_to_create = {
    "file_tes_eicar.txt": EICAR_STRING,
    "file_tes_aman.txt": "This is a perfectly safe test file.",
}

for filename, content in files_to_create.items():
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  [OK] Created: {filename}")
    except IOError as e:
        print(f"  [ERROR] Could not create {filename}: {e}")

print("\nTest files created successfully. You are now ready to run a scan.")