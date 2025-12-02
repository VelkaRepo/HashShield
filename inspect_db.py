import random
import sys
import os

# Import your own engine
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from shield_engine import download_clamav_hashes

def get_real_names():
    print("[-] Loading database...")
    db = download_clamav_hashes()
    
    # Get all unique virus names from the values
    print("[-] Picking random threats...")
    all_names = list(db.values())
    
    # Pick 20 random ones
    real_threats = random.sample(all_names, 20)
    
    print("\n--- REAL MALWARE NAMES FOUND IN YOUR DB ---")
    for name in real_threats:
        print(f"-> {name}")

if __name__ == "__main__":
    get_real_names()