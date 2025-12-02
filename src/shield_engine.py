import tarfile
import io
import os
import requests
import glob
import subprocess
import time
import yara  # pip install yara-python

# --- CONFIGURATION ---
# "0" means NO LIMIT. Load EVERYTHING.
# Warning: This will consume 1.5GB+ RAM and take ~60 seconds to compile.
NDB_SIGNATURE_LIMIT = 0
CHUNK_SIZE = 8000 # Safety limit per YARA rule (Max is usually 10k)

# NEW: Direct download from your stable GitHub Release
DB_URL = "https://github.com/VelkaRepo/HashShield/releases/download/v2.0-beta/main.cvd"

def format_clamav_to_yara(hex_string):
    """
    Converts ClamAV 'Smashed' Hex to YARA 'Spaced' Hex.
    """
    if any(c in hex_string for c in "*{}-()"): 
        return None
    try:
        chunks = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
        return " ".join(chunks)
    except:
        return None

def update_database(local_path):
    """
    Forces a fresh download of the database using system wget.
    """
    print(f"[Shield Engine] Starting update from {DB_URL}...")
    
    command = [
        "wget",
        "--user-agent=Mozilla/5.0",
        "-O", local_path,
        DB_URL
    ]
    
    try:
        subprocess.run(command, check=True)
        print("[Shield Engine] Update successful!")
        return True
    except subprocess.CalledProcessError:
        print("[Shield Engine] Update failed. Check internet connection.")
        return False
    except FileNotFoundError:
        print("[Shield Engine] Error: 'wget' is not installed on this system.")
        return False

def download_clamav_hashes():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    local_db_path = os.path.join(current_dir, 'main.cvd')
    
    hash_db = {}
    
    # We will build a massive string containing MANY rules
    yara_rules_source = ""
    ndb_total_count = 0
    
    # Chunking trackers
    current_chunk_count = 0
    current_rule_index = 0
    
    # Open the first rule
    yara_rules_source += f"rule ClamAV_NDB_{current_rule_index} {{\nstrings:\n"

    # 1. CHECK / DOWNLOAD DATA
    if not os.path.exists(local_db_path):
        print("[Shield Engine] Local DB missing. Initializing first download...")
        success = update_database(local_db_path)
        if not success:
            print("[Shield Engine] CRITICAL: Could not obtain database.")
            return {}, None

    # LOAD THE FILE
    data = None
    print(f"[Shield Engine] Found local database: {local_db_path}")
    try:
        with open(local_db_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"[Shield Engine] Error reading local file: {e}")

    if data:
        try:
            tar_data = data[512:] 
            print("[Shield Engine] Parsing FULL database (This will take time)...")
            
            with tarfile.open(fileobj=io.BytesIO(tar_data), mode='r:gz') as tar:
                for member in tar.getmembers():
                    # --- HASHE (Fast) ---
                    if member.name.endswith('.hdb') or member.name.endswith('.hsb'):
                        f = tar.extractfile(member)
                        if f:
                            for line in f:
                                try:
                                    parts = line.decode('utf-8').strip().split(':')
                                    if len(parts) >= 3:
                                        hash_db[parts[0]] = parts[2]
                                except: continue

                    # --- HEURISTICS (Heavy) ---
                    if member.name.endswith('.ndb'):
                        f = tar.extractfile(member)
                        if f:
                            for line in f:
                                try:
                                    # Check Global Limit (if set)
                                    if NDB_SIGNATURE_LIMIT > 0 and ndb_total_count >= NDB_SIGNATURE_LIMIT:
                                        break
                                        
                                    parts = line.decode('utf-8').strip().split(':')
                                    if len(parts) >= 4:
                                        raw_sig = parts[3]
                                        yara_sig = format_clamav_to_yara(raw_sig)
                                        
                                        if yara_sig:
                                            # Add string to current rule
                                            yara_rules_source += f"    $s_{ndb_total_count} = {{ {yara_sig} }}\n"
                                            ndb_total_count += 1
                                            current_chunk_count += 1
                                            
                                            # CHUNKING LOGIC:
                                            # If we hit 8000 strings, close this rule and start a new one.
                                            if current_chunk_count >= CHUNK_SIZE:
                                                yara_rules_source += "\ncondition:\n    any of them\n}\n\n"
                                                
                                                current_rule_index += 1
                                                current_chunk_count = 0
                                                yara_rules_source += f"rule ClamAV_NDB_{current_rule_index} {{\nstrings:\n"
                                                
                                except: continue
                                
        except Exception as e:
            print(f"[Shield Engine] Error parsing DB: {e}")

    # Close the final rule
    yara_rules_source += "\ncondition:\n    any of them\n}"
    
    # 2. LOAD CUSTOM DBs
    custom_dbs = glob.glob(os.path.join(current_dir, "*.hdb"))
    for db_file in custom_dbs:
        try:
            with open(db_file, 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 3:
                        hash_db[parts[0]] = parts[2]
        except: pass

    # 3. COMPILE MASSIVE ENGINE
    compiled_yara = None
    if ndb_total_count > 0:
        print(f"[Shield Engine] Compiling {ndb_total_count} patterns into RAM...")
        print("[Shield Engine] (WARNING: This may freeze your system for 30-60s)")
        try:
            compiled_yara = yara.compile(source=yara_rules_source)
            print(f"[Shield Engine] HEURISTIC GOD MODE ONLINE. ({ndb_total_count} rules)")
        except yara.Error as e:
            print(f"[Shield Engine] YARA Compilation Failed: {e}")
            # Fallback: Print the error line to debug
            # print(yara_rules_source[-500:]) 
    
    print(f"[Shield Engine] Hash Engine Online. Loaded {len(hash_db)} signatures.")
    return hash_db, compiled_yara