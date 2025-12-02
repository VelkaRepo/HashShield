import socket
import hashlib
import os
import sys
from dotenv import load_dotenv

# Configuration
current_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(current_dir, 'src', '.env')
load_dotenv(env_path)
DAEMON_PORT = int(os.getenv("SHIELD_DAEMON_PORT", 65432))

# Import Engine
try:
    from src.shield_engine import download_clamav_hashes
except ImportError:
    sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
    from shield_engine import download_clamav_hashes

# --- ADVANCED SCANNING LOGIC ---
def scan_file_robust(filepath, hash_db, yara_engine):
    """
    1. Checks MD5/SHA256 against Hash DB (Fast Lane)
    2. Checks content against NDB YARA Rules (Smart Lane)
    """
    if not os.path.exists(filepath):
        return False

    try:
        # --- 1. HASH SCAN (O(1) Speed) ---
        md5_hasher = hashlib.md5()
        sha256_hasher = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hasher.update(chunk)
                sha256_hasher.update(chunk)
        
        file_md5 = md5_hasher.hexdigest()
        file_sha256 = sha256_hasher.hexdigest()
        
        if file_md5 in hash_db:
            print(f"[ALERT] HASH MATCH (MD5): {hash_db[file_md5]}")
            return True
        if file_sha256 in hash_db:
            print(f"[ALERT] HASH MATCH (SHA256): {hash_db[file_sha256]}")
            return True

        # --- 2. HEURISTIC SCAN (NDB / YARA) ---
        if yara_engine:
            try:
                # We scan the file using the compiled NDB patterns
                matches = yara_engine.match(filepath)
                if matches:
                    # If any string matched, we have a hit
                    # Since we bundled them into one rule, we check the 'strings' that matched
                    print(f"[ALERT] HEURISTIC MATCH (NDB): Pattern detected in {filepath}")
                    return True
            except Exception as e:
                print(f"[!] YARA Scan Error: {e}")

    except Exception as e:
        print(f"Error scanning file: {e}")
        
    return False

# --- MAIN SERVER ---
if __name__ == "__main__":
    print(f"--- HashShield Daemon v2.0 (Hybrid Engine) ---")
    
    # LOAD BOTH ENGINES
    # Note: We now unpack two return values
    db_hashes, db_heuristics = download_clamav_hashes()
    
    if not db_hashes:
        print("CRITICAL: Failed to load database. Exiting.")
        sys.exit(1)

    print(f"Daemon Ready! Listening on 127.0.0.1:{DAEMON_PORT}...")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', DAEMON_PORT))
    server.listen()

    while True:
        try:
            conn, addr = server.accept()
            filepath = conn.recv(1024).decode().strip()
            
            if not filepath:
                conn.close()
                continue

            print(f"Scanning: {filepath}")

            # Use the new robust scan function
            if scan_file_robust(filepath, db_hashes, db_heuristics):
                conn.send(b"INFECTED")
            else:
                conn.send(b"CLEAN")
                
            conn.close()
        except KeyboardInterrupt:
            print("\nStopping Daemon...")
            break
        except Exception as e:
            print(f"Server Error: {e}")