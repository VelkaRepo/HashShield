import socket
import hashlib
import os
import sys
from dotenv import load_dotenv

# --- CONFIGURATION ---
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

# --- SCAN LOGIC ---
def scan_file_robust(filepath, hash_db, yara_engine):
    if not os.path.exists(filepath):
        return None

    try:
        # 1. HASH CHECK (Fast Lane)
        md5_hasher = hashlib.md5()
        sha256_hasher = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hasher.update(chunk)
                sha256_hasher.update(chunk)
        
        file_md5 = md5_hasher.hexdigest()
        file_sha256 = sha256_hasher.hexdigest()
        
        # Return nama virus yang spesifik dari database
        if file_md5 in hash_db:
            name = hash_db[file_md5]
            print(f"[ALERT] HASH MATCH (MD5): {name}")
            return name
            
        if file_sha256 in hash_db:
            name = hash_db[file_sha256]
            print(f"[ALERT] HASH MATCH (SHA256): {name}")
            return name

        # 2. HEURISTIC CHECK (Smart Lane)
        if yara_engine:
            try:
                matches = yara_engine.match(filepath)
                if matches:
                    print(f"[ALERT] HEURISTIC MATCH (NDB) in {filepath}")
                    return "Heuristic.ClamAV.NDB.Match"
            except Exception as e:
                print(f"[!] YARA Scan Error: {e}")

    except Exception as e:
        print(f"Error scanning file: {e}")
        
    return None

# --- MAIN ---
if __name__ == "__main__":
    print(f"--- HashShield Daemon v2.0 (Hybrid Engine) ---")
    
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
            request = conn.recv(1024).decode().strip()
            
            if not request:
                conn.close()
                continue

            # --- STATS HANDLER ---
            if request == "STATS":
                hash_count = len(db_hashes)
                heur_status = "Active" if db_heuristics else "Inactive"

                stats_msg = f"STATS:{hash_count}:{heur_status}"
                conn.send(stats_msg.encode())
                conn.close()
                continue
            # --------------------------

            # Standard Scanning Logic
            print(f"Scanning: {request}")
            detection_name = scan_file_robust(request, db_hashes, db_heuristics)
            
            if detection_name:
                response = f"INFECTED:{detection_name}".encode()
                conn.send(response)
            else:
                conn.send(b"CLEAN")
                
            conn.close()
        except KeyboardInterrupt:
            print("\nStopping Daemon...")
            break
        except Exception as e:
            print(f"Server Error: {e}")