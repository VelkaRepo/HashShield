import socket
import hashlib
import os
import sys
import json
import time
from dotenv import load_dotenv

# --- CONFIGURATION ---
current_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(current_dir, 'src', '.env')
load_dotenv(env_path)
DAEMON_PORT = int(os.getenv("SHIELD_DAEMON_PORT", 65432))

# Whitelist untuk mitigasi False Positive (Revisi Pak Ivo)
WHITELIST_DIRS = ["C:\\Windows\\System32", "C:\\Windows\\SysWOW64"]

try:
    from src.shield_engine import download_clamav_hashes
except ImportError:
    sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
    from shield_engine import download_clamav_hashes

# --- HELPER LOGIC ---
def is_system_protected(filepath):
    """Menghindari false positive pada file inti sistem Windows."""
    return any(filepath.startswith(path) for path in WHITELIST_DIRS)

def scan_file_robust(filepath, hash_db, yara_engine):
    if not os.path.exists(filepath):
        return None
    
    # 0. WHITELIST CHECK
    if is_system_protected(filepath):
        return None

    try:
        # 1. HASH CHECK (MD5 & SHA256 in one pass)
        md5_hasher = hashlib.md5()
        sha256_hasher = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5_hasher.update(chunk)
                sha256_hasher.update(chunk)
        
        file_md5 = md5_hasher.hexdigest()
        file_sha256 = sha256_hasher.hexdigest()
        
        if file_md5 in hash_db:
            return hash_db[file_md5]
        if file_sha256 in hash_db:
            return hash_db[file_sha256]

        # 2. HEURISTIC CHECK (YARA)
        if yara_engine:
            matches = yara_engine.match(filepath)
            if matches:
                # Mengambil identitas rule pertama yang cocok
                return str(matches[0])

    except Exception as e:
        print(f"[!] Engine Error while scanning {filepath}: {e}")
        
    return None

# --- SERVER CORE ---
if __name__ == "__main__":
    print(f"--- HashShield Daemon v2.0 (Hybrid Engine) ---")
    
    # Loading database dengan stopwatch (Data untuk Bab 4)
    db_hashes, db_heuristics = download_clamav_hashes()
    
    if not db_hashes:
        print("[CRITICAL] Failed to load database engine.")
        sys.exit(1)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(('0.0.0.0', DAEMON_PORT)) # Listen on all interfaces
        server.listen(10)
        print(f"[*] Daemon Online. Listening on port {DAEMON_PORT}...")
    except Exception as e:
        print(f"[!] Socket Bind Error: {e}")
        sys.exit(1)

    while True:
        try:
            conn, addr = server.accept()
            raw_payload = conn.recv(2048).decode().strip()
            
            if not raw_payload:
                conn.close()
                continue

            client_identity = addr[0]
            target_path = ""

            # Protocol Parsing (JSON Support for Revision Pak Rofiq)
            try:
                data = json.loads(raw_payload)
                target_path = data.get("path", "")
                client_identity = data.get("hostname", addr[0])
            except json.JSONDecodeError:
                target_path = raw_payload

            # System Command: STATS
            if target_path == "STATS":
                stats = f"STATS:{len(db_hashes)}:{'Active' if db_heuristics else 'Inactive'}"
                conn.send(stats.encode())
                conn.close()
                continue

            # Core Scanning Execution
            print(f"[*] [{client_identity}] Request: {target_path}")
            
            result = scan_file_robust(target_path, db_hashes, db_heuristics)
            
            if result:
                print(f"[ALERT] Infected: {result}")
                conn.send(f"INFECTED:{result}".encode())
            else:
                conn.send(b"CLEAN")
                
            conn.close()

        except KeyboardInterrupt:
            print("\n[!] Shutting down daemon...")
            break
        except Exception as e:
            print(f"[!] Connection Error: {e}")