import base64
import hashlib
import json
import os
import socket
import sys
import time
import uuid
from dotenv import load_dotenv

# --- CONFIGURATION ---
current_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(current_dir, 'src', '.env')
load_dotenv(env_path)
DAEMON_PORT = int(os.getenv("SHIELD_DAEMON_PORT", 65432))
TEMP_DIR    = "/tmp"

WHITELIST_DIRS = ["C:\\Windows\\System32", "C:\\Windows\\SysWOW64"]

try:
    from src.shield_engine import download_clamav_hashes
except ImportError:
    sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
    from shield_engine import download_clamav_hashes


# --- HELPERS ---

def recv_full(conn):
    conn.settimeout(0.5)
    buffer = b""
    while True:
        try:
            chunk = conn.recv(65536)
            if not chunk:
                break
            buffer += chunk
            try:
                json.loads(buffer.decode())
                break
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
        except socket.timeout:
            break
    return buffer.decode().strip()


def is_system_protected(filepath):
    return any(filepath.startswith(path) for path in WHITELIST_DIRS)


def scan_file_robust(filepath, hash_db, yara_engine, ndb_map):
    if not os.path.exists(filepath):
        return None

    if is_system_protected(filepath):
        return None

    try:
        md5_hasher    = hashlib.md5()
        sha256_hasher = hashlib.sha256()

        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5_hasher.update(chunk)
                sha256_hasher.update(chunk)

        file_md5    = md5_hasher.hexdigest()
        file_sha256 = sha256_hasher.hexdigest()

        if file_md5 in hash_db:
            return hash_db[file_md5]
        if file_sha256 in hash_db:
            return hash_db[file_sha256]

        if yara_engine:
            matches = yara_engine.match(filepath)
            if matches:
                match = matches[0]
                if match.strings:
                    try:
                        var_name_with_sigil = match.strings[0].identifier
                    except AttributeError:
                        var_name_with_sigil = match.strings[0][1]

                    var_id          = var_name_with_sigil.replace('$', '')
                    real_threat_name = ndb_map.get(var_id, match.rule)
                    return real_threat_name

                return str(match.rule)

    except Exception as e:
        print(f"[!] Engine Error while scanning {filepath}: {e}")

    return None


def handle_remote_scan(data, hash_db, yara_engine, ndb_map):
    tmp_path = os.path.join(TEMP_DIR, f"hs_{uuid.uuid4().hex}.tmp")
    try:
        file_bytes = base64.b64decode(data["content"])
        with open(tmp_path, 'wb') as f:
            f.write(file_bytes)
        return scan_file_robust(tmp_path, hash_db, yara_engine, ndb_map)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


# --- SERVER CORE ---

if __name__ == "__main__":
    print("--- HashShield Daemon v2.0 (Hybrid Engine) ---")

    db_hashes, db_heuristics, ndb_map = download_clamav_hashes()

    if not db_hashes:
        print("[CRITICAL] Failed to load database engine.")
        sys.exit(1)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(('0.0.0.0', DAEMON_PORT))
        server.listen(10)
        print(f"[*] Daemon Online. Listening on port {DAEMON_PORT}...")
    except Exception as e:
        print(f"[!] Socket Bind Error: {e}")
        sys.exit(1)

    while True:
        try:
            conn, addr = server.accept()
            raw_payload = recv_full(conn)

            if not raw_payload:
                conn.close()
                continue

            client_identity = addr[0]
            target_path     = ""

            try:
                data            = json.loads(raw_payload)
                target_path     = data.get("path", "")
                client_identity = data.get("hostname", addr[0])
            except json.JSONDecodeError:
                target_path = raw_payload
                data        = {}

            if target_path == "STATS":
                stats = f"STATS:{len(db_hashes)}:{'Active' if db_heuristics else 'Inactive'}"
                conn.send(stats.encode())
                conn.close()
                continue

            print(f"[*] [{client_identity}] Request: {target_path}")

            if "content" in data:
                result = handle_remote_scan(data, db_hashes, db_heuristics, ndb_map)
            else:
                result = scan_file_robust(target_path, db_hashes, db_heuristics, ndb_map)

            if result:
                print(f"[ALERT] [{client_identity}] Infected: {result}")
                conn.send(f"INFECTED:{result}".encode())
            else:
                conn.send(b"CLEAN")

            conn.close()

        except KeyboardInterrupt:
            print("\n[!] Shutting down daemon...")
            break
        except Exception as e:
            print(f"[!] Connection Error: {e}")