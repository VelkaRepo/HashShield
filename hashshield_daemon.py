import base64
import csv
import hashlib
import io
import json
import os
import socket
import sys
import uuid
from datetime import datetime
from dotenv import load_dotenv

# --- CONFIGURATION ---
current_dir  = os.path.dirname(os.path.abspath(__file__))
env_path     = os.path.join(current_dir, 'src', '.env')
load_dotenv(env_path)
DAEMON_PORT  = int(os.getenv("SHIELD_DAEMON_PORT", 65432))
AUTH_TOKEN   = os.getenv("SHIELD_AUTH_TOKEN", "")
TEMP_DIR     = "/tmp"
TEMPLATE_DIR = os.path.join(current_dir, 'src', 'templates')

WHITELIST_DIRS = ["C:\\Windows\\System32", "C:\\Windows\\SysWOW64"]

try:
    from src.shield_engine import download_clamav_hashes
except ImportError:
    sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
    from shield_engine import download_clamav_hashes


# --- HELPERS ---

def recv_full(conn, timeout=0.1):
    conn.settimeout(timeout)
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


def is_authorized(data):
    if not AUTH_TOKEN:
        return True
    return data.get("token", "") == AUTH_TOKEN


def is_system_protected(filepath):
    return any(filepath.startswith(path) for path in WHITELIST_DIRS)


# --- SCAN ENGINE ---

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
            return hash_db[file_md5], "HASH"
        if file_sha256 in hash_db:
            return hash_db[file_sha256], "HASH"

        if yara_engine:
            matches = yara_engine.match(filepath)
            if matches:
                match = matches[0]
                if match.strings:
                    try:
                        var_name_with_sigil = match.strings[0].identifier
                    except AttributeError:
                        var_name_with_sigil = match.strings[0][1]

                    var_id           = var_name_with_sigil.replace('$', '')
                    real_threat_name = ndb_map.get(var_id, match.rule)
                    return real_threat_name, "YARA"

                return str(match.rule), "YARA"

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


# --- REPORT GENERATION ---

def generate_report(data):
    fmt         = data.get("format", "html")
    results     = data.get("results", [])
    hostname    = data.get("hostname", "Unknown")
    client_ip   = data.get("client_ip", "Unknown")
    system_info = data.get("system_info", "Unknown")
    duration    = data.get("scan_duration", 0)
    scan_time   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    total    = len(results)
    infected = sum(1 for r in results if r["infected"])
    clean    = total - infected
    speed    = round(total / duration, 2) if duration > 0 else 0

    if fmt == "html":
        return _generate_html(results, hostname, client_ip, system_info,
                              scan_time, total, infected, clean, duration, speed)
    elif fmt == "json":
        return _generate_json(results, hostname, client_ip, scan_time,
                              total, infected, clean, duration)
    elif fmt == "csv":
        return _generate_csv(results, scan_time)
    else:
        return _generate_txt(results, hostname, client_ip, scan_time,
                             total, infected, clean, duration)


def _generate_html(results, hostname, client_ip, system_info, scan_time,
                   total, infected, clean, duration, speed):
    try:
        from jinja2 import Environment, FileSystemLoader

        dist_data   = {"Hash": 0, "Heuristic": 0, "Cloud": 0, "Clean": clean}
        report_data = []

        sorted_results = sorted(results, key=lambda r: not r["infected"])

        for r in sorted_results:
            is_infected  = r["infected"]
            threat       = r["detail"]
            engine_type  = r.get("engine_type", "YARA")
            engine_label = "Shield Engine" if is_infected else "Local Engine"

            severity       = "INFORMATIONAL"
            severity_badge = "bg-hs-info text-white"

            if is_infected:
                if engine_type == "HASH":
                    severity       = "CRITICAL"
                    severity_badge = "bg-hs-critical text-white"
                    dist_data["Hash"] += 1
                else:
                    severity       = "HIGH"
                    severity_badge = "bg-hs-high text-white"
                    dist_data["Heuristic"] += 1

            report_data.append({
                "status":         "INFECTED" if is_infected else "CLEAN",
                "is_infected":    is_infected,
                "file":           r["file"],
                "client":         hostname,
                "engine":         engine_label,
                "threat":         threat,
                "severity":       severity,
                "severity_badge": severity_badge
            })

        env      = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
        template = env.get_template("report.html")

        return template.render(
            results         = report_data,
            summary         = {
                "total":     total,
                "infected":  infected,
                "clean":     clean,
                "duration":  round(duration, 2),
                "speed":     speed,
                "client":    hostname,
                "client_ip": client_ip
            },
            chart_data_json = dist_data,
            scan_time       = scan_time,
            system_info     = system_info
        )

    except Exception as e:
        return f"<html><body><h1>Report Error: {e}</h1></body></html>"


def _generate_json(results, hostname, client_ip, scan_time,
                   total, infected, clean, duration):
    output = {
        "scan_time": scan_time,
        "client":    hostname,
        "client_ip": client_ip,
        "summary":   {"total": total, "infected": infected,
                      "clean": clean, "duration": duration},
        "results":   results
    }
    return json.dumps(output, indent=2)


def _generate_csv(results, scan_time):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Scan Time", "File", "Status", "Engine", "Detail"])
    for r in results:
        writer.writerow([scan_time, r["file"],
                         "INFECTED" if r["infected"] else "CLEAN",
                         r.get("engine_type", ""), r["detail"]])
    return output.getvalue()


def _generate_txt(results, hostname, client_ip, scan_time,
                  total, infected, clean, duration):
    lines = [
        "HashShield Agent Report",
        f"{'=' * 55}",
        f"Scan Time : {scan_time}",
        f"Client    : {hostname} ({client_ip})",
        f"Scanned   : {total} | Infected: {infected} | Clean: {clean}",
        f"Duration  : {duration}s",
        f"{'=' * 55}",
        ""
    ]
    for r in sorted(results, key=lambda r: not r["infected"]):
        status = "INFECTED" if r["infected"] else "CLEAN"
        lines.append(f"[{status}] {r['file']} | {r['detail']}")
    return "\n".join(lines)


# --- SERVER CORE ---

if __name__ == "__main__":
    print("--- HashShield Daemon v2.0 (Hybrid Engine) ---")

    if not AUTH_TOKEN:
        print("[WARN] SHIELD_AUTH_TOKEN not set. All connections will be accepted.")
    else:
        print("[*] Token authentication enabled.")

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
            conn, addr  = server.accept()
            raw_payload = recv_full(conn, timeout=2.0)

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

            if not is_authorized(data):
                print(f"[!] Unauthorized connection from {addr[0]}.")
                conn.send(b"UNAUTHORIZED")
                conn.close()
                continue

            if data.get("type") == "generate_report":
                print(f"[*] [{client_identity}] Report request ({data.get('format', 'html')})")
                content = generate_report(data)
                conn.sendall(content.encode())
                conn.close()
                continue

            if target_path == "STATS":
                stats = f"STATS:{len(db_hashes)}:{'Active' if db_heuristics else 'Inactive'}"
                conn.send(stats.encode())
                conn.close()
                continue

            print(f"[*] [{client_identity}] Request: {target_path}")

            scan_result = None
            if "content" in data:
                scan_result = handle_remote_scan(data, db_hashes, db_heuristics, ndb_map)
            else:
                scan_result = scan_file_robust(target_path, db_hashes, db_heuristics, ndb_map)

            if scan_result:
                threat_name, engine_type = scan_result
                print(f"[ALERT] [{client_identity}] Infected: {threat_name} ({engine_type})")
                conn.send(f"INFECTED:{engine_type}:{threat_name}".encode())
            else:
                conn.send(b"CLEAN")

            conn.close()

        except KeyboardInterrupt:
            print("\n[!] Shutting down daemon...")
            break
        except Exception as e:
            print(f"[!] Connection Error: {e}")