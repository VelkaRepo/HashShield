import base64
import csv
import hashlib
import io
import json
import os
import secrets
import socket
import sys
import threading
import uuid
import urllib.request
import urllib.error
from datetime import datetime
from dotenv import load_dotenv
import asyncio
from aiohttp import web
import time
import sqlite3

# Thread-safe lock untuk semua SQLite writes
_db_lock = threading.Lock()

# --- CONFIGURATION ---
current_dir    = os.path.dirname(os.path.abspath(__file__))
env_path       = os.path.join(current_dir, 'src', '.env')
load_dotenv(env_path)

DAEMON_PORT    = int(os.getenv("SHIELD_DAEMON_PORT", 65432))
AUTH_TOKEN     = os.getenv("SHIELD_AUTH_TOKEN", "")
TAILSCALE_IP   = os.getenv("SHIELD_TAILSCALE_IP", "")
LOCAL_IP       = os.getenv("SHIELD_LOCAL_IP", "")
HTTP_PORT      = int(os.getenv("SHIELD_HTTP_PORT", 8080))
VT_API_KEY     = os.getenv("VIRUSTOTAL_API_KEY", "")

DB_FILE        = os.path.join(current_dir, "hashshield.db")
TEMP_DIR       = "/tmp"
TEMPLATE_DIR   = os.path.join(current_dir, 'src', 'templates')
DIST_DIR       = os.path.join(current_dir, 'dist')
CACHE_FILE     = os.path.join(current_dir, 'scan_cache.txt')

WHITELIST_DIRS = ["C:\\Windows\\System32", "C:\\Windows\\SysWOW64"]

try:
    from src.shield_engine import download_clamav_hashes
except ImportError:
    sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
    from shield_engine import download_clamav_hashes

# --- SQLITE DATABASE INITIALIZATION ---
def init_db():
    with _db_lock:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS agents (
                        hostname TEXT PRIMARY KEY, os TEXT, localIp TEXT, tailscaleIp TEXT,
                        last_heartbeat REAL, scans INTEGER DEFAULT 0, threats INTEGER DEFAULT 0, status TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS threats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, sev TEXT, name TEXT, family TEXT,
                        engine TEXT, path TEXT, agent TEXT, status TEXT, time TEXT, hash TEXT,
                        desc TEXT, mitigation TEXT, vt TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS scan_reports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, agent TEXT, scan_date TEXT,
                        duration REAL, total_scanned INTEGER, infected_count INTEGER)''')

        # Tabel auth
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id       INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS sessions (
                        token      TEXT PRIMARY KEY,
                        username   TEXT NOT NULL,
                        expires_at REAL NOT NULL)''')

        # Buat default admin jika belum ada user sama sekali
        user_count = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0:
            default_user = os.getenv("DASHBOARD_USER", "admin")
            default_pass = os.getenv("DASHBOARD_PASS", "hashshield2025")
            salt      = secrets.token_hex(16)
            pass_hash = hashlib.sha256(f"{salt}:{default_pass}".encode()).hexdigest()
            c.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                      (default_user, f"{salt}:{pass_hash}", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            print(f"[AUTH] Default admin dibuat → user: '{default_user}' | pass: '{default_pass}'")
            print(f"[AUTH] Ganti password via DASHBOARD_USER / DASHBOARD_PASS di src/.env")

        conn.commit()
        conn.close()

init_db()

def run_query(query, params=(), fetch=False):
    with _db_lock:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(query, params)
        result = None
        if fetch:
            result = [dict(row) for row in c.fetchall()]
        else:
            conn.commit()
        conn.close()
    return result

def log_threat_to_db(client_id, threat_name, engine, path, f_hash, sev="HIGH", desc="Detected by scanner."):
    vt_url = f"https://www.virustotal.com/gui/file/{f_hash}" if f_hash and f_hash != "—" else ""
    run_query("""
        INSERT INTO threats (sev, name, family, engine, path, agent, status, time, hash, desc, mitigation, vt)
        VALUES (?, ?, 'Malware Detection', ?, ?, ?, 'INFECTED', ?, ?, ?, 'Isolasi file segera.', ?)
    """, (sev, threat_name, engine, path, client_id, datetime.now().strftime("%H:%M:%S"), f_hash, desc, vt_url))
    # Menghapus penambahan threats akumulatif dari sini agar bisa di-handle di level deduplikasi

# --- NETWORK HELPERS ---

def get_active_ip():
    if TAILSCALE_IP:
        try:
            with socket.create_connection((TAILSCALE_IP, 65432), timeout=1):
                pass
        except OSError:
            pass
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((TAILSCALE_IP, 80))
            bound_ip = s.getsockname()[0]
            s.close()
            if bound_ip.startswith("100."):
                return TAILSCALE_IP
        except:
            pass
    return LOCAL_IP or "127.0.0.1"


def _check_session(request):
    """Return username jika session valid, None jika tidak."""
    token = request.cookies.get('hs_session', '')
    if not token:
        return None
    rows = run_query(
        "SELECT username FROM sessions WHERE token=? AND expires_at > ?",
        (token, time.time()), fetch=True
    )
    return rows[0]['username'] if rows else None


def start_http_server(active_ip):
    if not os.path.exists(DIST_DIR):
        print(f"[WARN] dist/ folder not found. HTTP server not started.")
        return

    # ------------------------------------------------------------------
    # AUTH MIDDLEWARE
    # ------------------------------------------------------------------
    UNPROTECTED_PATHS = {'/login', '/api/login'}

    @web.middleware
    async def auth_middleware(request, handler):
        if request.path in UNPROTECTED_PATHS:
            return await handler(request)

        username = await asyncio.to_thread(_check_session, request)
        if not username:
            # API → 401 JSON  |  Page → redirect ke /login
            if request.path.startswith('/api/'):
                return web.json_response({"error": "unauthorized"}, status=401)
            raise web.HTTPFound('/login')

        return await handler(request)

    # ------------------------------------------------------------------
    # AUTH ENDPOINTS
    # ------------------------------------------------------------------

    async def login_page(request):
        """GET /login — serve login.html"""
        login_path = os.path.join(DIST_DIR, 'login.html')
        if not os.path.exists(login_path):
            return web.Response(text="login.html not found in dist/", status=404)
        return web.FileResponse(login_path)

    async def api_login(request):
        """POST /api/login — validasi credential, set cookie session 8 jam."""
        try:
            data     = await request.post()
            username = data.get('username', '').strip()
            password = data.get('password', '').strip()

            if not username or not password:
                raise web.HTTPFound('/login?error=empty')

            users = run_query(
                "SELECT password_hash FROM users WHERE username=?",
                (username,), fetch=True
            )
            if not users:
                raise web.HTTPFound('/login?error=invalid')

            stored   = users[0]['password_hash']        # format: "salt:hash"
            salt, stored_hash = stored.split(':', 1)
            computed = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()

            if computed != stored_hash:
                raise web.HTTPFound('/login?error=invalid')

            # Buat session baru
            token      = secrets.token_hex(32)
            expires_at = time.time() + (8 * 3600)       # 8 jam

            run_query(
                "INSERT INTO sessions (token, username, expires_at) VALUES (?, ?, ?)",
                (token, username, expires_at)
            )
            # Bersihkan session expired lama
            run_query("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))

            print(f"[AUTH] Login sukses — user: '{username}'")

            response = web.HTTPFound('/')
            response.set_cookie(
                'hs_session', token,
                max_age=8 * 3600,
                httponly=True,
                samesite='Strict'
            )
            raise response

        except web.HTTPException:
            raise
        except Exception as e:
            print(f"[AUTH] Login error: {e}")
            raise web.HTTPFound('/login?error=invalid')

    async def api_logout(request):
        """POST /api/logout — hapus session, redirect ke /login."""
        token = request.cookies.get('hs_session', '')
        if token:
            run_query("DELETE FROM sessions WHERE token=?", (token,))
            print(f"[AUTH] Logout — token invalidated")
        response = web.HTTPFound('/login')
        response.del_cookie('hs_session')
        raise response

    # ------------------------------------------------------------------
    # DATA API ENDPOINTS
    # ------------------------------------------------------------------

    async def api_get_agents(request):
        agents = run_query("SELECT * FROM agents", fetch=True)
        now = time.time()
        for a in agents:
            if now - a['last_heartbeat'] > 15:
                a['status'] = 'offline'
        return web.json_response(agents)

    async def api_get_threats(request):
        threats = run_query(
            "SELECT * FROM threats GROUP BY hash ORDER BY id DESC LIMIT 1000",
            fetch=True
        )
        return web.json_response(threats)

    async def api_get_activity(request):
        query = """
            SELECT
                date(scan_date) as date_val,
                SUM(total_scanned) as total,
                SUM(infected_count) as infected
            FROM scan_reports
            WHERE date(scan_date) >= date('now', '-6 days')
            GROUP BY date(scan_date)
            ORDER BY date(scan_date) ASC
        """
        rows = run_query(query, fetch=True)
        labels, clean_data, threat_data = [], [], []
        for row in rows:
            labels.append(row['date_val'][5:])
            infected = row['infected'] or 0
            total    = row['total'] or 0
            threat_data.append(infected)
            clean_data.append(total - infected)
        return web.json_response({"labels": labels, "clean": clean_data, "threats": threat_data})

    async def api_heartbeat(request):
        try:
            data = await request.json()
            h    = data.get('hostname', 'Unknown')
            run_query("""
                INSERT INTO agents (hostname, os, localIp, tailscaleIp, last_heartbeat, status)
                VALUES (?, ?, ?, ?, ?, 'online')
                ON CONFLICT(hostname) DO UPDATE SET
                os=excluded.os, localIp=excluded.localIp, tailscaleIp=excluded.tailscaleIp,
                last_heartbeat=excluded.last_heartbeat, status='online'
            """, (h, data.get('os', ''), data.get('localIp', ''), data.get('tailscaleIp', ''), time.time()))
            return web.json_response({"status": "ok"})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def api_event(request):
        try:
            t = await request.json()
            run_query("""
                INSERT INTO threats (sev, name, family, engine, path, agent, status, time, hash, desc, mitigation, vt)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (t.get('sev'), t.get('name'), t.get('family'), t.get('engine'), t.get('path'),
                  t.get('agent'), t.get('status'), t.get('time'), t.get('hash'), t.get('desc'),
                  t.get('mitigation'), t.get('vt')))
            return web.json_response({"status": "logged"})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def index_handler(request):
        return web.FileResponse(os.path.join(DIST_DIR, 'dashboard.html'))

    # ------------------------------------------------------------------
    # APP SETUP
    # ------------------------------------------------------------------
    app = web.Application(middlewares=[auth_middleware])
    app.router.add_get('/login',         login_page)
    app.router.add_post('/api/login',    api_login)
    app.router.add_post('/api/logout',   api_logout)
    app.router.add_get('/api/agents',    api_get_agents)
    app.router.add_get('/api/activity',  api_get_activity)
    app.router.add_get('/api/threats',   api_get_threats)
    app.router.add_post('/api/heartbeat', api_heartbeat)
    app.router.add_post('/api/event',    api_event)
    app.router.add_get('/',              index_handler)
    app.router.add_static('/',           path=DIST_DIR, name='static')

    def run_server():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        runner = web.AppRunner(app)
        loop.run_until_complete(runner.setup())
        site = web.TCPSite(runner, '0.0.0.0', HTTP_PORT)
        loop.run_until_complete(site.start())
        loop.run_forever()

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    print(f"[*] EDR Dashboard → http://{active_ip}:{HTTP_PORT}")
    print(f"[*] Login page  → http://{active_ip}:{HTTP_PORT}/login")


# --- PROTOCOL HELPERS ---

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


# --- VIRUSTOTAL INTEGRATION ---

def check_virustotal_sync(file_sha256):
    if not VT_API_KEY:
        return None
    
    cache = {}
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    if ':' in line:
                        h, val = line.strip().split(':', 1)
                        cache[h] = val
        except Exception:
            pass
    
    if file_sha256 in cache:
        cached_data = cache[file_sha256]
        if "|" in cached_data:
            parts = cached_data.split("|")
            is_mal_str = parts[0]
            msg = parts[1]
            vt_url = parts[2] if len(parts) > 2 else ""
            
            if is_mal_str == "True":
                clean_msg = msg.replace("DANGER! ", "")
                final_msg = f"[Cached] {clean_msg}|{vt_url}" if vt_url else f"[Cached] {clean_msg}"
                return final_msg, "Cloud"
            else:
                return None
        else:
            if cached_data == 'malicious':
                return "Result from cache: malicious", "Cloud"
            return None

    url = f"https://www.virustotal.com/api/v3/files/{file_sha256}"
    req = urllib.request.Request(url, headers={"x-apikey": VT_API_KEY, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            
            is_malicious = (malicious_count > 0)
            report_msg = f"Detected by {malicious_count} vendors on VirusTotal." if is_malicious else "Clean on VirusTotal."
            vt_url = f"https://www.virustotal.com/gui/file/{file_sha256}"
            
            try:
                with open(CACHE_FILE, 'a', encoding='utf-8') as f:
                    f.write(f"{file_sha256}:{is_malicious}|{report_msg}|{vt_url}\n")
            except:
                pass
            
            if is_malicious:
                return f"{report_msg}|{vt_url}", "Cloud"
            return None
            
    except urllib.error.HTTPError as e:
        if e.code == 404: 
            return None
    except Exception as e:
        print(f"[!] VT API Error in Daemon: {e}")
        
    return None


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

        vt_result = check_virustotal_sync(file_sha256)
        if vt_result:
            return vt_result[0], vt_result[1] 

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

        dist_data       = {"Hash": 0, "Heuristic": 0, "Cloud": 0, "Clean": clean}
        report_data     = []

        for r in results:
            is_infected  = r["infected"]
            threat       = r["detail"]
            engine_type  = r.get("engine_type", "YARA")
            status       = r.get("status", "INFECTED" if is_infected else "CLEAN")
            engine_label = "Shield Engine" if engine_type in ["HASH", "YARA"] else "Cloud Engine"

            severity       = "INFORMATIONAL"
            severity_badge = "bg-hs-info text-white"
            
            clean_threat = threat or ""
            vt_link = ""
            if "|" in clean_threat and "virustotal.com" in clean_threat:
                parts = clean_threat.split("|", 1)
                clean_threat = parts[0]
                vt_link = parts[1]

            for prefix in ["DANGER! Shield Engine Detected: ", "DANGER! Locally detected by YARA rule: ", "DANGER! ", "[Cached] "]:
                if clean_threat.startswith(prefix):
                    clean_threat = clean_threat[len(prefix):]
                    break

            if status == "QUARANTINED" or status == "DELETED":
                severity       = "REMEDIATED"
                severity_badge = "bg-hs-remediated text-white" if status == "QUARANTINED" else "bg-hs-deleted text-white"
                if engine_type == "HASH": dist_data["Hash"] += 1
                elif engine_type == "Cloud": dist_data["Cloud"] += 1
                else: dist_data["Heuristic"] += 1

            elif is_infected:
                if engine_type == "HASH":
                    severity       = "CRITICAL"
                    severity_badge = "bg-hs-critical text-white"
                    dist_data["Hash"] += 1
                elif engine_type == "Cloud":
                    severity       = "MEDIUM"
                    severity_badge = "bg-hs-medium text-dark"
                    dist_data["Cloud"] += 1
                else:
                    severity       = "HIGH"
                    severity_badge = "bg-hs-high text-white"
                    dist_data["Heuristic"] += 1

            REMEDIATED_WEIGHT = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "REMEDIATED": 3, "INFORMATIONAL": 4}

            report_data.append({
                "status":         status,
                "is_infected":    is_infected,
                "file":           r["file"],
                "client":         hostname,
                "engine":         engine_label,
                "threat":         clean_threat,
                "vt_url":         vt_link,
                "severity":       severity,
                "severity_badge": severity_badge,
                "_weight":        REMEDIATED_WEIGHT.get(severity, 4)
            })

        report_data.sort(key=lambda x: x["_weight"])

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

def check_global_cache(sha256_hash):
    if not os.path.exists(CACHE_FILE): return None
    try:
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith(sha256_hash + ":"):
                    val = line.strip().split(':', 1)[1]
                    parts = val.split('|')
                    is_mal = parts[0]
                    if is_mal == "True":
                        threat = parts[1]
                        engine = parts[2] if len(parts) > 2 else "Cloud"
                        if engine.startswith("http"): engine = "Cloud"
                        return f"INFECTED:{engine}:{threat}"
                    elif is_mal == "False":
                        return "CLEAN"
    except: pass
    return None

# --- SERVER CORE ---

if __name__ == "__main__":
    print("--- HashShield Daemon v2.0 (Hybrid Engine) ---")

    if not AUTH_TOKEN:
        print("[WARN] SHIELD_AUTH_TOKEN not set. All connections will be accepted.")
    else:
        print("[*] Token authentication enabled.")

    db_hashes, db_heuristics, ndb_map = download_clamav_hashes()

    custom_hash_file = os.path.join(current_dir, "custom_hash.db")
    if os.path.exists(custom_hash_file):
        import re 
        custom_count = 0
        with open(custom_hash_file, "r") as f:
            for line in f:
                parts = line.strip().split(maxsplit=1)
                if len(parts) >= 2:
                    custom_md5 = parts[0].lower()
                    
                    raw_filename = parts[1].strip()
                    if raw_filename.startswith('*'):
                        raw_filename = raw_filename[1:]
                        
                    platform_prefix = "Win"
                    if raw_filename.lower().endswith('.apk'):
                        platform_prefix = "Android"
                    elif raw_filename.lower().endswith(('.elf', '.sh')):
                        platform_prefix = "Linux"
                    elif raw_filename.lower().endswith(('.doc', '.pdf')):
                        platform_prefix = "Doc"

                    clean_name = re.sub(r'\.(exe|apk|elf|zip)$', '', raw_filename, flags=re.IGNORECASE)
                    
                    clean_name = re.sub(r'[^a-zA-Z0-9]', '', clean_name.title())
                    
                    authentic_label = f"{platform_prefix}.Malware.{clean_name}"
                    
                    db_hashes[custom_md5] = authentic_label
                    custom_count += 1

    if not db_hashes:
        print("[CRITICAL] Failed to load database engine.")
        sys.exit(1)

    active_ip = get_active_ip()
    print(f"[*] Active network interface: {active_ip}")
    start_http_server(active_ip)

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

            req_type = data.get("type", "")

            if req_type == "generate_report":
                print(f"[*] [{client_identity}] Report request ({data.get('format', 'html')})")
                
                # PERUBAHAN 2: Menimpa (Overwrite) total_scanned dan infected ke SQLite saat scan selesai
                total_scanned_now = len(data.get("results", []))
                infected_now = sum(1 for r in data.get("results", []) if r["infected"])
                
                # Update agent stats
                run_query("UPDATE agents SET scans = ?, threats = ? WHERE hostname = ?", 
                          (total_scanned_now, infected_now, client_identity))
                
                # Simpan histori scan report
                run_query("INSERT INTO scan_reports (agent, scan_date, duration, total_scanned, infected_count) VALUES (?, ?, ?, ?, ?)",
                          (client_identity, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), data.get("scan_duration", 0), total_scanned_now, infected_now))

                content = generate_report(data)
                conn.sendall(content.encode())
                conn.close()
                continue

            if target_path == "STATS":
                stats = f"STATS:{len(db_hashes)}:{'Active' if db_heuristics else 'Inactive'}"
                conn.send(stats.encode())
                conn.close()
                continue

            if req_type == "check_hash":
                md5_hash = data.get("md5", "")
                sha256_hash = data.get("sha256", "")
                
                if md5_hash in db_hashes:
                    log_threat_to_db(client_identity, db_hashes[md5_hash], "HASH", "Fast-Scan (Handshake)", md5_hash, "CRITICAL", "Terdeteksi seketika pada Phase-1.")
                    conn.send(f"INFECTED:HASH:{db_hashes[md5_hash]}".encode())
                    conn.close()
                    continue
                if sha256_hash in db_hashes:
                    log_threat_to_db(client_identity, db_hashes[sha256_hash], "HASH", "Fast-Scan (Handshake)", sha256_hash, "CRITICAL", "Terdeteksi seketika pada Phase-1.")
                    conn.send(f"INFECTED:HASH:{db_hashes[sha256_hash]}".encode())
                    conn.close()
                    continue
                
                cached_res = check_global_cache(sha256_hash)
                if cached_res:
                    if cached_res.startswith("INFECTED"):
                        parts = cached_res.split(":")
                        eng = parts[1] if len(parts) > 1 else "Cloud"
                        threat = parts[2] if len(parts) > 2 else "Unknown"
                        sev = "HIGH" if eng == "YARA" else "MEDIUM"
                        log_threat_to_db(client_identity, threat, eng, "Unknown (Hash Check)", sha256_hash, sev, "Terdeteksi via cache.")
                    conn.send(cached_res.encode())
                    conn.close()
                    continue
                
                conn.send(b"UNKNOWN")
                conn.close()
                continue

            print(f"[*] [{client_identity}] Request Scan: {target_path}")

            scan_result = None
            file_sha256 = data.get("sha256", "")
            
            if "content" in data:
                scan_result = handle_remote_scan(data, db_hashes, db_heuristics, ndb_map)
            else:
                scan_result = scan_file_robust(target_path, db_hashes, db_heuristics, ndb_map)

            if scan_result:
                threat_name, engine_type = scan_result
                print(f"[ALERT] [{client_identity}] Infected: {threat_name} ({engine_type})")
                
                sev = "CRITICAL" if engine_type == "HASH" else "HIGH"
                log_threat_to_db(client_identity, threat_name, engine_type, target_path, file_sha256, sev, "Deteksi mendalam via analisis payload.")
                
                if file_sha256 and engine_type != "Cloud": 
                    with open(CACHE_FILE, 'a', encoding='utf-8') as f:
                        f.write(f"{file_sha256}:True|{threat_name}|{engine_type}\n")
                        
                conn.send(f"INFECTED:{engine_type}:{threat_name}".encode())
            else:
                if file_sha256:
                    with open(CACHE_FILE, 'a', encoding='utf-8') as f:
                        f.write(f"{file_sha256}:False|Clean|None\n")
                conn.send(b"CLEAN")

            conn.close()

        except KeyboardInterrupt:
            print("\n[!] Shutting down daemon...")
            break
        except Exception as e:
            print(f"[!] Connection Error: {e}")