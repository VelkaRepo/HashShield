# --- Standard Library Imports ---
import argparse
import asyncio
import base64
import csv
import fnmatch
import hashlib
import io
import json
import logging
import os
import platform
import getpass
import shutil
import socket
import subprocess
import sys
import tarfile
import textwrap
import time
import zipfile
from datetime import datetime
from pathlib import Path

# --- Third-Party Imports ---
import aiohttp
import colorama
from dotenv import load_dotenv
from tqdm.asyncio import tqdm

# --- Optional Imports (Reporting) ---
try:
    from jinja2 import Environment, FileSystemLoader
    import matplotlib.pyplot as plt
    HAS_REPORTING = True
except ImportError:
    HAS_REPORTING = False

# --- Critical Imports (Engine) ---
try:
    import yara
except ImportError:
    print("\n[FATAL ERROR] 'yara-python' library not found.")
    print("Please install it by running: pip install yara-python\n")
    sys.exit(1)

# =======================================================
# 1. CONFIGURATION
# =======================================================
load_dotenv()
colorama.init(autoreset=True)

API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
API_URL = "https://www.virustotal.com/api/v3/files/"
ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/"
BLOCK_SIZE = 65536

# Load Port from .env or default to 65432
DAEMON_PORT = int(os.environ.get("SHIELD_DAEMON_PORT", 65432))

PROJECT_ROOT = Path(__file__).resolve().parent.parent
YARA_RULES_FILE = PROJECT_ROOT / "rules.yara"
CACHE_FILE = PROJECT_ROOT / "scan_cache.txt"
QUARANTINE_DIR = PROJECT_ROOT / "quarantine"
QUARANTINE_LOG = QUARANTINE_DIR / "quarantine_log.txt"
TEMP_SCAN_DIR = PROJECT_ROOT / "temp_scans"
TEMPLATE_DIR = PROJECT_ROOT / "src" / "templates"

EXCLUDED_DIRS = {'.git', '.vscode', '__pycache__', 'venv', 'env', '.venv'}
EXCLUDED_FILES = {'rules.yara', 'scan_cache.txt'}

# --- THEME CONFIGURATION (ORANGE & BLACK) ---
C_RED = colorama.Fore.RED
C_GREEN = colorama.Fore.GREEN
C_YELLOW = colorama.Fore.YELLOW
C_GREY = colorama.Fore.LIGHTBLACK_EX
C_RESET = colorama.Style.RESET_ALL
C_BRIGHT = colorama.Style.BRIGHT

if not API_KEY:
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    logging.warning(f"{C_YELLOW}WARNING: VIRUSTOTAL_API_KEY not set. Online features will be disabled.{C_RESET}")

# =======================================================
# 2. HELPER FUNCTIONS
# =======================================================
def print_banner():
    """Prints the HashShield ASCII Art Banner."""
    banner = f"""{C_YELLOW}{C_BRIGHT}
  _   _           _     _____ _     _      _     _ 
 | | | | __ _ ___| |__ / ____| |__ (_) ___| | __| |
 | |_| |/ _` / __| '_ \\\\___ \\| '_ \\| |/ _ \\ |/ _` |
 |  _  | (_| \\__ \\ | | |___) | | | | |  __/ | (_| |
 |_| |_|\\__,_|___/_| |_|_____/|_| |_|_|\\___|_|\\__,_|
                                                     
    {C_RESET}{C_GREY}[ {C_YELLOW}HashShield v2.0{C_GREY} | {C_YELLOW}Hybrid Antivirus Engine{C_GREY} ]{C_RESET}
    {C_GREY}[ {C_YELLOW}Author: Dion{C_GREY}    | {C_YELLOW}Skripsi Project{C_GREY}         ]{C_RESET}
    """
    print(textwrap.dedent(banner))

def load_cache():
    """Loads the scan cache from a file."""
    cache = {}
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, 'r') as f:
                for line in f:
                    if ':' in line:
                        file_hash, status = line.strip().split(':', 1)
                        cache[file_hash] = status
            logging.debug(f"Cache loaded with {len(cache)} entries.")
        except IOError:
            pass
    return cache

def save_cache(cache):
    """Saves the scan cache to a file."""
    try:
        with open(CACHE_FILE, 'w') as f:
            for file_hash, status in cache.items():
                f.write(f"{file_hash}:{status}\n")
    except IOError as e:
        logging.warning(f"Could not save cache file: {e}")

def load_yara_rules(filepath=None, source=None):
    """Loads and compiles YARA rules."""
    try:
        if filepath:
            if not Path(filepath).exists():
                logging.warning(f"YARA rules file '{filepath}' not found. Local scanning will be disabled.")
                return None
            logging.debug(f"Compiling YARA rules from file: {filepath}")
            return yara.compile(filepath=str(filepath))
        elif source:
            logging.debug("Compiling YARA rules from downloaded source.")
            return yara.compile(source=source)
    except yara.Error as e:
        logging.critical(f"{C_RED}FATAL ERROR: Could not compile YARA rules: {e}")
        sys.exit(1)
    return None

async def fetch_yara_rules_from_url(url):
    """Downloads YARA rule content from a given URL."""
    logging.info(f"Downloading YARA rules from URL...")
    logging.debug(f"URL: {url}")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=30) as response:
                response.raise_for_status()
                return await response.text()
    except Exception as e:
        logging.critical(f"{C_RED}FATAL ERROR: Failed to download YARA rules from URL: {e}")
        return None

def load_ignore_patterns(scan_path):
    """Looks for a .shieldignore file in the scan path."""
    ignore_file = Path(scan_path) / ".shieldignore"
    patterns = []
    if ignore_file.is_file():
        logging.info(f"Found '{ignore_file.name}', loading custom ignore patterns.")
        try:
            with open(ignore_file, 'r', encoding='utf-8') as f:
                for line in f:
                    stripped_line = line.strip()
                    if stripped_line and not stripped_line.startswith('#'):
                        patterns.append(stripped_line)
        except IOError as e:
            logging.warning(f"Could not read {ignore_file.name}: {e}")
    return patterns

def format_display_path(filepath):
    """Converts temp extraction paths into readable format."""
    path_str = str(filepath)
    if "temp_scans" in path_str:
        try:
            rel = Path(filepath).relative_to(TEMP_SCAN_DIR)
            clean_path = str(rel).replace("_extracted", " -> ").replace("/ ->", " ->")
            return clean_path.replace(os.sep, "/")
        except:
            return path_str
    return path_str

def extract_archive(filepath, extract_to):
    """Extracts .zip, .tar, .tar.gz files to a target directory."""
    try:
        if zipfile.is_zipfile(filepath):
            logging.debug(f"Extracting ZIP: {filepath}")
            with zipfile.ZipFile(filepath, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
            return True
        elif tarfile.is_tarfile(filepath):
            logging.debug(f"Extracting TAR: {filepath}")
            with tarfile.open(filepath, 'r:*') as tar_ref:
                def is_within_directory(directory, target):
                    abs_directory = os.path.abspath(directory)
                    abs_target = os.path.abspath(target)
                    prefix = os.path.commonprefix([abs_directory, abs_target])
                    return prefix == abs_directory
                def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
                    for member in tar.getmembers():
                        member_path = os.path.join(path, member.name)
                        if not is_within_directory(path, member_path):
                            raise Exception("Attempted Path Traversal in Tar File")
                    tar.extractall(path, members, numeric_owner=numeric_owner) 
                safe_extract(tar_ref, extract_to)
            return True
    except Exception as e:
        logging.warning(f"Failed to extract archive {filepath}: {e}")
        return False
    return False

def get_all_files_recursively(directory_path, excluded_extensions, scan_archives=False):
    """Collects file paths from a directory recursively."""
    logging.info(f"Searching for files in {directory_path}...")
    filepaths = []
    skipped_by_ext_count = 0
    p = Path(directory_path)
    
    if not p.is_dir():
        logging.error(f"Path '{directory_path}' is not a valid directory.")
        return [], 0
        
    excluded_ext_set = {ext.lower() for ext in excluded_extensions}
    user_ignore_patterns = load_ignore_patterns(directory_path)
    
    for item in p.rglob('*'):
        if not item.is_file(): continue
        if item.suffix.lower() in excluded_ext_set:
            skipped_by_ext_count += 1
            continue
            
        is_user_ignored = False
        try:
            relative_path = item.relative_to(p).as_posix()
            for pattern in user_ignore_patterns:
                if fnmatch.fnmatch(item.name, pattern) or fnmatch.fnmatch(relative_path, pattern):
                    is_user_ignored = True
                    break
        except: pass
        if is_user_ignored: continue
        if item.name in EXCLUDED_FILES: continue
        
        is_hard_excluded = False
        for part in item.parts:
            if part in EXCLUDED_DIRS or part.endswith('.egg-info'):
                is_hard_excluded = True
                break
        if is_hard_excluded: continue
            
        if scan_archives and item.suffix.lower() in ['.zip', '.tar', '.gz', '.tgz']:
            if str(TEMP_SCAN_DIR) in str(item.parent):
                unique_extract_dir = item.parent / f"{item.name}_extracted"
            else:
                unique_extract_dir = TEMP_SCAN_DIR / f"{item.name}_extracted"

            if not unique_extract_dir.exists():
                unique_extract_dir.mkdir(parents=True, exist_ok=True)
                if extract_archive(item, unique_extract_dir):
                    extracted_files, extracted_skipped = get_all_files_recursively(
                        str(unique_extract_dir), excluded_extensions, scan_archives=True
                    )
                    filepaths.extend(extracted_files)
                    skipped_by_ext_count += extracted_skipped
        filepaths.append(str(item))
        
    return filepaths, skipped_by_ext_count

def quarantine_file(filepath, reason):
    """Memindahkan file ke isolasi dan mencabut izin eksekusi (Revisi Pak Rofiq)."""
    try:
        QUARANTINE_DIR.mkdir(exist_ok=True)
        original_path = Path(filepath)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{original_path.name}.{timestamp}.locked"
        destination_path = QUARANTINE_DIR / safe_filename
        
        # Pindahkan file ke folder karantina
        shutil.move(filepath, destination_path)
        
        # CABUT IZIN EKSEKUSI (Revisi Pak Rofiq)
        if platform.system() == "Windows":
            # Deny 'Execute' permission untuk semua user di Windows
            subprocess.run(['icacls', str(destination_path), '/deny', 'Everyone:(X)'], capture_output=True)
        else:
            # Mode Read-Only (no execute) untuk Linux/Kali
            os.chmod(destination_path, 0o444)

        with open(QUARANTINE_LOG, 'a', encoding='utf-8') as log_file:
            log_entry = f"[{datetime.now()}] QUARANTINED: {filepath} | Reason: {reason} | Action: No-Execute Applied\n"
            log_file.write(log_entry)
            
        return True
    except Exception as e:
        logging.error(f"Failed to secure quarantine for {filepath}: {e}")
        return False
        
def delete_file(filepath, reason):
    """Deletes a file permanently."""
    try:
        logging.debug(f"Attempting to delete file: {filepath}")
        os.remove(filepath)
        QUARANTINE_DIR.mkdir(exist_ok=True)
        with open(QUARANTINE_LOG, 'a', encoding='utf-8') as log_file:
            log_entry = f"Timestamp: {datetime.now()}\n  Action: DELETED\n  Original: {filepath}\n  Reason: {reason}\n---\n"
            log_file.write(log_entry)
        logging.info(f"Successfully deleted file: {filepath}")
        return True
    except Exception as e:
        logging.error(f"Failed to delete file {filepath}: {e}")
        return False

def is_port_open(host, port):
    """Checks if a port is open (Daemon is running)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0

def ensure_daemon_running():
    """Checks if the daemon is alive. If not, starts it automatically."""
    if is_port_open('127.0.0.1', DAEMON_PORT):
        return True
    print(f"{C_YELLOW}[*] Daemon is OFFLINE. Auto-starting engine... (This takes ~10s){C_RESET}")
    daemon_script = PROJECT_ROOT / "hashshield_daemon.py"
    if not daemon_script.exists():
        print(f"{C_RED}[ERROR] Daemon script missing at {daemon_script}{C_RESET}")
        return False
    try:
        if sys.platform == "win32":
            subprocess.Popen([sys.executable, str(daemon_script)], creationflags=subprocess.CREATE_NEW_CONSOLE)
        else:
            subprocess.Popen([sys.executable, str(daemon_script)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except Exception as e:
        logging.error(f"Failed to start daemon: {e}")
        return False
    for _ in range(30):
        if is_port_open('127.0.0.1', DAEMON_PORT):
            print(f"{C_GREEN}[+] Daemon is online! Connected.{C_RESET}")
            return True
        time.sleep(1)
        print(".", end="", flush=True)
    print(f"\n{C_RED}[!] Daemon start timed out. Proceeding with limited scanning.{C_RESET}")
    return False

def get_daemon_stats():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5) # Fast timeout
            s.connect(('127.0.0.1', DAEMON_PORT))
            s.sendall(json.dumps({
                "token": os.environ.get("SHIELD_AUTH_TOKEN", ""),
                "path":  "STATS"
            }).encode())
            response = s.recv(1024).decode()
            
            if response.startswith("STATS:"):
                _, hash_count, heur_status = response.split(":")
                return hash_count, heur_status
    except:
        return None, None
    return None, None

def check_cloud_status():
    """Checks VirusTotal connectivity without using API quota."""
    if not API_KEY:
        return f"{C_RED}Disabled (No API Key){C_RESET}"
    
    try:
        with socket.create_connection(("www.virustotal.com", 443), timeout=1.5):
            return f"{C_GREEN}Online (Ready){C_RESET}"
    except OSError:
        return f"{C_YELLOW}Offline (Connection Failed){C_RESET}"

# =======================================================
# 3. CORE SCANNING LOGIC
# =======================================================
async def calculate_file_hash_async(filepath):
    def sync_hash():
        logging.debug(f"Hashing file: {filepath}")
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while True:
                    data = f.read(BLOCK_SIZE)
                    if not data: break
                    sha256.update(data)
            return sha256.hexdigest()
        except OSError: return None
    return await asyncio.to_thread(sync_hash)

def scan_file_yara(filepath, yara_rules):
    if not yara_rules: return False, None
    try:
        matches = yara_rules.match(filepath=filepath)
        if matches: return True, matches[0].rule
    except yara.Error: pass
    return False, None

def scan_file_daemon(filepath):
    """Mengirim data ke Daemon menggunakan format JSON (Revisi Pak Rofiq)."""
    try:
        abs_path = os.path.abspath(filepath)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect(('127.0.0.1', DAEMON_PORT))
            
            payload = json.dumps({
                "token":    os.environ.get("SHIELD_AUTH_TOKEN", ""),
                "hostname": socket.gethostname(),
                "path": abs_path
            })
            
            s.sendall(payload.encode())
            response = s.recv(1024).decode()
            
            if response.startswith("INFECTED"):
                parts = response.split(":", 1)
                return parts[1] if len(parts) > 1 else "Unknown Threat"
    except Exception as e:
        logging.debug(f"Daemon communication failed: {e}")
    return None

async def upload_file_to_virustotal(filepath, session):
    logging.info(f"File hash not found. Uploading: {os.path.basename(filepath)}")
    try:
        if os.path.getsize(filepath) > 32 * 1024 * 1024: return None, "File too large (>32MB)"
    except OSError: return None, "Error accessing file"
    headers = {"x-apikey": API_KEY}
    data = aiohttp.FormData()
    try:
        data.add_field('file', open(filepath, 'rb'), filename=os.path.basename(filepath))
    except IOError: return None, "Error opening file"
    try:
        async with session.post(API_URL.rstrip('/'), headers=headers, data=data, timeout=300) as response:
            response.raise_for_status()
            result = await response.json()
            return result.get('data', {}).get('id'), "File uploaded, awaiting analysis..."
    except Exception as e: return None, f"Upload failed: {e}"

async def get_analysis_result(analysis_id, session):
    if not analysis_id: return None
    logging.info(f"Waiting for analysis: {analysis_id[:15]}...")
    headers = {"x-apikey": API_KEY}
    url = f"{ANALYSIS_URL}{analysis_id}"
    for attempt in range(20):
        try:
            async with session.get(url, headers=headers, timeout=20) as response:
                if response.status == 404 and attempt < 3: 
                    await asyncio.sleep(15)
                    continue
                response.raise_for_status()
                result = await response.json()
                if result.get('data', {}).get('attributes', {}).get('status') == 'completed':
                    return result
                else: await asyncio.sleep(15)
        except: return None
    return None

def _process_analysis_data(data):
    if not data: return False, "Analysis timed out or failed."
    stats = data.get("data", {}).get("attributes", {}).get("stats") or data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious_count = stats.get("malicious", 0)
    if malicious_count > 0: return True, f"DANGER! Detected by {malicious_count} vendors on VirusTotal."
    return False, "Scan complete. Clean on VirusTotal."

async def scan_file_hybrid_async(filepath, cache, session, yara_rules, args):
    # 1. Daemon (Hash + Heuristics)
    daemon_result = await asyncio.to_thread(scan_file_daemon, filepath)
    if daemon_result:
        return filepath, True, f"DANGER! Shield Engine Detected: {daemon_result}"

    # 2. YARA (Local Patterns)
    is_malicious_yara, rule_name = scan_file_yara(filepath, yara_rules)
    if is_malicious_yara:
        return filepath, True, f"DANGER! Locally detected by YARA rule: {rule_name}"
        
    # 3. VirusTotal (Cloud)
    if not API_KEY: return filepath, False, "Clean (Daemon/YARA passed, VT disabled)"

    file_hash = await calculate_file_hash_async(filepath)
    if not file_hash: return filepath, False, "Error: Could not calculate file hash."
    
    if file_hash in cache:
        return filepath, (cache[file_hash] == 'malicious'), f"Result from cache: {cache[file_hash]}"
    logging.debug(f"Querying VirusTotal API for hash: {file_hash}...")    
    headers = {"x-apikey": API_KEY, "Accept": "application/json"}
    try:
        async with session.get(f"{API_URL}{file_hash}", headers=headers, timeout=20) as response:
            if response.status >= 400 and response.status != 404: response.raise_for_status()
            is_malicious, report_msg = False, ""
            
            if response.status == 200:
                is_malicious, report_msg = _process_analysis_data(await response.json())
            elif response.status == 404:
                if args.upload:
                    aid, msg = await upload_file_to_virustotal(filepath, session)
                    if aid: is_malicious, report_msg = _process_analysis_data(await get_analysis_result(aid, session))
                    else: report_msg = msg
                else: report_msg = "File hash not in VirusTotal DB. Assumed clean."
            
            cache[file_hash] = 'malicious' if is_malicious else 'clean'
            save_cache(cache)
            return filepath, is_malicious, report_msg
    except Exception as e: return filepath, False, f"Error: {e}"

# =======================================================
# 4. REPORT GENERATOR (EXECUTIVE HUB VERSION)
# =======================================================

def generate_html_report(results, output_path, scan_duration=0):
    """
    Laporan Executive Hub: Mengintegrasikan Chart.js Interaktif, 
    Standard Security Severity, dan Audit Search.
    """
    if not HAS_REPORTING:
        return
    
    try:
        env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
        template = env.get_template('report.html')
        
        # 1. Metrik Dasar
        total_files = len(results)
        infected_results = [item for item in results if item[1]]
        infected_count = len(infected_results)
        clean_count = total_files - infected_count
        
        # 2. Metrik Performa (Data untuk Pak Ivo)
        files_per_sec = round(total_files / scan_duration, 2) if scan_duration > 0 else 0
        
        # 3. Persiapan Data Laporan & Distribusi Ancaman
        # Kita menggunakan dictionary mentah untuk dikirim ke Chart.js di sisi HTML
        dist_data = {"Hash": 0, "Heuristic": 0, "Cloud": 0, "Clean": clean_count}
        report_data = []
        
        current_hostname = socket.gethostname()
        try:
            current_ip = socket.gethostbyname(current_hostname)
        except:
            current_ip = "127.0.0.1"

        for file_path, is_infected, threat_name, engine_name in results:
            # --- SKEMA WARNA SEVERITY (Standard Security) ---
            # Default: Safe/Informational
            severity = "INFORMATIONAL"
            severity_badge = "bg-hs-info text-white" 
            
            if is_infected:
                if "Shield Engine" in engine_name:
                    if "Hash" in threat_name:
                        severity = "CRITICAL"
                        severity_badge = "bg-hs-critical text-white" # Deep Red
                    else:
                        severity = "HIGH"
                        severity_badge = "bg-hs-high text-white" # Orange
                elif "Cloud" in engine_name:
                    severity = "MEDIUM"
                    severity_badge = "bg-hs-medium text-dark" # Yellow/Gold
            
            # Memasukkan ke list data laporan
            report_data.append({
                'status': 'INFECTED' if is_infected else 'CLEAN',
                'is_infected': is_infected,
                'file': file_path,
                'client': current_hostname,
                'engine': engine_name,
                'threat': threat_name,
                'severity': severity,
                'severity_badge': severity_badge
            })
            
            # Update data untuk Chart Interaktif
            if is_infected:
                if "Shield Engine" in engine_name:
                    dist_data["Heuristic" if "Heuristic" in threat_name else "Hash"] += 1
                elif "Cloud" in engine_name:
                    dist_data["Cloud"] += 1

        # 4. Render Template
        # Kita mengirim 'dist_data' sebagai 'chart_data_json'
        html_out = template.render(
            results=report_data,
            summary={
                'total': total_files,
                'infected': infected_count,
                'clean': clean_count,
                'duration': round(scan_duration, 2),
                'speed': files_per_sec,
                'client': current_hostname,
                'client_ip': current_ip
            },
            chart_data_json=dist_data, # Data JSON untuk Chart.js
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            system_info=f"{platform.system()} {platform.release()}"
        )
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_out)
        print(f"\n{colorama.Fore.GREEN}[+] Executive Dashboard generated: {output_path}")
        
    except Exception as e:
        print(f"{colorama.Fore.RED}[!] Report Error: {e}")
        
# =======================================================
# 5. MAIN EXECUTION
# =======================================================

async def main_async_scanner(filepaths, args):
    scan_cache = load_cache()
    yara_rules = load_yara_rules(source=await fetch_yara_rules_from_url(args.yara_url)) if args.yara_url else load_yara_rules(filepath=YARA_RULES_FILE)
    results = []
    if yara_rules: logging.info(f"Loaded {sum(1 for _ in yara_rules)} YARA rules.")
        
    limit = args.threads
    is_free_tier = (limit <= 4)
    logging.info(f"Concurrency limit set to: {limit} threads.")
    sem = asyncio.Semaphore(limit)

    async def semaphore_wrapper(filepath, cache, session, yara_rules, args):
        async with sem:
            if is_free_tier: await asyncio.sleep(15) 
            return await scan_file_hybrid_async(filepath, cache, session, yara_rules, args)

    async with aiohttp.ClientSession() as session:
        tasks = [semaphore_wrapper(fp, scan_cache, session, yara_rules, args) for fp in filepaths]
        logging.info(f"Starting hybrid scan of {len(filepaths)} files...")
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Scanning Files"):
            results.append(await coro)
    return results

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="HashShield: Hybrid Malware Scanner", epilog="Examples:\n  hashshield . --daemon\n  hashshield . --scan-archives", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("scan_path", metavar="PATH", type=str, nargs='?', help="Path to scan.")
    parser.add_argument("--daemon", action="store_true", help="Launch engine daemon.")
    parser.add_argument("--scan-archives", action="store_true", help="Scan inside archives.")
    
    parser.add_argument("-o", "--output", metavar="FILE", type=str, help="Save report to file.")
    parser.add_argument("--format", choices=['txt', 'csv', 'json', 'html'], default='txt', help="Report format.")
    parser.add_argument("-f", "--fresh", action="store_true", help="Ignore cache.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output.")
    parser.add_argument("-E", "--exclude-ext", nargs="+", metavar="EXT", type=str, default=[], help="Exclude extensions.")
    parser.add_argument("-u", "--yara-url", type=str, default=None, help="Remote YARA URL.")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Threads (Default: 4).")
    parser.add_argument("--upload", action="store_true", help="Upload unknown files.")
    args = parser.parse_args()
    
    if args.daemon:
        daemon_script = PROJECT_ROOT / "hashshield_daemon.py"
        if not daemon_script.exists():
            print(f"{C_RED}[ERROR] Daemon script not found.{C_RESET}")
            sys.exit(1)
        print(f"{C_GREEN}[*] Launching HashShield Daemon...{C_RESET}")
        try:
            subprocess.run([sys.executable, str(daemon_script)])
        except KeyboardInterrupt:
            print("\n[*] Daemon stopped.")
        sys.exit(0)

    if not args.scan_path:
        parser.print_help()
        print(f"\n{C_RED}[!] Error: Provide a path or use --daemon.{C_RESET}")
        sys.exit(1)

    if not args.daemon:
        db_count, heur_status = get_daemon_stats()
        cloud_status = check_cloud_status()
        if db_count:
            print(f"{C_GREEN}[INFO] Connected to Shield Daemon Engine{C_RESET}")
            print(f"{C_GREY}[INFO] Database Status : {C_BRIGHT}{db_count} signatures loaded{C_RESET}")
            print(f"{C_GREY}[INFO] Heuristic Engine: {C_BRIGHT}{heur_status}{C_RESET}")
            print(f"{C_GREY}[INFO] Cloud Engine    : {C_BRIGHT}{cloud_status}{C_RESET}")
            
        else:
            if args.scan_path:
                print(f"{C_YELLOW}[WARN] Daemon not detected. Starting temporary instance...{C_RESET}")

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="[%(levelname)s] %(message)s")

    if TEMP_SCAN_DIR.exists(): shutil.rmtree(TEMP_SCAN_DIR, ignore_errors=True)

    target_path = Path(args.scan_path)
    if not target_path.exists():
        logging.critical(f"{C_RED}Path not found: {target_path}{C_RESET}")
        sys.exit(1)

    filepaths_to_scan = []
    if target_path.is_file():
        if args.scan_archives and target_path.suffix.lower() in ['.zip', '.tar', '.gz', '.tgz']:
             TEMP_SCAN_DIR.mkdir(exist_ok=True)
             extract_dir = TEMP_SCAN_DIR / f"{target_path.name}_extracted"
             if extract_archive(str(target_path), extract_dir):
                  files, _ = get_all_files_recursively(str(extract_dir), args.exclude_ext, scan_archives=True)
                  filepaths_to_scan.extend(files)
        else:
             filepaths_to_scan.append(str(target_path))
    elif target_path.is_dir():
        filepaths_to_scan, _ = get_all_files_recursively(str(target_path), args.exclude_ext, scan_archives=args.scan_archives)

    if not filepaths_to_scan:
        logging.info("No files to scan.")
        sys.exit(0)

    try:
        ensure_daemon_running()
        print("\nRunning scan...\n")
        start_time = time.time()
        results = asyncio.run(main_async_scanner(filepaths_to_scan, args))
        end_time = time.time()
        scan_duration = end_time - start_time

        # --- POST-PROCESSING RESULTS ---
        infected_results = []
        uploaded_results = []
        clean_paths = set()
        clean_results_list = []

        for filepath, is_malicious, message in results:
            if is_malicious:
                infected_results.append((filepath, message))
            elif "uploaded" in message.lower() or "error" in message.lower() or "limit" in message.lower():
                uploaded_results.append((filepath, message))
            else:
                clean_paths.add(filepath)
                clean_results_list.append((filepath, message))

        # Propagate Infection
        bad_archives = set()
        for fp, _ in infected_results:
            if "temp_scans" in fp:
                parts = Path(fp).parts
                if "temp_scans" in parts:
                    idx = parts.index("temp_scans")
                    for part in parts[idx:]:
                        if part.endswith("_extracted"):
                            archive_name = part.replace("_extracted", "")
                            bad_archives.add(archive_name)

        final_clean_results = []
        for fp, msg in clean_results_list:
            filename = Path(fp).name
            if filename in bad_archives:
                infected_results.append((fp, "CONTAINER THREAT: Archive contains malicious files."))
            else:
                final_clean_results.append(fp)

        # --- REPORTING ---
        print("\n\n--- SCAN RESULTS ---")
        if infected_results:
            print(f"\n{C_YELLOW}--- DETECTED THREATS ({len(infected_results)}) ---{C_RESET}")
            action_all = None
            for i, (fp, msg) in enumerate(sorted(infected_results)):
                print("-" * 40)
                print(f"  FILE    : {format_display_path(fp)}")
                print(f"  STATUS  : {C_RED}INFECTED{C_RESET}")
                print(f"  REASON  : {msg}")
                if "temp_scans" in str(fp) or "CONTAINER THREAT" in msg:
                    print(f"  {C_YELLOW}[!] Note: Archive handling required.{C_RESET}")
                else:
                    if action_all: action = action_all
                    elif not sys.stdin.isatty():
                        print(f"  {C_YELLOW}[!] Non-interactive mode detected. Defaulting to 'Ignore'.{C_RESET}")
                        action = 'i'
                    else: action = input(f"\n  Action? ({C_YELLOW}Q{C_RESET})uarantine, ({C_RED}D{C_RESET})elete, ({C_GREEN}I{C_RESET})gnore | ({C_YELLOW}A{C_RESET})ll Q, A({C_RED}l{C_RESET})l D, All ({C_GREEN}S{C_RESET})kip? ").lower()
                    if action == 'q': quarantine_file(fp, msg)
                    elif action == 'd': delete_file(fp, msg)
                    elif action == 'a': action_all = 'q'; quarantine_file(fp, msg)
                    elif action == 'l': action_all = 'd'; delete_file(fp, msg)
                    elif action == 's': action_all = 'i'
        
        if uploaded_results:
             print(f"\n{C_YELLOW}--- OTHER STATUSES ---{C_RESET}")
             for fp, msg in uploaded_results: print(f"  - {format_display_path(fp)} : {msg}")

        print("-" * 40)
        print(f"Scan complete. Found {len(infected_results)} malicious files.")

        # --- REPORTING (Revisi Pak Rofiq & Pak Ivo) ---
        final_report_list = []
        for fp, msg in infected_results: 
            final_report_list.append((fp, True, msg, "Shield Engine")) 
        for fp, msg in uploaded_results: 
            final_report_list.append((fp, False, msg, "Cloud Engine")) 
        for fp in final_clean_results: 
            final_report_list.append((fp, False, "Clean", "Local Engine")) 

        # Memastikan fungsi yang dipanggil adalah generate_html_report
        if args.output or args.format == 'html':
            report_file = args.output if args.output else "report.html"
            generate_html_report(final_report_list, report_file, scan_duration=scan_duration)

    finally:
        if TEMP_SCAN_DIR.exists(): shutil.rmtree(TEMP_SCAN_DIR, ignore_errors=True)

if __name__ == "__main__":
    main()