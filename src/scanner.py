import hashlib
import aiohttp
import asyncio
import os
import sys
import argparse
import logging
import fnmatch
import shutil
import textwrap
import socket
import subprocess
import zipfile
import tarfile
import time
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from tqdm.asyncio import tqdm
import colorama

# --- YARA INTEGRATION ---
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

EXCLUDED_DIRS = {'.git', '.vscode', '__pycache__', 'venv', 'env', '.venv'}
EXCLUDED_FILES = {'rules.yara', 'scan_cache.txt'}

# --- THEME CONFIGURATION (ORANGE & BLACK) ---
C_RED = colorama.Fore.RED
C_GREEN = colorama.Fore.GREEN
C_YELLOW = colorama.Fore.YELLOW  # Acts as Orange
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
    """Prints the HashShield ASCII Art Banner in Orange & Black style."""
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
    """Loads and compiles YARA rules from a file path OR a string source."""
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
                rules_content = await response.text()
                logging.debug("Successfully downloaded YARA rule content.")
                return rules_content
    except Exception as e:
        logging.critical(f"{C_RED}FATAL ERROR: Failed to download YARA rules from URL: {e}")
        return None

def load_ignore_patterns(scan_path):
    """Looks for a .shieldignore file in the scan path and loads the patterns."""
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
    """
    Converts .../temp_scans/bad.zip_extracted/virus.exe -> bad.zip -> virus.exe
    """
    path_str = str(filepath)
    if "temp_scans" in path_str:
        try:
            rel = Path(filepath).relative_to(TEMP_SCAN_DIR)
            # Clean up the formatting
            clean_path = str(rel).replace("_extracted", " -> ").replace("/ ->", " ->")
            clean_path = clean_path.replace(os.sep, "/")
            return clean_path
        except:
            return path_str
    return path_str

def extract_archive(filepath, extract_to):
    """
    Extracts .zip, .tar, .tar.gz files to a target directory.
    """
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
    """
    Collects file paths from a directory recursively.
    """
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
        if not item.is_file():
            continue
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
        if is_user_ignored:
            continue
        if item.name in EXCLUDED_FILES:
            continue
        is_hard_excluded = False
        for part in item.parts:
            if part in EXCLUDED_DIRS or part.endswith('.egg-info'):
                is_hard_excluded = True
                break
        if is_hard_excluded:
            continue
            
        # --- ARCHIVE HANDLING ---
        if scan_archives and item.suffix.lower() in ['.zip', '.tar', '.gz', '.tgz']:
            unique_extract_dir = TEMP_SCAN_DIR / f"{item.name}_extracted"
            if not unique_extract_dir.exists():
                unique_extract_dir.mkdir(parents=True, exist_ok=True)
                if extract_archive(item, unique_extract_dir):
                    extracted_files, extracted_skipped = get_all_files_recursively(
                        str(unique_extract_dir), 
                        excluded_extensions, 
                        scan_archives=True
                    )
                    filepaths.extend(extracted_files)
                    skipped_by_ext_count += extracted_skipped

        filepaths.append(str(item))
        
    return filepaths, skipped_by_ext_count

def quarantine_file(filepath, reason):
    """Moves a file to the quarantine directory."""
    try:
        QUARANTINE_DIR.mkdir(exist_ok=True)
        logging.debug(f"Attempting to quarantine file: {filepath}")
        original_path = Path(filepath)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        safe_filename = f"{original_path.name}.{timestamp}.quarantined"
        destination_path = QUARANTINE_DIR / safe_filename
        shutil.move(filepath, destination_path)
        with open(QUARANTINE_LOG, 'a', encoding='utf-8') as log_file:
            log_entry = (
                f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"  Original Path: {filepath}\n"
                f"  Quarantined To: {destination_path}\n"
                f"  Reason: {reason}\n"
                f"---\n"
            )
            log_file.write(log_entry)
        logging.debug(f"Successfully quarantined file to: {destination_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to quarantine file {filepath}: {e}")
        return False
        
def delete_file(filepath, reason):
    """Deletes a file permanently."""
    try:
        logging.debug(f"Attempting to delete file: {filepath}")
        os.remove(filepath)
        QUARANTINE_DIR.mkdir(exist_ok=True)
        with open(QUARANTINE_LOG, 'a', encoding='utf-8') as log_file:
            log_entry = (
                f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"  Action: DELETED\n"
                f"  Original Path: {filepath}\n"
                f"  Reason: {reason}\n"
                f"---\n"
            )
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
    """
    Checks if the daemon is alive. If not, starts it automatically.
    """
    if is_port_open('127.0.0.1', DAEMON_PORT):
        return True

    print(f"{C_YELLOW}[*] Daemon is OFFLINE. Auto-starting engine... (This takes ~10s){C_RESET}")
    
    daemon_script = PROJECT_ROOT / "hashshield_daemon.py"
    if not daemon_script.exists():
        print(f"{C_RED}[ERROR] Daemon script missing at {daemon_script}{C_RESET}")
        return False

    try:
        if sys.platform == "win32":
            subprocess.Popen([sys.executable, str(daemon_script)], 
                             creationflags=subprocess.CREATE_NEW_CONSOLE)
        else:
            subprocess.Popen([sys.executable, str(daemon_script)], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL,
                             start_new_session=True)
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

# =======================================================
# 3. CORE SCANNING LOGIC
# =======================================================
async def calculate_file_hash_async(filepath):
    """Calculates the SHA256 hash of a file in a separate thread."""
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
        except OSError:
            return None
    return await asyncio.to_thread(sync_hash)

def scan_file_yara(filepath, yara_rules):
    """Scans a file against a set of compiled YARA rules."""
    if not yara_rules:
        return False, None
    try:
        logging.debug(f"Performing YARA scan on: {filepath}")
        matches = yara_rules.match(filepath=filepath)
        if matches:
            return True, matches[0].rule
    except yara.Error:
        logging.debug(f"YARA error scanning file (likely permissions): {filepath}")
        return False, None
    return False, None

def scan_file_daemon(filepath):
    """Connects to the local HashShield Daemon."""
    try:
        # FIX: Convert to Absolute Path so Daemon can find it from anywhere
        abs_path = os.path.abspath(filepath)
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect(('127.0.0.1', DAEMON_PORT))
            
            # Send the ABSOLUTE path
            s.sendall(abs_path.encode())
            
            response = s.recv(1024).decode()
            
            # Parse "INFECTED:VirusName"
            if response.startswith("INFECTED"):
                parts = response.split(":", 1)
                threat_name = parts[1] if len(parts) > 1 else "Unknown Threat"
                return threat_name # Return name string (Truthiness is True)
                
    except ConnectionRefusedError:
        # Daemon is unreachable, just return False (skip local db check)
        pass
    except Exception as e:
        logging.debug(f"Daemon check failed: {e}")
    return None

async def upload_file_to_virustotal(filepath, session):
    """Uploads a file to VirusTotal and returns the analysis ID."""
    logging.info(f"File hash not found. Uploading for analysis: {os.path.basename(filepath)}")
    try:
        file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
        if file_size_mb > 32:
            return None, "File too large to upload (>32MB)"
    except OSError as e:
        return None, f"Error accessing file: {e}"
    headers = {"x-apikey": API_KEY}
    data = aiohttp.FormData()
    try:
        data.add_field('file', open(filepath, 'rb'), filename=os.path.basename(filepath))
    except IOError as e:
        return None, "Error opening file for upload"
    try:
        upload_url = API_URL.rstrip('/')
        async with session.post(upload_url, headers=headers, data=data, timeout=300) as response:
            response.raise_for_status()
            result = await response.json()
            analysis_id = result.get('data', {}).get('id')
            return analysis_id, "File uploaded, awaiting analysis..."
    except Exception as e:
        return None, f"Upload failed: {e}"

async def get_analysis_result(analysis_id, session):
    """Polls VirusTotal for a completed analysis report."""
    if not analysis_id: return None
    logging.info(f"Waiting for analysis results for ID: {analysis_id[:15]}...")
    headers = {"x-apikey": API_KEY}
    url = f"{ANALYSIS_URL}{analysis_id}"
    max_retries = 20
    poll_interval = 15
    await asyncio.sleep(5)
    for attempt in range(max_retries):
        try:
            async with session.get(url, headers=headers, timeout=20) as response:
                if response.status == 404 and attempt < 3: 
                    await asyncio.sleep(poll_interval)
                    continue
                response.raise_for_status()
                result = await response.json()
                status = result.get('data', {}).get('attributes', {}).get('status')
                if status == 'completed':
                    return result
                else:
                    await asyncio.sleep(poll_interval)
        except Exception as e:
            logging.error(f"Error while polling for results: {e}")
            return None
    return None

def _process_analysis_data(data):
    if not data: return False, "Analysis timed out or failed."
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("stats") or attributes.get("last_analysis_stats", {})
    malicious_count = stats.get("malicious", 0)
    if malicious_count > 0:
        return True, f"DANGER! Detected by {malicious_count} vendors on VirusTotal."
    return False, "Scan complete. Clean on VirusTotal."

async def scan_file_hybrid_async(filepath, cache, session, yara_rules, args):
    """Scans a file using Local Daemon, then YARA rules, then VirusTotal API."""
    
    # 1. Daemon (Hash + Heuristics)
    daemon_result = await asyncio.to_thread(scan_file_daemon, filepath)
    if daemon_result:
        # Report specific virus name
        return filepath, True, f"DANGER! Shield Engine Detected: {daemon_result}"

    # 2. YARA (Local Patterns)
    is_malicious_yara, rule_name = scan_file_yara(filepath, yara_rules)
    if is_malicious_yara:
        return filepath, True, f"DANGER! Locally detected by YARA rule: {rule_name}"
        
    # 3. VirusTotal (Cloud)
    if not API_KEY:
        return filepath, False, "Clean (Daemon/YARA passed, VT disabled)"

    file_hash = await calculate_file_hash_async(filepath)
    if not file_hash:
        return filepath, False, "Error: Could not calculate file hash."
    
    if file_hash in cache:
        status = cache[file_hash]
        return filepath, (status == 'malicious'), f"Result from cache: {status}"
        
    headers = {"x-apikey": API_KEY, "Accept": "application/json"}
    url = f"{API_URL}{file_hash}"
    try:
        async with session.get(url, headers=headers, timeout=20) as response:
            if response.status >= 400 and response.status != 404:
                response.raise_for_status()
            
            is_malicious, report_msg = False, ""
            if response.status == 200:
                file_report = await response.json()
                is_malicious, report_msg = _process_analysis_data(file_report)
            elif response.status == 404:
                if args.upload:
                    analysis_id, temp_message = await upload_file_to_virustotal(filepath, session)
                    if analysis_id:
                        analysis_report = await get_analysis_result(analysis_id, session)
                        is_malicious, report_msg = _process_analysis_data(analysis_report)
                    else:
                        report_msg = temp_message
                else:
                    report_msg = "File hash not in VirusTotal DB. Assumed clean."
            
            cache[file_hash] = 'malicious' if is_malicious else 'clean'
            save_cache(cache)
            return filepath, is_malicious, report_msg

    except Exception as e:
        return filepath, False, f"An unexpected error occurred: {e}"

# =======================================================
# 4. MAIN EXECUTION
# =======================================================
async def main_async_scanner(filepaths, args):
    scan_cache = load_cache()
    yara_rules = None
    if args.yara_url:
        rules_content = await fetch_yara_rules_from_url(args.yara_url)
        if rules_content:
            yara_rules = load_yara_rules(source=rules_content)
    else:
        yara_rules = load_yara_rules(filepath=YARA_RULES_FILE)
    
    results = []
    if yara_rules:
        rule_count = sum(1 for _ in yara_rules)
        logging.info(f"Loaded {rule_count} YARA rules for this session.")
        
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
    # 1. SHOW BRANDING (Orange & Black)
    print_banner()
    
    description_text = "HashShield: Hybrid Malware Scanner (Hash + Heuristic + Cloud)"
    epilog_text = "Examples:\n  hashshield . --daemon\n  hashshield . --scan-archives"
    
    parser = argparse.ArgumentParser(description=description_text, epilog=epilog_text, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("scan_path", metavar="PATH", type=str, nargs='?', help="Path to scan.")
    parser.add_argument("--daemon", action="store_true", help="Launch the engine daemon.")
    
    # --- FEATURES ---
    parser.add_argument("--scan-archives", action="store_true", help="Recursively extract and scan archives (.zip, .tar, .tar.gz).")
    parser.add_argument("-f", "--fresh", action="store_true", help="Ignore cache.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output.")
    parser.add_argument("-E", "--exclude-ext", nargs="+", metavar="EXT", type=str, default=[], help="Exclude extensions.")
    parser.add_argument("-u", "--yara-url", type=str, default=None, help="Remote YARA rules URL.")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Threads (Default: 4).")
    parser.add_argument("--upload", action="store_true", help="Upload unknown files.")
    
    args = parser.parse_args()
    
    # Daemon Launch Mode
    if args.daemon:
        daemon_script = PROJECT_ROOT / "hashshield_daemon.py"
        if not daemon_script.exists():
            print(f"{C_RED}[ERROR] Daemon script not found: {daemon_script}{C_RESET}")
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

    # Setup Logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="[%(levelname)s] %(message)s")

    # Cleanup Temp from Previous Crashes
    if TEMP_SCAN_DIR.exists():
        try:
            shutil.rmtree(TEMP_SCAN_DIR)
        except: pass

    target_path = Path(args.scan_path)
    if not target_path.exists():
        logging.critical(f"{C_RED}Path not found: {target_path}{C_RESET}")
        sys.exit(1)

    # Collection Phase
    filepaths_to_scan = []
    skipped_count = 0
    
    if target_path.is_file():
        if args.scan_archives and target_path.suffix.lower() in ['.zip', '.tar', '.gz', '.tgz']:
             TEMP_SCAN_DIR.mkdir(exist_ok=True)
             extract_dir = TEMP_SCAN_DIR / f"{target_path.name}_extracted"
             if extract_archive(str(target_path), extract_dir):
                  files, skips = get_all_files_recursively(str(extract_dir), args.exclude_ext, scan_archives=True)
                  filepaths_to_scan.extend(files)
        else:
             filepaths_to_scan.append(str(target_path))
             
    elif target_path.is_dir():
        filepaths_to_scan, skipped_count = get_all_files_recursively(str(target_path), args.exclude_ext, scan_archives=args.scan_archives)

    if not filepaths_to_scan:
        logging.info("No files to scan.")
        sys.exit(0)

    # Scan Phase
    try:
        # AUTO-START BRAIN
        ensure_daemon_running()
        
        print("\nRunning scan...\n")
        results = asyncio.run(main_async_scanner(filepaths_to_scan, args))

        # Reporting Phase
        print("\n\n--- SCAN RESULTS ---")
        infected_results = []
        uploaded_results = []
        clean_count = 0

        for filepath, is_malicious, message in results:
            if is_malicious:
                infected_results.append((filepath, message))
            elif "uploaded" in message.lower() or "error" in message.lower() or "limit" in message.lower():
                uploaded_results.append((filepath, message))
            else:
                clean_count += 1

        if infected_results:
            print(f"\n{C_YELLOW}--- DETECTED THREATS ({len(infected_results)}) ---{C_RESET}")
            take_action_for_all = None
            for i, (filepath, message) in enumerate(sorted(infected_results)):
                display_path = format_display_path(filepath)
                
                print("-" * 40)
                print(f"  FILE    : {display_path}")
                print(f"  STATUS  : {C_RED}INFECTED{C_RESET}")
                print(f"  REASON  : {message}")
                
                if "temp_scans" in str(filepath):
                    print(f"  {C_YELLOW}[!] Note: File is inside an archive. Delete the source archive to remove.{C_RESET}")
                else:
                    if take_action_for_all:
                        action = take_action_for_all
                    else:
                        prompt = (
                            f"\n  Action for this file? "
                            f"({C_YELLOW}Q{C_RESET})uarantine, ({C_RED}D{C_RESET})elete, ({C_GREEN}I{C_RESET})gnore | "
                            f"({C_YELLOW}A{C_RESET})ll Quarantine, A({C_RED}l{C_RESET})l Delete, All ({C_GREEN}S{C_RESET})kip? "
                        )
                        action = input(prompt).lower()
                    
                    if action == 'q':
                        quarantine_file(filepath, message)
                    elif action == 'd':
                        delete_file(filepath, message)
                    elif action == 'i':
                        logging.info(f"Ignored file: {filepath}")
                    elif action == 'a':
                        take_action_for_all = 'q'
                        quarantine_file(filepath, message)
                    elif action == 'l':
                        take_action_for_all = 'd'
                        delete_file(filepath, message)
                    elif action == 's':
                        take_action_for_all = 'i'
                    else:
                        logging.info(f"Unknown action. Ignored file: {filepath}")

        if uploaded_results:
             print(f"\n{C_YELLOW}--- OTHER STATUSES ---{C_RESET}")
             for fp, msg in uploaded_results:
                 print(f"  - {format_display_path(fp)} : {msg}")

        print("-" * 40)
        print(f"Scan complete. Found {len(infected_results)} malicious files.")
        if not infected_results and not uploaded_results:
             print(f"All {len(results)} files scanned are clean.")

    finally:
        # CLEANUP
        if TEMP_SCAN_DIR.exists():
            try:
                shutil.rmtree(TEMP_SCAN_DIR)
            except Exception as e:
                logging.warning(f"Cleanup failed: {e}")

if __name__ == "__main__":
    main()