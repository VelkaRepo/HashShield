import hashlib
import aiohttp
import asyncio
import os
import sys
import argparse
import logging
import fnmatch
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
BLOCK_SIZE = 65536

PROJECT_ROOT = Path(__file__).resolve().parent.parent
YARA_RULES_FILE = PROJECT_ROOT / "rules.yara"
CACHE_FILE = PROJECT_ROOT / "scan_cache.txt"

EXCLUDED_DIRS = {'.git', '.vscode', '__pycache__', 'venv', 'env', '.venv'}
EXCLUDED_FILES = {'rules.yara', 'scan_cache.txt'}

C_RED = colorama.Fore.RED
C_GREEN = colorama.Fore.GREEN
C_RESET = colorama.Style.RESET_ALL # <-- FIX: Add the missing C_RESET definition

if not API_KEY:
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    logging.critical(f"{C_RED}FATAL ERROR: VIRUSTOTAL_API_KEY not set in environment or .env file.")
    sys.exit(1)

# =======================================================
# 2. HELPER FUNCTIONS
# =======================================================

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

def load_yara_rules():
    """Loads and compiles YARA rules from the rules file."""
    if YARA_RULES_FILE.exists():
        try:
            logging.debug(f"Compiling YARA rules from {YARA_RULES_FILE}")
            rules = yara.compile(filepath=str(YARA_RULES_FILE))
            return rules
        except yara.Error as e:
            logging.critical(f"{C_RED}FATAL ERROR: Could not compile YARA rules: {e}")
            sys.exit(1)
    else:
        logging.warning(f"YARA rules file '{YARA_RULES_FILE}' not found. Local scanning will be disabled.")
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

def get_all_files_recursively(directory_path):
    """Collects file paths from a directory recursively, applying exclusions."""
    logging.info(f"Searching for files in {directory_path}...")
    filepaths = []
    p = Path(directory_path)
    if not p.is_dir():
        logging.error(f"Path '{directory_path}' is not a valid directory.")
        return []

    user_ignore_patterns = load_ignore_patterns(directory_path)

    for item in p.rglob('*'):
        if not item.is_file():
            continue

        is_in_excluded_dir = False
        for part in item.parts:
            if part in EXCLUDED_DIRS or part.endswith('.egg-info'):
                is_in_excluded_dir = True
                break
        
        if item.name in EXCLUDED_FILES or is_in_excluded_dir:
            continue

        is_user_ignored = False
        relative_path = item.relative_to(p).as_posix()
        for pattern in user_ignore_patterns:
            if fnmatch.fnmatch(item.name, pattern) or fnmatch.fnmatch(relative_path, pattern):
                is_user_ignored = True
                break
        
        if is_user_ignored:
            continue
            
        filepaths.append(str(item))

    logging.info(f"Found {len(filepaths)} files to scan.")
    return filepaths

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

async def scan_file_hybrid_async(filepath, cache, session, yara_rules):
    """Scans a file using YARA rules first, then VirusTotal API."""
    is_malicious_yara, rule_name = scan_file_yara(filepath, yara_rules)
    if is_malicious_yara:
        return filepath, True, f"DANGER! Locally detected by YARA rule: {rule_name}"

    file_hash = await calculate_file_hash_async(filepath)
    if not file_hash:
        return filepath, False, "Error: Could not calculate file hash."
    logging.debug(f"File hash for {os.path.basename(filepath)}: {file_hash[:10]}...")

    if file_hash in cache:
        status = cache[file_hash]
        is_malware = status == 'malicious'
        return filepath, is_malware, f"Result from cache: {status}"

    logging.debug(f"Querying VirusTotal API for hash: {file_hash[:10]}...")
    headers = {"x-apikey": API_KEY, "Accept": "application/json"}
    url = f"{API_URL}{file_hash}"
    try:
        async with session.get(url, headers=headers, timeout=20) as response:
            logging.debug(f"API response for {file_hash[:10]}...: Status {response.status}")
            if response.status == 429:
                return filepath, False, "API Error: Rate limit exceeded."
            if response.status >= 400 and response.status != 404:
                response.raise_for_status()

            data = await response.json()
            is_malicious = False
            report_msg = "Scan complete. Clean."

            if response.status == 200:
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                if malicious_count > 0:
                    is_malicious = True
                    report_msg = f"DANGER! Detected by {malicious_count} vendors on VirusTotal."
                else:
                    report_msg = "Scan complete. Clean on VirusTotal."
            elif response.status == 404:
                report_msg = "File hash not in VirusTotal DB. Assumed clean."

            cache[file_hash] = 'malicious' if is_malicious else 'clean'
            save_cache(cache)
            return filepath, is_malicious, report_msg
    except aiohttp.ClientResponseError as e:
        return filepath, False, f"HTTP Error {e.status}: {e.message}"
    except asyncio.TimeoutError:
        return filepath, False, "Network Error: Request timed out."
    except Exception as e:
        return filepath, False, f"An unexpected error occurred: {e}"

# =======================================================
# 4. MAIN EXECUTION
# =======================================================

async def main_async_scanner(filepaths):
    """Runs all file scans concurrently and displays progress."""
    scan_cache = load_cache()
    yara_rules = load_yara_rules()
    results = []

    if yara_rules:
        # A bit of a hack to count rules, but works for yara-python's object
        rule_count = sum(1 for _ in yara_rules)
        logging.info(f"Loaded {rule_count} YARA rules.")

    async with aiohttp.ClientSession() as session:
        tasks = [scan_file_hybrid_async(filepath, scan_cache, session, yara_rules) for filepath in filepaths]
        logging.info(f"Starting hybrid scan of {len(filepaths)} files...")
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Scanning Files"):
            result = await coro
            results.append(result)
    return results

def main():
    """Main function to handle argument parsing and orchestrate the scan."""
    parser = argparse.ArgumentParser(
        description="A hybrid malware scanner using YARA rules and the VirusTotal API.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("scan_path", metavar="PATH", type=str, help="The file or directory path to scan.")
    parser.add_argument("-f", "--fresh", action="store_true", help="Perform a fresh scan by deleting the existing cache file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose (DEBUG) logging output.")
    args = parser.parse_args()
    
    log_level = logging.DEBUG if args.verbose else logging.INFO
    log_format = "[%(levelname)s] %(message)s" if args.verbose else "[*] %(message)s"
    logging.basicConfig(level=log_level, format=log_format)

    if args.fresh:
        if CACHE_FILE.exists():
            try:
                CACHE_FILE.unlink()
                logging.info("Cache file deleted for a fresh scan.")
            except OSError as e:
                logging.warning(f"Could not delete cache file: {e}")

    target_path = Path(args.scan_path)
    filepaths_to_scan = []

    if not target_path.exists():
        logging.critical(f"{C_RED}FATAL ERROR: The path '{target_path}' does not exist.")
        sys.exit(1)

    if target_path.is_file():
        filepaths_to_scan.append(str(target_path))
    elif target_path.is_dir():
        filepaths_to_scan = get_all_files_recursively(str(target_path))

    if not filepaths_to_scan:
        logging.info("No files to scan. Exiting.")
        sys.exit(0)

    print("\nRunning scan...\n")
    results = asyncio.run(main_async_scanner(filepaths_to_scan))

    print("\n\n--- SCAN RESULTS SUMMARY ---")
    malicious_files_count = 0
    for filepath, is_malicious, message in sorted(results, key=lambda r: r[0]):
        if is_malicious:
            status_tag = f"{C_RED}[INFECTED]{C_RESET}"
            malicious_files_count += 1
        else:
            status_tag = f"{C_GREEN}[OK]      {C_RESET}"

        total_width = 85
        tag_visible_len = 10
        available_path_len = total_width - (tag_visible_len + 1)

        if len(filepath) <= available_path_len:
            left_part = f"{status_tag} {filepath}"
            print(f"{left_part:<{total_width}} | {message}")
        else:
            print(f"{status_tag} {filepath}")
            indentation = " " * (tag_visible_len + 1)
            print(f"{indentation:<{total_width}} | {message}")

    print("-" * 80)
    print(f"Scan complete. Found {malicious_files_count} malicious file(s).")
    print("-" * 80)

if __name__ == "__main__":
    main()