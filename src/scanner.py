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
BLOCK_SIZE = 65536

PROJECT_ROOT = Path(__file__).resolve().parent.parent
YARA_RULES_FILE = PROJECT_ROOT / "rules.yara"
CACHE_FILE = PROJECT_ROOT / "scan_cache.txt"
QUARANTINE_DIR = PROJECT_ROOT / "quarantine"
QUARANTINE_LOG = QUARANTINE_DIR / "quarantine_log.txt"

EXCLUDED_DIRS = {'.git', '.vscode', '__pycache__', 'venv', 'env', '.venv'}
EXCLUDED_FILES = {'rules.yara', 'scan_cache.txt'}

C_RED = colorama.Fore.RED
C_GREEN = colorama.Fore.GREEN
C_YELLOW = colorama.Fore.YELLOW
C_RESET = colorama.Style.RESET_ALL

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

def get_all_files_recursively(directory_path, excluded_extensions):
    """Collects file paths from a directory recursively, applying exclusions and counting skipped files."""
    logging.info(f"Searching for files in {directory_path}...")
    filepaths = []
    skipped_by_ext_count = 0  # Counter untuk file yang diskip
    p = Path(directory_path)

    if not p.is_dir():
        logging.error(f"Path '{directory_path}' is not a valid directory.")
        return [], 0 # Return 0 for skipped count

    excluded_ext_set = {ext.lower() for ext in excluded_extensions}
    user_ignore_patterns = load_ignore_patterns(directory_path)

    for item in p.rglob('*'):
        if not item.is_file():
            continue

        if item.suffix.lower() in excluded_ext_set:
            skipped_by_ext_count += 1
            continue

        is_user_ignored = False
        relative_path = item.relative_to(p).as_posix()
        for pattern in user_ignore_patterns:
            if fnmatch.fnmatch(item.name, pattern) or fnmatch.fnmatch(relative_path, pattern):
                is_user_ignored = True
                break
        if is_user_ignored:
            continue

        is_hard_excluded = False
        if item.name in EXCLUDED_FILES:
            is_hard_excluded = True
        if not is_hard_excluded:
            for part in item.parts:
                if part in EXCLUDED_DIRS or part.endswith('.egg-info'):
                    is_hard_excluded = True
                    break
        if is_hard_excluded:
            continue
            
        filepaths.append(str(item))

    logging.info(f"Found {len(filepaths)} files to scan.")
    return filepaths, skipped_by_ext_count # Return count

# (Sisa dari Helper Functions dan Core Scanning Logic tidak berubah)
def quarantine_file(filepath, reason):
    """Moves a file to the quarantine directory, renames it, and logs the action."""
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
    """Deletes a file permanently and logs the action."""
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

async def main_async_scanner(filepaths, args):
    """Runs all file scans concurrently and displays progress."""
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

    async with aiohttp.ClientSession() as session:
        tasks = [scan_file_hybrid_async(filepath, scan_cache, session, yara_rules) for filepath in filepaths]
        logging.info(f"Starting hybrid scan of {len(filepaths)} files...")
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Scanning Files"):
            result = await coro
            results.append(result)
    return results

def main():
    """Main function to handle argument parsing and orchestrate the scan."""
    
    description_text = """An interactive, hybrid malware scanner using local/remote YARA rules and the VirusTotal API.

To customize exclusions for a specific scan, create a `.shieldignore` file in the target directory.

Features:
  - Interactive prompts for handling threats (Quarantine, Delete, Ignore).
  - Dynamic YARA scanning via URL (`--yara-url`).
  - Custom Exclusions via a `.shieldignore` file (supports wildcards).
  - Local YARA rule scanning for offline detection.
  - Online hash checking with VirusTotal API for in-depth analysis.
  - Smart Caching of scan results to avoid redundant API calls.
"""

    epilog_text = f"""Examples:
  # Scan the current directory. Will prompt for action if threats are found.
  hashshield .

  # Scan a specific directory with verbose logging
  hashshield "C:{os.sep}Users{os.sep}Your Name{os.sep}Downloads" -v

  # Perform a fresh scan using a remote YARA rule set
  hashshield . --fresh --yara-url https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Eicar.yar
"""
    
    parser = argparse.ArgumentParser(
        description=description_text,
        epilog=epilog_text,
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("scan_path", metavar="PATH", type=str, help="The file or directory path to scan.")
    parser.add_argument("-f", "--fresh", action="store_true", help="Perform a fresh scan by deleting the existing cache file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose (DEBUG) logging output.")
    parser.add_argument(
        "-E", "--exclude-ext",
        nargs="+",
        metavar="EXT",
        type=str,
        default=[],
        help="Exclude files with specific extensions (e.g., .log .tmp)."
    )
    parser.add_argument(
        "-u", "--yara-url",
        metavar="URL",
        type=str,
        default=None,
        help="Use YARA rules from a URL instead of the local rules.yara file."
    )
    parser.add_argument(
    "-U", "--upload",
    action="store_true",
    help="Upload files for analysis if their hash is not found on VirusTotal."
    )
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
        filepaths_to_scan, skipped_count = get_all_files_recursively(str(target_path), args.exclude_ext)

    if not filepaths_to_scan:
        logging.info("No files to scan. Exiting.")
        sys.exit(0)

    print("\nRunning scan...\n")
    results = asyncio.run(main_async_scanner(filepaths_to_scan, args))

    print("\n\n--- SCAN RESULTS ---")
    
    infected_results = []
    clean_results = []
    
    for filepath, is_malicious, message in results:
        if is_malicious:
            infected_results.append((filepath, message))
        else:
            clean_results.append(filepath)

    if not infected_results:
        print(f"\n{C_GREEN}Scan complete. No threats found in {len(clean_results)} files.{C_RESET}")
    else:
        print(f"\n{C_YELLOW}--- DETECTED THREATS ({len(infected_results)}) ---{C_RESET}")
        take_action_for_all = None
        for i, (filepath, message) in enumerate(sorted(infected_results)):
            print("-" * 40)
            print(f"  FILE    : {filepath}")
            print(f"  STATUS  : {C_RED}INFECTED{C_RESET}")
            print(f"  REASON  : {message}")
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
                logging.info("Applying 'Quarantine' to all subsequent detections.")
                take_action_for_all = 'q'
                quarantine_file(filepath, message)
            elif action == 'l':
                logging.info("Applying 'Delete' to all subsequent detections.")
                take_action_for_all = 'd'
                delete_file(filepath, message)
            elif action == 's':
                logging.info("Ignoring all subsequent detections.")
                take_action_for_all = 'i'
            else:
                logging.info(f"Unknown action. Ignored file: {filepath}")

    terminal_width = shutil.get_terminal_size((80, 24)).columns
    line_separator = "-" * terminal_width
    print(f"\n{line_separator}")
    
    if skipped_count > 0:
        excluded_str = ", ".join(args.exclude_ext)
        print(f"[*] Note: {skipped_count} file(s) were skipped due to --exclude-ext flag ({excluded_str}).")

    print(f"Scan complete. Found {len(infected_results)} malicious file(s).")
    if not args.verbose and len(clean_results) > 0:
        print(f"(Run with --verbose to see a list of {len(clean_results)} clean files)")
    print(line_separator)

if __name__ == "__main__":
    main()