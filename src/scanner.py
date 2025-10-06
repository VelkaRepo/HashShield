import hashlib
import aiohttp
import asyncio
import os
import sys
import argparse
from pathlib import Path
from dotenv import load_dotenv
from tqdm.asyncio import tqdm
import colorama

# =======================================================
# 1. CONFIGURATION
# =======================================================
load_dotenv()
colorama.init(autoreset=True)

API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
API_URL = "https://www.virustotal.com/api/v3/files/"
BLOCK_SIZE = 65536

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SIGNATURE_FILE = PROJECT_ROOT / "signatures.txt"
CACHE_FILE = PROJECT_ROOT / "scan_cache.txt"

EXCLUDED_DIRS = {'.git', '.vscode', '__pycache__', 'venv', 'env', '.venv'}
EXCLUDED_FILES = {'signatures.txt', 'scan_cache.txt'}

C_RED = colorama.Fore.RED
C_GREEN = colorama.Fore.GREEN
C_RESET = colorama.Style.RESET_ALL

if not API_KEY:
    print(f"{C_RED}FATAL ERROR: VIRUSTOTAL_API_KEY not set in environment or .env file.")
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
        print(f"Warning: Could not save cache file: {e}")

def load_signatures():
    """Loads malware signatures from the signature file."""
    signatures = {}
    if SIGNATURE_FILE.exists():
        try:
            with open(SIGNATURE_FILE, 'r') as f:
                for line in f:
                    if ':' in line:
                        name, signature = line.strip().split(':', 1)
                        signatures[name] = signature
        except IOError as e:
            print(f"Warning: Could not read signature file: {e}")
    else:
        print(f"Warning: Signature file '{SIGNATURE_FILE}' not found.")
    return signatures

def get_all_files_recursively(directory_path):
    """Collects file paths from a directory recursively, applying exclusions."""
    print(f"[*] Searching for files in {directory_path}...")
    filepaths = []
    p = Path(directory_path)
    if not p.is_dir():
        print(f"[!] Error: Path '{directory_path}' is not a valid directory.")
        return []

    for item in p.rglob('*'):
        # --- PERUBAHAN DI SINI: Logika pengecualian yang lebih baik ---
        # Check if any parent directory should be excluded
        is_in_excluded_dir = False
        for part in item.parts:
            if part in EXCLUDED_DIRS or part.endswith('.egg-info'):
                is_in_excluded_dir = True
                break
        
        # Final check including file-specific exclusions
        if item.is_file() and not is_in_excluded_dir and item.name not in EXCLUDED_FILES:
            filepaths.append(str(item))

    print(f"[*] Found {len(filepaths)} files to scan.")
    return filepaths

# =======================================================
# 3. CORE SCANNING LOGIC
# =======================================================

async def calculate_file_hash_async(filepath):
    """Calculates the SHA256 hash of a file in a separate thread."""
    def sync_hash():
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

def scan_file_locally(filepath, signatures):
    """Scans a file against a dictionary of local string-based signatures."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            for name, signature in signatures.items():
                if signature in content:
                    return True, name
    except (IOError, OSError):
        return False, None
    return False, None

async def scan_file_hybrid_async(filepath, cache, session, signatures):
    """Scans a file using local signatures first, then VirusTotal API."""
    is_malicious_local, detected_by = scan_file_locally(filepath, signatures)
    if is_malicious_local:
        return filepath, True, f"DANGER! Locally detected by signature: {detected_by}"

    file_hash = await calculate_file_hash_async(filepath)
    if not file_hash:
        return filepath, False, "Error: Could not calculate file hash."

    if file_hash in cache:
        status = cache[file_hash]
        is_malware = status == 'malicious'
        return filepath, is_malware, f"Result from cache: {status}"

    headers = {"x-apikey": API_KEY, "Accept": "application/json"}
    url = f"{API_URL}{file_hash}"
    try:
        async with session.get(url, headers=headers, timeout=20) as response:
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
    signatures = load_signatures()
    results = []

    print(f"[*] Loaded {len(signatures)} local signatures.")

    async with aiohttp.ClientSession() as session:
        tasks = [scan_file_hybrid_async(filepath, scan_cache, session, signatures) for filepath in filepaths]
        print(f"[*] Starting hybrid scan of {len(filepaths)} files...")
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Scanning Files"):
            result = await coro
            results.append(result)
    return results

def main():
    """Main function to handle argument parsing and orchestrate the scan."""
    description_text = """A hybrid malware scanner that uses both local signatures and the VirusTotal API.

Features:
  - Local signature scanning for instant detection of known threats.
  - Online hash checking with VirusTotal API for in-depth analysis.
  - Recursive directory scanning to check all files within a folder.
  - Caching of scan results to avoid redundant API calls.
  - Exclusion of common development directories and specific files.
"""
    epilog_text = f"""Examples:
  # Scan a single file
  hashshield C:{os.sep}path{os.sep}to{os.sep}somefile.exe

  # Scan the current directory
  hashshield .

  # Scan a specific directory and force a fresh scan (ignore cache)
  hashshield "C:{os.sep}Users{os.sep}Your Name{os.sep}Downloads" --fresh
"""

    parser = argparse.ArgumentParser(
        description=description_text,
        epilog=epilog_text,
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("scan_path", metavar="PATH", type=str, help="The file or directory path to scan.")
    parser.add_argument(
        "-f", "--fresh",
        action="store_true",
        help="Perform a fresh scan by deleting the existing cache file."
    )
    args = parser.parse_args()

    if args.fresh:
        if CACHE_FILE.exists():
            try:
                CACHE_FILE.unlink()
                print("[*] Cache file deleted for a fresh scan.")
            except OSError as e:
                print(f"{C_RED}[!] Warning: Could not delete cache file: {e}")

    target_path = Path(args.scan_path)
    filepaths_to_scan = []

    if not target_path.exists():
        print(f"{C_RED}FATAL ERROR: The path '{target_path}' does not exist.")
        sys.exit(1)

    if target_path.is_file():
        filepaths_to_scan.append(str(target_path))
    elif target_path.is_dir():
        filepaths_to_scan = get_all_files_recursively(str(target_path))

    if not filepaths_to_scan:
        print("No files to scan. Exiting.")
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

        left_part = f"{status_tag} {filepath}"
        print(f"{left_part:<85} | {message}")

    print("-" * 80)
    print(f"Scan complete. Found {malicious_files_count} malicious file(s).")
    print("-" * 80)

if __name__ == "__main__":
    main()