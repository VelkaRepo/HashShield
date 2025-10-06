import hashlib
import aiohttp
import asyncio
import os
import sys
from dotenv import load_dotenv
from tqdm.asyncio import tqdm
import argparse
from pathlib import Path

# =======================================================
# --- 1. CONFIGURATION ---
# =======================================================

# Load environment variables from the .env file
load_dotenv() 

API_KEY = os.environ.get("VIRUSTOTAL_API_KEY") 
API_URL = "https://www.virustotal.com/api/v3/files/"
BLOCK_SIZE = 65536 # Chunk size for file hashing

# --- PERUBAHAN DI SINI: Path yang lebih kuat dan anti-salah ---
# Build a robust, absolute path relative to the script's location
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SIGNATURE_FILE = PROJECT_ROOT / "signatures.txt"
CACHE_FILE = PROJECT_ROOT / "scan_cache.txt"

# Check for API Key security
if not API_KEY:
    print("FATAL ERROR: VIRUSTOTAL_API_KEY not set!")
    print("Please create a .env file and set the key, or set the environment variable.")
    sys.exit(1)

# =======================================================
# --- 2. CACHE FUNCTIONS (Synchronous) ---
# =======================================================

def load_cache():
    """Loads the scan cache from a file."""
    cache = {}
    if os.path.exists(CACHE_FILE):
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

# =======================================================
# --- BAGIAN BARU: SIGNATURE SCAN FUNCTIONS ---
# =======================================================

def load_signatures():
    """Loads malware signatures from the signature file."""
    signatures = {}
    if os.path.exists(SIGNATURE_FILE):
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

def scan_file_locally(filepath, signatures):
    """Scans a file against a dictionary of local signatures."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            for name, signature in signatures.items():
                if signature in content:
                    return True, name 
    except (IOError, OSError):
        return False, None
    return False, None

# =======================================================
# --- ASYNCHRONOUS CORE FUNCTIONS ---
# =======================================================

async def calculate_file_hash_async(filepath):
    """Calculates the SHA256 hash of a file non-blockingly."""
    def sync_hash():
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while True:
                    data = f.read(BLOCK_SIZE)
                    if not data:
                        break
                    sha256.update(data)
            return sha256.hexdigest()
        except Exception:
            return None
    return await asyncio.to_thread(sync_hash)

async def scan_file_hybrid_async(filepath, cache, session, signatures):
    """
    Scans a file using a hybrid approach: local signatures first, then VirusTotal.
    """
    # 1. Lakukan scan signature lokal terlebih dahulu
    is_malicious_local, detected_by = scan_file_locally(filepath, signatures)
    if is_malicious_local:
        return filepath, True, f"DANGER! Locally detected by signature: {detected_by}"

    # 2. Jika tidak ditemukan, lanjutkan dengan hashing dan scan online
    file_hash = await calculate_file_hash_async(filepath)
    if not file_hash:
        return filepath, False, "Error: Could not calculate file hash."

    # 3. Cek cache lokal
    if file_hash in cache:
        status = cache[file_hash]
        is_malware = status == 'malicious'
        return filepath, is_malware, f"Result from cache: {status}"

    # 4. Panggil API jika tidak ada di cache
    headers = {"x-apikey": API_KEY, "Accept": "application/json"}
    url = f"{API_URL}{file_hash}"
    try:
        async with session.get(url, headers=headers) as response:
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
    except Exception as e:
        return filepath, False, f"Network/Other Error: {e}"

# =======================================================
# --- MAIN EXECUTION ---
# =======================================================

async def main_async_scanner(filepaths):
    """Runs all file scans concurrently and displays progress."""
    scan_cache = load_cache()
    signatures = load_signatures()
    results = []
    
    # Baris debugging untuk memastikan signature termuat
    if signatures:
        print(f"[*] DEBUG: Signatures loaded successfully: {list(signatures.keys())}")
    else:
        print("[!] DEBUG: No signatures were loaded. Check 'signatures.txt' path and content.")

    async with aiohttp.ClientSession() as session:
        tasks = [
            scan_file_hybrid_async(filepath, scan_cache, session, signatures)
            for filepath in filepaths
        ]
        print(f"[*] Starting hybrid scan of {len(filepaths)} files...")
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Scanning Files"):
            result = await coro
            results.append(result)
    return results

def get_all_files_recursively(directory_path):
    """Collects a list of all file paths from a starting directory, recursively."""
    print(f"[*] Searching for files in {directory_path}...")
    filepaths = []
    p = Path(directory_path)
    if not p.exists() or not p.is_dir():
        print(f"[!] Error: Path '{directory_path}' is not a valid directory.")
        return []
    for item in p.rglob('*'):
        if item.is_file():
            filepaths.append(str(item))
    print(f"[*] Found {len(filepaths)} files to scan.")
    return filepaths

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Hybrid Malware Scanner (Local Signature + VirusTotal).",
        epilog="Example: python scanner.py \"C:\\Users\\YourName\\Downloads\""
    )
    parser.add_argument("scan_path", metavar="PATH", type=str, help="The file or directory path to scan.")
    args = parser.parse_args()

    target_path = Path(args.scan_path)
    filepaths_to_scan = []
    if not target_path.exists():
        print(f"FATAL ERROR: The path '{target_path}' does not exist.")
        sys.exit(1)
    if target_path.is_file():
        filepaths_to_scan.append(str(target_path))
    elif target_path.is_dir():
        filepaths_to_scan = get_all_files_recursively(str(target_path))

    if not filepaths_to_scan:
        print("No files to scan. Exiting.")
        sys.exit(0)

    print("\nRunning asynchronous scan...\n")
    results = asyncio.run(main_async_scanner(filepaths_to_scan))

    print("\n\n--- SCAN RESULTS SUMMARY ---")
    malicious_files_count = 0
    for filepath, is_malicious, message in sorted(results):
        if is_malicious:
            status_icon = "⚠️ MALICIOUS"
            malicious_files_count += 1
        else:
            status_icon = "✅ CLEAN"
        print(f"[{status_icon:<12}] {filepath:<60} | {message}")
    
    print("-" * 80)
    print(f"Scan complete. Found {malicious_files_count} malicious file(s).")
    print("-" * 80)