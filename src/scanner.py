import hashlib
import aiohttp
import asyncio
import os
import sys
from dotenv import load_dotenv
from tqdm.asyncio import tqdm

# =======================================================
# --- 1. CONFIGURATION ---
# =======================================================

# Load environment variables from the .env file
load_dotenv() 

API_KEY = os.environ.get("VIRUSTOTAL_API_KEY") 
API_URL = "https://www.virustotal.com/api/v3/files/"
CACHE_FILE = "scan_cache.txt"
BLOCK_SIZE = 65536 # Chunk size for file hashing

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
            # If there's an issue reading, just start with an empty cache
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
# --- 3. ASYNCHRONOUS CORE FUNCTIONS ---
# =======================================================

async def calculate_file_hash_async(filepath):
    """
    Calculates the SHA256 hash of a file in a separate thread 
    to prevent blocking the asyncio event loop.
    """
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

async def scan_file_virustotal_async(filepath, cache, session):
    """
    Scans a file using the VirusTotal API asynchronously and a local cache.
    """
    file_hash = await calculate_file_hash_async(filepath)
    
    if not file_hash:
        return filepath, False, "Error: Could not calculate file hash."

    # 1. Check the local cache first
    if file_hash in cache:
        status = cache[file_hash]
        is_malware = status == 'malicious'
        return filepath, is_malware, f"Result from cache: {status}"

    # 2. API call if not in cache
    headers = {
        "x-apikey": API_KEY,
        "Accept": "application/json"
    }
    url = f"{API_URL}{file_hash}"

    try:
        async with session.get(url, headers=headers) as response:
            
            if response.status == 429:
                return filepath, False, "API Error: Rate limit exceeded. Please wait."
            
            response.raise_for_status() 
            data = await response.json()
            
            is_malicious = False
            report_msg = "Scan complete. File is clean."
            
            if response.status == 200:
                attributes = data.get("data", {}).get("attributes", {})
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                malicious_count = last_analysis_stats.get("malicious", 0)

                if malicious_count > 0:
                    is_malicious = True
                    report_msg = f"DANGER! Detected by {malicious_count} vendors."
                else:
                    report_msg = "Scan complete. File is clean."
            
            elif response.status == 404:
                report_msg = "File hash not found in VirusTotal database. Assumed clean."
            
            # 3. Update and save the cache (synchronous)
            cache[file_hash] = 'malicious' if is_malicious else 'clean'
            save_cache(cache) 

            return filepath, is_malicious, report_msg

    except aiohttp.ClientResponseError as e:
        return filepath, False, f"HTTP Error {e.status}: {e.message}"
    except Exception as e:
        return filepath, False, f"Network/Other Error: {e}"

# =======================================================
# --- 4. MAIN EXECUTION ---
# =======================================================

async def main_async_scanner(filepaths):
    """Runs all file scans concurrently and displays progress."""
    scan_cache = load_cache()
    results = []
    
    # Use aiohttp.ClientSession for connection pooling
    async with aiohttp.ClientSession() as session:
        # Create tasks for all files
        tasks = [
            scan_file_virustotal_async(filepath, scan_cache, session)
            for filepath in filepaths
        ]

        # Run tasks concurrently with a progress bar
        print(f"Starting concurrent scan of {len(filepaths)} files...")
        
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Scanning Files"):
            result = await coro
            results.append(result)

    return results

def setup_test_files():
    """Creates temporary files for demonstration purposes."""
    eicar_test_string = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    
    test_files_data = [
        ("eicar_1.txt", eicar_test_string), 
        ("benign_a.txt", "This is a safe file A."), 
        ("eicar_2.txt", eicar_test_string), # Duplikat untuk menguji cache
        ("benign_b.txt", "This is a safe file B."), 
        ("new_file.txt", "A third unique clean file.") 
    ]
    
    filepaths_to_scan = []
    try:
        for filename, content in test_files_data:
            with open(filename, "w") as f:
                f.write(content)
            filepaths_to_scan.append(filename)
        print("Test files created.")
        return filepaths_to_scan
    except IOError as e:
        print(f"Could not create test files: {e}")
        return []

def cleanup(filepaths_to_scan):
    """Removes temporary files and cache file."""
    for filepath in filepaths_to_scan:
        if os.path.exists(filepath):
            os.remove(filepath)
    
    if os.path.exists(CACHE_FILE):
        os.remove(CACHE_FILE)
    print("\nTest files and cache removed.")

if __name__ == "__main__":
    
    filepaths_to_scan = setup_test_files()
    if not filepaths_to_scan:
        sys.exit(1)

    print("Running asynchronous scan...\n")

    # The main entry point for running async code
    results = asyncio.run(main_async_scanner(filepaths_to_scan))

    # --- Print Final Results ---
    print("\n\n--- SCAN RESULTS SUMMARY ---")
    for filepath, is_malicious, message in results:
        status_icon = "⚠️ MALICIOUS" if is_malicious else "✅ CLEAN"
        print(f"[{status_icon:<12}] {filepath:<15} | {message}")
    print("-" * 35)

    cleanup(filepaths_to_scan)